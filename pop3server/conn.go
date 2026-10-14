package pop3server

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// connState represents the POP3 session state (RFC 1939 §4).
type connState int

const (
	stateAuthorization connState = iota // Before authentication
	stateTransaction                    // After successful authentication
)

// Conn is a POP3 connection. It holds the per-connection state and drives
// the command loop. The consumer receives a *Conn in the NewSession callback
// to inspect the peer address, TLS state, etc.
type Conn struct {
	netConn net.Conn
	server  *Server
	reader  *bufio.Reader
	writer  *bufio.Writer
	session Session
	state   connState
	ctx     context.Context
	cancel  context.CancelFunc

	// rawConn is the connection as originally accepted. STLS replaces
	// netConn with a *tls.Conn that wraps it, but never rawConn, so deadline
	// operations on rawConn always reach the socket — including from another
	// goroutine while this one is blocked mid-handshake.
	rawConn net.Conn

	// deadlineMu serialises read-deadline changes against forceReadUnblock.
	// Once poisoned is set (server shutdown), no later SetReadDeadline may
	// re-arm or clear the expired deadline, or a read racing with Close could
	// block again and outlive Server.Close.
	deadlineMu sync.Mutex
	poisoned   bool

	// Pre-auth state for USER/PASS two-step flow.
	username string

	// rawArg holds the current command's argument as the untokenised
	// remainder of the line (delimiter stripped, internal/trailing
	// whitespace preserved). handlePass reads it so a password's embedded
	// whitespace survives; other handlers use the tokenised args slice.
	rawArg string

	// Error tracking
	errorCount int

	// TLS state
	isTLS bool

	// Session start time for absolute session timeout.
	startTime time.Time

	// hijacked is set by Hijack: the library stops driving the connection
	// and no longer closes the underlying net.Conn.
	hijacked bool

	// closePending is set by sessionError when a handler's error requests
	// connection closure (via *Error{Close:true} or ErrCloseConnection).
	closePending bool

	// lastErr holds the session error produced by the current command, for
	// the OnCommand observability hook.
	lastErr error
}

// Context returns the connection-scoped context, cancelled when the
// connection is closed or the server shuts down.
func (c *Conn) Context() context.Context {
	return c.ctx
}

// NetConn returns the underlying net.Conn. Useful for consumers that need
// to inspect the peer address, apply PROXY protocol, etc.
func (c *Conn) NetConn() net.Conn {
	return c.netConn
}

// IsTLS reports whether the connection is currently using TLS (either
// implicit TLS or upgraded via STLS).
func (c *Conn) IsTLS() bool {
	return c.isTLS
}

// SetTLS overrides the library's TLS detection. Call it from NewSession when
// the connection is TLS but the library cannot detect it (e.g. an implicit-TLS
// listener that hands out a wrapper type the unwrap walk does not recognise).
func (c *Conn) SetTLS(v bool) {
	c.isTLS = v
}

// Session returns the session associated with this connection. It is set once
// NewSession returns and is primarily intended for UnknownCommandHandler
// implementations that need to reach the consumer's own session state.
func (c *Conn) Session() Session {
	return c.session
}

// OK writes a "+OK" response line (with the given message when non-empty).
// Exposed for UnknownCommandHandler implementations.
func (c *Conn) OK(msg string) { c.ok(msg) }

// Err writes a "-ERR" response line (with the given message when non-empty).
// Exposed for UnknownCommandHandler implementations.
func (c *Conn) Err(msg string) { c.err(msg) }

// Hijack detaches the underlying connection from the library's command loop.
// It may only be called from within a Session's Login or AuthenticatePlain
// method (i.e. while the connection is still in the AUTHORIZATION state).
//
// On success the library will not write any further response for the current
// command, will exit the command loop as soon as the authenticating method
// returns, and will NOT close the returned net.Conn (the caller owns it).
// Session.Close is still invoked exactly once during teardown.
//
// It returns the raw net.Conn together with a *bufio.Reader holding any bytes
// already buffered from the client, so a command pipelined in the same TCP
// segment as PASS/AUTH is preserved for the caller (e.g. a proxy taking over
// the relay). This is analogous to net/http's Hijacker.
//
// The connection-scoped context (Conn.Context) is cancelled as soon as the
// authenticating method returns, because the library's command loop exits at
// that point. The hijacker must therefore manage the relay's lifetime with
// its own context and must not derive it from Conn.Context.
func (c *Conn) Hijack() (net.Conn, *bufio.Reader, error) {
	if c.state != stateAuthorization {
		return nil, nil, errors.New("pop3server: Hijack only valid during authentication")
	}
	if c.hijacked {
		return nil, nil, errors.New("pop3server: connection already hijacked")
	}
	// Flush anything we may have queued before handing off write ownership.
	if err := c.writer.Flush(); err != nil {
		return nil, nil, err
	}
	c.setDeadline(time.Time{})
	c.hijacked = true
	c.server.unregisterConn(c)
	return c.netConn, c.reader, nil
}

// serve runs the POP3 command loop for this connection.
func (c *Conn) serve() {
	defer c.cancel()
	defer c.close()

	opts := c.server.opts

	// Send greeting
	c.ok(opts.Greeting)
	if err := c.writer.Flush(); err != nil {
		return
	}

	for {
		if c.server.ctx.Err() != nil {
			return
		}

		// Set idle timeout for reading the next command.
		if d := c.nextReadDeadline(); !d.IsZero() {
			c.setReadDeadline(d)
		}

		line, err := c.readLine()
		if err != nil {
			if c.server.ctx.Err() != nil {
				// Server.Close kicked this connection out of its blocked read.
				return
			}
			if isTimeout(err) {
				// Distinguish absolute session timeout from idle timeout.
				if opts.AbsoluteSessionTimeout > 0 && time.Since(c.startTime) >= opts.AbsoluteSessionTimeout {
					c.err("[IN-USE] Maximum session duration exceeded")
					c.writer.Flush()
					opts.Logger.Info("POP3: absolute session timeout",
						"duration", time.Since(c.startTime))
					if h := opts.OnTimeout; h != nil {
						h(TimeoutAbsolute)
					}
				} else {
					c.err("Idle timeout, connection timed out")
					c.writer.Flush()
					opts.Logger.Info("POP3: connection timed out")
					if h := opts.OnTimeout; h != nil {
						h(TimeoutIdle)
					}
				}
			} else if errors.Is(err, errLineTooLong) {
				// Courtesy response before dropping: the oversized line was
				// not drained, so resuming the parser is not safe.
				c.err("Line too long")
				c.writer.Flush()
			}
			return
		}

		if strings.TrimSpace(line) == "" {
			continue
		}
		line = strings.TrimLeft(line, " \t")

		// Parse command and arguments. The verb is split from its raw
		// argument so PASS can recover a password containing runs of
		// whitespace or tabs (strings.Fields would collapse them); every
		// other command uses the tokenised args, which are identical to the
		// previous strings.Fields(line) result.
		verb, rawArg := splitCommand(line)
		cmd := strings.ToUpper(verb)
		args := strings.Fields(rawArg)
		c.rawArg = rawArg

		// Create per-command context with optional timeout.
		cmdCtx := c.ctx
		var cmdCancel context.CancelFunc
		if opts.CommandTimeout > 0 {
			cmdCtx, cmdCancel = context.WithTimeout(c.ctx, opts.CommandTimeout)
		} else {
			cmdCtx, cmdCancel = context.WithCancel(c.ctx)
		}

		// Clear the connection deadline during command execution (the
		// per-command context governs cancellation now). Write deadlines,
		// when configured, are re-armed per write by writeDeadlineConn.
		c.setDeadline(time.Time{})

		c.lastErr = nil
		start := time.Now()
		quit := c.dispatch(cmdCtx, cmd, args)
		cmdCancel()

		if h := opts.OnCommand; h != nil {
			h(cmd, time.Since(start), c.lastErr)
		}

		// A handler hijacked the connection: ownership has transferred, so
		// do not flush or close via the loop.
		if c.hijacked {
			return
		}

		// Central enforcement: a handler may have requested closure, and any
		// error-counting path (failed login, bad SASL, unknown command) is
		// checked here so no path can bypass MaxErrors (see E1).
		if !quit && c.closePending {
			quit = true
		}
		if !quit && c.maxErrorsExceeded() {
			c.err("Too many errors, closing connection")
			quit = true
		}

		// Flush response to the client.
		if err := c.writer.Flush(); err != nil {
			if isTimeout(err) {
				opts.Logger.Info("POP3: write timeout", "command", cmd)
			}
			return
		}

		if quit {
			return
		}
	}
}

// setReadDeadline arms (or, with the zero Time, clears) the read deadline,
// unless the connection has been poisoned by server shutdown, in which case
// the already-expired deadline is left in place so pending and future reads
// fail immediately.
func (c *Conn) setReadDeadline(t time.Time) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.poisoned {
		return
	}
	c.netConn.SetReadDeadline(t)
}

// setDeadline is setReadDeadline's counterpart for the paths that arm both
// read and write deadlines (the STLS handshake, the per-command clear).
func (c *Conn) setDeadline(t time.Time) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.poisoned {
		return
	}
	c.netConn.SetDeadline(t)
}

// forceReadUnblock permanently expires the read deadline. Server.Close uses
// it to kick a connection out of a blocked read (cancelling a context cannot
// unblock net.Conn reads); serve then observes the cancelled context and
// exits. It targets rawConn so the poke reaches the socket even while netConn
// is being swapped by a STLS upgrade, and it marks the connection poisoned so
// a SetReadDeadline racing with shutdown cannot re-arm a live deadline.
func (c *Conn) forceReadUnblock() {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.poisoned = true
	c.rawConn.SetReadDeadline(time.Now())
}

// nextReadDeadline computes the read deadline for the next command, honouring
// AuthIdleTimeout during AUTHORIZATION and capping to AbsoluteSessionTimeout.
// Returns the zero Time when no deadline applies.
func (c *Conn) nextReadDeadline() time.Time {
	opts := c.server.opts

	idleTimeout := opts.IdleTimeout
	if c.state == stateAuthorization && opts.AuthIdleTimeout > 0 {
		idleTimeout = opts.AuthIdleTimeout
	}

	var deadline time.Time
	if idleTimeout > 0 {
		deadline = time.Now().Add(idleTimeout)
	}
	if opts.AbsoluteSessionTimeout > 0 {
		absDeadline := c.startTime.Add(opts.AbsoluteSessionTimeout)
		if deadline.IsZero() || absDeadline.Before(deadline) {
			deadline = absDeadline
		}
	}
	return deadline
}

// dispatch executes a single POP3 command. Returns true if the connection
// should be closed (QUIT, too many errors).
func (c *Conn) dispatch(ctx context.Context, cmd string, args []string) bool {
	opts := c.server.opts

	switch c.state {
	case stateAuthorization:
		return c.dispatchAuth(ctx, cmd, args)
	case stateTransaction:
		return c.dispatchTransaction(ctx, cmd, args)
	default:
		c.err("Internal server error")
		opts.Logger.Error("POP3: unknown connection state", "state", c.state)
		return true
	}
}

// dispatchAuth handles commands in the AUTHORIZATION state.
func (c *Conn) dispatchAuth(ctx context.Context, cmd string, args []string) bool {
	switch cmd {
	case "CAPA":
		c.handleCapa(args)
	case "USER":
		c.handleUser(args)
	case "PASS":
		c.handlePass(ctx)
	case "AUTH":
		c.handleAuth(ctx, args)
	case "STLS":
		c.handleSTLS(ctx, args)
	case "QUIT":
		if len(args) > 0 {
			c.clientError("Syntax: QUIT")
			return false
		}
		c.ok("Goodbye")
		return true
	case "UTF8":
		// RFC 6856 §2: the UTF8 command is only valid in the AUTHORIZATION
		// state (it must precede the credentials it applies to).
		c.handleUTF8(ctx, args)
	case "LANG":
		// RFC 6856 §3: LANG is valid in both AUTHORIZATION and TRANSACTION.
		c.handleLang(ctx, args)
	case "STAT", "LIST", "UIDL", "RETR", "TOP", "DELE", "RSET", "NOOP":
		// TRANSACTION-state commands before authentication (RFC 1939 §5; NOOP
		// is TRANSACTION-only per §5 as well). A known verb in the wrong state
		// is a client protocol error, not an unknown command.
		c.clientError("Not authenticated")
	case "LAST":
		// LAST is obsolete (RFC 1081, removed in RFC 1939). Legacy clients
		// probe for it; reject without counting as an error.
		c.err("LAST is obsolete (RFC 1939)")
	default:
		return c.dispatchUnknown(ctx, cmd, args)
	}
	return false
}

// dispatchTransaction handles commands in the TRANSACTION state.
func (c *Conn) dispatchTransaction(ctx context.Context, cmd string, args []string) bool {
	switch cmd {
	case "CAPA":
		c.handleCapa(args)
	case "STAT":
		c.handleStat(ctx, args)
	case "LIST":
		c.handleList(ctx, args)
	case "UIDL":
		c.handleUidl(ctx, args)
	case "RETR":
		c.handleRetr(ctx, args)
	case "TOP":
		c.handleTop(ctx, args)
	case "DELE":
		c.handleDele(ctx, args)
	case "RSET":
		c.handleRset(ctx, args)
	case "NOOP":
		c.handleNoop(ctx, args)
	case "QUIT":
		return c.handleQuit(ctx, args)
	case "LANG":
		c.handleLang(ctx, args)
	case "UTF8":
		// RFC 6856 §2 restricts UTF8 to the AUTHORIZATION state, but classic
		// Outlook sends it right after PASS whenever CAPA advertised it, and
		// treats the -ERR as a fatal server error (0x800CCC90): it drops the
		// connection and fails the whole download. Large providers accept the
		// post-auth form for the same reason, so accept it here too — enabling
		// UTF-8 mid-session only widens what the responses may carry.
		c.handleUTF8(ctx, args)
	case "USER", "PASS", "AUTH":
		// AUTHORIZATION-state commands after authentication (RFC 1939 §5,
		// RFC 5034 §4). A known verb in the wrong state is a client protocol
		// error, not an unknown command.
		c.clientError("Already authenticated")
	case "STLS":
		// RFC 2595 §4: STLS is only valid in AUTHORIZATION state.
		c.clientError("STLS only allowed before authentication")
	case "LAST":
		c.err("LAST is obsolete (RFC 1939)")
	default:
		return c.dispatchUnknown(ctx, cmd, args)
	}
	return false
}

// dispatchUnknown handles a command not recognised by the built-in
// dispatcher, giving the consumer's UnknownCommandHandler first refusal
// before counting the command against MaxErrors.
func (c *Conn) dispatchUnknown(ctx context.Context, cmd string, args []string) bool {
	if h := c.server.opts.UnknownCommandHandler; h != nil {
		if handled, closeConn := h(ctx, c, cmd, args); handled {
			return closeConn
		}
	}
	c.lastErr = fmt.Errorf("unknown command: %s", cmd)
	c.clientError("Unknown command: " + cmd)
	// Closure, if warranted, is applied centrally in serve via maxErrorsExceeded.
	return false
}

// --- Command handlers ---

// capSuppressed reports whether a capability name is listed in
// Options.SuppressedCaps (case-insensitive). Suppression hides the
// advertisement only; the command stays functional.
func (c *Conn) capSuppressed(name string) bool {
	for _, s := range c.server.opts.SuppressedCaps {
		if strings.EqualFold(s, name) {
			return true
		}
	}
	return false
}

// writeCap writes one capability line unless the name is suppressed.
func (c *Conn) writeCap(name string, params ...string) {
	if c.capSuppressed(name) {
		return
	}
	c.writer.WriteString(name)
	if len(params) > 0 {
		c.writer.WriteString(" ")
		c.writer.WriteString(strings.Join(params, " "))
	}
	c.writer.WriteString("\r\n")
}

func (c *Conn) handleCapa(args []string) {
	if len(args) > 0 {
		c.clientError("Syntax: CAPA")
		return
	}
	opts := c.server.opts
	authAllowed := opts.InsecureAuth || c.isTLS

	c.writer.WriteString("+OK Capability list follows\r\n")
	c.writeCap("TOP")
	c.writeCap("UIDL")
	if authAllowed {
		c.writeCap("USER")
	}
	c.writeCap("RESP-CODES")
	c.writeCap("PIPELINING")

	// STLS: only advertise when TLS is available and we're not already on TLS
	if opts.TLSConfig != nil && !c.isTLS {
		c.writeCap("STLS")
	}

	// SASL: advertise if the session supports it and auth is allowed
	if authAllowed {
		if sasl, ok := c.session.(SessionSASL); ok {
			mechs := sasl.AuthenticateMechanisms()
			if len(mechs) > 0 {
				c.writeCap("SASL", mechs...)
			}
		}
	}

	// LANG / UTF8
	if _, ok := c.session.(SessionLang); ok {
		c.writeCap("LANG")
	}
	if _, ok := c.session.(SessionUTF8); ok {
		c.writeCap("UTF8")
	}

	// Custom capabilities from server options
	for _, cap := range opts.Caps {
		c.writeCap(cap.Name, cap.Params...)
	}

	c.writer.WriteString(".\r\n")
}

func (c *Conn) handleUser(args []string) {
	if !c.authAllowed() {
		c.clientError("Authentication requires TLS. Use STLS first")
		return
	}
	if len(args) != 1 {
		c.clientError("Syntax: USER <username>")
		return
	}
	// Control characters (including NUL) are invalid in POP3 arguments
	// (RFC 1939 §3) and would corrupt downstream credential frames a consumer
	// builds from the username (e.g. a proxy's SASL PLAIN re-authentication).
	if containsCTL(args[0]) {
		c.clientError("Invalid username")
		return
	}
	c.username = args[0]
	c.ok("")
}

func (c *Conn) handlePass(ctx context.Context) {
	if !c.authAllowed() {
		c.clientError("Authentication requires TLS. Use STLS first")
		return
	}
	if c.username == "" {
		c.clientError("Send USER first")
		return
	}
	// The password is the raw remainder of the PASS line, not the tokenised
	// args: it may legitimately contain runs of spaces or tabs.
	password := c.rawArg
	if password == "" {
		c.clientError("Syntax: PASS <password>")
		return
	}

	if err := c.session.Login(ctx, c.username, password); err != nil {
		if !c.server.opts.AuthFailuresExemptFromMaxErrors {
			c.errorCount++
		}
		c.applyErrorDelay()
		c.sessionError(err)
		// The username is retained so the client may retry with a bare PASS
		// (RFC 1939 permits either; retaining matches common server behavior).
		return
	}

	// The session may have hijacked the connection during Login (proxy
	// hand-off): if so, do not emit a success response.
	if c.hijacked {
		return
	}

	c.state = stateTransaction
	c.ok("Authentication successful")
}

func (c *Conn) handleAuth(ctx context.Context, args []string) {
	if !c.authAllowed() {
		c.clientError("Authentication requires TLS. Use STLS first")
		return
	}

	sasl, ok := c.session.(SessionSASL)
	if !ok {
		c.clientError("SASL not supported")
		return
	}

	if len(args) > 2 {
		c.clientError("Syntax: AUTH [mechanism [initial-response]]")
		return
	}

	if len(args) < 1 {
		// AUTH with no args: list mechanisms
		c.writer.WriteString("+OK\r\n")
		for _, mech := range sasl.AuthenticateMechanisms() {
			c.writer.WriteString(mech)
			c.writer.WriteString("\r\n")
		}
		c.writer.WriteString(".\r\n")
		return
	}

	// The library implements the PLAIN exchange only; verify the requested
	// mechanism is one the session actually advertises (see G7).
	mech := strings.ToUpper(args[0])
	if mech != "PLAIN" || !mechanismAdvertised(sasl, "PLAIN") {
		c.clientError("Unsupported SASL mechanism")
		return
	}

	// AUTH PLAIN can carry the initial response on the same line or as a
	// continuation.
	var encoded string
	if len(args) > 1 {
		encoded = args[1]
	} else {
		// Send continuation prompt.
		c.writer.WriteString("+ \r\n")
		c.writer.Flush()

		// Bound the continuation read so a client that requests AUTH PLAIN
		// and then goes silent cannot hold the connection open (pre-auth
		// slowloris — see E2). The command loop cleared the deadline.
		if d := c.nextReadDeadline(); !d.IsZero() {
			c.setReadDeadline(d)
		}
		line, readErr := c.readLine()
		c.setReadDeadline(time.Time{})
		if readErr != nil {
			// A silent client (or one that dropped) must not linger; tear the
			// connection down now instead of waiting another idle cycle (E2).
			c.closePending = true
			return
		}
		encoded = strings.TrimSpace(line)
	}

	// Abort
	if encoded == "*" {
		c.err("Authentication aborted")
		return
	}

	identity, username, password, parseErr := decodeSASLPlain(encoded)
	if parseErr != nil {
		c.lastErr = parseErr
		c.clientError("Invalid SASL PLAIN response")
		return
	}

	if err := sasl.AuthenticatePlain(ctx, identity, username, password); err != nil {
		if !c.server.opts.AuthFailuresExemptFromMaxErrors {
			c.errorCount++
		}
		c.applyErrorDelay()
		c.sessionError(err)
		return
	}

	if c.hijacked {
		return
	}

	c.state = stateTransaction
	c.ok("Authentication successful")
}

func (c *Conn) handleSTLS(ctx context.Context, args []string) {
	if len(args) > 0 {
		c.clientError("Syntax: STLS")
		return
	}
	opts := c.server.opts

	if c.isTLS {
		c.clientError("Already using TLS")
		return
	}
	if opts.TLSConfig == nil {
		c.clientError("TLS not available")
		return
	}
	if c.state != stateAuthorization {
		c.clientError("STLS only allowed before authentication")
		return
	}

	// Reject plaintext bytes pipelined after STLS: they would either be lost
	// (a ClientHello buffered here never reaches the handshake below) or, in
	// the response-injection case, attacker-supplied plaintext smuggled ahead
	// of the TLS upgrade. The client must wait for +OK before negotiating.
	if c.reader.Buffered() > 0 {
		c.clientError("Pipelining after STLS not permitted")
		c.closePending = true
		return
	}

	c.ok("Begin TLS negotiation")
	c.writer.Flush()

	tlsConn := tls.Server(c.netConn, opts.TLSConfig)

	// Bound the handshake: a client that sends STLS and then stalls mid-
	// negotiation must not hold the connection open indefinitely (a pre-auth
	// slowloris). Use the same idle deadline that governs command reads; the
	// per-command ctx additionally aborts the handshake on server shutdown or
	// CommandTimeout.
	if d := c.nextReadDeadline(); !d.IsZero() {
		c.setDeadline(d)
	}
	err := tlsConn.HandshakeContext(ctx)
	c.setDeadline(time.Time{})
	if err != nil {
		// The peer has already switched to TLS, so no plaintext -ERR can be
		// delivered; drop the connection rather than looping in a broken state
		// (the old plaintext reader would only see TLS record bytes).
		opts.Logger.Warn("POP3: TLS handshake failed", "error", err)
		c.closePending = true
		return
	}

	c.netConn = tlsConn
	c.reader = bufio.NewReader(tlsConn)
	c.writer = c.server.newWriter(tlsConn)
	c.isTLS = true

	// RFC 2595 §4: the server MUST discard knowledge obtained from the client
	// prior to the TLS negotiation. A USER sent over plaintext (possible only
	// with InsecureAuth) must not pair with a post-upgrade PASS.
	c.username = ""
}

func (c *Conn) handleStat(ctx context.Context, args []string) {
	if len(args) > 0 {
		c.clientError("Syntax: STAT")
		return
	}
	count, size, err := c.session.Stat(ctx)
	if err != nil {
		c.sessionError(err)
		return
	}
	fmt.Fprintf(c.writer, "+OK %d %d\r\n", count, size)
}

func (c *Conn) handleList(ctx context.Context, args []string) {
	msg, err := c.parseOptionalMsgNum(args)
	if err != nil {
		c.clientError(err.Error())
		return
	}

	items, listErr := c.session.List(ctx, msg)
	if listErr != nil {
		c.sessionError(listErr)
		return
	}

	if msg > 0 {
		// A single-message query gets a single-line response. A Session that
		// returns anything but exactly one item here has violated the
		// contract; emitting the multi-line form instead would desync the
		// client's framing (it wouldn't consume the ".\r\n"), so fail closed.
		if len(items) != 1 {
			c.sessionError(&Error{Message: "No such message"})
			return
		}
		fmt.Fprintf(c.writer, "+OK %d %d\r\n", items[0].Num, items[0].Size)
		return
	}

	// Multi-line response
	fmt.Fprintf(c.writer, "+OK %d messages\r\n", len(items))
	for _, item := range items {
		fmt.Fprintf(c.writer, "%d %d\r\n", item.Num, item.Size)
	}
	c.writer.WriteString(".\r\n")
}

func (c *Conn) handleUidl(ctx context.Context, args []string) {
	msg, err := c.parseOptionalMsgNum(args)
	if err != nil {
		c.clientError(err.Error())
		return
	}

	items, uidlErr := c.session.Uidl(ctx, msg)
	if uidlErr != nil {
		c.sessionError(uidlErr)
		return
	}

	if msg > 0 {
		// Same contract enforcement as handleList: never answer a
		// single-message query with a multi-line response.
		if len(items) != 1 {
			c.sessionError(&Error{Message: "No such message"})
			return
		}
		c.writer.WriteString(fmt.Sprintf("+OK %d %s\r\n", items[0].Num, sanitizeResponse(items[0].UniqueID)))
		return
	}

	c.writer.WriteString(fmt.Sprintf("+OK %d messages\r\n", len(items)))
	for _, item := range items {
		c.writer.WriteString(fmt.Sprintf("%d %s\r\n", item.Num, sanitizeResponse(item.UniqueID)))
	}
	c.writer.WriteString(".\r\n")
}

func (c *Conn) handleRetr(ctx context.Context, args []string) {
	msg, err := c.parseMsgNum(args)
	if err != nil {
		c.clientError(err.Error())
		return
	}

	body, retrErr := c.session.Retr(ctx, msg)
	if retrErr != nil {
		c.sessionError(retrErr)
		return
	}
	defer body.Close()

	// Announce the exact octet count when the session provided one via
	// SizedBody; byte-counting clients use it to track download progress.
	if sb, ok := body.(*sizedBody); ok {
		c.ok(fmt.Sprintf("%d octets", sb.octets))
	} else {
		c.ok("Message follows")
	}
	c.writer.Flush()

	dsw := newDotStuffWriter(c.writer)
	if _, copyErr := io.Copy(dsw, body); copyErr != nil {
		// The +OK line is already on the wire, so no -ERR can follow — and a
		// body READ error leaves the multiline response unterminated on an
		// otherwise healthy connection, where anything written next would be
		// parsed as message content. The only safe move is to drop the
		// connection (a connection write error ends up here too; closing is
		// equally correct then).
		c.lastErr = copyErr
		c.closePending = true
		return
	}
	dsw.Close()
}

func (c *Conn) handleTop(ctx context.Context, args []string) {
	if len(args) != 2 {
		c.clientError("Syntax: TOP <msg> <lines>")
		return
	}

	msg, err := c.parseMsgNum(args[:1])
	if err != nil {
		c.clientError(err.Error())
		return
	}

	lines, parseErr := parseInt(args[1])
	if parseErr != nil || lines < 0 {
		c.clientError("Invalid number of lines")
		return
	}

	body, topErr := c.session.Top(ctx, msg, lines)
	if topErr != nil {
		c.sessionError(topErr)
		return
	}
	defer body.Close()

	c.ok("Top of message follows")
	c.writer.Flush()

	dsw := newDotStuffWriter(c.writer)
	if _, copyErr := io.Copy(dsw, body); copyErr != nil {
		// Same as handleRetr: the multiline response is unterminated, so the
		// connection must be dropped rather than resumed.
		c.lastErr = copyErr
		c.closePending = true
		return
	}
	dsw.Close()
}

func (c *Conn) handleDele(ctx context.Context, args []string) {
	msg, err := c.parseMsgNum(args)
	if err != nil {
		c.clientError(err.Error())
		return
	}

	if deleErr := c.session.Dele(ctx, msg); deleErr != nil {
		c.sessionError(deleErr)
		return
	}
	c.ok("Message deleted")
}

func (c *Conn) handleRset(ctx context.Context, args []string) {
	if len(args) > 0 {
		c.clientError("Syntax: RSET")
		return
	}
	if err := c.session.Rset(ctx); err != nil {
		c.sessionError(err)
		return
	}
	c.ok("Maildrop has been reset")
}

func (c *Conn) handleNoop(ctx context.Context, args []string) {
	if len(args) > 0 {
		c.clientError("Syntax: NOOP")
		return
	}
	if err := c.session.Noop(ctx); err != nil {
		c.sessionError(err)
		return
	}
	c.ok("")
}

func (c *Conn) handleQuit(ctx context.Context, args []string) bool {
	if len(args) > 0 {
		c.clientError("Syntax: QUIT")
		return false
	}
	expunged, err := c.session.Quit(ctx)
	if err != nil {
		c.sessionError(err)
		return true
	}
	if expunged > 0 {
		c.writer.WriteString(fmt.Sprintf("+OK %d messages expunged\r\n", expunged))
	} else {
		c.ok("Goodbye")
	}
	return true
}

func (c *Conn) handleLang(ctx context.Context, args []string) {
	lang, ok := c.session.(SessionLang)
	if !ok {
		c.clientError("LANG not supported")
		return
	}
	if len(args) > 1 {
		c.clientError("Syntax: LANG [tag]")
		return
	}

	if len(args) == 0 {
		// List available languages
		langs, err := lang.ListLanguages(ctx)
		if err != nil {
			c.sessionError(err)
			return
		}
		c.writer.WriteString("+OK Language list follows\r\n")
		for _, l := range langs {
			fmt.Fprintf(c.writer, "%s %s\r\n", sanitizeResponse(l.Tag), sanitizeResponse(l.Description))
		}
		c.writer.WriteString(".\r\n")
		return
	}

	// Set language
	tag, err := lang.SetLanguage(ctx, args[0])
	if err != nil {
		c.sessionError(err)
		return
	}
	fmt.Fprintf(c.writer, "+OK Language set to %s\r\n", sanitizeResponse(tag))
}

func (c *Conn) handleUTF8(ctx context.Context, args []string) {
	if len(args) > 0 {
		c.clientError("Syntax: UTF8")
		return
	}
	utf8, ok := c.session.(SessionUTF8)
	if !ok {
		c.clientError("UTF8 not supported")
		return
	}

	if err := utf8.EnableUTF8(ctx); err != nil {
		c.sessionError(err)
		return
	}
	c.ok("UTF8 mode enabled")
}

// --- Response helpers ---

func (c *Conn) ok(msg string) {
	if msg == "" {
		c.writer.WriteString("+OK\r\n")
	} else {
		c.writer.WriteString("+OK ")
		c.writer.WriteString(sanitizeResponse(msg))
		c.writer.WriteString("\r\n")
	}
}

func (c *Conn) err(msg string) {
	if msg == "" {
		c.writer.WriteString("-ERR\r\n")
	} else {
		c.writer.WriteString("-ERR ")
		c.writer.WriteString(sanitizeResponse(msg))
		c.writer.WriteString("\r\n")
	}
}

// clientError records a client protocol error — bad syntax, an invalid
// argument, a command sent in the wrong state, or an unknown/unsupported
// command — then applies the progressive error delay and writes the -ERR
// response. It is the single choke point that feeds MaxErrors, so brute-force
// and fuzzing via malformed commands are bounded exactly like failed logins.
//
// Errors returned by a Session are deliberately NOT routed here (see
// sessionError): the library cannot distinguish a client fault ("no such
// message") from a transient server-side failure (a backend timeout), so those
// must not count against the client. A session that wants a specific error to
// be fatal signals it with *Error{Close: true} or ErrCloseConnection.
func (c *Conn) clientError(msg string) {
	c.errorCount++
	// Surface the error to the OnCommand hook (unless the handler already
	// recorded a more specific one) so protocol errors the library detects
	// are not reported as successful commands.
	if c.lastErr == nil {
		c.lastErr = &Error{Message: msg}
	}
	c.applyErrorDelay()
	c.err(msg)
}

// sessionError maps an error returned by a Session method onto a -ERR
// response and records whether the connection should be closed afterwards.
//
//   - *Error: its Code/Message are sent and Close is honoured.
//   - ErrCloseConnection (bare or wrapped): a generic "internal error" is
//     sent and the connection is closed.
//   - any other error: its text is forwarded as-is (the documented Session
//     contract), unless Options.StrictSessionErrors is set, in which case a
//     generic "internal error" is sent and the original error is logged.
//     Sessions that must not leak internal strings should return an *Error
//     (or enable StrictSessionErrors as a safety net).
func (c *Conn) sessionError(err error) {
	c.lastErr = err

	var perr *Error
	if errors.As(err, &perr) {
		c.err(perr.wireMessage())
		if perr.Close {
			c.closePending = true
		}
		return
	}

	if errors.Is(err, ErrCloseConnection) {
		c.err("internal error")
		c.closePending = true
		return
	}

	if c.server.opts.StrictSessionErrors {
		c.server.opts.Logger.Warn("POP3: masked plain session error (StrictSessionErrors)",
			"error", err, "remote", c.netConn.RemoteAddr())
		c.err("internal error")
		return
	}

	c.err(err.Error())
}

// --- Internal helpers ---

// errLineTooLong is returned by readLine when a line exceeds MaxLineLength.
// The command loop sends a courtesy "-ERR Line too long" before dropping the
// connection (the remainder of the oversized line is not drained, so the
// parser cannot safely resume).
var errLineTooLong = errors.New("line too long")

func (c *Conn) readLine() (string, error) {
	maxLen := c.server.opts.MaxLineLength
	var line []byte
	for {
		chunk, isPrefix, err := c.reader.ReadLine()
		if err != nil {
			return "", err
		}
		line = append(line, chunk...)
		if !isPrefix {
			break
		}
		if len(line) > maxLen {
			return "", errLineTooLong
		}
	}
	if len(line) > maxLen {
		return "", errLineTooLong
	}
	return string(line), nil
}

func (c *Conn) authAllowed() bool {
	return c.server.opts.InsecureAuth || c.isTLS
}

// applyErrorDelay sleeps for a progressive, capped back-off after a client
// error. The sleep is interruptible by connection/server shutdown so it never
// blocks Server.Close (see E6).
func (c *Conn) applyErrorDelay() {
	delay := c.server.opts.ErrorDelay
	if delay <= 0 {
		return
	}
	d := time.Duration(c.errorCount) * delay
	if limit := c.server.opts.MaxErrorDelay; limit > 0 && d > limit {
		d = limit
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-c.ctx.Done():
	}
}

// maxErrorsExceeded reports whether the client has hit the MaxErrors limit.
// A non-positive MaxErrors disables the limit (see E5).
func (c *Conn) maxErrorsExceeded() bool {
	max := c.server.opts.MaxErrors
	return max > 0 && c.errorCount >= max
}

func (c *Conn) close() {
	if c.session != nil {
		c.session.Close()
	}
	if !c.hijacked {
		c.netConn.Close()
	}
}

func (c *Conn) parseOptionalMsgNum(args []string) (int, error) {
	if len(args) == 0 {
		return 0, nil
	}
	return c.parseMsgNum(args)
}

func (c *Conn) parseMsgNum(args []string) (int, error) {
	if len(args) < 1 {
		return 0, errors.New("message number required")
	}
	if len(args) > 1 {
		return 0, errors.New("too many arguments")
	}
	n, err := parseInt(args[0])
	if err != nil || n < 1 {
		return 0, errors.New("invalid message number")
	}
	return n, nil
}

// --- Utility functions ---

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// splitCommand separates the command verb from its raw argument string. The
// verb is the text up to the first space or tab; the argument is the
// remainder with that single delimiter removed but its own internal and
// trailing whitespace preserved. Unlike strings.Fields it keeps a password's
// embedded whitespace intact, which matters for PASS.
func splitCommand(line string) (verb, arg string) {
	i := strings.IndexAny(line, " \t")
	if i < 0 {
		return line, ""
	}
	return line[:i], line[i+1:]
}

// sanitizeResponse strips CR and LF from a session-supplied string before it
// is written into a response line, so a value derived from message data or an
// upstream server (a UIDL unique-id, a LANG tag, a Session error message)
// cannot smuggle extra response lines or a premature "." terminator onto the
// wire. The common case (no CR/LF present) allocates nothing.
func sanitizeResponse(s string) string {
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// parseInt parses a non-negative decimal integer, rejecting anything that is
// not all-digits or that would overflow a POP3 message number. POP3 message
// numbers and TOP line counts fit comfortably in int32, so values above
// math.MaxInt32 are rejected rather than silently wrapping (see E7).
func parseInt(s string) (int, error) {
	if len(s) == 0 {
		return 0, errors.New("not a number")
	}
	const maxVal = 1<<31 - 1
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int(ch-'0')
		if n > maxVal {
			return 0, errors.New("number too large")
		}
	}
	return n, nil
}

// mechanismAdvertised reports whether mech is in the session's advertised
// SASL mechanism list.
func mechanismAdvertised(sasl SessionSASL, mech string) bool {
	for _, m := range sasl.AuthenticateMechanisms() {
		if strings.EqualFold(m, mech) {
			return true
		}
	}
	return false
}

func decodeSASLPlain(encoded string) (identity, username, password string, err error) {
	decoded, decodeErr := base64.StdEncoding.DecodeString(encoded)
	if decodeErr != nil {
		return "", "", "", decodeErr
	}

	// SASL PLAIN format: authzid\x00authcid\x00password
	parts := splitNull(decoded)
	if len(parts) != 3 {
		return "", "", "", errors.New("invalid SASL PLAIN format")
	}
	// Identities carrying control characters would corrupt downstream
	// credential frames rebuilt from them (see handleUser); the password is
	// already framed by the NUL separators and is not checked.
	if containsCTL(parts[0]) || containsCTL(parts[1]) {
		return "", "", "", errors.New("control characters in SASL PLAIN identity")
	}
	return parts[0], parts[1], parts[2], nil
}

// containsCTL reports whether s contains ASCII control characters (including
// NUL and DEL), which are invalid in POP3 command arguments (RFC 1939 §3).
func containsCTL(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7F {
			return true
		}
	}
	return false
}

func splitNull(data []byte) []string {
	var parts []string
	var current []byte
	for _, b := range data {
		if b == 0 {
			parts = append(parts, string(current))
			current = nil
		} else {
			current = append(current, b)
		}
	}
	parts = append(parts, string(current))
	return parts
}
