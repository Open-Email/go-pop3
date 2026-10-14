package pop3server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"runtime/debug"
	"sync"
	"time"
)

// Server is a POP3 server that accepts connections and dispatches them
// to sessions created by the Options.NewSession callback.
type Server struct {
	opts     Options
	listener net.Listener
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc

	// mu guards conns, the set of live connections the library still owns
	// (hijacked connections are removed). Close walks it to kick blocked
	// reads, which context cancellation alone cannot unblock.
	mu    sync.Mutex
	conns map[*Conn]struct{}
}

// New creates a new POP3 server with the given options.
func New(opts Options) *Server {
	resolved := opts.defaults()
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		opts:   resolved,
		ctx:    ctx,
		cancel: cancel,
		conns:  make(map[*Conn]struct{}),
	}
}

func (s *Server) registerConn(c *Conn) {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) unregisterConn(c *Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// Serve accepts connections on the given listener. It blocks until the
// listener is closed or the server is shut down via Close. For implicit
// TLS listeners, wrap the listener with tls.NewListener before calling
// Serve.
//
// Serve spawns one goroutine per accepted connection and imposes no built-in
// cap on the number of concurrent connections. To bound concurrency:
//   - For a hard limit that stops accepting past N connections, wrap the
//     listener with golang.org/x/net/netutil.LimitListener(ln, N); the library
//     closes each connection on teardown, which releases its slot.
//   - For a graceful, per-connection decision (e.g. a "-ERR [IN-USE] Too many
//     connections" banner), enforce the limit in Options.NewSession and return
//     a *pop3server.Error — the connection is rejected with that banner and
//     closed.
func (s *Server) Serve(ln net.Listener) error {
	s.listener = ln
	s.opts.Logger.Info("POP3: server listening", "addr", ln.Addr())

	// backoff bounds the retry rate on transient Accept errors (e.g. EMFILE)
	// so a persistent failure cannot spin the loop hot (see E9).
	const maxBackoff = 1 * time.Second
	var backoff time.Duration

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil // graceful shutdown
			default:
			}

			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else {
				backoff *= 2
			}
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			s.opts.Logger.Error("POP3: accept error; backing off",
				"error", err, "delay", backoff)

			select {
			case <-time.After(backoff):
			case <-s.ctx.Done():
				return nil
			}
			continue
		}
		backoff = 0

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.recoverConn(conn)
			s.handleConn(conn)
		}()
	}
}

// ListenAndServe creates a plaintext TCP listener on addr and calls Serve.
// It does NOT wrap the listener with TLS even when TLSConfig is set; for
// implicit-TLS ports (e.g. 995) use ListenAndServeTLS, and for a listener you
// wrap yourself pass it to Serve directly.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// ListenAndServeTLS creates a TLS listener on addr and calls Serve.
func (s *Server) ListenAndServeTLS(addr string) error {
	if s.opts.TLSConfig == nil {
		return net.ErrClosed // no TLS configured
	}
	ln, err := tls.Listen("tcp", addr, s.opts.TLSConfig)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Close gracefully shuts down the server. It closes the listener,
// cancels all active connections — kicking any that are blocked in a read,
// since context cancellation alone cannot unblock a net.Conn — and waits for
// them to finish. Hijacked connections are caller-owned and are left untouched.
func (s *Server) Close() error {
	s.cancel()
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	s.mu.Lock()
	for c := range s.conns {
		c.forceReadUnblock()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

// newWriter builds the buffered writer for a connection, wrapping the raw
// conn so each network write is bounded by WriteTimeout when configured.
func (s *Server) newWriter(conn net.Conn) *bufio.Writer {
	if s.opts.WriteTimeout > 0 {
		return bufio.NewWriter(&writeDeadlineConn{Conn: conn, timeout: s.opts.WriteTimeout})
	}
	return bufio.NewWriter(conn)
}

// ServeConn runs the POP3 command loop on a single connection. The caller
// owns the listener; panics are recovered exactly as in Serve (logged,
// reported via OnPanic, connection closed).
func (s *Server) ServeConn(netConn net.Conn) {
	defer s.recoverConn(netConn)
	s.handleConn(netConn)
}

// recoverConn is the shared per-connection panic handler for Serve and
// ServeConn. It must be invoked directly by a defer so recover() applies to
// the panicking goroutine. Closing the connection here also covers a panic
// inside the NewSession callback, before any session teardown exists.
func (s *Server) recoverConn(conn net.Conn) {
	if r := recover(); r != nil {
		stack := debug.Stack()
		s.opts.Logger.Error("POP3: panic in connection handler",
			"panic", r, "remote", conn.RemoteAddr())
		if h := s.opts.OnPanic; h != nil {
			h(r, stack)
		}
		conn.Close()
	}
}

// handleConn sets up a Conn and runs the command loop.
func (s *Server) handleConn(netConn net.Conn) {
	var ctx context.Context
	var cancel context.CancelFunc

	if s.opts.AbsoluteSessionTimeout > 0 {
		ctx, cancel = context.WithTimeout(s.ctx, s.opts.AbsoluteSessionTimeout)
	} else {
		ctx, cancel = context.WithCancel(s.ctx)
	}
	defer cancel()

	// Detect implicit TLS, unwrapping any listener/conn wrappers (e.g. a
	// PROXY-protocol or throughput-checking wrapper) that embed the tls.Conn
	// but are not themselves *tls.Conn (see G1). Consumers can still override
	// via Conn.SetTLS in NewSession.
	c := &Conn{
		netConn:   netConn,
		rawConn:   netConn,
		server:    s,
		reader:    bufio.NewReader(netConn),
		writer:    s.newWriter(netConn),
		state:     stateAuthorization,
		ctx:       ctx,
		cancel:    cancel,
		isTLS:     isTLSConn(netConn),
		startTime: time.Now(),
	}

	s.registerConn(c)
	defer s.unregisterConn(c)

	// Create the session via the consumer's callback.
	session, err := s.opts.NewSession(c)
	if err != nil {
		// A silent rejection closes the socket without any banner (abuse
		// control: don't inform the peer it is being limited).
		if errors.Is(err, ErrSilentReject) {
			s.opts.Logger.Debug("POP3: connection silently rejected",
				"remote", netConn.RemoteAddr(), "error", err)
			netConn.Close()
			return
		}
		s.opts.Logger.Warn("POP3: session creation failed",
			"remote", netConn.RemoteAddr(), "error", err)
		// A limiter can steer the rejection banner by returning an *Error,
		// e.g. -ERR [IN-USE] Too many connections (see G5).
		msg := s.opts.RejectMessage
		var perr *Error
		if errors.As(err, &perr) {
			msg = perr.wireMessage()
		}
		c.err(msg)
		c.writer.Flush()
		netConn.Close()
		return
	}

	c.session = session
	c.serve()
}

// isTLSConn reports whether conn is (or wraps) a *tls.Conn. It follows the
// conventional Unwrap() net.Conn chain used by connection wrappers.
func isTLSConn(conn net.Conn) bool {
	for conn != nil {
		if _, ok := conn.(*tls.Conn); ok {
			return true
		}
		u, ok := conn.(interface{ Unwrap() net.Conn })
		if !ok {
			return false
		}
		conn = u.Unwrap()
	}
	return false
}

// writeDeadlineConn wraps a net.Conn to arm a write deadline before every
// Write, so a slow-reading client cannot block a flush (or a streamed
// RETR/TOP body) indefinitely (see E3). Only the write path is wrapped; read
// deadlines are managed separately by the command loop.
type writeDeadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (w *writeDeadlineConn) Write(p []byte) (int, error) {
	if w.timeout > 0 {
		_ = w.Conn.SetWriteDeadline(time.Now().Add(w.timeout))
	}
	return w.Conn.Write(p)
}
