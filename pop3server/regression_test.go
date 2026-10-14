package pop3server_test

import (
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3"
	"github.com/migadu/go-pop3/pop3server"
)

// --- PASS must preserve a password's internal and trailing whitespace ---

// captureSession records the exact password it receives and authenticates
// only when it equals want.
type captureSession struct {
	mockLikeSession
	want   string
	got    chan string
	closed atomic.Bool
}

func (s *captureSession) Close() error {
	s.closed.Store(true)
	return nil
}

func (s *captureSession) Login(_ context.Context, _, password string) error {
	select {
	case s.got <- password:
	default:
	}
	if password == s.want {
		return nil
	}
	return &pop3server.Error{Code: "AUTH", Message: "authentication failed"}
}

func TestServer_PassPreservesWhitespace(t *testing.T) {
	const password = "a  b\tc d " // repeated spaces, a tab, and a trailing space
	const wantSeen = "a  b\tc d " // internal and trailing whitespace preserved

	got := make(chan string, 1)
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
		NewSession: func(*pop3server.Conn) (pop3server.Session, error) {
			return &captureSession{want: wantSeen, got: got}, nil
		},
	})

	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting
	writeLine(t, conn, "USER u")
	mustLine(t, r) // +OK
	// Send PASS with the raw password bytes (do not go through writeLine's
	// own formatting — the point is the exact bytes after "PASS ").
	if _, err := conn.Write([]byte("PASS " + password + "\r\n")); err != nil {
		t.Fatal(err)
	}
	resp := mustLine(t, r)

	select {
	case seen := <-got:
		if seen != wantSeen {
			t.Fatalf("password corrupted: server saw %q, want %q", seen, wantSeen)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Login was not called")
	}
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("expected +OK after correct password, got %q", resp)
	}
}

func TestServer_PassWhitespaceOnlyPassword(t *testing.T) {
	const password = "   " // three spaces after the single delimiter space

	got := make(chan string, 1)
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
		NewSession: func(*pop3server.Conn) (pop3server.Session, error) {
			return &captureSession{want: password, got: got}, nil
		},
	})

	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting
	writeLine(t, conn, "USER u")
	mustLine(t, r) // +OK
	if _, err := conn.Write([]byte("PASS " + password + "\r\n")); err != nil {
		t.Fatal(err)
	}
	resp := mustLine(t, r)

	select {
	case seen := <-got:
		if seen != password {
			t.Fatalf("whitespace-only password corrupted: server saw %q, want %q", seen, password)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Login was not called for whitespace-only password")
	}
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("expected +OK after whitespace-only password, got %q", resp)
	}
}

func TestServer_CloseUnblocksIdleConnectionsAndClosesSession(t *testing.T) {
	for _, idleTimeout := range []time.Duration{10 * time.Minute, -1} {
		sess := &captureSession{want: "pass", got: make(chan string, 1)}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var timeoutFired atomic.Bool
		srv := pop3server.New(pop3server.Options{
			InsecureAuth: true,
			IdleTimeout:  idleTimeout,
			OnTimeout:    func(string) { timeoutFired.Store(true) },
			NewSession: func(*pop3server.Conn) (pop3server.Session, error) {
				return sess, nil
			},
		})
		go srv.Serve(ln)

		conn, r := rawDial(t, ln.Addr().String())
		mustLine(t, r) // greeting
		writeLine(t, conn, "USER u")
		mustLine(t, r)
		writeLine(t, conn, "PASS pass")
		if resp := mustLine(t, r); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("PASS: %q", resp)
		}

		// Connection is now parked in c.readLine() in TRANSACTION state.
		done := make(chan error, 1)
		go func() { done <- srv.Close() }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("Server.Close blocked on idle connection (IdleTimeout=%v)", idleTimeout)
		}

		if !sess.closed.Load() {
			t.Fatalf("Session.Close was not called before Server.Close returned (IdleTimeout=%v)", idleTimeout)
		}
		if timeoutFired.Load() {
			t.Fatalf("OnTimeout must not fire when Server.Close unblocks an idle connection (IdleTimeout=%v)", idleTimeout)
		}
	}
}

func TestServer_TransactionStateRejectsAuthAndSTLSAndTrailingArgs(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		MaxErrors:    -1,
		IdleTimeout:  5 * time.Second,
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	// Trailing args on pre-auth commands must be rejected.
	for _, cmd := range []string{"CAPA extra", "STLS extra", "UTF8 extra", "QUIT extra", "USER alice bob"} {
		writeLine(t, conn, cmd)
		resp := mustLine(t, r)
		if !strings.HasPrefix(resp, "-ERR") {
			t.Fatalf("pre-auth %q: expected -ERR, got %q", cmd, resp)
		}
	}

	writeLine(t, conn, "USER user")
	mustLine(t, r)
	writeLine(t, conn, "PASS pass")
	if resp := mustLine(t, r); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS: %q", resp)
	}

	// USER, PASS, AUTH, STLS in TRANSACTION state must not say "Unknown command".
	for _, cmd := range []string{"USER user", "PASS pass", "AUTH PLAIN", "STLS"} {
		writeLine(t, conn, cmd)
		resp := mustLine(t, r)
		if !strings.HasPrefix(resp, "-ERR") {
			t.Fatalf("post-auth %q: expected -ERR, got %q", cmd, resp)
		}
		if strings.Contains(resp, "Unknown command") {
			t.Fatalf("post-auth %q reported as Unknown command: %q", cmd, resp)
		}
	}

	// Trailing args on TRANSACTION-state commands must be rejected.
	for _, cmd := range []string{
		"STAT extra", "RSET extra", "NOOP extra", "QUIT extra", "CAPA extra",
		"UTF8 extra", "RETR 1 2", "DELE 1 2", "LIST 1 2", "UIDL 1 2", "TOP 1 0 extra",
	} {
		writeLine(t, conn, cmd)
		resp := mustLine(t, r)
		if !strings.HasPrefix(resp, "-ERR") {
			t.Fatalf("post-auth %q: expected -ERR, got %q", cmd, resp)
		}
	}
}

// --- Session-supplied strings must not inject response lines ---

type injectSession struct {
	mockLikeSession
	uid string
}

func (injectSession) Login(context.Context, string, string) error { return nil }
func (s injectSession) Uidl(_ context.Context, msg int) ([]pop3.MessageUidl, error) {
	return []pop3.MessageUidl{{Num: 1, UniqueID: s.uid}}, nil
}

func TestServer_UidlSanitizesCRLF(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
		NewSession: func(*pop3server.Conn) (pop3server.Session, error) {
			return injectSession{uid: "abc\r\n+OK injected\r\n.\r\n+OK spoof"}, nil
		},
	})

	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting
	writeLine(t, conn, "USER u")
	mustLine(t, r)
	writeLine(t, conn, "PASS p")
	mustLine(t, r) // +OK auth

	writeLine(t, conn, "UIDL 1")
	// A single-message UIDL response is exactly one "+OK" line. If the UID had
	// leaked CR/LF it would appear as several lines here.
	line := mustLine(t, r)
	if !strings.HasPrefix(line, "+OK 1 ") {
		t.Fatalf("unexpected UIDL response: %q", line)
	}
	if strings.Contains(line, "\r") || strings.Contains(line, "\n") {
		t.Fatalf("UID leaked CR/LF into the line: %q", line)
	}
	// The very next line the client can read must be its own next command's
	// response, not an injected "+OK". Prove framing is intact by pipelining
	// NOOP and requiring a single +OK.
	writeLine(t, conn, "NOOP")
	next := mustLine(t, r)
	if next != "+OK" && !strings.HasPrefix(next, "+OK") {
		t.Fatalf("framing broken; expected NOOP +OK, got %q", next)
	}
	if strings.Contains(next, "injected") || strings.Contains(next, "spoof") {
		t.Fatalf("injected content surfaced as a response line: %q", next)
	}
}

// errSession returns a plain error whose text embeds CRLF, exercising the
// c.err sanitisation path.
type errSession struct {
	mockLikeSession
}

func (errSession) Login(context.Context, string, string) error { return nil }
func (errSession) Stat(context.Context) (int, int64, error) {
	return 0, 0, &pop3server.Error{Message: "boom\r\n+OK injected via error"}
}

func TestServer_SessionErrorSanitizesCRLF(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
		NewSession: func(*pop3server.Conn) (pop3server.Session, error) {
			return errSession{}, nil
		},
	})

	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting
	writeLine(t, conn, "USER u")
	mustLine(t, r)
	writeLine(t, conn, "PASS p")
	mustLine(t, r) // +OK auth

	writeLine(t, conn, "STAT")
	line := mustLine(t, r)
	if !strings.HasPrefix(line, "-ERR") {
		t.Fatalf("expected -ERR, got %q", line)
	}
	if strings.Contains(line, "\r") || strings.Contains(line, "\n") {
		t.Fatalf("error text leaked CR/LF: %q", line)
	}
	// Confirm no injected +OK line follows before our next command.
	writeLine(t, conn, "NOOP")
	if next := mustLine(t, r); !strings.HasPrefix(next, "+OK") || strings.Contains(next, "injected") {
		t.Fatalf("framing broken after error; got %q", next)
	}
}

// mockLikeSession is a no-op Session used as an embedding base for the
// regression sessions above; individual tests override the methods they
// exercise.
type mockLikeSession struct{}

func (mockLikeSession) Close() error                                { return nil }
func (mockLikeSession) Login(context.Context, string, string) error { return nil }
func (mockLikeSession) Stat(context.Context) (int, int64, error)    { return 0, 0, nil }
func (mockLikeSession) List(context.Context, int) ([]pop3.MessageInfo, error) {
	return nil, nil
}
func (mockLikeSession) Uidl(context.Context, int) ([]pop3.MessageUidl, error) {
	return nil, nil
}
func (mockLikeSession) Retr(context.Context, int) (io.ReadCloser, error) { return nil, nil }
func (mockLikeSession) Top(context.Context, int, int) (io.ReadCloser, error) {
	return nil, nil
}
func (mockLikeSession) Dele(context.Context, int) error   { return nil }
func (mockLikeSession) Rset(context.Context) error        { return nil }
func (mockLikeSession) Noop(context.Context) error        { return nil }
func (mockLikeSession) Quit(context.Context) (int, error) { return 0, nil }

