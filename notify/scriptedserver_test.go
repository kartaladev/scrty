package notify_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/notify"
)

// scriptedServer is an in-process SMTP server whose behaviour each test
// chooses. It exists so the deadline, the STARTTLS rules and the encoding can
// be driven against a server that stalls, lies or refuses on command — none of
// which a real server does reliably.
type scriptedServer struct {
	ln  net.Listener
	scr script

	mu       sync.Mutex
	lines    []string
	mailFrom string
	rcpt     []string
	data     string

	dialled atomic.Bool

	closeOnce sync.Once
	done      chan struct{}
}

// script decides what the server does at each point of the exchange.
type script struct {
	// greet is written on connect. An empty greet means the server accepts the
	// connection and says nothing, which is what a stalled server looks like.
	greet string

	// offerSTARTTLS puts STARTTLS in the EHLO response.
	offerSTARTTLS bool

	// tlsConfig serves the upgrade. Nil with offerSTARTTLS true is a server
	// that advertises STARTTLS and then cannot speak it.
	tlsConfig *tls.Config

	// rejectAt names a command the server answers with 550.
	rejectAt string
}

func scriptOK() script {
	return script{greet: "220 scripted ESMTP ready"}
}

func scriptSilentGreeting() script { return script{} }

func scriptNoSTARTTLS() script { return script{greet: "220 scripted ESMTP ready"} }

func scriptSTARTTLS(t *testing.T) script {
	t.Helper()

	return script{
		greet:         "220 scripted ESMTP ready",
		offerSTARTTLS: true,
		tlsConfig:     selfSignedTLSConfig(t),
	}
}

func scriptBrokenTLS() script {
	return script{greet: "220 scripted ESMTP ready", offerSTARTTLS: true}
}

func scriptRejectAt(cmd string) script {
	return script{greet: "220 scripted ESMTP ready", rejectAt: cmd}
}

func startScriptedServer(t *testing.T, scr script) *scriptedServer {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &scriptedServer{ln: ln, scr: scr, done: make(chan struct{})}

	go srv.accept()

	t.Cleanup(srv.stop)

	return srv
}

func (s *scriptedServer) stop() {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.ln.Close()
	})
}

// Host is the host the sender under test is pointed at. The certificate the
// TLS scripts serve is issued for it.
func (s *scriptedServer) Host() string { return "127.0.0.1" }

func (s *scriptedServer) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// Dial is the DialFunc the sender under test is given, so the server sees the
// connection attempt even when it intends to stall.
func (s *scriptedServer) Dial(ctx context.Context, network, _ string) (net.Conn, error) {
	s.dialled.Store(true)

	return (&net.Dialer{}).DialContext(ctx, network, s.ln.Addr().String())
}

func (s *scriptedServer) Dialled() bool { return s.dialled.Load() }

func (s *scriptedServer) Lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.lines...)
}

func (s *scriptedServer) MailFrom() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.mailFrom
}

func (s *scriptedServer) Rcpt() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.rcpt...)
}

func (s *scriptedServer) Data() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.data
}

func (s *scriptedServer) record(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lines = append(s.lines, line)
}

func (s *scriptedServer) accept() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}

		go s.serve(conn)
	}
}

// serve speaks only as much SMTP as submission needs, and records every
// command line it was sent so a test can assert that DATA never happened.
func (s *scriptedServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	go func() {
		<-s.done
		_ = conn.Close()
	}()

	if s.scr.greet == "" {
		// A server that accepts the connection and never says anything. Read
		// and discard so the client is the only one holding the exchange up.
		_, _ = io.Copy(io.Discard, conn)

		return
	}

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	write := func(lines ...string) bool {
		for _, l := range lines {
			if _, err := rw.WriteString(l + "\r\n"); err != nil {
				return false
			}
		}

		return rw.Flush() == nil
	}

	if !write(s.scr.greet) {
		return
	}

	upgraded := false

	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimRight(line, "\r\n")
		s.record(line)

		verb := strings.ToUpper(line)
		if i := strings.IndexAny(line, " :"); i >= 0 {
			verb = strings.ToUpper(line[:i])
		}

		if s.scr.rejectAt != "" && verb == strings.ToUpper(s.scr.rejectAt) {
			if !write("550 scripted rejection") {
				return
			}

			continue
		}

		switch verb {
		case "EHLO":
			resp := []string{"250-scripted"}
			if s.scr.offerSTARTTLS && !upgraded {
				resp = append(resp, "250-STARTTLS")
			}

			resp = append(resp, "250 OK")

			if !write(resp...) {
				return
			}
		case "HELO":
			if !write("250 OK") {
				return
			}
		case "STARTTLS":
			if !write("220 ready to start TLS") {
				return
			}

			if s.scr.tlsConfig == nil {
				// Advertised it, cannot speak it: hang up so the client's
				// handshake fails.
				return
			}

			tlsConn := tls.Server(conn, s.scr.tlsConfig)
			if err := tlsConn.HandshakeContext(context.Background()); err != nil {
				return
			}

			conn = tlsConn
			upgraded = true
			rw = bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
		case "MAIL":
			s.mu.Lock()
			s.mailFrom = addressOf(line)
			s.mu.Unlock()

			if !write("250 OK") {
				return
			}
		case "RCPT":
			s.mu.Lock()
			s.rcpt = append(s.rcpt, addressOf(line))
			s.mu.Unlock()

			if !write("250 OK") {
				return
			}
		case "DATA":
			if !write("354 end with <CR><LF>.<CR><LF>") {
				return
			}

			var payload strings.Builder

			for {
				l, err := rw.ReadString('\n')
				if err != nil {
					return
				}

				if strings.TrimRight(l, "\r\n") == "." {
					break
				}

				payload.WriteString(l)
			}

			s.mu.Lock()
			s.data = payload.String()
			s.mu.Unlock()

			if !write("250 queued") {
				return
			}
		case "QUIT":
			_ = write("221 bye")

			return
		default:
			if !write("250 OK") {
				return
			}
		}
	}
}

// addressOf pulls the bare address out of `MAIL FROM:<a@b>` or `RCPT TO:<a@b>`.
func addressOf(line string) string {
	if open := strings.IndexByte(line, '<'); open >= 0 {
		if shut := strings.IndexByte(line[open:], '>'); shut >= 0 {
			return line[open+1 : open+shut]
		}
	}

	if colon := strings.IndexByte(line, ':'); colon >= 0 {
		return strings.TrimSpace(line[colon+1:])
	}

	return ""
}

// selfSignedTLSConfig issues a certificate for 127.0.0.1 at test time, so the
// TLS scripts need no fixture file on disk.
func selfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
	}
}

// trustFor builds the client-side TLS configuration that trusts what the given
// server script serves, verifying the name as a consumer's own configuration
// would.
func trustFor(t *testing.T, scr script) *tls.Config {
	t.Helper()

	pool := x509.NewCertPool()

	if scr.tlsConfig != nil {
		require.NotEmpty(t, scr.tlsConfig.Certificates)
		pool.AddCert(scr.tlsConfig.Certificates[0].Leaf)
	}

	return &tls.Config{ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12, RootCAs: pool}
}

func TestScriptedServerDelivers(t *testing.T) {
	t.Parallel()

	srv := startScriptedServer(t, scriptOK())

	s, err := notify.NewSMTPSender(srv.Host(),
		notify.WithSMTPPort(srv.Port()),
		notify.WithSMTPFrom("no-reply@example.com"),
		notify.WithSMTPOpportunisticTLS(),
		notify.WithSMTPDialer(srv.Dial),
	)
	require.NoError(t, err)

	require.NoError(t, s.Send(t.Context(), notify.Message{
		To:       "ada@example.com",
		Subject:  "Sign in",
		TextBody: "here is your link",
	}))

	assert.Contains(t, srv.MailFrom(), "no-reply@example.com")
	assert.Contains(t, srv.Rcpt(), "ada@example.com")
	assert.Contains(t, srv.Data(), "here is your link")
	assert.Contains(t, srv.Lines(), "QUIT")
}
