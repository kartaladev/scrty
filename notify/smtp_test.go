package notify_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/notify"
)

func TestNewSMTPSender(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		host   string
		opts   []notify.SMTPOption
		assert func(t *testing.T, s *notify.SMTPSender, err error)
	}

	configError := func(t *testing.T, s *notify.SMTPSender, err error) {
		require.Error(t, err)
		assert.ErrorIs(t, err, notify.ErrConfig)
		assert.Nil(t, s)
	}

	cases := []testCase{
		{
			name: "defaults",
			host: "smtp.example.com",
			assert: func(t *testing.T, s *notify.SMTPSender, err error) {
				require.NoError(t, err)
				assert.Equal(t, 587, s.Port())
				assert.Equal(t, 30*time.Second, s.Timeout())
			},
		},
		{name: "missing host", host: "", assert: configError},
		{
			name:   "port zero",
			host:   "smtp.example.com",
			opts:   []notify.SMTPOption{notify.WithSMTPPort(0)},
			assert: configError,
		},
		{
			name:   "port too high",
			host:   "smtp.example.com",
			opts:   []notify.SMTPOption{notify.WithSMTPPort(65536)},
			assert: configError,
		},
		{
			name:   "negative port",
			host:   "smtp.example.com",
			opts:   []notify.SMTPOption{notify.WithSMTPPort(-1)},
			assert: configError,
		},
		{
			name:   "zero timeout",
			host:   "smtp.example.com",
			opts:   []notify.SMTPOption{notify.WithSMTPTimeout(0)},
			assert: configError,
		},
		{
			name:   "negative timeout",
			host:   "smtp.example.com",
			opts:   []notify.SMTPOption{notify.WithSMTPTimeout(-time.Second)},
			assert: configError,
		},
		{
			name:   "nil dialler",
			host:   "smtp.example.com",
			opts:   []notify.SMTPOption{notify.WithSMTPDialer(nil)},
			assert: configError,
		},
		{
			name: "consumer port and timeout",
			host: "smtp.example.com",
			opts: []notify.SMTPOption{notify.WithSMTPPort(2525), notify.WithSMTPTimeout(5 * time.Second)},
			assert: func(t *testing.T, s *notify.SMTPSender, err error) {
				require.NoError(t, err)
				assert.Equal(t, 2525, s.Port())
				assert.Equal(t, 5*time.Second, s.Timeout())
			},
		},
		{
			name: "does not declare itself non-blocking",
			host: "smtp.example.com",
			assert: func(t *testing.T, s *notify.SMTPSender, err error) {
				require.NoError(t, err)

				_, ok := any(s).(notify.NonBlocking)
				assert.False(t, ok, "SMTP waits for delivery and must not claim otherwise")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := notify.NewSMTPSender(tc.host, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestSMTPSenderFrom(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []notify.SMTPOption
		msgFrom string
		assert  func(t *testing.T, srv *scriptedServer, err error)
	}

	cases := []testCase{
		{
			name:    "the configured default is used when the message names none",
			opts:    []notify.SMTPOption{notify.WithSMTPFrom("no-reply@example.com")},
			msgFrom: "",
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.NoError(t, err)
				assert.Contains(t, srv.MailFrom(), "no-reply@example.com")
			},
		},
		{
			name:    "the message overrides the default",
			opts:    []notify.SMTPOption{notify.WithSMTPFrom("no-reply@example.com")},
			msgFrom: "support@example.com",
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.NoError(t, err)
				assert.Contains(t, srv.MailFrom(), "support@example.com")
				assert.NotContains(t, srv.MailFrom(), "no-reply@example.com")
			},
		},
		{
			name:    "neither is an error before any network activity",
			msgFrom: "",
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.Error(t, err)
				assert.False(t, srv.Dialled(), "nothing may be dialled")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := startScriptedServer(t, scriptOK())

			s, err := notify.NewSMTPSender(srv.Host(), append(tc.opts,
				notify.WithSMTPPort(srv.Port()),
				notify.WithSMTPOpportunisticTLS(),
				notify.WithSMTPDialer(srv.Dial),
			)...)
			require.NoError(t, err)

			tc.assert(t, srv, s.Send(t.Context(), notify.Message{
				To:       "ada@example.com",
				From:     tc.msgFrom,
				Subject:  "Sign in",
				TextBody: "link",
			}))
		})
	}
}

// newTestSMTPSenderRaw points a sender at srv with the real encryption
// default — required STARTTLS — so these cases exercise it rather than the
// opportunistic setting the other tasks' helper turns on. It trusts the
// certificate srv's script serves, as a consumer with a private authority
// would.
func newTestSMTPSenderRaw(t *testing.T, srv *scriptedServer, opts ...notify.SMTPOption) *notify.SMTPSender {
	t.Helper()

	base := []notify.SMTPOption{
		notify.WithSMTPPort(srv.Port()),
		notify.WithSMTPFrom("no-reply@example.com"),
		notify.WithSMTPDialer(srv.Dial),
		notify.WithSMTPTLSConfig(trustFor(t, srv.scr)),
	}

	s, err := notify.NewSMTPSender(srv.Host(), append(base, opts...)...)
	require.NoError(t, err)

	return s
}

func TestSMTPSenderRequiresSTARTTLS(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		script script
		opts   []notify.SMTPOption
		assert func(t *testing.T, srv *scriptedServer, err error)
	}

	refusedBeforeData := func(t *testing.T, srv *scriptedServer, err error) {
		require.Error(t, err)
		assert.NotContains(t, srv.Lines(), "DATA", "no message data may be sent")
		assert.Empty(t, srv.Data())
	}

	cases := []testCase{
		{
			name:   "a server without STARTTLS is refused",
			script: scriptNoSTARTTLS(),
			assert: refusedBeforeData,
		},
		{
			name:   "a server that offers STARTTLS but cannot speak it is refused",
			script: scriptBrokenTLS(),
			assert: refusedBeforeData,
		},
		{
			name:   "a server that offers STARTTLS is upgraded and delivers",
			script: scriptSTARTTLS(t),
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.NoError(t, err)
				assert.Contains(t, srv.Lines(), "STARTTLS")
				assert.Contains(t, srv.Data(), "here is your link")
			},
		},
		{
			name:   "opportunistic delivers to a local relay without STARTTLS",
			script: scriptNoSTARTTLS(),
			opts:   []notify.SMTPOption{notify.WithSMTPOpportunisticTLS()},
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.NoError(t, err)
				assert.Contains(t, srv.Data(), "here is your link")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := startScriptedServer(t, tc.script)
			s := newTestSMTPSenderRaw(t, srv, tc.opts...)

			tc.assert(t, srv, s.Send(t.Context(), testMessage()))
		})
	}
}

// It stands apart from the STARTTLS table: its sender is built for a
// non-loopback host with credentials, not through newTestSMTPSenderRaw.
func TestSMTPSenderOpportunisticTLS(t *testing.T) {
	t.Parallel()

	t.Run("credentials are not sent over an unencrypted non-loopback connection", func(t *testing.T) {
		t.Parallel()

		srv := startScriptedServer(t, scriptNoSTARTTLS())

		// PlainAuth is constructed for a non-loopback host name, so net/smtp's
		// own rule applies even though the connection goes to the test server.
		s, err := notify.NewSMTPSender("smtp.example.com",
			notify.WithSMTPPort(srv.Port()),
			notify.WithSMTPFrom("no-reply@example.com"),
			notify.WithSMTPOpportunisticTLS(),
			notify.WithSMTPAuth("ada", "hunter2"),
			notify.WithSMTPDialer(srv.Dial),
		)
		require.NoError(t, err)

		err = s.Send(t.Context(), testMessage())
		require.Error(t, err, "net/smtp refuses PLAIN over an unencrypted connection")
		assert.NotContains(t, strings.Join(srv.Lines(), "\n"), "hunter2")
		assert.NotContains(t, srv.Lines(), "DATA")
	})
}

// freePort returns a port nothing is listening on, so a send that reaches the
// network fails at the dial rather than talking to something.
func freePort(t *testing.T) int {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, ln.Close())

	return ln.Addr().(*net.TCPAddr).Port
}

func TestSMTPSenderRefusesUnsafeHeaders(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		msg    notify.Message
		assert func(t *testing.T, err error, dialled bool)
	}

	good := notify.Message{
		To:       "ada@example.com",
		From:     "no-reply@example.com",
		Subject:  "Sign in",
		TextBody: "link",
	}

	unsafe := func(mutate func(m *notify.Message)) notify.Message {
		m := good
		mutate(&m)

		return m
	}

	refused := func(t *testing.T, err error, dialled bool) {
		assert.ErrorIs(t, err, notify.ErrUnsafeHeaderValue)
		assert.False(t, dialled, "nothing may be dialled before the refusal")
	}

	cases := []testCase{
		{
			name:   "line break in the subject",
			msg:    unsafe(func(m *notify.Message) { m.Subject = "Hello\r\nBcc: attacker@example.com" }),
			assert: refused,
		},
		{
			name:   "line feed in the recipient",
			msg:    unsafe(func(m *notify.Message) { m.To = "a@example.com\nBcc: b@example.com" }),
			assert: refused,
		},
		{
			name:   "carriage return in the sender",
			msg:    unsafe(func(m *notify.Message) { m.From = "no-reply@example.com\rBcc: b@example.com" }),
			assert: refused,
		},
		{
			name: "a bare line feed in the body is not a header refusal",
			msg:  unsafe(func(m *notify.Message) { m.TextBody = "line one\nline two" }),
			assert: func(t *testing.T, err error, dialled bool) {
				assert.NotErrorIs(t, err, notify.ErrUnsafeHeaderValue)
				assert.True(t, dialled, "a clean message reaches the network")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var dialled atomic.Bool

			s, err := notify.NewSMTPSender("127.0.0.1",
				notify.WithSMTPPort(freePort(t)),
				notify.WithSMTPTimeout(200*time.Millisecond),
				notify.WithSMTPDialer(func(_ context.Context, _, _ string) (net.Conn, error) {
					dialled.Store(true)

					return nil, errors.New("refused")
				}),
			)
			require.NoError(t, err)

			tc.assert(t, s.Send(t.Context(), tc.msg), dialled.Load())
		})
	}
}

// parseData reads the payload the scripted server recorded at DATA as the RFC
// 5322 message it is meant to be.
func parseData(t *testing.T, data string) *mail.Message {
	t.Helper()

	m, err := mail.ReadMessage(strings.NewReader(data))
	require.NoError(t, err, "the DATA payload must parse as a message")

	return m
}

// headerValue returns one header exactly as it was written, without decoding.
func headerValue(t *testing.T, data, name string) string {
	t.Helper()

	return parseData(t, data).Header.Get(name)
}

// headersOf returns every header, each value joined, for assertions that look
// across all of them.
func headersOf(t *testing.T, data string) map[string]string {
	t.Helper()

	out := map[string]string{}
	for name, values := range parseData(t, data).Header {
		out[name] = strings.Join(values, " ")
	}

	return out
}

// bodyOf returns the message body with its line endings untouched.
func bodyOf(t *testing.T, data string) string {
	t.Helper()

	body, err := io.ReadAll(parseData(t, data).Body)
	require.NoError(t, err)

	return string(body)
}

func TestSMTPSenderEncoding(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		msg    notify.Message
		assert func(t *testing.T, data string)
	}

	cases := []testCase{
		{
			name: "a non-ASCII subject is Q-encoded and decodes back exactly",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Masuk ke akun Anda — tautan",
				TextBody: "link",
			},
			assert: func(t *testing.T, data string) {
				raw := headerValue(t, data, "Subject")
				assert.True(t, strings.HasPrefix(raw, "=?UTF-8?"), "got %q", raw)

				decoded, err := new(mime.WordDecoder).DecodeHeader(raw)
				require.NoError(t, err)
				assert.Equal(t, "Masuk ke akun Anda — tautan", decoded)
			},
		},
		{
			name: "an ASCII subject is written as-is",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Sign in",
				TextBody: "link",
			},
			assert: func(t *testing.T, data string) {
				assert.Equal(t, "Sign in", headerValue(t, data, "Subject"))
			},
		},
		{
			name: "bare line feeds in the body are normalised to CRLF",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Sign in",
				TextBody: "line one\nline two",
			},
			assert: func(t *testing.T, data string) {
				body := bodyOf(t, data)
				assert.Contains(t, body, "line one\r\nline two")
				assert.NotRegexp(t, regexp.MustCompile(`[^\r]\n`), body)
			},
		},
		{
			name: "a line starting with a dot after CR normalisation is dot-stuffed on the wire",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Sign in",
				TextBody: "hello\r.\rMAIL FROM",
			},
			assert: func(t *testing.T, data string) {
				// The scripted server records the transfer as sent, so the
				// stuffed dot is visible and the lone "." never ends the data.
				assert.Contains(t, data, "hello\r\n..\r\nMAIL FROM")
			},
		},
		{
			name: "the content type names UTF-8 plain text",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Sign in",
				TextBody: "link",
			},
			assert: func(t *testing.T, data string) {
				assert.Equal(t, "text/plain; charset=UTF-8", headerValue(t, data, "Content-Type"))
			},
		},
		{
			name: "no header names scrty or any product",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Sign in",
				TextBody: "link",
			},
			assert: func(t *testing.T, data string) {
				for name, value := range headersOf(t, data) {
					assert.NotContains(t, strings.ToLower(name), "scrty")
					assert.NotContains(t, strings.ToLower(value), "scrty")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := startScriptedServer(t, scriptOK())
			s := newTestSMTPSender(t, srv)

			require.NoError(t, s.Send(t.Context(), tc.msg))
			tc.assert(t, srv.Data())
		})
	}
}

// It stands apart from the encoding table: it reads the sender's log after a
// rejected DATA, not the message a server accepted.
func TestSMTPSenderLogsCarryNoBody(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	srv := startScriptedServer(t, scriptRejectAt("DATA"))
	s := newTestSMTPSender(t, srv, notify.WithSMTPLogger(logger))

	link := "https://app.example.com/login/magic/confirm?token=abc123secret"
	require.Error(t, s.Send(t.Context(), notify.Message{
		To:       "ada@example.com",
		Subject:  "Sign in",
		TextBody: "Follow " + link + " to sign in.",
	}))

	assert.NotContains(t, buf.String(), link)
	assert.NotContains(t, buf.String(), "abc123secret")
	assert.NotContains(t, buf.String(), "Follow ")
}

// newTestSMTPSender points a sender at srv with opportunistic encryption, for
// the tests whose subject is not the TLS rule.
func newTestSMTPSender(t *testing.T, srv *scriptedServer, opts ...notify.SMTPOption) *notify.SMTPSender {
	t.Helper()

	base := []notify.SMTPOption{
		notify.WithSMTPPort(srv.Port()),
		notify.WithSMTPFrom("no-reply@example.com"),
		notify.WithSMTPOpportunisticTLS(),
		notify.WithSMTPDialer(srv.Dial),
	}

	s, err := notify.NewSMTPSender(srv.Host(), append(base, opts...)...)
	require.NoError(t, err)

	return s
}

func TestSMTPSenderDeadline(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		script script
		opts   []notify.SMTPOption
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, srv *scriptedServer, err error, elapsed time.Duration)
	}

	cases := []testCase{
		{
			name:   "a server that never greets fails within the bound",
			script: scriptSilentGreeting(),
			opts:   []notify.SMTPOption{notify.WithSMTPTimeout(2 * time.Second)},
			assert: func(t *testing.T, _ *scriptedServer, err error, elapsed time.Duration) {
				require.Error(t, err)
				assert.Less(t, elapsed, 3*time.Second, "the bound must hold")
				assert.GreaterOrEqual(t, elapsed, 1500*time.Millisecond, "and must not fire early")
			},
		},
		{
			name:   "a context already ended fails before any network activity",
			script: scriptOK(),
			ctx: func(ctx context.Context) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				cancel()

				return ctx
			},
			assert: func(t *testing.T, srv *scriptedServer, err error, _ time.Duration) {
				require.Error(t, err)
				assert.False(t, srv.Dialled(), "an ended context must not reach the network")
			},
		},
		{
			name:   "context deadline",
			script: scriptSilentGreeting(), // the sender keeps its default 30s bound
			ctx: func(ctx context.Context) context.Context {
				ctx, cancel := context.WithTimeout(ctx, time.Second)
				context.AfterFunc(ctx, cancel) // releases the timer once the deadline or the case ends ctx

				return ctx
			},
			assert: func(t *testing.T, _ *scriptedServer, err error, elapsed time.Duration) {
				require.Error(t, err)
				assert.Less(t, elapsed, 2*time.Second, "the earlier caller deadline wins")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := startScriptedServer(t, tc.script)
			s := newTestSMTPSender(t, srv, tc.opts...)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			start := time.Now()
			err := s.Send(ctx, testMessage())
			elapsed := time.Since(start)

			tc.assert(t, srv, err, elapsed)
		})
	}
}

// It stands apart from the deadline table: its sender is built with a slow
// dialer of its own.
func TestSMTPSenderDeadlineSpansDial(t *testing.T) {
	t.Parallel()

	srv := startScriptedServer(t, scriptSilentGreeting())

	slowDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		select {
		case <-time.After(1500 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		return srv.Dial(ctx, network, address)
	}

	s, err := notify.NewSMTPSender(srv.Host(),
		notify.WithSMTPPort(srv.Port()),
		notify.WithSMTPFrom("no-reply@example.com"),
		notify.WithSMTPOpportunisticTLS(),
		notify.WithSMTPTimeout(2*time.Second),
		notify.WithSMTPDialer(slowDial),
	)
	require.NoError(t, err)

	start := time.Now()
	sendErr := s.Send(t.Context(), testMessage())
	elapsed := time.Since(start)

	require.Error(t, sendErr)
	assert.Less(t, elapsed, 3*time.Second,
		"the bound covers the dial: 1.5s connecting plus a stalled greeting must not cost 3.5s")
}

// It stands apart from the deadline table: it cancels from another goroutine
// while the send waits on the server.
func TestSMTPSenderCancelMidTransfer(t *testing.T) {
	t.Parallel()

	srv := startScriptedServer(t, scriptSilentGreeting())
	s := newTestSMTPSender(t, srv, notify.WithSMTPTimeout(30*time.Second))

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() { done <- s.Send(ctx, testMessage()) }()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation must unblock a send waiting on the server")
	}
}

// errDialFixture is the fixture every leak row in this change is proven
// against: a dependency's error quoting an address and a user reference the
// returned error must never repeat.
var errDialFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// rejectReply is a scripted 5xx reply that quotes the fixture values the way a
// real mail server routinely quotes the recipient — or, at other stages, an
// address or a rewording of what the client sent.
const rejectReply = "550 5.1.1 <alice@example.com>: rejected, user u-123"

// assertNoLeak is shared by every stage row: the returned error carries
// neither fixture value, and the underlying *textproto.Error the scripted
// server sent is still reachable through errors.As.
func assertNoLeak(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "alice@example.com",
		"the returned error quoted the server's own reply")
	assert.NotContains(t, err.Error(), "u-123",
		"the returned error quoted the server's own reply")

	var perr *textproto.Error
	assert.ErrorAs(t, err, &perr, "the server's reply is no longer reachable through errors.As")
}

// senderAt builds a sender pointed at srv, wired the way each stage row
// needs: opportunistic TLS by default, so a row that is not itself proving
// the STARTTLS or AUTH stage does not have to carry a certificate.
func senderAt(t *testing.T, srv *scriptedServer, opts ...notify.SMTPOption) *notify.SMTPSender {
	t.Helper()

	base := []notify.SMTPOption{
		notify.WithSMTPPort(srv.Port()),
		notify.WithSMTPFrom("no-reply@example.com"),
		notify.WithSMTPOpportunisticTLS(),
		notify.WithSMTPDialer(srv.Dial),
	}

	s, err := notify.NewSMTPSender(srv.Host(), append(base, opts...)...)
	require.NoError(t, err)

	return s
}

// rcptReasonCase proves the RCPT stage row's redaction alongside Send's own
// record: the returned error is scrubbed and its record is still filed under
// the "rcpt" reason, so the stage tag Send keys its reason on is unaffected by
// how the returned error's text is now built.
func rcptReasonCase() struct {
	name   string
	run    func(t *testing.T) error
	assert func(t *testing.T, err error)
} {
	var buf strings.Builder

	return struct {
		name   string
		run    func(t *testing.T) error
		assert func(t *testing.T, err error)
	}{
		name: "the server rejects the recipient",
		run: func(t *testing.T) error {
			t.Helper()

			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			srv := startScriptedServer(t, scriptRejectAtWith("RCPT", rejectReply))
			s := senderAt(t, srv, notify.WithSMTPLogger(logger))

			return s.Send(t.Context(), testMessage())
		},
		assert: func(t *testing.T, err error) {
			t.Helper()

			assertNoLeak(t, err)

			var rec map[string]any
			require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec))
			assert.Equal(t, "rcpt", rec["reason"],
				"Send's record reason must still key off the rcpt stage after the text changed")
		},
	}
}

// TestSMTPReturnedErrors pins the diagnostic-redaction requirement for
// SMTPSender.Send's own returned error (design decision 8): every stage the
// exchange can fail at comes back as fixed library text, with the dependency
// error still reachable by errors.Is/errors.As. The dial address is library
// configuration, not dependency text, and may stay in the dial row's text.
//
// A mid-transfer write failure has no row here: a real server has no reply to
// quote until the client sends the closing ".", so there is nothing for a
// scripted server to leak at that point — the DATA and close rows below cover
// the replies either side of it.
func TestSMTPReturnedErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		run    func(t *testing.T) error
		assert func(t *testing.T, err error)
	}{
		{
			name: "the dialer cannot open a connection",
			run: func(t *testing.T) error {
				t.Helper()

				s, err := notify.NewSMTPSender("smtp.example.com",
					notify.WithSMTPFrom("no-reply@example.com"),
					notify.WithSMTPDialer(func(context.Context, string, string) (net.Conn, error) {
						return nil, errDialFixture
					}),
				)
				require.NoError(t, err)

				return s.Send(t.Context(), testMessage())
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.NotContains(t, err.Error(), "alice@example.com",
					"the returned error quoted the dialer's own text")
				assert.NotContains(t, err.Error(), "u-123",
					"the returned error quoted the dialer's own text")
				assert.ErrorIs(t, err, errDialFixture, "the dialer's own error is no longer reachable")
			},
		},
		{
			name: "the server's greeting is a failure",
			run: func(t *testing.T) error {
				t.Helper()

				srv := startScriptedServer(t, script{greet: rejectReply})
				s := senderAt(t, srv)

				return s.Send(t.Context(), testMessage())
			},
			assert: assertNoLeak,
		},
		{
			name: "the server rejects EHLO",
			run: func(t *testing.T) error {
				t.Helper()

				srv := startScriptedServer(t, scriptRejectAtWith("EHLO", rejectReply))
				s := senderAt(t, srv)

				return s.Send(t.Context(), testMessage())
			},
			assert: assertNoLeak,
		},
		{
			name: "the server rejects the STARTTLS command",
			run: func(t *testing.T) error {
				t.Helper()

				srv := startScriptedServer(t, script{
					greet:         "220 scripted ESMTP ready",
					offerSTARTTLS: true,
					rejectAt:      "STARTTLS",
					rejectMsg:     rejectReply,
				})
				// Required STARTTLS is the default; no WithSMTPOpportunisticTLS
				// here, so the rejection is what fails the send.
				s, err := notify.NewSMTPSender(srv.Host(),
					notify.WithSMTPPort(srv.Port()),
					notify.WithSMTPFrom("no-reply@example.com"),
					notify.WithSMTPDialer(srv.Dial),
				)
				require.NoError(t, err)

				return s.Send(t.Context(), testMessage())
			},
			assert: assertNoLeak,
		},
		{
			name: "the server rejects AUTH",
			run: func(t *testing.T) error {
				t.Helper()

				scr := scriptSTARTTLS(t)
				scr.offerAUTH = true
				scr.rejectAt = "AUTH"
				scr.rejectMsg = rejectReply

				srv := startScriptedServer(t, scr)
				s, err := notify.NewSMTPSender(srv.Host(),
					notify.WithSMTPPort(srv.Port()),
					notify.WithSMTPFrom("no-reply@example.com"),
					notify.WithSMTPAuth("ada", "hunter2"),
					notify.WithSMTPTLSConfig(trustFor(t, scr)),
					notify.WithSMTPDialer(srv.Dial),
				)
				require.NoError(t, err)

				return s.Send(t.Context(), testMessage())
			},
			assert: assertNoLeak,
		},
		{
			name: "the server rejects MAIL FROM",
			run: func(t *testing.T) error {
				t.Helper()

				srv := startScriptedServer(t, scriptRejectAtWith("MAIL", rejectReply))
				s := senderAt(t, srv)

				return s.Send(t.Context(), testMessage())
			},
			assert: assertNoLeak,
		},
		{
			name: "the server rejects DATA",
			run: func(t *testing.T) error {
				t.Helper()

				srv := startScriptedServer(t, scriptRejectAtWith("DATA", rejectReply))
				s := senderAt(t, srv)

				return s.Send(t.Context(), testMessage())
			},
			assert: assertNoLeak,
		},
		{
			name: "the server rejects the closing dot after the message body",
			run: func(t *testing.T) error {
				t.Helper()

				srv := startScriptedServer(t, script{
					greet:     "220 scripted ESMTP ready",
					rejectAt:  ".",
					rejectMsg: rejectReply,
				})
				s := senderAt(t, srv)

				return s.Send(t.Context(), testMessage())
			},
			assert: assertNoLeak,
		},
		{
			name: "the server rejects QUIT after accepting the message",
			run: func(t *testing.T) error {
				t.Helper()

				srv := startScriptedServer(t, scriptRejectAtWith("QUIT", rejectReply))
				s := senderAt(t, srv)

				return s.Send(t.Context(), testMessage())
			},
			assert: assertNoLeak,
		},
	}

	cases = append(cases, rcptReasonCase())

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.run(t))
		})
	}
}

// TestNormalizeCRLF pins the function itself rather than the delivered
// message.
//
// The end-to-end encoding table cannot tell normalizeCRLF apart from doing
// nothing, because net/textproto's dot-writer converts a bare LF to CRLF on
// its way out as well. What build produces has to be a correct RFC 5322
// message whatever writes it, so the normalisation is asserted here.
func TestNormalizeCRLF(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		in     string
		assert func(t *testing.T, got string)
	}

	cases := []testCase{
		{
			name: "a bare line feed becomes a CRLF pair",
			in:   "line one\nline two",
			assert: func(t *testing.T, got string) {
				assert.Equal(t, "line one\r\nline two", got)
			},
		},
		{
			name: "an existing CRLF pair is not doubled",
			in:   "line one\r\nline two",
			assert: func(t *testing.T, got string) {
				assert.Equal(t, "line one\r\nline two", got)
			},
		},
		{
			name: "a body mixing both ends up consistent",
			in:   "one\r\ntwo\nthree",
			assert: func(t *testing.T, got string) {
				assert.Equal(t, "one\r\ntwo\r\nthree", got)
			},
		},
		{
			name: "a body with no line break is untouched",
			in:   "here is your link",
			assert: func(t *testing.T, got string) {
				assert.Equal(t, "here is your link", got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, notify.NormalizeCRLF(tc.in))
		})
	}
}

// TestBuild_WireCarriesNoBareCarriageReturn pins what reaches DATA: whatever
// mix of CR, LF and CRLF a body holds, every line ends in CRLF and no CR stands
// alone. A bare CR is dangerous because some servers treat it as a line end,
// so a body like "\r.\r" can smuggle the end-of-data marker or a command.
func TestBuild_WireCarriesNoBareCarriageReturn(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		body   string
		assert func(t *testing.T, body string)
	}

	cases := []testCase{
		{
			name: "a bare carriage return becomes CRLF",
			body: "hello\r.\r\nMAIL FROM",
			assert: func(t *testing.T, body string) {
				assert.Equal(t, "hello\r\n.\r\nMAIL FROM", body)
			},
		},
		{
			name: "a bare line feed becomes CRLF",
			body: "one\ntwo",
			assert: func(t *testing.T, body string) {
				assert.Equal(t, "one\r\ntwo", body)
			},
		},
		{
			name: "a CRLF stays one CRLF",
			body: "one\r\ntwo",
			assert: func(t *testing.T, body string) {
				assert.Equal(t, "one\r\ntwo", body)
			},
		},
		{
			name: "all three mixed",
			body: "a\rb\nc\r\nd\r\r\ne",
			assert: func(t *testing.T, body string) {
				assert.Equal(t, "a\r\nb\r\nc\r\nd\r\n\r\ne", body)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wire := string(notify.Build("noreply@example.com", notify.Message{To: "a@example.com", Subject: "s", TextBody: tc.body}))
			_, body, found := strings.Cut(wire, "\r\n\r\n")

			assert.True(t, found, "the header block ends in a blank line")
			assert.NotRegexp(t, "\r[^\n]|\r$", wire, "a carriage return stands alone")
			tc.assert(t, body)
		})
	}
}
