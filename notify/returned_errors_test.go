package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/notify"
)

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
