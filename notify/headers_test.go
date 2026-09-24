package notify_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/notify"
)

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
