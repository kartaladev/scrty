package notify_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/notify"
)

// deadlineFailConn is a dialled connection whose SetDeadline fails with text
// that names a subject.
type deadlineFailConn struct {
	net.Conn
	err error
}

func (c deadlineFailConn) SetDeadline(time.Time) error { return c.err }
func (deadlineFailConn) Close() error                  { return nil }

// TestSMTPSender_SendKeepsConnectionDeadlineTextOutOfError pins that the text of
// a connection's deadline failure, which the consumer's dialler owns, does not
// reach the returned error, while the cause stays reachable.
func TestSMTPSender_SendKeepsConnectionDeadlineTextOutOfError(t *testing.T) {
	t.Parallel()

	cause := errors.New("set deadline for user u-123 failed")

	s, err := notify.NewSMTPSender("127.0.0.1",
		notify.WithSMTPPort(2525),
		notify.WithSMTPFrom("no-reply@example.com"),
		notify.WithSMTPTimeout(time.Second),
		notify.WithSMTPDialer(func(context.Context, string, string) (net.Conn, error) {
			c1, c2 := net.Pipe()
			t.Cleanup(func() { _ = c2.Close() })

			return deadlineFailConn{Conn: c1, err: cause}, nil
		}),
	)
	require.NoError(t, err)

	err = s.Send(t.Context(), testMessage())

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "u-123")
	assert.ErrorIs(t, err, cause)
}
