package notify_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/notify"
)

// testMessage is the message every SMTP test sends unless it cares about the
// content.
func testMessage() notify.Message {
	return notify.Message{
		To:       "ada@example.com",
		Subject:  "Sign in",
		TextBody: "here is your link",
	}
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

	t.Run("a server that never greets fails within the bound", func(t *testing.T) {
		t.Parallel()

		srv := startScriptedServer(t, scriptSilentGreeting())
		s := newTestSMTPSender(t, srv, notify.WithSMTPTimeout(2*time.Second))

		start := time.Now()
		err := s.Send(t.Context(), testMessage())
		elapsed := time.Since(start)

		require.Error(t, err)
		assert.Less(t, elapsed, 3*time.Second, "the bound must hold")
		assert.GreaterOrEqual(t, elapsed, 1500*time.Millisecond, "and must not fire early")
	})

	t.Run("a context already ended fails before any network activity", func(t *testing.T) {
		t.Parallel()

		srv := startScriptedServer(t, scriptOK())
		s := newTestSMTPSender(t, srv)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		require.Error(t, s.Send(ctx, testMessage()))
		assert.False(t, srv.Dialled(), "an ended context must not reach the network")
	})
}

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

func TestSMTPSenderContextDeadline(t *testing.T) {
	t.Parallel()

	srv := startScriptedServer(t, scriptSilentGreeting())
	s := newTestSMTPSender(t, srv) // default 30s

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	start := time.Now()
	require.Error(t, s.Send(ctx, testMessage()))
	assert.Less(t, time.Since(start), 2*time.Second, "the earlier caller deadline wins")
}

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
