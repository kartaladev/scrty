package notify_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/notify"
)

// routeBuffer is a bytes.Buffer safe for concurrent writes.
type routeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *routeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *routeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

func routeLogger(w *routeBuffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// routeCase is one row of the routing tables below: which logger sources exist
// and what each one saw.
type routeCase struct {
	name   string
	own    bool
	chain  bool
	assert func(t *testing.T, chain, own, def string)
}

func routeCases(want string) []routeCase {
	return []routeCase{
		{
			name:  "no option, inside a configured chain",
			chain: true,
			assert: func(t *testing.T, chain, _, def string) {
				assert.Contains(t, chain, want)
				assert.Empty(t, def)
			},
		},
		{
			name:  "own option wins",
			own:   true,
			chain: true,
			assert: func(t *testing.T, chain, own, def string) {
				assert.Contains(t, own, want)
				assert.Empty(t, chain)
				assert.Empty(t, def)
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, _, _, def string) {
				assert.Contains(t, def, want)
			},
		},
	}
}

func swapDefault(t *testing.T, w *routeBuffer) {
	t.Helper()

	prev := slog.Default()
	slog.SetDefault(routeLogger(w))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// TestLogRoute_SMTPSender pins where a failed delivery's record goes. It swaps
// the default logger, so it does not run in parallel.
func TestLogRoute_SMTPSender(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	for _, tc := range routeCases("notify: smtp send failed") {
		t.Run(tc.name, func(t *testing.T) {
			var chain, own, def routeBuffer
			swapDefault(t, &def)

			opts := []notify.SMTPOption{
				notify.WithSMTPDialer(func(context.Context, string, string) (net.Conn, error) {
					return nil, errors.New("refused")
				}),
			}
			if tc.own {
				opts = append(opts, notify.WithSMTPLogger(routeLogger(&own)))
			}

			s, err := notify.NewSMTPSender("mail.example.test", opts...)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, routeLogger(&chain))
			}

			require.Error(t, s.Send(ctx, notify.Message{To: "a@example.test", From: "b@example.test", Subject: "s"}))

			tc.assert(t, chain.String(), own.String(), def.String())
		})
	}
}

// TestLogRoute_SMTPSender_NilLogger pins that a nil logger option fails
// construction, naming the option.
func TestLogRoute_SMTPSender_NilLogger(t *testing.T) {
	t.Parallel()

	_, err := notify.NewSMTPSender("mail.example.test", notify.WithSMTPLogger(nil))

	require.ErrorIs(t, err, notify.ErrConfig)
	assert.Contains(t, err.Error(), "WithSMTPLogger")
}

// routeBlocker holds every delivery until release is closed.
type routeBlocker struct{ release chan struct{} }

func (b routeBlocker) Send(context.Context, notify.Message) error {
	<-b.release

	return nil
}

// TestLogRoute_QueuedSender pins where a dropped message's record goes: the
// record is written for the request that queued the dropped message. It swaps
// the default logger, so it does not run in parallel.
func TestLogRoute_QueuedSender(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	for _, tc := range routeCases("notify: send queue is full") {
		t.Run(tc.name, func(t *testing.T) {
			var chain, own, def routeBuffer
			swapDefault(t, &def)

			release := make(chan struct{})
			opts := []notify.QueuedOption{notify.WithQueueWorkers(1), notify.WithQueueMaxMessages(1)}
			if tc.own {
				opts = append(opts, notify.WithQueueLogger(routeLogger(&own)))
			}

			q, err := notify.NewQueuedSender(routeBlocker{release: release}, opts...)
			require.NoError(t, err)
			t.Cleanup(func() {
				close(release)
				_ = q.Shutdown(context.Background())
			})

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, routeLogger(&chain))
			}

			var dropped bool
			for range 5 {
				if errors.Is(q.Send(ctx, notify.Message{To: "a@example.test"}), notify.ErrQueueFull) {
					dropped = true

					break
				}
			}
			require.True(t, dropped, "the queue never filled")

			tc.assert(t, chain.String(), own.String(), def.String())
		})
	}
}

// routeSenderFunc adapts a function to notify.Sender.
type routeSenderFunc func(context.Context, notify.Message) error

func (f routeSenderFunc) Send(ctx context.Context, m notify.Message) error { return f(ctx, m) }

// TestLogRoute_QueuedSender_WorkerRecords pins where the records written on the
// worker goroutine go: the delivery runs after the queuing request has
// returned, and its record is written for that request, so it lands on the
// logger of the chain that queued the message. It swaps the default logger, so
// it does not run in parallel.
func TestLogRoute_QueuedSender_WorkerRecords(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	senders := []struct {
		name  string
		want  string
		inner routeSenderFunc
	}{
		{
			name: "inner sender fails",
			want: "notify: delivery failed",
			inner: func(context.Context, notify.Message) error {
				return errors.New("smtp down")
			},
		},
		{
			name: "inner sender panics",
			want: "notify: sender panicked while delivering",
			inner: func(context.Context, notify.Message) error {
				panic("boom")
			},
		},
	}

	for _, sc := range senders {
		for _, tc := range routeCases(sc.want) {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				var chain, own, def routeBuffer
				swapDefault(t, &def)

				// The delivery starts only once the queuing request is over.
				requestDone := make(chan struct{})
				inner := routeSenderFunc(func(ctx context.Context, m notify.Message) error {
					<-requestDone

					return sc.inner(ctx, m)
				})

				var opts []notify.QueuedOption
				if tc.own {
					opts = append(opts, notify.WithQueueLogger(routeLogger(&own)))
				}

				q, err := notify.NewQueuedSender(inner, opts...)
				require.NoError(t, err)

				reqCtx, cancel := context.WithCancel(t.Context())
				if tc.chain {
					reqCtx = ctxlog.With(reqCtx, routeLogger(&chain))
				}

				require.NoError(t, q.Send(reqCtx, notify.Message{To: "a@example.test"}))

				// The request returns and its context ends before the worker delivers.
				cancel()
				close(requestDone)

				require.NoError(t, q.Shutdown(t.Context()))

				tc.assert(t, chain.String(), own.String(), def.String())
			})
		}
	}
}

// TestLogRoute_QueuedSender_NilLogger pins that a nil logger option fails
// construction, naming the option.
func TestLogRoute_QueuedSender_NilLogger(t *testing.T) {
	t.Parallel()

	_, err := notify.NewQueuedSender(routeBlocker{release: make(chan struct{})}, notify.WithQueueLogger(nil))

	require.ErrorIs(t, err, notify.ErrConfig)
	assert.Contains(t, err.Error(), "WithQueueLogger")
}
