package notify_test

import (
	"bytes"
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/kartaladev/scrty/notify"
)

// senderFunc adapts a function to the Sender port, for the cases whose whole
// subject is what the wrapped sender does.
type senderFunc func(ctx context.Context, msg notify.Message) error

func (f senderFunc) Send(ctx context.Context, msg notify.Message) error { return f(ctx, msg) }

// recordingSender counts what reached it, optionally taking its time.
type recordingSender struct {
	delay time.Duration
	count atomic.Int64
}

func (s *recordingSender) Send(ctx context.Context, _ notify.Message) error {
	// It honours its context, as a real sender does, so a test can tell a
	// detached delivery from one that inherited the caller's cancellation.
	if err := ctx.Err(); err != nil {
		return err
	}

	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	s.count.Add(1)

	return nil
}

func (s *recordingSender) Count() int { return int(s.count.Load()) }

// blockingSender occupies a worker until the test releases it.
type blockingSender struct {
	release  chan struct{}
	inflight atomic.Int64
}

func (s *blockingSender) Send(ctx context.Context, _ notify.Message) error {
	s.inflight.Add(1)

	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newQueued(t *testing.T, inner notify.Sender, opts ...notify.QueuedOption) *notify.QueuedSender {
	t.Helper()

	s, err := notify.NewQueuedSender(inner, opts...)
	require.NoError(t, err)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
		defer cancel()

		_ = s.Close(ctx)
	})

	return s
}

func TestNewQueuedSender(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		inner  notify.Sender
		opts   []notify.QueuedOption
		assert func(t *testing.T, s *notify.QueuedSender, err error)
	}

	configError := func(t *testing.T, s *notify.QueuedSender, err error) {
		require.Error(t, err)
		assert.ErrorIs(t, err, notify.ErrConfig)
		assert.Nil(t, s)
	}

	cases := []testCase{
		{
			name:  "defaults",
			inner: &recordingSender{},
			assert: func(t *testing.T, s *notify.QueuedSender, err error) {
				require.NoError(t, err)

				t.Cleanup(func() { _ = s.Close(context.WithoutCancel(t.Context())) })

				assert.Equal(t, 2, s.Workers())
				assert.Equal(t, 256, s.QueueSize())
				assert.Equal(t, 30*time.Second, s.SendTimeout())
				assert.True(t, s.NonBlocking())
			},
		},
		{name: "no inner sender", inner: nil, assert: configError},
		{name: "typed-nil inner sender", inner: (*recordingSender)(nil), assert: configError},
		{
			name:   "zero workers",
			inner:  &recordingSender{},
			opts:   []notify.QueuedOption{notify.WithQueueWorkers(0)},
			assert: configError,
		},
		{
			name:   "negative workers",
			inner:  &recordingSender{},
			opts:   []notify.QueuedOption{notify.WithQueueWorkers(-1)},
			assert: configError,
		},
		{
			name:   "zero queue",
			inner:  &recordingSender{},
			opts:   []notify.QueuedOption{notify.WithQueueSize(0)},
			assert: configError,
		},
		{
			name:   "zero send timeout",
			inner:  &recordingSender{},
			opts:   []notify.QueuedOption{notify.WithQueueSendTimeout(0)},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := notify.NewQueuedSender(tc.inner, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestQueuedSenderReturnsBeforeDelivery(t *testing.T) {
	t.Parallel()

	t.Run("returns while the inner sender is still working", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			inner := &blockingSender{release: make(chan struct{})}
			s := newQueued(t, inner)

			start := time.Now()
			require.NoError(t, s.Send(t.Context(), testMessage()))
			assert.Less(t, time.Since(start), 50*time.Millisecond)

			synctest.Wait()
			assert.Equal(t, int64(1), inner.inflight.Load(), "the delivery is still in flight")

			close(inner.release)
			require.NoError(t, s.Close(context.WithoutCancel(t.Context())))
		})
	})

	t.Run("the caller's cancellation does not stop the delivery", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			inner := &recordingSender{}
			s := newQueued(t, inner)

			ctx, cancel := context.WithCancel(t.Context())
			require.NoError(t, s.Send(ctx, testMessage()))
			cancel()

			require.NoError(t, s.Close(context.WithoutCancel(t.Context())))
			assert.Equal(t, 1, inner.Count())
		})
	})

	t.Run("the caller's values survive", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			type key struct{}

			var seen atomic.Value

			inner := senderFunc(func(ctx context.Context, _ notify.Message) error {
				if v := ctx.Value(key{}); v != nil {
					seen.Store(v)
				}

				return nil
			})

			s := newQueued(t, inner)

			ctx, cancel := context.WithCancel(context.WithValue(t.Context(), key{}, "tenant-acme"))
			require.NoError(t, s.Send(ctx, testMessage()))
			cancel()

			require.NoError(t, s.Close(context.WithoutCancel(t.Context())))
			assert.Equal(t, "tenant-acme", seen.Load())
		})
	})
}

func TestQueuedSenderFull(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var buf bytes.Buffer

		logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

		inner := &blockingSender{release: make(chan struct{})}

		s, err := notify.NewQueuedSender(inner,
			notify.WithQueueWorkers(1),
			notify.WithQueueSize(1),
			notify.WithQueueLogger(logger),
		)
		require.NoError(t, err)

		// One message occupies the single worker.
		require.NoError(t, s.Send(t.Context(), testMessage()))
		synctest.Wait()
		require.Equal(t, int64(1), inner.inflight.Load())

		// One fills the queue of 1.
		require.NoError(t, s.Send(t.Context(), testMessage()))

		// The next has nowhere to go.
		start := time.Now()
		err = s.Send(t.Context(), testMessage())
		assert.ErrorIs(t, err, notify.ErrQueueFull)
		assert.Less(t, time.Since(start), 50*time.Millisecond, "it must not wait for space")
		assert.Contains(t, buf.String(), `"level":"ERROR"`, "a drop is logged at error")

		close(inner.release)
		require.NoError(t, s.Close(context.WithoutCancel(t.Context())))
	})
}

func TestQueuedSenderClose(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		inner := &recordingSender{delay: 100 * time.Millisecond}
		s := newQueued(t, inner)

		for range 3 {
			require.NoError(t, s.Send(t.Context(), testMessage()))
		}

		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
		defer cancel()

		require.NoError(t, s.Close(ctx))
		assert.Equal(t, 3, inner.Count(), "close drains what was queued")
		assert.ErrorIs(t, s.Send(t.Context(), testMessage()), notify.ErrSenderClosed)
	})
}

func TestQueuedSenderRecoversPanic(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var calls atomic.Int64

	inner := senderFunc(func(context.Context, notify.Message) error {
		if calls.Add(1) == 1 {
			panic("inner sender exploded")
		}

		return nil
	})

	s, err := notify.NewQueuedSender(inner,
		notify.WithQueueWorkers(1),
		notify.WithQueueLogger(logger),
	)
	require.NoError(t, err)

	require.NoError(t, s.Send(t.Context(), testMessage()))
	require.NoError(t, s.Send(t.Context(), testMessage()))
	require.NoError(t, s.Close(context.WithoutCancel(t.Context())))

	assert.Equal(t, int64(2), calls.Load(), "the worker survives the panic and takes the next message")
	assert.Contains(t, buf.String(), `"reason":"panic"`, "the panic is logged")
	assert.Contains(t, buf.String(), `"value_type":"string"`, "the panic's type is logged")
	assert.NotContains(t, buf.String(), "inner sender exploded", "the panic's own value is not logged")
}

func TestQueuedSenderWorkers(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var concurrent, peak atomic.Int64

		inner := senderFunc(func(context.Context, notify.Message) error {
			n := concurrent.Add(1)

			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}

			time.Sleep(100 * time.Millisecond)
			concurrent.Add(-1)

			return nil
		})

		s, err := notify.NewQueuedSender(inner, notify.WithQueueWorkers(8), notify.WithQueueSize(32))
		require.NoError(t, err)

		for range 16 {
			require.NoError(t, s.Send(t.Context(), testMessage()))
		}

		require.NoError(t, s.Close(context.WithoutCancel(t.Context())))

		assert.Equal(t, int64(8), peak.Load(), "eight workers run eight deliveries at once")
	})
}

func TestQueuedSenderNoLeak(t *testing.T) {
	defer goleak.VerifyNone(t)

	s, err := notify.NewQueuedSender(&recordingSender{}, notify.WithQueueWorkers(4))
	require.NoError(t, err)
	require.NoError(t, s.Send(t.Context(), testMessage()))
	require.NoError(t, s.Close(context.WithoutCancel(t.Context())))
}

// swapDefaultLogger installs l as the process-wide default logger and returns
// a function that restores the previous one. slog's default is process state,
// so a test that replaces it runs alone: neither the test nor its cases may be
// parallel.
func swapDefaultLogger(t *testing.T, l *slog.Logger) func() {
	t.Helper()

	prev := slog.Default()
	slog.SetDefault(l)

	return func() { slog.SetDefault(prev) }
}

// TestQueuedSenderReportsDropsByDefault pins where a drop goes when the
// consumer has configured no logger: to slog's default, not into silence. A
// dropped message is a sign-in link that never arrives, and Send returned
// before the drop was decided, so a default that discarded the record would
// leave the failure invisible at both ends.
//
// Neither this test nor its cases call t.Parallel, because they hold the
// process-wide default logger and no two tests may hold it at once.
func TestQueuedSenderReportsDropsByDefault(t *testing.T) {
	const body = "here is your single-use sign-in link"

	type testCase struct {
		name   string
		opts   []notify.QueuedOption
		assert func(t *testing.T, logged string, err error)
	}

	cases := []testCase{
		{
			name: "a drop is reported with no logger configured",
			assert: func(t *testing.T, logged string, err error) {
				require.ErrorIs(t, err, notify.ErrQueueFull)
				assert.Contains(t, logged, "queue",
					"a dropped sign-in message is reported without configuration")
				assert.NotContains(t, logged, body,
					"and the record still carries no message body")
			},
		},
		{
			name: "silence is available but must be asked for",
			opts: []notify.QueuedOption{notify.WithQueueLogger(slog.New(slog.DiscardHandler))},
			assert: func(t *testing.T, logged string, err error) {
				require.ErrorIs(t, err, notify.ErrQueueFull)
				assert.Empty(t, logged, "a supplied discarding logger writes nothing")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer

			restore := swapDefaultLogger(t, slog.New(slog.NewTextHandler(&buf, nil)))
			defer restore()

			synctest.Test(t, func(t *testing.T) {
				inner := &blockingSender{release: make(chan struct{})}

				msg := testMessage()
				msg.TextBody = body

				opts := append([]notify.QueuedOption{
					notify.WithQueueWorkers(1),
					notify.WithQueueSize(1),
				}, tc.opts...)

				s, err := notify.NewQueuedSender(inner, opts...)
				require.NoError(t, err)

				// One message occupies the only worker, the next fills the
				// queue of one, and the third has nowhere to go.
				require.NoError(t, s.Send(t.Context(), msg))
				synctest.Wait()
				require.Equal(t, int64(1), inner.inflight.Load())
				require.NoError(t, s.Send(t.Context(), msg))

				err = s.Send(t.Context(), msg)

				close(inner.release)
				require.NoError(t, s.Close(context.WithoutCancel(t.Context())))

				tc.assert(t, buf.String(), err)
			})
		})
	}
}
