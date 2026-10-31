// The queued sender cases are separate TestXxx functions where their setup
// differs in kind — a blocking, recording, panicking or concurrency-measuring
// inner sender, inside or outside a synctest bubble — and tables wherever the
// rows share one call shape.
package notify_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/kartaladev/scrty/notify"
)

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

		_ = s.Shutdown(ctx)
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

				t.Cleanup(func() { _ = s.Shutdown(context.WithoutCancel(t.Context())) })

				assert.Equal(t, 2, s.Workers())
				assert.Equal(t, 256, s.QueueMaxMessages())
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
			opts:   []notify.QueuedOption{notify.WithQueueMaxMessages(0)},
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
			require.NoError(t, s.Shutdown(context.WithoutCancel(t.Context())))
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

			require.NoError(t, s.Shutdown(context.WithoutCancel(t.Context())))
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

			require.NoError(t, s.Shutdown(context.WithoutCancel(t.Context())))
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
			notify.WithQueueMaxMessages(1),
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
		require.NoError(t, s.Shutdown(context.WithoutCancel(t.Context())))
	})
}

func TestQueuedSender_Shutdown(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		delay time.Duration // how long the wrapped sender takes per message
		sends int           // messages queued before the shutdown under test
		// before runs between the sends and the shutdown under test, for the
		// cases that are about a second shutdown.
		before func(t *testing.T, s *notify.QueuedSender)
		ctx    func(t *testing.T, ctx context.Context) context.Context
		assert func(t *testing.T, s *notify.QueuedSender, inner *recordingSender, err error, took time.Duration)
	}

	within := func(d time.Duration) func(t *testing.T, ctx context.Context) context.Context {
		return func(t *testing.T, ctx context.Context) context.Context {
			ctx, cancel := context.WithTimeout(ctx, d)
			t.Cleanup(cancel)

			return ctx
		}
	}

	cases := []testCase{
		{
			name:  "close drains",
			delay: 100 * time.Millisecond,
			sends: 3,
			ctx:   within(10 * time.Second),
			assert: func(t *testing.T, s *notify.QueuedSender, inner *recordingSender, err error, _ time.Duration) {
				require.NoError(t, err)
				assert.Equal(t, 3, inner.Count(), "shutdown drains what was queued")

				err = s.Send(t.Context(), testMessage())
				require.ErrorIs(t, err, notify.ErrAlreadyShutdown, "a later send is refused")
			},
		},
		{
			name:  "shutdown bounded by its context",
			delay: 5 * time.Second,
			sends: 1,
			ctx:   within(time.Second),
			assert: func(t *testing.T, _ *notify.QueuedSender, inner *recordingSender, err error, took time.Duration) {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				assert.Equal(t, time.Second, took, "it waits exactly as long as its context allows")
				assert.Zero(t, inner.Count(), "the slow delivery had not finished")
			},
		},
		{
			name:  "shutdown twice",
			sends: 1,
			before: func(t *testing.T, s *notify.QueuedSender) {
				require.NoError(t, s.Shutdown(t.Context()))
			},
			ctx: within(10 * time.Second),
			assert: func(t *testing.T, _ *notify.QueuedSender, inner *recordingSender, err error, _ time.Duration) {
				require.NoError(t, err, "a second shutdown after the drain returns nil")
				assert.Equal(t, 1, inner.Count())
			},
		},
		{
			name:  "a later shutdown waits again",
			delay: 5 * time.Second,
			sends: 1,
			before: func(t *testing.T, s *notify.QueuedSender) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()

				require.ErrorIs(t, s.Shutdown(ctx), context.DeadlineExceeded)
			},
			ctx: within(10 * time.Second),
			assert: func(t *testing.T, _ *notify.QueuedSender, inner *recordingSender, err error, took time.Duration) {
				require.NoError(t, err)
				assert.Equal(t, 1, inner.Count(), "it returned only once the drain had delivered the message")
				assert.Equal(t, 4*time.Second, took, "it waited for the rest of the delivery")
			},
		},
		{
			name:  "completion wins over a done context",
			sends: 1,
			before: func(t *testing.T, s *notify.QueuedSender) {
				require.NoError(t, s.Shutdown(t.Context()))
			},
			ctx: func(_ *testing.T, ctx context.Context) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				cancel()

				return ctx
			},
			assert: func(t *testing.T, _ *notify.QueuedSender, _ *recordingSender, err error, _ time.Duration) {
				require.NoError(t, err, "the drain has finished, so the done context does not matter")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				inner := &recordingSender{delay: tc.delay}
				s := newQueued(t, inner)

				for range tc.sends {
					require.NoError(t, s.Send(t.Context(), testMessage()))
				}

				if tc.before != nil {
					tc.before(t, s)
				}

				ctx := t.Context()
				if tc.ctx != nil {
					ctx = tc.ctx(t, ctx)
				}

				start := time.Now()
				err := s.Shutdown(ctx)
				tc.assert(t, s, inner, err, time.Since(start))
			})
		})
	}
}

// TestQueuedSender_CompletionWinsRepeatedly runs the completion-wins case many
// times outside a bubble: with both the drain finished and the context done, a
// select alone would pick either case at random, so one run proves nothing.
func TestQueuedSender_CompletionWinsRepeatedly(t *testing.T) {
	t.Parallel()

	s, err := notify.NewQueuedSender(&recordingSender{})
	require.NoError(t, err)
	require.NoError(t, s.Shutdown(t.Context()))

	done, cancel := context.WithCancel(t.Context())
	cancel()

	for range 1000 {
		require.NoError(t, s.Shutdown(done))
	}
}

// deliveredSet records which messages reached the wrapped sender, by subject.
type deliveredSet struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (d *deliveredSet) Send(_ context.Context, msg notify.Message) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.seen[msg.Subject] = true

	return nil
}

func (d *deliveredSet) has(subject string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.seen[subject]
}

// TestQueuedSender_SendsRacingShutdown pins the accept-then-deliver promise
// under contention: a send that returned nil has a message the drain
// delivers, and every other send was refused with the shut-down error. Run it
// under -race.
func TestQueuedSender_SendsRacingShutdown(t *testing.T) {
	t.Parallel()

	const (
		senders = 100
		perSend = 10
	)

	inner := &deliveredSet{seen: map[string]bool{}}

	s, err := notify.NewQueuedSender(inner,
		notify.WithQueueWorkers(4),
		notify.WithQueueMaxMessages(senders*perSend),
	)
	require.NoError(t, err)

	type outcome struct {
		subject string
		err     error
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		outcomes []outcome
		panicked atomic.Int64
		accepted atomic.Int64
	)

	release := make(chan struct{})

	for g := range senders {
		wg.Go(func() {
			defer func() {
				if recover() != nil {
					panicked.Add(1)
				}
			}()

			<-release

			// Each sender keeps going until it is refused, so the refusal
			// path is always exercised alongside the accepting one.
			for i := range perSend {
				msg := testMessage()
				msg.Subject = fmt.Sprintf("message %d-%d", g, i)

				err := s.Send(t.Context(), msg)

				mu.Lock()
				outcomes = append(outcomes, outcome{subject: msg.Subject, err: err})
				mu.Unlock()

				if err != nil {
					return
				}

				accepted.Add(1)
				runtime.Gosched()
			}
		})
	}

	shutdown := make(chan error, 1)

	go func() {
		<-release

		// Shut down mid-stream: once some sends have been accepted, while
		// others are still arriving.
		for accepted.Load() < senders/2 {
			runtime.Gosched()
		}

		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
		defer cancel()

		shutdown <- s.Shutdown(ctx)
	}()

	close(release)
	wg.Wait()
	require.NoError(t, <-shutdown, "the drain finishes within its context")

	assert.Zero(t, panicked.Load(), "no send panics")

	refused := 0

	for _, o := range outcomes {
		if o.err == nil {
			assert.True(t, inner.has(o.subject), "%s was accepted, so it must be delivered", o.subject)

			continue
		}

		refused++

		assert.ErrorIs(t, o.err, notify.ErrAlreadyShutdown, "%s was refused with the wrong error", o.subject)
	}

	assert.Positive(t, refused, "some sends raced past the shutdown and were refused")
	assert.GreaterOrEqual(t, accepted.Load(), int64(senders/2), "some sends were accepted before it")
}

// TestQueuedSender_ShutdownFromInsideWrappedSender shows a wrapped sender that
// calls Shutdown cannot wait for its own delivery: the call returns its
// context's error once that context ends, rather than deadlocking.
func TestQueuedSender_ShutdownFromInsideWrappedSender(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var (
			s      *notify.QueuedSender
			inside = make(chan error, 1)
		)

		inner := senderFunc(func(ctx context.Context, _ notify.Message) error {
			sctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			defer cancel()

			inside <- s.Shutdown(sctx)

			return nil
		})

		var err error

		s, err = notify.NewQueuedSender(inner)
		require.NoError(t, err)

		require.NoError(t, s.Send(t.Context(), testMessage()))
		require.ErrorIs(t, <-inside, context.DeadlineExceeded)
		require.NoError(t, s.Shutdown(t.Context()), "the drain finishes once the wrapped sender returns")
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
	require.NoError(t, s.Shutdown(context.WithoutCancel(t.Context())))

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

		s, err := notify.NewQueuedSender(inner, notify.WithQueueWorkers(8), notify.WithQueueMaxMessages(32))
		require.NoError(t, err)

		for range 16 {
			require.NoError(t, s.Send(t.Context(), testMessage()))
		}

		require.NoError(t, s.Shutdown(context.WithoutCancel(t.Context())))

		assert.Equal(t, int64(8), peak.Load(), "eight workers run eight deliveries at once")
	})
}

func TestQueuedSenderNoLeak(t *testing.T) {
	defer goleak.VerifyNone(t)

	s, err := notify.NewQueuedSender(&recordingSender{}, notify.WithQueueWorkers(4))
	require.NoError(t, err)
	require.NoError(t, s.Send(t.Context(), testMessage()))
	require.NoError(t, s.Shutdown(context.WithoutCancel(t.Context())))
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
					notify.WithQueueMaxMessages(1),
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
				require.NoError(t, s.Shutdown(context.WithoutCancel(t.Context())))

				tc.assert(t, buf.String(), err)
			})
		})
	}
}
