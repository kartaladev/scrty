// The queued sender cases are separate TestXxx functions where their setup
// differs in kind — a blocking, recording, panicking, goroutine-ending or
// concurrency-measuring inner sender, inside or outside a synctest bubble — and
// tables wherever the rows share one call shape.
package notify_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

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

// nilContext returns the nil context a caller's unset variable would pass.
// It is a function so the tests below hand Start and Shutdown a nil without a
// context-typed variable of their own in scope.
func nilContext() context.Context { return nil }

// TestQueuedSender_NilContext pins that Shutdown refuses a nil context with an
// error wrapping ErrConfig and changes nothing: the sender is not marked shut
// down, so it still accepts sends and a real Shutdown still drains and
// returns nil.
func TestQueuedSender_NilContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, s *notify.QueuedSender, inner *recordingSender)
	}

	cases := []testCase{
		{
			name: "shutdown",
			assert: func(t *testing.T, s *notify.QueuedSender, inner *recordingSender) {
				var err error
				require.NotPanics(t, func() { err = s.Shutdown(nilContext()) }, "Shutdown must refuse a nil context, not panic")
				require.ErrorIs(t, err, notify.ErrConfig)

				require.NoError(t, s.Send(t.Context(), notify.Message{Subject: "after"}),
					"the refused Shutdown did not stop intake")
				require.NoError(t, s.Shutdown(t.Context()), "a real Shutdown still drains")
				assert.Equal(t, 1, inner.Count(), "the message accepted after the refused Shutdown was delivered")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inner := &recordingSender{}
			tc.assert(t, newQueued(t, inner), inner)
		})
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

// blockingHandler is a slog handler that parks the goroutine logging a
// matching record until the test releases it, standing in for a slow or
// re-entrant log handler.
type blockingHandler struct {
	match   string
	entered chan struct{}
	once    sync.Once
	release chan struct{}
}

func (h *blockingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *blockingHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Message != h.match {
		return nil
	}

	h.once.Do(func() { close(h.entered) })
	<-h.release

	return nil
}

func (h *blockingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *blockingHandler) WithGroup(string) slog.Handler { return h }

// TestQueuedSender_ShutdownNotHeldByASlowLogger shows a Send that is logging a
// dropped message does not hold Shutdown past its context: the drop is
// decided under the lock and logged after it is released.
//
// It runs on real time rather than in a synctest bubble, because a goroutine
// blocked on a mutex is not durably blocked, so a bubble would never advance
// its clock to end Shutdown's context. It is not parallel, so goleak sees only
// its own goroutines.
func TestQueuedSender_ShutdownNotHeldByASlowLogger(t *testing.T) {
	defer goleak.VerifyNone(t)

	handler := &blockingHandler{
		match:   "notify: send queue is full, message dropped",
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}

	inner := &blockingSender{release: make(chan struct{})}

	s, err := notify.NewQueuedSender(inner,
		notify.WithQueueWorkers(1),
		notify.WithQueueMaxMessages(1),
		notify.WithQueueLogger(slog.New(handler)),
	)
	require.NoError(t, err)

	sendDone := make(chan error, 1)
	shutdownDone := make(chan error, 1)

	// Everything the test parks is released before goleak looks, whether the
	// assertions passed or not, so a failing run reports instead of hanging.
	defer func() {
		close(handler.release)
		close(inner.release)

		select {
		case err := <-sendDone:
			assert.ErrorIs(t, err, notify.ErrQueueFull, "the parked Send reports the drop")
		case <-time.After(5 * time.Second):
			t.Error("the parked Send did not return after the handler was released")
		}

		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()

		assert.NoError(t, s.Shutdown(ctx), "the drain finishes once the worker is released")
	}()

	// One message occupies the single worker.
	require.NoError(t, s.Send(t.Context(), testMessage()))
	require.Eventually(t, func() bool { return inner.inflight.Load() == 1 },
		time.Second, time.Millisecond, "the worker takes the first message")

	// One fills the queue of 1.
	require.NoError(t, s.Send(t.Context(), testMessage()))

	// The next is dropped, and its Send parks in the handler logging the drop.
	go func() { sendDone <- s.Send(context.WithoutCancel(t.Context()), testMessage()) }()

	select {
	case <-handler.entered:
	case <-time.After(time.Second):
		require.FailNow(t, "the dropped Send never reached the log handler")
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 100*time.Millisecond)
		defer cancel()

		shutdownDone <- s.Shutdown(ctx)
	}()

	select {
	case err := <-shutdownDone:
		require.ErrorIs(t, err, context.DeadlineExceeded,
			"Shutdown gives up when its context ends, the worker still being busy")
	case <-time.After(time.Second):
		require.FailNow(t, "Shutdown did not return within 1s of a 100ms context: "+
			"it is held by the Send logging a drop")
	}
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

// queuedTestBound is how long a goroutine-ending test waits for something that
// must happen. It bounds the failing run, which would otherwise wait forever.
const queuedTestBound = 5 * time.Second

// goexitSender ends the goroutine of its first deliveries with runtime.Goexit,
// which is what t.FailNow does inside a sender and which recover cannot stop.
// Those deliveries stay in flight together until the test releases them, so a
// test can decide what happens first. Every later delivery is recorded.
type goexitSender struct {
	ending    int64
	arrived   atomic.Int64
	allIn     chan struct{}
	release   chan struct{}
	once      sync.Once
	delivered chan string

	// lateDelay is how long a later delivery takes. completed counts the
	// later deliveries that have finished, so a test can read it the moment
	// Shutdown returns, and delivered carries their subjects.
	lateDelay time.Duration
	completed atomic.Int64
}

func newGoexitSender(ending int, lateDelay time.Duration) *goexitSender {
	return &goexitSender{
		ending:    int64(ending),
		lateDelay: lateDelay,
		allIn:     make(chan struct{}),
		release:   make(chan struct{}),
		delivered: make(chan string, 16),
	}
}

func (s *goexitSender) Send(ctx context.Context, msg notify.Message) error {
	n := s.arrived.Add(1)
	if n > s.ending {
		time.Sleep(s.lateDelay)
		s.completed.Add(1)
		s.delivered <- msg.Subject

		return nil
	}

	if n == s.ending {
		close(s.allIn)
	}

	select {
	case <-s.allIn:
	case <-ctx.Done():
	}

	select {
	case <-s.release:
	case <-ctx.Done():
	}

	runtime.Goexit()

	return nil
}

// end lets the held deliveries end their goroutines. Calling it twice is safe.
func (s *goexitSender) end() { s.once.Do(func() { close(s.release) }) }

// lockedBuffer lets a test read what a logger wrote while a worker may still be
// writing, which a failing run can leave happening.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// TestQueuedSender_WrappedSenderEndsItsGoroutine pins that a delivery whose
// wrapped sender ends its goroutine is logged as failed and costs the pool
// nothing, whether it happens in service or during the drain, and that no
// worker is left running afterwards. It does not run in parallel, so goleak
// sees only its own goroutines.
func TestQueuedSender_WrappedSenderEndsItsGoroutine(t *testing.T) {
	const laterSubject = "later message"

	type testCase struct {
		name    string
		workers int
		// later is how many later messages the row queues, all of which must
		// have been delivered by the time the final Shutdown returns.
		later int
		// act runs once every ending delivery is in flight. It never waits for
		// a later message: the final Shutdown does that.
		act    func(t *testing.T, s *notify.QueuedSender, inner *goexitSender)
		assert func(t *testing.T, shutdownErr error, records string)
	}

	sendLater := func(t *testing.T, s *notify.QueuedSender) {
		t.Helper()

		msg := testMessage()
		msg.Subject = laterSubject

		require.NoError(t, s.Send(t.Context(), msg))
	}

	// closeQueue begins the shutdown without waiting for it. An already-ended
	// context makes Shutdown close the queue and return at once, because the
	// held delivery keeps the drain from having finished.
	closeQueue := func(t *testing.T, s *notify.QueuedSender) {
		t.Helper()

		ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
		cancel()

		require.ErrorIs(t, s.Shutdown(ctx), context.Canceled)
		require.ErrorIs(t, s.Send(t.Context(), testMessage()), notify.ErrAlreadyShutdown)
	}

	// drainedAndLogged is the expectation of a row whose ending deliveries are
	// each logged once, at error, naming nothing of the message.
	drainedAndLogged := func(ending int) func(t *testing.T, shutdownErr error, records string) {
		return func(t *testing.T, shutdownErr error, records string) {
			t.Helper()

			assert.NoError(t, shutdownErr, "shutdown drains and returns no error")
			assert.Equal(t, ending, strings.Count(records, `"reason":"goexit"`),
				"each failed delivery is logged once: %s", records)
			assert.Equal(t, ending, strings.Count(records, `"level":"ERROR"`),
				"and at error, with nothing else logged: %s", records)
			assert.NotContains(t, records, testMessage().To, "the record names no recipient")
			assert.NotContains(t, records, testMessage().Subject, "the record names no subject")
			assert.NotContains(t, records, testMessage().TextBody, "the record names no body")
		}
	}

	endThenSendLater := func(t *testing.T, s *notify.QueuedSender, inner *goexitSender) {
		t.Helper()

		inner.end()
		sendLater(t, s)
	}

	cases := []testCase{
		{
			name:    "wrapped sender ends its goroutine",
			workers: 1,
			later:   1,
			act:     endThenSendLater,
			assert:  drainedAndLogged(1),
		},
		{
			name:    "several workers end their goroutines",
			workers: 2,
			later:   1,
			act:     endThenSendLater,
			assert:  drainedAndLogged(2),
		},
		{
			name:    "a delivery ends its goroutine during the drain with a message left",
			workers: 1,
			later:   1,
			act: func(t *testing.T, s *notify.QueuedSender, inner *goexitSender) {
				sendLater(t, s)
				closeQueue(t, s)
				inner.end()
			},
			assert: drainedAndLogged(1),
		},
		{
			name:    "the only worker ends its goroutine during the drain with two messages left",
			workers: 1,
			later:   2,
			act: func(t *testing.T, s *notify.QueuedSender, inner *goexitSender) {
				sendLater(t, s)
				sendLater(t, s)
				closeQueue(t, s)
				inner.end()
			},
			assert: drainedAndLogged(1),
		},
		{
			name:    "the drain's last delivery ends its goroutine with a message queued behind it",
			workers: 2,
			later:   1,
			act: func(t *testing.T, s *notify.QueuedSender, inner *goexitSender) {
				sendLater(t, s)
				closeQueue(t, s)
				inner.end()
			},
			assert: drainedAndLogged(2),
		},
		{
			name:    "the drain's last delivery ends its goroutine with nothing behind it",
			workers: 1,
			act: func(t *testing.T, s *notify.QueuedSender, inner *goexitSender) {
				closeQueue(t, s)
				inner.end()
			},
			assert: drainedAndLogged(1),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer goleak.VerifyNone(t)

			// The bubble's clock moves only when every goroutine is blocked,
			// so a later delivery is still in flight whenever Shutdown has
			// returned without waiting for it. goleak looks from outside the
			// bubble, after every goroutine in it has ended.
			synctest.Test(t, func(t *testing.T) {
				var logged lockedBuffer

				inner := newGoexitSender(tc.workers, time.Second)

				s, err := notify.NewQueuedSender(inner,
					notify.WithQueueWorkers(tc.workers),
					notify.WithQueueSendTimeout(2*queuedTestBound),
					notify.WithQueueLogger(slog.New(slog.NewJSONHandler(&logged, nil))),
				)
				require.NoError(t, err)

				// Everything is released before goleak looks, whether the
				// assertions passed or not, so a failing run reports its failure.
				defer func() {
					inner.end()

					ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), queuedTestBound)
					defer cancel()

					_ = s.Shutdown(ctx)
				}()

				for range tc.workers {
					require.NoError(t, s.Send(t.Context(), testMessage()))
				}

				select {
				case <-inner.allIn:
				case <-time.After(queuedTestBound):
					require.FailNow(t, "the deliveries never came to be in flight together")
				}

				tc.act(t, s, inner)

				ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), queuedTestBound)
				defer cancel()

				shutdownErr := s.Shutdown(ctx)

				// Read straight after Shutdown returns, with no wait: a
				// Shutdown that returned before the drain finished leaves a
				// later message in flight here.
				assert.Equal(t, int64(tc.later), inner.completed.Load(),
					"every later message is delivered by the time Shutdown returns")

				for range inner.completed.Load() {
					assert.Equal(t, laterSubject, <-inner.delivered)
				}

				tc.assert(t, shutdownErr, logged.String())
			})
		})
	}
}

// sendCarryingProbe sends one message whose body is a heap allocation that
// reports through released once the runtime has reclaimed it. It is a function
// of its own so the caller's frame holds no reference to the allocation.
//
// The probe rides in the body rather than in the context's values because
// delivery bounds the wrapped sender with a timeout: the runtime may keep a
// stopped timer, and the context it was made from, until its processor next
// schedules, and that would read as a worker holding the value.
//
//go:noinline
func sendCarryingProbe(t *testing.T, s *notify.QueuedSender, released chan<- struct{}) {
	t.Helper()

	backing := make([]byte, 256)
	runtime.AddCleanup(&backing[0], func(chan<- struct{}) { close(released) }, released)

	msg := testMessage()
	msg.TextBody = unsafe.String(&backing[0], len(backing)) //nolint:gosec // G103: a string over the probed allocation, so the body is what is reclaimed

	require.NoError(t, s.Send(t.Context(), msg))
}

// TestQueuedSender_IdleWorkerReleasesLastDelivery pins that a worker waiting
// for its next message keeps nothing of the last one: the message body is a
// sign-in link, and it may not outlive the delivery.
func TestQueuedSender_IdleWorkerReleasesLastDelivery(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		workers int
		assert  func(t *testing.T, released <-chan struct{})
	}

	collected := func(t *testing.T, released <-chan struct{}) {
		t.Helper()

		deadline := time.After(queuedTestBound)

		for {
			runtime.GC()

			select {
			case <-released:
				return
			case <-deadline:
				assert.Fail(t, "the delivered message is still reachable",
					"an idle worker held it for %s after its delivery", queuedTestBound)

				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}

	cases := []testCase{
		{name: "a single idle worker", workers: 1, assert: collected},
		{name: "a pool of idle workers", workers: 3, assert: collected},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			delivered := make(chan struct{}, 1)

			s := newQueued(t, senderFunc(func(context.Context, notify.Message) error {
				delivered <- struct{}{}

				return nil
			}), notify.WithQueueWorkers(tc.workers))

			released := make(chan struct{})

			sendCarryingProbe(t, s, released)

			select {
			case <-delivered:
			case <-time.After(queuedTestBound):
				require.FailNow(t, "the message was never delivered")
			}

			tc.assert(t, released)
		})
	}
}

// goexitHandler ends the goroutine logging a record with the given message, as
// a log handler calling t.FailNow would.
type goexitHandler struct{ match string }

func (h goexitHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h goexitHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Message == h.match {
		runtime.Goexit()
	}

	return nil
}

func (h goexitHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h goexitHandler) WithGroup(string) slog.Handler { return h }

// TestQueuedSender_PoolKeepsItsSize pins that a misbehaving delivery leaves the
// pool at exactly its configured size: a worker that is lost is replaced even
// when the log handler reporting it blocks, and a worker that survives is not
// replaced as well, so no failed message is delivered again.
func TestQueuedSender_PoolKeepsItsSize(t *testing.T) {
	t.Parallel()

	const (
		workers  = 3
		messages = workers + 16
	)

	// outcome is what one row observed. settled is the number of completed
	// deliveries counted before the row released its log handler; finished is
	// the number counted straight after Shutdown returned, with no wait.
	type outcome struct {
		peak     int64
		settled  int64
		finished int64
		seen     map[string]int
	}

	type testCase struct {
		name      string
		misbehave func()
		// settle is how long the row lets the clock run before it releases
		// its handler and shuts down; zero shuts down at once, so Shutdown is
		// what has to wait for the deliveries.
		settle time.Duration
		// handler builds the row's log handler and the function that releases
		// it; nil means a discarding handler.
		handler func() (slog.Handler, func())
		assert  func(t *testing.T, o outcome)
	}

	// exactlyConfigured builds one row's expectation: the most deliveries ever
	// in flight together equal the configured pool size, neither short of it
	// (a lost worker) nor over it (a worker replaced that was still alive), and
	// the wrapped sender saw every message exactly once, so none was redelivered.
	exactlyConfigured := func(t *testing.T, o outcome) {
		t.Helper()

		assert.Equal(t, int64(workers), o.peak, "the pool runs exactly its configured number of deliveries")
		assert.Len(t, o.seen, messages, "every message reached the wrapped sender")
		assert.Equal(t, int64(messages-workers), o.finished,
			"every delivery has completed by the time Shutdown returns")

		for subject, n := range o.seen {
			assert.Equal(t, 1, n, "%s reached the wrapped sender once", subject)
		}
	}

	cases := []testCase{
		{
			name:      "deliveries end their goroutines",
			misbehave: runtime.Goexit,
			assert:    exactlyConfigured,
		},
		{
			name:      "deliveries panic",
			misbehave: func() { panic("inner sender exploded") },
			assert:    exactlyConfigured,
		},
		{
			name:      "the log handler ends the goroutine reporting a lost worker",
			misbehave: runtime.Goexit,
			handler: func() (slog.Handler, func()) {
				return goexitHandler{match: "notify: sender ended its goroutine while delivering"}, func() {}
			},
			assert: exactlyConfigured,
		},
		{
			name:      "a blocking log handler does not shrink the pool",
			misbehave: runtime.Goexit,
			settle:    time.Minute,
			handler: func() (slog.Handler, func()) {
				h := &blockingHandler{
					match:   "notify: sender ended its goroutine while delivering",
					entered: make(chan struct{}),
					release: make(chan struct{}),
				}

				return h, func() { close(h.release) }
			},
			assert: func(t *testing.T, o outcome) {
				t.Helper()

				assert.Equal(t, int64(messages-workers), o.settled,
					"every message the failed deliveries left behind is delivered while the handler still blocks")
				exactlyConfigured(t, o)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var (
					calls, concurrent, peak, settled atomic.Int64
					mu                               sync.Mutex
				)

				seen := map[string]int{}

				inner := senderFunc(func(_ context.Context, msg notify.Message) error {
					mu.Lock()
					seen[msg.Subject]++
					mu.Unlock()

					if calls.Add(1) <= workers {
						tc.misbehave()
					}

					n := concurrent.Add(1)

					for {
						p := peak.Load()
						if n <= p || peak.CompareAndSwap(p, n) {
							break
						}
					}

					time.Sleep(100 * time.Millisecond)
					concurrent.Add(-1)
					settled.Add(1)

					return nil
				})

				handler := slog.DiscardHandler

				release := func() {}

				if tc.handler != nil {
					handler, release = tc.handler()
				}

				s, err := notify.NewQueuedSender(inner,
					notify.WithQueueWorkers(workers),
					notify.WithQueueLogger(slog.New(handler)),
				)
				require.NoError(t, err)

				for i := range messages {
					msg := testMessage()
					msg.Subject = fmt.Sprintf("message %d", i)

					require.NoError(t, s.Send(t.Context(), msg))
				}

				// Let the clock run far past every delivery before the handler
				// is released, so a worker held by it shows as undelivered mail.
				time.Sleep(tc.settle)

				settledBefore := settled.Load()

				release()

				require.NoError(t, s.Shutdown(context.WithoutCancel(t.Context())))

				mu.Lock()
				defer mu.Unlock()

				tc.assert(t, outcome{
					peak:     peak.Load(),
					settled:  settledBefore,
					finished: settled.Load(),
					seen:     seen,
				})
			})
		})
	}
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

	// run provokes the failure inside a synctest bubble and returns the error
	// Send gave for it.
	type testCase struct {
		name   string
		opts   []notify.QueuedOption
		run    func(t *testing.T, opts []notify.QueuedOption) error
		assert func(t *testing.T, logged string, err error)
	}

	// dropOnFullQueue fills the only worker and the queue of one, so the third
	// message has nowhere to go.
	dropOnFullQueue := func(t *testing.T, opts []notify.QueuedOption) error {
		t.Helper()

		inner := &blockingSender{release: make(chan struct{})}

		msg := testMessage()
		msg.TextBody = body

		opts = append([]notify.QueuedOption{
			notify.WithQueueWorkers(1),
			notify.WithQueueMaxMessages(1),
		}, opts...)

		s, err := notify.NewQueuedSender(inner, opts...)
		require.NoError(t, err)

		require.NoError(t, s.Send(t.Context(), msg))
		synctest.Wait()
		require.Equal(t, int64(1), inner.inflight.Load())
		require.NoError(t, s.Send(t.Context(), msg))

		err = s.Send(t.Context(), msg)

		close(inner.release)
		require.NoError(t, s.Shutdown(context.WithoutCancel(t.Context())))

		return err
	}

	// endGoroutine has the wrapped sender end its goroutine while delivering.
	endGoroutine := func(t *testing.T, opts []notify.QueuedOption) error {
		t.Helper()

		msg := testMessage()
		msg.TextBody = body

		s, err := notify.NewQueuedSender(senderFunc(func(context.Context, notify.Message) error {
			runtime.Goexit()

			return nil
		}), append([]notify.QueuedOption{notify.WithQueueWorkers(1)}, opts...)...)
		require.NoError(t, err)

		require.NoError(t, s.Send(t.Context(), msg))
		require.NoError(t, s.Shutdown(context.WithoutCancel(t.Context())))

		return nil
	}

	cases := []testCase{
		{
			name: "a drop is reported with no logger configured",
			run:  dropOnFullQueue,
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
			run:  dropOnFullQueue,
			assert: func(t *testing.T, logged string, err error) {
				require.ErrorIs(t, err, notify.ErrQueueFull)
				assert.Empty(t, logged, "a supplied discarding logger writes nothing")
			},
		},
		{
			name: "an ended goroutine is reported with no logger configured",
			run:  endGoroutine,
			assert: func(t *testing.T, logged string, err error) {
				require.NoError(t, err)
				assert.Contains(t, logged, "ended its goroutine",
					"a lost delivery is reported without configuration")
				assert.Contains(t, logged, "goexit", "with the fixed reason")
				assert.NotContains(t, logged, body, "and no message body")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer

			restore := swapDefaultLogger(t, slog.New(slog.NewTextHandler(&buf, nil)))
			defer restore()

			synctest.Test(t, func(t *testing.T) {
				err := tc.run(t, tc.opts)

				tc.assert(t, buf.String(), err)
			})
		})
	}
}
