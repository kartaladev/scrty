package sweep_test

//go:generate mockgen -destination=locker_mock_test.go -package=sweep_test -typed github.com/go-co-op/gocron/v2 Locker,Lock

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/sweep"
)

// waitLimit bounds every wait on a real channel, so a broken schedule fails
// the test instead of hanging it. No assertion depends on it elapsing.
const waitLimit = 5 * time.Second

// quiet is how long a test watches for a run that must not happen. A passing
// run never depends on it; it only gives a wrong run the chance to show.
const quiet = 100 * time.Millisecond

func recv[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(waitLimit):
		require.FailNow(t, "timed out waiting on a channel")
	}
	var zero T
	return zero
}

// probe is the task a test schedules: it counts runs and reports each start
// and end on a channel, and runs body in between.
type probe struct {
	name      string
	runs      atomic.Int32
	started   chan struct{}
	done      chan error
	cancelled chan struct{}
	dropped   chan struct{}
	release   chan struct{}
	once      sync.Once
	body      func(ctx context.Context, p *probe) error
	rec       *recorder
}

// Release lets every blocked and future run of the probe finish.
func (p *probe) Release() { p.once.Do(func() { close(p.release) }) }

func (p *probe) run(ctx context.Context) (int, error) {
	p.runs.Add(1)
	p.rec.add("run:" + p.name)
	p.started <- struct{}{}
	var err error
	if p.body != nil {
		err = p.body(ctx, p)
	}
	p.done <- err
	return 0, err
}

// waitRelease blocks until the test releases the probe, ignoring ctx.
func waitRelease(_ context.Context, p *probe) error {
	<-p.release
	return nil
}

// waitCtx blocks until the run's context is done.
func waitCtx(ctx context.Context, _ *probe) error {
	<-ctx.Done()
	return ctx.Err()
}

// noteCancelThenRelease reports the run's context being cancelled, then keeps
// running until the test releases it: a purge that sees the cancellation but
// still needs time to finish.
func noteCancelThenRelease(ctx context.Context, p *probe) error {
	select {
	case <-p.release:
		return nil
	case <-ctx.Done():
		p.cancelled <- struct{}{}
		<-p.release
		return ctx.Err()
	}
}

// recorder keeps the order of runs and lock calls across goroutines.
type recorder struct {
	mu     sync.Mutex
	events []string
	notify chan string
}

func (r *recorder) add(e string) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
	select {
	case r.notify <- e:
	default:
	}
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

// logCapture is a slog.Handler that hands every record to the test.
type logCapture struct{ records chan slog.Record }

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	select {
	case c.records <- r.Clone():
	default:
	}
	return nil
}

func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }

func recordAttrs(r slog.Record) map[string]string {
	attrs := map[string]string{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	return attrs
}

// dropMonitor is a gocron.Monitor that reports, on the probe's dropped
// channel, each tick gocron's singleton mode drops because it still counts
// the previous run of the job as in progress.
type dropMonitor struct{ probes map[string]*probe } // keyed by job name

func (m dropMonitor) IncrementJob(_ uuid.UUID, name string, _ []string, status gocron.JobStatus) {
	if p, ok := m.probes[name]; ok && status == gocron.SingletonRescheduled {
		// Never block gocron's executor: a test that leaves drops unread
		// past the buffer loses the surplus, not the scheduler.
		select {
		case p.dropped <- struct{}{}:
		default:
		}
	}
}

func (dropMonitor) RecordJobTiming(time.Time, time.Time, uuid.UUID, string, []string) {}

type taskSpec struct {
	name     string
	interval time.Duration
	body     func(ctx context.Context, p *probe) error
}

type harness struct {
	fc      *clockwork.FakeClock
	rec     *recorder
	logs    *logCapture
	probes  map[string]*probe
	sweeper *sweep.Sweeper
}

// newHarness builds a sweeper on a fake clock over one probe per spec. opts
// may read h.fc, h.rec and h.logs, which are set before it is called. The
// sweeper is shut down when the test ends, after every probe is released.
func newHarness(t *testing.T, specs []taskSpec, opts func(t *testing.T, h *harness) []sweep.Option) *harness {
	t.Helper()
	h := &harness{
		fc:     clockwork.NewFakeClock(),
		rec:    &recorder{notify: make(chan string, 64)},
		logs:   &logCapture{records: make(chan slog.Record, 64)},
		probes: map[string]*probe{},
	}

	tasks := make([]expiry.Task, 0, len(specs))
	for _, spec := range specs {
		p := &probe{
			name:      spec.name,
			started:   make(chan struct{}, 64),
			done:      make(chan error, 64),
			cancelled: make(chan struct{}, 64),
			dropped:   make(chan struct{}, 64),
			release:   make(chan struct{}),
			body:      spec.body,
			rec:       h.rec,
		}
		h.probes[spec.name] = p
		tasks = append(tasks, expiry.Task{Name: spec.name, Interval: spec.interval, Run: p.run})
	}

	runner, err := expiry.NewRunner(tasks, expiry.WithLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)

	mon := dropMonitor{probes: map[string]*probe{}}
	for name, p := range h.probes {
		mon.probes[sweep.JobPrefix+name] = p
	}
	all := []sweep.Option{
		sweep.WithClock(h.fc),
		sweep.WithLogger(slog.New(h.logs)),
		sweep.WithSchedulerOptionsForTest(gocron.WithMonitor(mon)),
	}
	if opts != nil {
		all = append(all, opts(t, h)...)
	}
	h.sweeper, err = sweep.New(runner, all...)
	require.NoError(t, err)

	// Cleanups run last-registered first: release the probes, then shut down.
	t.Cleanup(func() { _ = h.sweeper.Shutdown(context.Background()) })
	t.Cleanup(func() {
		for _, p := range h.probes {
			p.Release()
		}
	})
	return h
}

func (h *harness) start(t *testing.T) {
	t.Helper()
	require.NoError(t, h.sweeper.Start(t.Context()))
}

// block waits until the fake clock holds n timers: every job is scheduled and
// waiting for its next tick.
func (h *harness) block(t *testing.T, n int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), waitLimit)
	defer cancel()
	require.NoError(t, h.fc.BlockUntilContext(ctx, n), "waiting for %d scheduled timers", n)
}

// advance moves the fake clock d plus one nanosecond, so time has moved on
// past each tick by the time gocron reschedules the job, as a real clock
// always has. gocron v2.22.0 sometimes processes a run's completion before its
// rescheduling; it then computes the next run from the job's start time, and
// on a fake clock stopped exactly on the tick that next run equals now and
// fires at once, a second time. A real clock is past the tick by then, so
// gocron moves the next run on to the following interval.
func (h *harness) advance(d time.Duration) {
	h.fc.Advance(d + time.Nanosecond)
}

// finish waits for one run of p to start and end, and returns its error.
func (h *harness) finish(t *testing.T, p *probe) error {
	t.Helper()
	recv(t, p.started)
	return recv(t, p.done)
}

// maxDrops bounds how often runOnTick re-advances past a dropped tick. A drop
// needs the tick to land in a window of microseconds, so even one is rare;
// the bound only stops a broken schedule from looping forever.
const maxDrops = 20

// maxDropPause caps the real-time pause runOnTick takes before re-advancing
// past a dropped tick.
const maxDropPause = 100 * time.Millisecond

// runOnTick waits for n timers, advances the clock d, and waits for that tick
// to run p once, returning the run's error.
//
// gocron's singleton mode frees a job's slot only after the job function has
// returned and gocron has finished its own bookkeeping for the run, and
// nothing it exposes marks that moment. So a test that has seen the previous
// run end can still advance onto a tick gocron drops as overlapping
// (executor.go: the default branch of the rescheduleLimiter select). gocron
// then moves the job on to the following interval, which is what a real clock
// would see too. runOnTick tells the two apart through dropMonitor and
// advances again on a drop, so a dropped tick never reads as a missing run.
// Before re-advancing it pauses, from a millisecond doubling up to
// maxDropPause, to give gocron time to free the slot; no assertion depends
// on the pause, which only keeps the next tick from landing in the same
// window.
func (h *harness) runOnTick(t *testing.T, p *probe, n int, d time.Duration) error {
	t.Helper()
	pause := time.Millisecond
	for range maxDrops + 1 {
		h.block(t, n)
		h.advance(d)
		select {
		case <-p.started:
			return recv(t, p.done)
		case <-p.dropped:
			time.Sleep(pause)
			pause = min(2*pause, maxDropPause)
		case <-time.After(waitLimit):
			require.FailNow(t, "timed out waiting for a tick to run or be dropped", "task %s", p.name)
		}
	}
	require.FailNow(t, "too many dropped ticks", "task %s: %d in a row", p.name, maxDrops+1)
	return nil
}

func assertNoRun(t *testing.T, p *probe) {
	t.Helper()
	select {
	case <-p.started:
		assert.Failf(t, "unexpected run", "task %s ran", p.name)
	case <-time.After(quiet):
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	withInterval := []expiry.Task{{Name: "sessions", Interval: time.Minute, Run: noop}}

	type testCase struct {
		name   string
		runner bool // false builds New with a nil runner
		tasks  []expiry.Task
		opts   []sweep.Option
		assert func(t *testing.T, s *sweep.Sweeper, err error)
	}

	invalid := func(t *testing.T, s *sweep.Sweeper, err error) {
		t.Helper()
		require.ErrorIs(t, err, sweep.ErrInvalidOption)
		assert.Nil(t, s)
	}

	cases := []testCase{
		{
			name:   "task intervals need no default",
			runner: true,
			tasks:  withInterval,
			assert: func(t *testing.T, s *sweep.Sweeper, err error) {
				require.NoError(t, err)
				require.NotNil(t, s)
				assert.NoError(t, s.Shutdown(t.Context()))
			},
		},
		{
			name:   "a default interval covers a task without one",
			runner: true,
			tasks:  []expiry.Task{{Name: "sessions", Run: noop}},
			opts:   []sweep.Option{sweep.WithDefaultInterval(time.Minute)},
			assert: func(t *testing.T, s *sweep.Sweeper, err error) {
				require.NoError(t, err)
				assert.NoError(t, s.Shutdown(t.Context()))
			},
		},
		{
			name:   "no interval anywhere names the task",
			runner: true,
			tasks:  []expiry.Task{{Name: "sessions", Interval: time.Minute, Run: noop}, {Name: "login-attempts", Run: noop}},
			assert: func(t *testing.T, s *sweep.Sweeper, err error) {
				require.ErrorIs(t, err, sweep.ErrNoInterval)
				assert.Contains(t, err.Error(), "login-attempts")
				assert.NotContains(t, err.Error(), "sessions")
				assert.Nil(t, s)
			},
		},
		{name: "nil runner", assert: invalid},
		{name: "nil option", runner: true, tasks: withInterval, opts: []sweep.Option{nil}, assert: invalid},
		{name: "nil locker", runner: true, tasks: withInterval, opts: []sweep.Option{sweep.WithDistributedLocker(nil)}, assert: invalid},
		{
			name: "typed nil locker", runner: true, tasks: withInterval,
			opts:   []sweep.Option{sweep.WithDistributedLocker((*MockLocker)(nil))},
			assert: invalid,
		},
		{name: "nil clock", runner: true, tasks: withInterval, opts: []sweep.Option{sweep.WithClock(nil)}, assert: invalid},
		{
			name: "typed nil clock", runner: true, tasks: withInterval,
			opts:   []sweep.Option{sweep.WithClock((*clockwork.FakeClock)(nil))},
			assert: invalid,
		},
		{name: "nil logger", runner: true, tasks: withInterval, opts: []sweep.Option{sweep.WithLogger(nil)}, assert: invalid},
		{name: "zero default interval", runner: true, tasks: withInterval, opts: []sweep.Option{sweep.WithDefaultInterval(0)}, assert: invalid},
		{
			name: "negative default interval", runner: true, tasks: withInterval,
			opts:   []sweep.Option{sweep.WithDefaultInterval(-time.Minute)},
			assert: invalid,
		},
		{name: "zero stop timeout", runner: true, tasks: withInterval, opts: []sweep.Option{sweep.WithStopTimeout(0)}, assert: invalid},
		{
			name: "negative stop timeout", runner: true, tasks: withInterval,
			opts:   []sweep.Option{sweep.WithStopTimeout(-time.Second)},
			assert: invalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var runner *expiry.Runner
			if tc.runner {
				var err error
				runner, err = expiry.NewRunner(tc.tasks)
				require.NoError(t, err)
			}

			s, err := sweep.New(runner, tc.opts...)
			if s != nil {
				t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
			}
			tc.assert(t, s, err)
		})
	}
}

func noop(context.Context) (int, error) { return 0, nil }

func TestSweeper_Schedule(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		tasks  []taskSpec
		opts   func(t *testing.T, h *harness) []sweep.Option
		assert func(t *testing.T, h *harness)
	}

	defaultInterval := func(d time.Duration) func(*testing.T, *harness) []sweep.Option {
		return func(*testing.T, *harness) []sweep.Option {
			return []sweep.Option{sweep.WithDefaultInterval(d)}
		}
	}

	cases := []testCase{
		{
			name:  "consumer default interval",
			tasks: []taskSpec{{name: "sessions"}, {name: "magiclink-tokens"}},
			opts:  defaultInterval(10 * time.Minute),
			assert: func(t *testing.T, h *harness) {
				h.start(t)
				h.block(t, 2)
				h.advance(10 * time.Minute)
				require.NoError(t, h.finish(t, h.probes["sessions"]))
				require.NoError(t, h.finish(t, h.probes["magiclink-tokens"]))
				h.block(t, 2)
				assert.EqualValues(t, 1, h.probes["sessions"].runs.Load())
				assert.EqualValues(t, 1, h.probes["magiclink-tokens"].runs.Load())
			},
		},
		{
			// The default is far longer than the task's interval: even three
			// runs that each re-advance past maxDrops drops stay well under
			// two hours, so the sessions tick is never reached.
			name:  "task interval",
			tasks: []taskSpec{{name: "login-attempts", interval: time.Minute}, {name: "sessions"}},
			opts:  defaultInterval(2 * time.Hour),
			assert: func(t *testing.T, h *harness) {
				h.start(t)
				for range 3 {
					require.NoError(t, h.runOnTick(t, h.probes["login-attempts"], 2, time.Minute))
				}
				h.block(t, 2)
				assert.EqualValues(t, 3, h.probes["login-attempts"].runs.Load())
				assert.EqualValues(t, 0, h.probes["sessions"].runs.Load())
			},
		},
		{
			name:  "no boot-time sweep by default",
			tasks: []taskSpec{{name: "sessions"}},
			opts:  defaultInterval(time.Minute),
			assert: func(t *testing.T, h *harness) {
				h.start(t)
				h.block(t, 1)
				assertNoRun(t, h.probes["sessions"])
				assert.EqualValues(t, 0, h.probes["sessions"].runs.Load())
			},
		},
		{
			name:  "run immediately",
			tasks: []taskSpec{{name: "sessions"}, {name: "login-attempts", interval: time.Minute}},
			opts: func(*testing.T, *harness) []sweep.Option {
				return []sweep.Option{sweep.WithDefaultInterval(10 * time.Minute), sweep.WithRunImmediately()}
			},
			assert: func(t *testing.T, h *harness) {
				h.start(t)
				// No Advance: both runs happen at start.
				require.NoError(t, h.finish(t, h.probes["sessions"]))
				require.NoError(t, h.finish(t, h.probes["login-attempts"]))
				h.block(t, 2)
				assert.EqualValues(t, 1, h.probes["sessions"].runs.Load())
				assert.EqualValues(t, 1, h.probes["login-attempts"].runs.Load())
			},
		},
		{
			// Asserted after the blocked run is released: that is where a
			// queueing mode would fire the missed ticks back to back.
			name:  "slow run skips ticks",
			tasks: []taskSpec{{name: "sessions", interval: time.Minute, body: waitRelease}},
			assert: func(t *testing.T, h *harness) {
				p := h.probes["sessions"]
				h.start(t)
				h.block(t, 1)
				h.advance(time.Minute)
				recv(t, p.started) // the first run, now blocked

				for range 2 { // two more intervals pass while it runs
					h.block(t, 1)
					h.advance(time.Minute)
				}
				h.block(t, 1) // the last missed tick is rescheduled, not queued
				recv(t, p.dropped)
				recv(t, p.dropped) // both missed ticks were dropped as overlapping

				p.Release()
				require.NoError(t, recv(t, p.done))
				assertNoRun(t, p)
				assert.EqualValues(t, 1, p.runs.Load())

				require.NoError(t, h.runOnTick(t, p, 1, time.Minute))
				h.block(t, 1)
				assertNoRun(t, p)
				assert.EqualValues(t, 2, p.runs.Load())
			},
		},
		{
			name:  "distributed lock consulted",
			tasks: []taskSpec{{name: "sessions", interval: time.Minute}},
			opts: func(t *testing.T, h *harness) []sweep.Option {
				ctrl := gomock.NewController(t)
				lock := NewMockLock(ctrl)
				lock.EXPECT().Unlock(gomock.Any()).DoAndReturn(func(context.Context) error {
					h.rec.add("unlock")
					return nil
				})
				locker := NewMockLocker(ctrl)
				locker.EXPECT().Lock(gomock.Any(), "sweep:sessions").DoAndReturn(
					func(_ context.Context, key string) (gocron.Lock, error) {
						h.rec.add("lock:" + key)
						return lock, nil
					})
				return []sweep.Option{sweep.WithDistributedLocker(locker)}
			},
			assert: func(t *testing.T, h *harness) {
				h.start(t)
				h.block(t, 1)
				h.advance(time.Minute)
				for e := ""; e != "unlock"; {
					e = recv(t, h.rec.notify)
				}
				assert.Equal(t, []string{"lock:sweep:sessions", "run:sessions", "unlock"}, h.rec.list())
			},
		},
		{
			name:  "failing lock is logged and skips the run",
			tasks: []taskSpec{{name: "sessions", interval: time.Minute}},
			opts: func(t *testing.T, _ *harness) []sweep.Option {
				locker := NewMockLocker(gomock.NewController(t))
				locker.EXPECT().Lock(gomock.Any(), "sweep:sessions").
					Return(nil, errors.New("lock server 10.0.0.5 refused")).AnyTimes()
				return []sweep.Option{sweep.WithDistributedLocker(locker)}
			},
			assert: func(t *testing.T, h *harness) {
				h.start(t)
				h.block(t, 1)
				h.advance(time.Minute)

				r := recv(t, h.logs.records)
				assert.Equal(t, slog.LevelError, r.Level)
				attrs := recordAttrs(r)
				assert.Equal(t, "sessions", attrs["task"])
				assert.Equal(t, "sweep:sessions", attrs["job"])
				assert.Equal(t, "lock", attrs["reason"])
				assert.Equal(t, "*errors.errorString", attrs["error_type"])
				assert.NotContains(t, attrs, "cancelled")
				for k, v := range attrs {
					assert.NotContains(t, v, "10.0.0.5", "attribute %s carries the locker's error text", k)
				}
				assert.NotContains(t, r.Message, "10.0.0.5")

				h.block(t, 1)
				assertNoRun(t, h.probes["sessions"])
				assert.EqualValues(t, 0, h.probes["sessions"].runs.Load())
			},
		},
		{
			name:  "a lock refused by cancellation is marked cancelled",
			tasks: []taskSpec{{name: "sessions", interval: time.Minute}},
			opts: func(t *testing.T, _ *harness) []sweep.Option {
				locker := NewMockLocker(gomock.NewController(t))
				locker.EXPECT().Lock(gomock.Any(), "sweep:sessions").
					Return(nil, fmt.Errorf("lock server: %w", context.Canceled)).AnyTimes()
				return []sweep.Option{sweep.WithDistributedLocker(locker)}
			},
			assert: func(t *testing.T, h *harness) {
				h.start(t)
				h.block(t, 1)
				h.advance(time.Minute)

				attrs := recordAttrs(recv(t, h.logs.records))
				assert.Equal(t, "sessions", attrs["task"])
				assert.Equal(t, "lock", attrs["reason"])
				assert.Equal(t, "true", attrs["cancelled"])
				assertNoRun(t, h.probes["sessions"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newHarness(t, tc.tasks, tc.opts))
		})
	}
}

func TestSweeper_Lifecycle(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		tasks  []taskSpec
		assert func(t *testing.T, h *harness)
	}

	oneTask := []taskSpec{{name: "sessions", interval: time.Minute}}

	cases := []testCase{
		{
			name:  "second start is refused",
			tasks: oneTask,
			assert: func(t *testing.T, h *harness) {
				h.start(t)
				require.ErrorIs(t, h.sweeper.Start(t.Context()), sweep.ErrAlreadyStarted)
			},
		},
		{
			name:  "start after shutdown is refused",
			tasks: oneTask,
			assert: func(t *testing.T, h *harness) {
				require.NoError(t, h.sweeper.Shutdown(t.Context()))
				require.ErrorIs(t, h.sweeper.Start(t.Context()), sweep.ErrAlreadyShutdown)
			},
		},
		{
			name:  "restart after a started sweeper shut down is refused",
			tasks: oneTask,
			assert: func(t *testing.T, h *harness) {
				h.start(t)
				require.NoError(t, h.sweeper.Shutdown(t.Context()))
				require.ErrorIs(t, h.sweeper.Start(t.Context()), sweep.ErrAlreadyShutdown)
			},
		},
		{
			name:  "shutdown twice is idempotent",
			tasks: oneTask,
			assert: func(t *testing.T, h *harness) {
				h.start(t)
				require.NoError(t, h.sweeper.Shutdown(t.Context()))
				require.NoError(t, h.sweeper.Shutdown(t.Context()))
			},
		},
		{
			name:  "shutdown stops runs",
			tasks: oneTask,
			assert: func(t *testing.T, h *harness) {
				h.start(t)
				h.block(t, 1)
				require.NoError(t, h.sweeper.Shutdown(t.Context()))
				for range 5 {
					h.advance(time.Minute)
				}
				assertNoRun(t, h.probes["sessions"])
				assert.EqualValues(t, 0, h.probes["sessions"].runs.Load())
			},
		},
		{
			name:  "a partial start shuts the sweeper down",
			tasks: []taskSpec{{name: "sessions", interval: time.Minute}, {name: "login-attempts", interval: time.Minute}},
			assert: func(t *testing.T, h *harness) {
				sweep.SetIntervalForTest(h.sweeper, "login-attempts", 0)

				err := h.sweeper.Start(t.Context())
				require.ErrorIs(t, err, gocron.ErrDurationJobIntervalZero)
				assert.Contains(t, err.Error(), "login-attempts")

				require.ErrorIs(t, h.sweeper.Start(t.Context()), sweep.ErrAlreadyShutdown)
				require.NoError(t, h.sweeper.Shutdown(t.Context()))
				for range 3 {
					h.advance(time.Minute)
				}
				assertNoRun(t, h.probes["sessions"])
			},
		},
		{
			name:  "the start context bounds each run",
			tasks: []taskSpec{{name: "sessions", interval: time.Minute, body: waitCtx}},
			assert: func(t *testing.T, h *harness) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				require.NoError(t, h.sweeper.Start(ctx))
				h.block(t, 1)
				h.advance(time.Minute)
				recv(t, h.probes["sessions"].started)

				cancel()
				require.ErrorIs(t, recv(t, h.probes["sessions"].done), context.Canceled)
			},
		},
		{
			name:  "no run starts once the start context is done",
			tasks: oneTask,
			assert: func(t *testing.T, h *harness) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				require.NoError(t, h.sweeper.Start(ctx))
				h.block(t, 1)

				cancel()
				for range 3 {
					h.advance(time.Minute)
				}
				assertNoRun(t, h.probes["sessions"])
				assert.EqualValues(t, 0, h.probes["sessions"].runs.Load())
			},
		},
		{
			name:  "a nil start context is refused and leaves the sweeper startable",
			tasks: oneTask,
			assert: func(t *testing.T, h *harness) {
				var nilCtx context.Context
				require.ErrorIs(t, h.sweeper.Start(nilCtx), sweep.ErrInvalidOption)

				h.start(t)
				h.block(t, 1)
				h.advance(time.Minute)
				require.NoError(t, h.finish(t, h.probes["sessions"]))
			},
		},
		{
			name:  "a nil shutdown context is refused and leaves the sweeper usable",
			tasks: oneTask,
			assert: func(t *testing.T, h *harness) {
				var nilCtx context.Context
				require.ErrorIs(t, h.sweeper.Shutdown(nilCtx), sweep.ErrInvalidOption)

				h.start(t)
				h.block(t, 1)
				h.advance(time.Minute)
				require.NoError(t, h.finish(t, h.probes["sessions"]))
				require.NoError(t, h.sweeper.Shutdown(t.Context()))
				require.ErrorIs(t, h.sweeper.Start(t.Context()), sweep.ErrAlreadyShutdown)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newHarness(t, tc.tasks, nil))
		})
	}
}

// TestSweeper_ShutdownReleasesGoroutines is not parallel: goleak compares
// against the goroutines alive when the case began, and a parallel test's
// scheduler would be counted as this one's leak.
func TestSweeper_ShutdownReleasesGoroutines(t *testing.T) {
	type testCase struct {
		name   string
		tasks  []taskSpec
		assert func(t *testing.T, h *harness)
	}

	cases := []testCase{
		{
			name:  "built and never started",
			tasks: []taskSpec{{name: "sessions", interval: time.Minute}},
			assert: func(t *testing.T, h *harness) {
				require.NoError(t, h.sweeper.Shutdown(t.Context()))
			},
		},
		{
			name:  "started and shut down after a run",
			tasks: []taskSpec{{name: "sessions", interval: time.Minute}},
			assert: func(t *testing.T, h *harness) {
				h.start(t)
				h.block(t, 1)
				h.advance(time.Minute)
				require.NoError(t, h.finish(t, h.probes["sessions"]))
				require.NoError(t, h.sweeper.Shutdown(t.Context()))
			},
		},
		{
			name:  "shutdown during a run",
			tasks: []taskSpec{{name: "sessions", interval: time.Minute, body: noteCancelThenRelease}},
			assert: func(t *testing.T, h *harness) {
				p := h.probes["sessions"]
				h.start(t)
				h.block(t, 1)
				h.advance(time.Minute)
				recv(t, p.started)

				shutdown := make(chan error, 1)
				go func() { shutdown <- h.sweeper.Shutdown(context.WithoutCancel(t.Context())) }()

				// Shutdown cancels the running sweep's context ...
				recv(t, p.cancelled)
				// ... and waits for the run to return.
				select {
				case err := <-shutdown:
					require.FailNow(t, "Shutdown returned while a run was in progress", "err: %v", err)
				case <-time.After(quiet):
				}

				p.Release()
				require.ErrorIs(t, recv(t, p.done), context.Canceled)
				require.NoError(t, recv(t, shutdown))

				for range 3 {
					h.advance(time.Minute)
				}
				assertNoRun(t, p)
				assert.EqualValues(t, 1, p.runs.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ignore := goleak.IgnoreCurrent()
			tc.assert(t, newHarness(t, tc.tasks, nil))
			goleak.VerifyNone(t, ignore)
		})
	}
}

// assertPending fails the test if a result arrives on ch within quiet.
func assertPending(t *testing.T, ch <-chan error, msg string) {
	t.Helper()
	select {
	case err := <-ch:
		require.FailNow(t, msg, "err: %v", err)
	case <-time.After(quiet):
	}
}

// shutdownAsync calls Shutdown on its own goroutine and hands back its result.
func shutdownAsync(ctx context.Context, h *harness) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- h.sweeper.Shutdown(ctx) }()
	return ch
}

func TestSweeper_SecondShutdownWaitsForTheFirst(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, h *harness, p *probe)
	}

	cases := []testCase{
		{
			name: "a concurrent second call waits for the run and shares the result",
			assert: func(t *testing.T, h *harness, p *probe) {
				first := shutdownAsync(context.WithoutCancel(t.Context()), h)
				recv(t, p.cancelled)

				second := shutdownAsync(context.WithoutCancel(t.Context()), h)
				assertPending(t, second, "second Shutdown returned while the run was still in progress")

				p.Release()
				firstErr, secondErr := recv(t, first), recv(t, second)
				require.NoError(t, firstErr)
				assert.Equal(t, firstErr, secondErr)
			},
		},
		{
			name: "a call after the first one's context ended still waits for the run",
			assert: func(t *testing.T, h *harness, p *probe) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				first := shutdownAsync(ctx, h)
				recv(t, p.cancelled)

				cancel()
				require.ErrorIs(t, recv(t, first), context.Canceled)

				second := shutdownAsync(context.WithoutCancel(t.Context()), h)
				assertPending(t, second, "second Shutdown returned while the run was still in progress")

				p.Release()
				require.NoError(t, recv(t, second))
				require.NoError(t, h.sweeper.Shutdown(t.Context()))
			},
		},
		{
			name: "a later call whose own context ends first returns its context error",
			assert: func(t *testing.T, h *harness, p *probe) {
				first := shutdownAsync(context.WithoutCancel(t.Context()), h)
				recv(t, p.cancelled)

				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				require.ErrorIs(t, h.sweeper.Shutdown(ctx), context.Canceled)
				assertPending(t, first, "first Shutdown returned while the run was still in progress")

				p.Release()
				require.NoError(t, recv(t, first))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, []taskSpec{{name: "sessions", interval: time.Minute, body: noteCancelThenRelease}}, nil)
			p := h.probes["sessions"]
			h.start(t)
			h.block(t, 1)
			h.advance(time.Minute)
			recv(t, p.started)

			tc.assert(t, h, p)
		})
	}
}

func TestSweeper_StopTimeout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []sweep.Option
		assert func(t *testing.T, h *harness, shutdown <-chan error)
	}

	// timesOutAfter asserts Shutdown keeps waiting until d has passed on the
	// fake clock, then returns gocron's stop timeout error, and that a later
	// call returns that same result.
	timesOutAfter := func(d time.Duration) func(*testing.T, *harness, <-chan error) {
		return func(t *testing.T, h *harness, shutdown <-chan error) {
			h.block(t, 1) // the executor's stop timer; the job's timer is stopped
			h.fc.Advance(d - time.Millisecond)
			assertPending(t, shutdown, "Shutdown returned before the stop timeout")

			h.fc.Advance(time.Millisecond)
			err := recv(t, shutdown)
			require.ErrorIs(t, err, gocron.ErrStopJobsTimedOut)
			assert.ErrorIs(t, h.sweeper.Shutdown(t.Context()), gocron.ErrStopJobsTimedOut)
		}
	}

	cases := []testCase{
		{name: "default is ten seconds", assert: timesOutAfter(10 * time.Second)},
		{name: "consumer override", opts: []sweep.Option{sweep.WithStopTimeout(time.Second)}, assert: timesOutAfter(time.Second)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, []taskSpec{{name: "sessions", interval: time.Minute, body: noteCancelThenRelease}},
				func(*testing.T, *harness) []sweep.Option { return tc.opts })
			p := h.probes["sessions"]
			h.start(t)
			h.block(t, 1)
			h.advance(time.Minute)
			recv(t, p.started)

			shutdown := shutdownAsync(context.WithoutCancel(t.Context()), h)
			recv(t, p.cancelled)
			tc.assert(t, h, shutdown)
		})
	}
}

// TestSweeper_ConcurrentStartAndShutdown races Start against Shutdown. At most
// one Start returns nil, every other returns one of the lifecycle sentinels,
// each Shutdown returns nil, and TestMain's goleak check proves no scheduler
// outlives the test.
func TestSweeper_ConcurrentStartAndShutdown(t *testing.T) {
	t.Parallel()

	for range 100 {
		h := newHarness(t, []taskSpec{{name: "sessions", interval: time.Minute}}, nil)

		var wg sync.WaitGroup
		starts := make(chan error, 4)
		shutdowns := make(chan error, 4)
		for range 4 {
			wg.Go(func() { starts <- h.sweeper.Start(t.Context()) })
			wg.Go(func() { shutdowns <- h.sweeper.Shutdown(t.Context()) })
		}
		wg.Wait()
		close(starts)
		close(shutdowns)

		started := 0
		for err := range starts {
			if err == nil {
				started++
				continue
			}
			if !errors.Is(err, sweep.ErrAlreadyStarted) && !errors.Is(err, sweep.ErrAlreadyShutdown) {
				require.Failf(t, "unexpected Start error", "%v", err)
			}
		}
		require.LessOrEqual(t, started, 1, "more than one Start succeeded")
		for err := range shutdowns {
			require.NoError(t, err)
		}
		require.ErrorIs(t, h.sweeper.Start(t.Context()), sweep.ErrAlreadyShutdown)
	}
}
