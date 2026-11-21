package sweep_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/expiry/sweep"
)

// gocronPanicRowEnv names the row a child process of TestGocron_JobPanic
// runs. It is empty in the parent.
const gocronPanicRowEnv = "SCRTY_SWEEP_GOCRON_PANIC_ROW"

// gocronSurvivedMarker is the line a child prints once its scheduler ran the
// panicking job twice and the process was still alive.
const gocronSurvivedMarker = "SCRTY_SWEEP_GOCRON_PANIC_SURVIVED: "

// TestGocron_JobPanic pins what gocron itself does with a job function that
// panics, because it decides what the sweeper must guard. Pinned for the
// version in go.mod (v2.23.0): gocron recovers a job's panic only when the job
// carries the AfterJobRunsWithPanic listener. Without it the panic ends the
// process. The sweeper's task is recovered by the expiry runner, so it never
// reaches gocron; the consumer's locker, clock and logger are called by gocron
// on goroutines of its own, with no recovery of any kind, which is why the
// sweeper guards them itself.
func TestGocron_JobPanic(t *testing.T) { //nolint:paralleltest // a child re-runs this test
	only := os.Getenv(gocronPanicRowEnv)

	type testCase struct {
		name     string
		listener bool
		survives bool
	}

	cases := []testCase{
		{name: "no listener: the panic ends the process", listener: false, survives: false},
		{name: "AfterJobRunsWithPanic: the panic is recovered and the job is scheduled again", listener: true, survives: true},
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if only == "" {
				out, err := runGocronChild(t, tc.name)
				if tc.survives {
					require.NoError(t, err, "the child failed:\n%s", out)
					assert.Contains(t, splitLines(out), gocronSurvivedMarker+tc.name)

					return
				}

				require.Error(t, err, "gocron survived an unrecovered job panic; the sweeper's guards may be unneeded:\n%s", out)
				assert.NotContains(t, splitLines(out), gocronSurvivedMarker+tc.name)
				assert.Contains(t, out, "panic: ", "the child did not die of the job's panic:\n%s", out)

				return
			}

			var runs atomic.Int32

			sched, err := gocron.NewScheduler()
			require.NoError(t, err)

			opts := []gocron.JobOption{}
			if tc.listener {
				opts = append(opts, gocron.WithEventListeners(gocron.AfterJobRunsWithPanic(func(uuid.UUID, string, any) {})))
			}

			_, err = sched.NewJob(gocron.DurationJob(20*time.Millisecond), gocron.NewTask(func() {
				runs.Add(1)
				panic("job panicked")
			}), opts...)
			require.NoError(t, err)

			sched.Start()
			require.Eventually(t, func() bool { return runs.Load() >= 2 }, waitLimit, 10*time.Millisecond)
			require.NoError(t, sched.Shutdown())

			_, _ = os.Stdout.WriteString(gocronSurvivedMarker + tc.name + "\n")
		})
	}
}

func runGocronChild(t *testing.T, row string) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGocron_JobPanic$", "-test.count=1")
	cmd.Env = append(os.Environ(), gocronPanicRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	return string(out), err
}

func splitLines(s string) []string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}

	return lines
}

// consumerPanicRowEnv names the row a child process of
// TestConsumerPanics runs. It is empty in the parent.
const consumerPanicRowEnv = "SCRTY_SWEEP_CONSUMER_PANIC_ROW"

// consumerPanicRanMarker prefixes the line a child prints, followed by the
// row's name, after the row ran and passed.
const consumerPanicRanMarker = "SCRTY_SWEEP_CONSUMER_PANIC_RAN: "

// panicSecret is text a panic value carries that no record may quote.
const panicSecret = "consumer-secret-5e1a"

const panickedMsg = "consumer code panicked"

// panicKind is one way a consumer's code panics.
type panicKind struct {
	name string
	boom func()
}

var (
	panicWithValue = panicKind{name: "a panic with a value", boom: func() { panic("boom: " + panicSecret) }}
	panicWithNil   = panicKind{name: "panic(nil)", boom: func() { panic(nil) }} //nolint:govet // the hostile case under test
	panicRuntime   = panicKind{name: "a runtime error", boom: func() {
		var m map[string]int
		m["k"] = 1 //nolint:staticcheck // the hostile case under test
	}}
)

// hostileClock is a clockwork.Clock that, once armed, panics (or returns a nil
// timer) in the one method named by mode. Everything else is the real clock.
type hostileClock struct {
	clockwork.Clock

	// mode is "now", "afterfunc", "afterfunc-nil", "newtimer", "newtimer-nil", or
	// a "timer-" mode ("timer-stop", "timer-chan", "timer-chan-nil"), which
	// misbehaves in a method of the timers the clock hands out.
	mode   string
	boom   func()
	armed  atomic.Bool
	raised atomic.Int32
}

func (c *hostileClock) hit(mode string) bool {
	if !c.armed.Load() || c.mode != mode {
		return false
	}

	c.raised.Add(1)

	return true
}

func (c *hostileClock) Now() time.Time {
	if c.hit("now") {
		c.boom()
	}

	return c.Clock.Now()
}

func (c *hostileClock) AfterFunc(d time.Duration, f func()) clockwork.Timer {
	if c.hit("afterfunc") {
		c.boom()
	}

	if c.hit("afterfunc-nil") {
		return nil
	}

	return c.wrap(c.Clock.AfterFunc(d, f))
}

func (c *hostileClock) NewTimer(d time.Duration) clockwork.Timer {
	if c.hit("newtimer") {
		c.boom()
	}

	if c.hit("newtimer-nil") {
		return nil
	}

	return c.wrap(c.Clock.NewTimer(d))
}

func (c *hostileClock) wrap(t clockwork.Timer) clockwork.Timer {
	if strings.HasPrefix(c.mode, "timer-") {
		return &hostileTimer{Timer: t, clock: c}
	}

	return t
}

// hostileTimer misbehaves in the method its clock's mode names, once armed.
type hostileTimer struct {
	clockwork.Timer

	clock *hostileClock
}

func (t *hostileTimer) Stop() bool {
	if t.clock.hit("timer-stop") {
		t.clock.boom()
	}

	return t.Timer.Stop()
}

func (t *hostileTimer) Chan() <-chan time.Time {
	if t.clock.hit("timer-chan") {
		t.clock.boom()
	}

	if t.clock.hit("timer-chan-nil") {
		return nil
	}

	return t.Timer.Chan()
}

// panicRig is what one row hands the sweeper.
type panicRig struct {
	locker  gocron.Locker
	clock   clockwork.Clock
	handler func(*lockRecords) slog.Handler // nil: the records handler itself
	arm     func()                          // called after Start returns
}

type panicRun struct {
	runs        int32
	panicked    []slog.Record
	other       []slog.Record
	shutdownErr error
}

// panicRunOnce runs a sweeper whose one task runs every 40ms on rig, waits,
// bounded, for the task to have run twice (so a run follows the faulty call),
// shuts it down and returns what happened.
func panicRunOnce(t *testing.T, rig panicRig) panicRun {
	t.Helper()

	var runs atomic.Int32

	runner, err := expiry.NewRunner([]expiry.Task{{
		Name: "sessions", Interval: 40 * time.Millisecond,
		Run: func(context.Context) (int, error) {
			runs.Add(1)
			return 0, nil
		},
	}}, expiry.WithLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)

	rec := &lockRecords{notify: make(chan struct{}, 1)}

	var h slog.Handler = rec
	if rig.handler != nil {
		h = rig.handler(rec)
	}

	opts := []sweep.Option{sweep.WithStopTimeout(time.Second), sweep.WithLogger(slog.New(h))}
	if rig.locker != nil {
		opts = append(opts, sweep.WithDistributedLocker(rig.locker))
	}

	if rig.clock != nil {
		opts = append(opts, sweep.WithClock(rig.clock))
	}

	s, err := sweep.New(runner, opts...)
	require.NoError(t, err)
	require.NoError(t, s.Start(t.Context()))

	if rig.arm != nil {
		rig.arm()
	}

	deadline := time.After(waitLimit)
	for runs.Load() < 2 {
		select {
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			require.FailNow(t, "no run followed the faulty call within the bound", "runs=%d", runs.Load())
		}
	}

	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), waitLimit)
	defer cancel()

	got := panicRun{runs: runs.Load(), shutdownErr: s.Shutdown(stopCtx)}

	for _, r := range rec.all() {
		if r.Message == panickedMsg {
			got.panicked = append(got.panicked, r)
		} else {
			got.other = append(got.other, r)
		}
	}

	return got
}

// noSecret fails when any record quotes the panic's value.
func noSecret(t *testing.T, recs ...[]slog.Record) {
	t.Helper()

	for _, rs := range recs {
		for _, r := range rs {
			assert.NotContains(t, r.Message, panicSecret)

			for k, v := range recordAttrs(r) {
				assert.NotContains(t, v, panicSecret, "the record's %s quotes the panic", k)
			}
		}
	}
}

func whats(recs []slog.Record) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, recordAttrs(r)["what"])
	}

	return out
}

func count(recs []slog.Record, msg string) int {
	n := 0

	for _, r := range recs {
		if r.Message == msg {
			n++
		}
	}

	return n
}

// panicLocker returns a locker whose first Lock panics with kind and whose
// later Locks, and every Unlock, succeed.
func panicLocker(t *testing.T, kind panicKind) *MockLocker {
	t.Helper()

	ctrl := gomock.NewController(t)
	lock := NewMockLock(ctrl)
	lock.EXPECT().Unlock(gomock.Any()).Return(nil).AnyTimes()

	var calls atomic.Int32

	locker := NewMockLocker(ctrl)
	locker.EXPECT().Lock(gomock.Any(), "sweep:sessions").DoAndReturn(func(context.Context, string) (gocron.Lock, error) {
		if calls.Add(1) == 1 {
			kind.boom()
		}

		return lock, nil
	}).AnyTimes()

	return locker
}

// refusingLocker returns a locker whose first Lock fails and whose later
// Locks succeed.
func refusingLocker(t *testing.T) *MockLocker {
	t.Helper()

	ctrl := gomock.NewController(t)
	lock := NewMockLock(ctrl)
	lock.EXPECT().Unlock(gomock.Any()).Return(nil).AnyTimes()

	var calls atomic.Int32

	locker := NewMockLocker(ctrl)
	locker.EXPECT().Lock(gomock.Any(), "sweep:sessions").DoAndReturn(func(context.Context, string) (gocron.Lock, error) {
		if calls.Add(1) == 1 {
			return nil, lockPortPlain
		}

		return lock, nil
	}).AnyTimes()

	return locker
}

// TestConsumerPanics pins that a panic in a consumer's locker, clock or
// logger, called by gocron on goroutines the sweeper does not own, is
// recovered: the run in hand is reported failed, exactly one record names the
// panic without its value, and the next run goes ahead. A task that panics is
// recovered by the expiry runner and is not a row here.
func TestConsumerPanics(t *testing.T) { //nolint:paralleltest // a child re-runs this test
	only := os.Getenv(consumerPanicRowEnv)

	type testCase struct {
		name  string
		child bool
		rig   func(t *testing.T) panicRig
		check func(t *testing.T, got panicRun, rig panicRig)
	}

	var cases []testCase

	lockRow := func(kind panicKind) testCase {
		return testCase{
			name: "Lock panics: " + kind.name, child: true,
			rig: func(t *testing.T) panicRig { return panicRig{locker: panicLocker(t, kind)} },
			check: func(t *testing.T, got panicRun, _ panicRig) {
				t.Helper()

				require.Len(t, got.panicked, 1, "exactly one panic record")
				assert.Equal(t, slog.LevelError, got.panicked[0].Level)
				assert.Equal(t, "locker.Lock", recordAttrs(got.panicked[0])["what"])
				assert.NotEmpty(t, recordAttrs(got.panicked[0])["panic_type"])
				assert.Equal(t, 1, count(got.other, lockFailedMsg), "the run is reported through the lock failure path")
				noSecret(t, got.panicked, got.other)
				assert.NoError(t, got.shutdownErr)
			},
		}
	}

	for _, kind := range []panicKind{panicWithValue, panicWithNil, panicRuntime} {
		cases = append(cases, lockRow(kind))
	}

	cases = append(cases,
		testCase{
			name: "Lock does not panic (the old outcome)", child: false,
			rig: func(t *testing.T) panicRig { return panicRig{locker: panicLocker(t, panicKind{boom: func() {}})} },
			check: func(t *testing.T, got panicRun, _ panicRig) {
				t.Helper()

				assert.Empty(t, got.panicked)
				assert.Zero(t, count(got.other, lockFailedMsg))
				assert.NoError(t, got.shutdownErr)
			},
		},
		testCase{
			name: "Lock returns no lock and no error", child: true,
			rig: func(t *testing.T) panicRig {
				ctrl := gomock.NewController(t)
				lock := NewMockLock(ctrl)
				lock.EXPECT().Unlock(gomock.Any()).Return(nil).AnyTimes()

				var calls atomic.Int32

				locker := NewMockLocker(ctrl)
				locker.EXPECT().Lock(gomock.Any(), "sweep:sessions").DoAndReturn(func(context.Context, string) (gocron.Lock, error) {
					if calls.Add(1) == 1 {
						return nil, nil //nolint:nilnil // the hostile case under test
					}

					return lock, nil
				}).AnyTimes()

				return panicRig{locker: locker}
			},
			check: func(t *testing.T, got panicRun, _ panicRig) {
				t.Helper()

				assert.Empty(t, got.panicked, "no panic: a nil lock is refused, not recovered")
				assert.Equal(t, 1, count(got.other, lockFailedMsg), "the run is reported through the lock failure path")
				assert.NoError(t, got.shutdownErr)
			},
		},
		testCase{
			name: "Unlock panics", child: true,
			rig: func(t *testing.T) panicRig {
				ctrl := gomock.NewController(t)
				lock := NewMockLock(ctrl)

				var calls atomic.Int32

				lock.EXPECT().Unlock(gomock.Any()).DoAndReturn(func(context.Context) error {
					if calls.Add(1) == 1 {
						panicWithValue.boom()
					}

					return nil
				}).AnyTimes()

				locker := NewMockLocker(ctrl)
				locker.EXPECT().Lock(gomock.Any(), "sweep:sessions").Return(lock, nil).AnyTimes()

				return panicRig{locker: locker}
			},
			check: func(t *testing.T, got panicRun, _ panicRig) {
				t.Helper()

				require.Len(t, got.panicked, 1)
				assert.Equal(t, "locker.Unlock", recordAttrs(got.panicked[0])["what"])
				noSecret(t, got.panicked, got.other)
				assert.NoError(t, got.shutdownErr)
			},
		},
		testCase{
			name: "the logger's handler panics on the lock failure record", child: true,
			rig: func(t *testing.T) panicRig {
				return panicRig{
					locker:  refusingLocker(t),
					handler: func(rec *lockRecords) slog.Handler { return &panicHandler{inner: rec, msg: lockFailedMsg} },
				}
			},
			check: func(t *testing.T, got panicRun, _ panicRig) {
				t.Helper()

				// The handler panicked on the lock failure record, so that
				// record never arrived; the panic record did.
				assert.Len(t, got.panicked, 1)
				assert.Zero(t, count(got.other, lockFailedMsg))
				assert.NoError(t, got.shutdownErr)
			},
		},
	)

	clockRow := func(name, mode string, boom func(), raisedIsRecords bool, what string) testCase {
		return testCase{
			name: name, child: true,
			rig: func(*testing.T) panicRig {
				c := &hostileClock{Clock: clockwork.NewRealClock(), mode: mode, boom: boom}

				return panicRig{clock: c, arm: func() { c.armed.Store(true) }}
			},
			check: func(t *testing.T, got panicRun, rig panicRig) {
				t.Helper()

				raised := int(rig.clock.(*hostileClock).raised.Load()) //nolint:forcetypeassert // the rig's own clock
				require.Positive(t, raised, "the hostile clock method was never reached")

				if raisedIsRecords {
					assert.Len(t, got.panicked, raised, "exactly one panic record per panic")
					assert.Subset(t, []string{what}, whats(got.panicked))
				} else {
					assert.Empty(t, got.panicked)
					assert.GreaterOrEqual(t, len(got.other), 1, "the missing timer is reported")
				}

				noSecret(t, got.panicked, got.other)
				assert.NoError(t, got.shutdownErr)
			},
		}
	}

	cases = append(cases,
		clockRow("Now panics: a runtime error", "now", panicRuntime.boom, true, "clock.Now"),
		clockRow("Now panics: panic(nil)", "now", panicWithNil.boom, true, "clock.Now"),
		clockRow("AfterFunc panics", "afterfunc", panicWithValue.boom, true, "clock.AfterFunc"),
		clockRow("AfterFunc returns no timer", "afterfunc-nil", nil, false, ""),
		clockRow("NewTimer panics at shutdown", "newtimer", panicWithValue.boom, true, "clock.NewTimer"),
		clockRow("NewTimer returns no timer", "newtimer-nil", nil, false, ""),
		clockRow("Timer.Stop panics", "timer-stop", panicWithValue.boom, true, "clock.Timer"),
	)

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				portErrInChild(t, consumerPanicRowEnv, consumerPanicRanMarker, tc.name)

				return
			}

			rig := tc.rig(t)
			got := panicRunOnce(t, rig)
			tc.check(t, got, rig)

			if only != "" && !t.Failed() {
				_, _ = os.Stdout.WriteString(consumerPanicRanMarker + tc.name + "\n")
			}
		})
	}
}

// TestGuardedTimer_ChanFiresAfterPanic pins that a timer whose Chan panics, or
// returns no channel, still fires: gocron reads Chan in the waits that bound a
// shutdown, and a channel that never fires would make a hung purge hang the
// shutdown with it.
func TestGuardedTimer_ChanFiresAfterPanic(t *testing.T) { //nolint:paralleltest // timing-sensitive shutdown
	type testCase struct {
		name   string
		mode   string
		assert func(t *testing.T, raised int, panicked []slog.Record)
	}

	for _, tc := range []testCase{
		{
			name: "Chan panics", mode: "timer-chan",
			assert: func(t *testing.T, raised int, panicked []slog.Record) {
				t.Helper()

				assert.Len(t, panicked, raised, "exactly one panic record per panic")
				assert.Subset(t, []string{"clock.Timer"}, whats(panicked))
			},
		},
		{
			name: "Chan returns no channel", mode: "timer-chan-nil",
			assert: func(t *testing.T, _ int, panicked []slog.Record) {
				t.Helper()

				assert.Empty(t, panicked, "no panic: a nil channel is replaced, not recovered")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			started := make(chan struct{}, 1)

			t.Cleanup(func() { close(release) })

			runner, err := expiry.NewRunner([]expiry.Task{{
				Name: "sessions", Interval: 40 * time.Millisecond,
				Run: func(context.Context) (int, error) {
					select {
					case started <- struct{}{}:
					default:
					}

					<-release

					return 0, nil
				},
			}}, expiry.WithLogger(slog.New(slog.DiscardHandler)))
			require.NoError(t, err)

			rec := &lockRecords{notify: make(chan struct{}, 1)}
			clock := &hostileClock{Clock: clockwork.NewRealClock(), mode: tc.mode, boom: panicWithValue.boom}

			s, err := sweep.New(runner, sweep.WithStopTimeout(100*time.Millisecond),
				sweep.WithLogger(slog.New(rec)), sweep.WithClock(clock))
			require.NoError(t, err)
			require.NoError(t, s.Start(t.Context()))

			select {
			case <-started:
			case <-time.After(waitLimit):
				require.FailNow(t, "the purge never started")
			}

			clock.armed.Store(true)

			done := make(chan error, 1)

			go func() {
				done <- s.Shutdown(context.WithoutCancel(t.Context()))
			}()

			select {
			case err := <-done:
				assert.Error(t, err, "the hung purge outlives the stop timeout")
			case <-time.After(10 * time.Second):
				require.FailNow(t, "Shutdown did not return: the timer's channel never fires")
			}

			require.Positive(t, clock.raised.Load(), "the timer's Chan was never reached")

			var panicked []slog.Record

			for _, r := range rec.all() {
				if r.Message == panickedMsg {
					panicked = append(panicked, r)
				}
			}

			tc.assert(t, int(clock.raised.Load()), panicked)
			noSecret(t, panicked)
		})
	}
}

// panicHandler is a slog.Handler that panics for one message and hands every
// other record to inner.
type panicHandler struct {
	inner slog.Handler
	msg   string
}

func (h *panicHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *panicHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == h.msg {
		panic("handler: " + panicSecret)
	}

	return h.inner.Handle(ctx, r)
}

func (h *panicHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return &panicHandler{inner: h.inner.WithAttrs(a), msg: h.msg}
}

func (h *panicHandler) WithGroup(n string) slog.Handler {
	return &panicHandler{inner: h.inner.WithGroup(n), msg: h.msg}
}

var _ = errors.New
