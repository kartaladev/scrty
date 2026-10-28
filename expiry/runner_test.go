package expiry_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/pkg/clock"
)

var errDB = errors.New("db: connection refused")

// logEntry is one record a recorder saw, with its attributes flattened.
type logEntry struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

// recorder is a slog.Handler that keeps every record, and an ordered event log
// that observers can append to, so a test can tell which came first.
type recorder struct {
	mu      sync.Mutex
	entries []logEntry
	events  []string
}

func (h *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (h *recorder) Handle(_ context.Context, rec slog.Record) error {
	e := logEntry{level: rec.Level, msg: rec.Message, attrs: map[string]any{}}
	rec.Attrs(func(a slog.Attr) bool {
		e.attrs[a.Key] = a.Value.Resolve().Any()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, e)
	h.events = append(h.events, fmt.Sprintf("log:%s:%v", rec.Level, e.attrs["task"]))
	return nil
}

func (h *recorder) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recorder) WithGroup(string) slog.Handler      { return h }

func (h *recorder) note(event string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, event)
}

// reset forgets every record and event seen so far.
func (h *recorder) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries, h.events = nil, nil
}

func (h *recorder) snapshot() ([]logEntry, []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]logEntry(nil), h.entries...), append([]string(nil), h.events...)
}

// entriesFor returns the records naming the given task.
func (h *recorder) entriesFor(task string) []logEntry {
	entries, _ := h.snapshot()
	var out []logEntry
	for _, e := range entries {
		if e.attrs["task"] == task {
			out = append(out, e)
		}
	}
	return out
}

// runEnv is what a run test's tasks write to and its assertions read.
type runEnv struct {
	cancel    context.CancelFunc
	logs      *recorder
	ran       []string
	deadlines map[string]time.Time
	starts    map[string]time.Time
	events    []string
}

func newRunEnv(cancel context.CancelFunc) *runEnv {
	return &runEnv{
		cancel:    cancel,
		logs:      &recorder{},
		deadlines: map[string]time.Time{},
		starts:    map[string]time.Time{},
	}
}

// fakeTask returns a task that records that it ran and returns removed and err.
func (e *runEnv) fakeTask(name string, removed int, err error) expiry.Task {
	return expiry.Task{Name: name, Run: func(context.Context) (int, error) {
		e.ran = append(e.ran, name)
		return removed, err
	}}
}

// panicTask returns a task that records that it ran and panics with value.
func (e *runEnv) panicTask(name string, value any) expiry.Task {
	return expiry.Task{Name: name, Run: func(context.Context) (int, error) {
		e.ran = append(e.ran, name)
		panic(value)
	}}
}

// cancellingTask returns a task that cancels the run's context and returns removed.
func (e *runEnv) cancellingTask(name string, removed int) expiry.Task {
	return expiry.Task{Name: name, Run: func(context.Context) (int, error) {
		e.ran = append(e.ran, name)
		e.cancel()
		return removed, nil
	}}
}

// deadlineTask returns a task that records when it started and its context's deadline.
func (e *runEnv) deadlineTask(name string) expiry.Task {
	return expiry.Task{Name: name, Run: func(ctx context.Context) (int, error) {
		e.ran = append(e.ran, name)
		e.starts[name] = time.Now()
		if d, ok := ctx.Deadline(); ok {
			e.deadlines[name] = d
		}
		return 0, nil
	}}
}

// sleepingTask returns a task that sleeps for d without ever reading its context.
func (e *runEnv) sleepingTask(name string, d time.Duration) expiry.Task {
	return expiry.Task{Name: name, Run: func(context.Context) (int, error) {
		e.events = append(e.events, name+":start@"+time.Now().UTC().Format(time.TimeOnly))
		time.Sleep(d)
		e.events = append(e.events, name+":end@"+time.Now().UTC().Format(time.TimeOnly))
		return 1, nil
	}}
}

// steppingClock advances by step on every read, so an elapsed time measured
// with it is an exact multiple of step.
type steppingClock struct {
	mu   sync.Mutex
	now  time.Time
	step time.Duration
}

func (c *steppingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(c.step)
	return c.now
}

// resultFor returns the result named task, failing the test when there is none.
func resultFor(t *testing.T, rep expiry.Report, task string) expiry.Result {
	t.Helper()
	for _, res := range rep.Results {
		if res.Task == task {
			return res
		}
	}
	require.FailNowf(t, "no result", "the report has no result for %q", task)
	return expiry.Result{}
}

// fixedClock is a clock.Clock that always reads the same instant.
type fixedClock struct{ now time.Time }

func (c *fixedClock) Now() time.Time { return c.now }

func noopRun(context.Context) (int, error) { return 0, nil }

func TestNewRunner(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		tasks  []expiry.Task
		opts   []expiry.Option
		assert func(t *testing.T, r *expiry.Runner, err error)
	}

	var typedNilClock *fixedClock

	cases := []testCase{
		{
			name:  "no tasks",
			tasks: nil,
			assert: func(t *testing.T, r *expiry.Runner, err error) {
				require.ErrorIs(t, err, expiry.ErrNoTasks)
				assert.Nil(t, r)
			},
		},
		{
			name:  "empty name",
			tasks: []expiry.Task{{Name: "", Run: noopRun}},
			assert: func(t *testing.T, r *expiry.Runner, err error) {
				require.ErrorIs(t, err, expiry.ErrInvalidTask)
				assert.Nil(t, r)
			},
		},
		{
			name:  "nil Run named audit",
			tasks: []expiry.Task{{Name: "audit"}},
			assert: func(t *testing.T, r *expiry.Runner, err error) {
				require.ErrorIs(t, err, expiry.ErrInvalidTask)
				assert.Contains(t, err.Error(), "audit")
				assert.Nil(t, r)
			},
		},
		{
			name:  "negative interval",
			tasks: []expiry.Task{{Name: "sessions", Interval: -time.Second, Run: noopRun}},
			assert: func(t *testing.T, r *expiry.Runner, err error) {
				require.ErrorIs(t, err, expiry.ErrInvalidTask)
				assert.Contains(t, err.Error(), "sessions")
				assert.Nil(t, r)
			},
		},
		{
			name: "two tasks named sessions",
			tasks: []expiry.Task{
				{Name: "sessions", Run: noopRun},
				{Name: "login-attempts", Run: noopRun},
				{Name: "sessions", Run: noopRun},
			},
			assert: func(t *testing.T, r *expiry.Runner, err error) {
				require.ErrorIs(t, err, expiry.ErrDuplicateTask)
				assert.Contains(t, err.Error(), "sessions")
				assert.Nil(t, r)
			},
		},
		{
			name:  "negative run timeout",
			tasks: []expiry.Task{{Name: "sessions", Run: noopRun}},
			opts:  []expiry.Option{expiry.WithRunTimeout(-time.Second)},
			assert: func(t *testing.T, r *expiry.Runner, err error) {
				require.ErrorIs(t, err, expiry.ErrInvalidOption)
				assert.Nil(t, r)
			},
		},
		{
			name:  "nil observer",
			tasks: []expiry.Task{{Name: "sessions", Run: noopRun}},
			opts:  []expiry.Option{expiry.WithObserver(nil)},
			assert: func(t *testing.T, r *expiry.Runner, err error) {
				require.ErrorIs(t, err, expiry.ErrInvalidOption)
				assert.Nil(t, r)
			},
		},
		{
			name:  "nil logger",
			tasks: []expiry.Task{{Name: "sessions", Run: noopRun}},
			opts:  []expiry.Option{expiry.WithLogger(nil)},
			assert: func(t *testing.T, r *expiry.Runner, err error) {
				require.ErrorIs(t, err, expiry.ErrInvalidOption)
				assert.Nil(t, r)
			},
		},
		{
			name:  "nil clock",
			tasks: []expiry.Task{{Name: "sessions", Run: noopRun}},
			opts:  []expiry.Option{expiry.WithClock(nil)},
			assert: func(t *testing.T, r *expiry.Runner, err error) {
				require.ErrorIs(t, err, expiry.ErrInvalidOption)
				assert.Nil(t, r)
			},
		},
		{
			name:  "typed nil clock",
			tasks: []expiry.Task{{Name: "sessions", Run: noopRun}},
			opts:  []expiry.Option{expiry.WithClock(typedNilClock)},
			assert: func(t *testing.T, r *expiry.Runner, err error) {
				require.ErrorIs(t, err, expiry.ErrInvalidOption)
				assert.Nil(t, r)
			},
		},
		{
			name:  "nil option",
			tasks: []expiry.Task{{Name: "sessions", Run: noopRun}},
			opts:  []expiry.Option{nil},
			assert: func(t *testing.T, r *expiry.Runner, err error) {
				require.ErrorIs(t, err, expiry.ErrInvalidOption)
				assert.Nil(t, r)
			},
		},
		{
			name: "valid",
			tasks: []expiry.Task{
				{Name: "sessions", Interval: time.Minute, Run: noopRun},
				{Name: "login-attempts", Run: noopRun},
			},
			opts: []expiry.Option{
				expiry.WithRunTimeout(30 * time.Second),
				expiry.WithObserver(func(expiry.Result) {}),
				expiry.WithLogger(slog.New(slog.DiscardHandler)),
				expiry.WithClock(clock.Clock(&fixedClock{now: time.Unix(0, 0)})),
			},
			assert: func(t *testing.T, r *expiry.Runner, err error) {
				require.NoError(t, err)
				require.NotNil(t, r)

				got := r.Tasks()
				require.Len(t, got, 2)
				assert.Equal(t, "sessions", got[0].Name)
				assert.Equal(t, time.Minute, got[0].Interval)
				assert.NotNil(t, got[0].Run)
				assert.Equal(t, "login-attempts", got[1].Name)
				assert.Zero(t, got[1].Interval)
				assert.NotNil(t, got[1].Run)

				got[0].Name = "mutated"
				got[1].Interval = time.Hour
				again := r.Tasks()
				assert.Equal(t, "sessions", again[0].Name)
				assert.Zero(t, again[1].Interval)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := expiry.NewRunner(tc.tasks, tc.opts...)
			tc.assert(t, r, err)
		})
	}
}

// The runner keeps its own copy of the task list, so a caller reusing the slice
// it passed cannot rewrite a configuration construction already validated.
//
// It stands apart from the TestNewRunner table because it mutates the caller's
// slice after construction and then inspects the runner, a different sequence
// from the table's build-and-assert shape.
func TestNewRunner_CopiesTasks(t *testing.T) {
	t.Parallel()

	tasks := []expiry.Task{{Name: "sessions", Run: noopRun}}
	r, err := expiry.NewRunner(tasks)
	require.NoError(t, err)

	tasks[0].Name = ""
	got := r.Tasks()
	require.Len(t, got, 1)
	assert.Equal(t, "sessions", got[0].Name)
}

func TestRunner_RunOnce(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []expiry.Option
		ctx    func(ctx context.Context) context.Context // nil means identity
		tasks  func(e *runEnv) []expiry.Task
		assert func(t *testing.T, e *runEnv, rep expiry.Report, err error)
	}

	cases := []testCase{
		{
			name: "failing task among healthy ones",
			tasks: func(e *runEnv) []expiry.Task {
				return []expiry.Task{e.fakeTask("a", 1, nil), e.fakeTask("b", 0, errDB), e.fakeTask("c", 2, nil)}
			},
			assert: func(t *testing.T, e *runEnv, rep expiry.Report, err error) {
				require.ErrorIs(t, err, errDB)
				require.Len(t, rep.Results, 3)
				assert.Equal(t, []string{"a", "b", "c"}, e.ran)
				assert.Equal(t, []string{"a", "b", "c"},
					[]string{rep.Results[0].Task, rep.Results[1].Task, rep.Results[2].Task})

				a, b, c := resultFor(t, rep, "a"), resultFor(t, rep, "b"), resultFor(t, rep, "c")
				assert.Equal(t, 1, a.Removed)
				require.NoError(t, a.Err)
				require.ErrorIs(t, b.Err, errDB)
				assert.False(t, b.Skipped)
				assert.Equal(t, 2, c.Removed)
				require.NoError(t, c.Err)
			},
		},
		{
			name: "panicking task",
			tasks: func(e *runEnv) []expiry.Task {
				return []expiry.Task{e.fakeTask("a", 1, nil), e.panicTask("b", "nil store"), e.fakeTask("c", 2, nil)}
			},
			assert: func(t *testing.T, e *runEnv, rep expiry.Report, err error) {
				require.ErrorIs(t, err, expiry.ErrTaskPanicked)
				assert.Equal(t, []string{"a", "b", "c"}, e.ran)

				b := resultFor(t, rep, "b")
				require.ErrorIs(t, b.Err, expiry.ErrTaskPanicked)
				assert.Contains(t, b.Err.Error(), "nil store")
				assert.Contains(t, b.Err.Error(), "b")
				assert.Equal(t, 2, resultFor(t, rep, "c").Removed)

				errs := e.logs.entriesFor("b")
				require.Len(t, errs, 1)
				assert.Equal(t, slog.LevelError, errs[0].level)
			},
		},
		{
			name: "cancelled between tasks",
			tasks: func(e *runEnv) []expiry.Task {
				return []expiry.Task{e.cancellingTask("a", 4), e.fakeTask("b", 1, nil), e.fakeTask("c", 1, nil)}
			},
			assert: func(t *testing.T, e *runEnv, rep expiry.Report, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Equal(t, []string{"a"}, e.ran)
				require.Len(t, rep.Results, 3)

				a := resultFor(t, rep, "a")
				assert.Equal(t, 4, a.Removed)
				require.NoError(t, a.Err)
				assert.False(t, a.Skipped)
				for _, name := range []string{"b", "c"} {
					res := resultFor(t, rep, name)
					assert.True(t, res.Skipped, name)
					require.ErrorIs(t, res.Err, context.Canceled, name)
					assert.Zero(t, res.Removed, name)
				}
			},
		},
		{
			name: "context done before the run skips every task",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			tasks: func(e *runEnv) []expiry.Task {
				return []expiry.Task{e.fakeTask("a", 1, nil), e.fakeTask("b", 1, nil)}
			},
			assert: func(t *testing.T, e *runEnv, rep expiry.Report, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Empty(t, e.ran)
				require.Len(t, rep.Results, 2)
				for _, name := range []string{"a", "b"} {
					res := resultFor(t, rep, name)
					assert.True(t, res.Skipped, name)
					require.ErrorIs(t, res.Err, context.Canceled, name)
					assert.Zero(t, res.Removed, name)
				}
			},
		},
		{
			name: "partial count with error is a failure",
			tasks: func(e *runEnv) []expiry.Task {
				return []expiry.Task{e.fakeTask("sessions", 3, errDB)}
			},
			assert: func(t *testing.T, e *runEnv, rep expiry.Report, err error) {
				require.ErrorIs(t, err, errDB)
				res := resultFor(t, rep, "sessions")
				assert.Equal(t, 3, res.Removed)
				require.ErrorIs(t, res.Err, errDB)
				assert.False(t, res.Skipped)

				entries := e.logs.entriesFor("sessions")
				require.Len(t, entries, 1)
				assert.Equal(t, slog.LevelError, entries[0].level)
				assert.Equal(t, int64(3), entries[0].attrs["removed"])
			},
		},
		{
			name: "success is logged at debug with its count",
			tasks: func(e *runEnv) []expiry.Task {
				return []expiry.Task{e.fakeTask("sessions", 3, nil)}
			},
			assert: func(t *testing.T, e *runEnv, rep expiry.Report, err error) {
				require.NoError(t, err)
				assert.Equal(t, 3, resultFor(t, rep, "sessions").Removed)

				entries := e.logs.entriesFor("sessions")
				require.Len(t, entries, 1)
				assert.Equal(t, slog.LevelDebug, entries[0].level)
				assert.Equal(t, int64(3), entries[0].attrs["removed"])
			},
		},
		{
			name: "no run timeout by default leaves no deadline",
			tasks: func(e *runEnv) []expiry.Task {
				return []expiry.Task{e.deadlineTask("sessions")}
			},
			assert: func(t *testing.T, e *runEnv, _ expiry.Report, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"sessions"}, e.ran)
				assert.NotContains(t, e.deadlines, "sessions")
			},
		},
		{
			name: "consumer run timeout",
			opts: []expiry.Option{expiry.WithRunTimeout(30 * time.Second)},
			tasks: func(e *runEnv) []expiry.Task {
				return []expiry.Task{e.sleepingTask("first", time.Minute), e.deadlineTask("a"), e.deadlineTask("b")}
			},
			assert: func(t *testing.T, e *runEnv, _ expiry.Report, err error) {
				require.NoError(t, err)
				for _, name := range []string{"a", "b"} {
					require.Contains(t, e.deadlines, name)
					assert.LessOrEqual(t, e.deadlines[name].Sub(e.starts[name]), 30*time.Second, name)
					assert.Positive(t, e.deadlines[name].Sub(e.starts[name]), name)
				}
			},
		},
		{
			name: "purge ignoring its deadline still returns and the next task runs",
			opts: []expiry.Option{expiry.WithRunTimeout(time.Second)},
			tasks: func(e *runEnv) []expiry.Task {
				return []expiry.Task{e.sleepingTask("slow", 5*time.Second), e.sleepingTask("next", 0)}
			},
			assert: func(t *testing.T, e *runEnv, rep expiry.Report, err error) {
				require.NoError(t, err)
				// The synctest bubble starts at midnight UTC, 2000-01-01.
				assert.Equal(t, []string{
					"slow:start@00:00:00", "slow:end@00:00:05",
					"next:start@00:00:05", "next:end@00:00:05",
				}, e.events)

				slow := resultFor(t, rep, "slow")
				assert.Equal(t, 1, slow.Removed)
				require.NoError(t, slow.Err)
				assert.Equal(t, 5*time.Second, slow.Elapsed)
				assert.Equal(t, 1, resultFor(t, rep, "next").Removed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Every row runs in a bubble, so time and elapsed values are exact.
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				e := newRunEnv(cancel)
				opts := append([]expiry.Option{expiry.WithLogger(slog.New(e.logs))}, tc.opts...)
				r, err := expiry.NewRunner(tc.tasks(e), opts...)
				require.NoError(t, err)

				if tc.ctx != nil {
					ctx = tc.ctx(ctx)
				}
				rep, err := r.RunOnce(ctx)
				tc.assert(t, e, rep, err)
			})
		})
	}
}

func TestRunner_RunTask(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		task   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, e *runEnv, res expiry.Result, err error)
	}

	cases := []testCase{
		{
			name: "unknown task",
			task: "nope",
			assert: func(t *testing.T, e *runEnv, res expiry.Result, err error) {
				require.ErrorIs(t, err, expiry.ErrUnknownTask)
				assert.Contains(t, err.Error(), "nope")
				assert.Empty(t, e.ran)
				assert.Equal(t, "nope", res.Task)
			},
		},
		{
			name: "named task",
			task: "b",
			assert: func(t *testing.T, e *runEnv, res expiry.Result, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"b"}, e.ran)
				// Elapsed is one step of the runner's clock, not wall time.
				assert.Equal(t, expiry.Result{Task: "b", Removed: 2, Elapsed: time.Second}, res)
			},
		},
		{
			name: "failing task returns its error",
			task: "c",
			assert: func(t *testing.T, e *runEnv, res expiry.Result, err error) {
				require.ErrorIs(t, err, errDB)
				require.ErrorIs(t, res.Err, errDB)
				assert.Equal(t, []string{"c"}, e.ran)
				assert.Equal(t, 5, res.Removed)
			},
		},
		{
			name: "cancelled context skips the task",
			task: "b",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			assert: func(t *testing.T, e *runEnv, res expiry.Result, err error) {
				require.ErrorIs(t, err, context.Canceled)
				require.ErrorIs(t, res.Err, context.Canceled)
				assert.True(t, res.Skipped)
				assert.Empty(t, e.ran)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			e := newRunEnv(func() {})
			r, err := expiry.NewRunner([]expiry.Task{
				e.fakeTask("a", 1, nil), e.fakeTask("b", 2, nil), e.fakeTask("c", 5, errDB),
			},
				expiry.WithLogger(slog.New(e.logs)),
				expiry.WithClock(&steppingClock{now: time.Unix(0, 0), step: time.Second}),
			)
			require.NoError(t, err)

			res, err := r.RunTask(ctx, tc.task)
			tc.assert(t, e, res, err)
		})
	}
}

// errRanConcurrently is what the busy test's task returns when a second run
// enters it while the first is still inside, instead of blocking forever.
var errRanConcurrently = errors.New("sessions ran concurrently")

// busyEnv is what a busy row's assertions work with. The runner holds two
// tasks in this order: login-attempts, which runs freely, then sessions, which
// blocks until released.
type busyEnv struct {
	r       *expiry.Runner
	ctx     context.Context
	logs    *recorder
	release func()
	first   <-chan busyOutcome
	// onLoginAttempts, when set, runs inside the login-attempts task.
	onLoginAttempts *func()
}

type busyOutcome struct {
	res expiry.Result
	err error
}

func TestRunner_Busy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// first starts the run that holds the task; it runs on its own goroutine.
		first  func(ctx context.Context, r *expiry.Runner) busyOutcome
		assert func(t *testing.T, e *busyEnv)
	}

	runTaskFirst := func(ctx context.Context, r *expiry.Runner) busyOutcome {
		res, err := r.RunTask(ctx, "sessions")
		return busyOutcome{res, err}
	}
	runOnceFirst := func(ctx context.Context, r *expiry.Runner) busyOutcome {
		rep, err := r.RunOnce(ctx)
		for _, res := range rep.Results {
			if res.Task == "sessions" {
				return busyOutcome{res, err}
			}
		}
		return busyOutcome{err: err}
	}

	// finish releases the held run and checks it was unaffected.
	finish := func(t *testing.T, e *busyEnv) {
		e.release()
		got := <-e.first
		require.NoError(t, got.err)
		assert.Equal(t, 3, got.res.Removed, "the first run is unaffected")
		assert.False(t, got.res.Skipped)
	}

	assertBusy := func(t *testing.T, e *busyEnv) {
		res, err := e.r.RunTask(e.ctx, "sessions")
		require.ErrorIs(t, err, expiry.ErrTaskBusy)
		require.ErrorIs(t, res.Err, expiry.ErrTaskBusy)
		assert.True(t, res.Skipped)
		assert.Equal(t, "sessions", res.Task)
		assert.Zero(t, res.Removed)

		// The busy skip is logged at WARN with its own reason, then observed.
		entries := e.logs.entriesFor("sessions")
		require.Len(t, entries, 1)
		assert.Equal(t, slog.LevelWarn, entries[0].level)
		assert.Equal(t, "busy", entries[0].attrs["reason"])
		_, events := e.logs.snapshot()
		assert.Equal(t, []string{"log:WARN:sessions", "observe:sessions"}, events)

		// Another task is not held by the busy one.
		other, err := e.r.RunTask(e.ctx, "login-attempts")
		require.NoError(t, err)
		assert.Equal(t, 7, other.Removed)

		finish(t, e)
	}

	cases := []testCase{
		{
			name:   "busy under concurrent RunTask",
			first:  runTaskFirst,
			assert: assertBusy,
		},
		{
			name:   "busy while RunOnce holds the task",
			first:  runOnceFirst,
			assert: assertBusy,
		},
		{
			name:  "RunOnce skips the busy task, runs the rest and joins the busy error",
			first: runTaskFirst,
			assert: func(t *testing.T, e *busyEnv) {
				rep, err := e.r.RunOnce(e.ctx)
				require.ErrorIs(t, err, expiry.ErrTaskBusy)
				require.Len(t, rep.Results, 2)

				login := resultFor(t, rep, "login-attempts")
				require.NoError(t, login.Err)
				assert.False(t, login.Skipped)
				assert.Equal(t, 7, login.Removed)

				sessions := resultFor(t, rep, "sessions")
				assert.True(t, sessions.Skipped)
				require.ErrorIs(t, sessions.Err, expiry.ErrTaskBusy)

				entries := e.logs.entriesFor("sessions")
				require.Len(t, entries, 1)
				assert.Equal(t, slog.LevelWarn, entries[0].level)
				assert.Equal(t, "busy", entries[0].attrs["reason"])
				_, events := e.logs.snapshot()
				assert.Equal(t, []string{
					"log:DEBUG:login-attempts", "observe:login-attempts",
					"log:WARN:sessions", "observe:sessions",
				}, events)

				finish(t, e)
			},
		},
		{
			name:  "cancelled mid-run reports the busy task with the context error",
			first: runTaskFirst,
			assert: func(t *testing.T, e *busyEnv) {
				ctx, cancel := context.WithCancel(e.ctx)
				defer cancel()
				*e.onLoginAttempts = cancel

				rep, err := e.r.RunOnce(ctx)
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, expiry.ErrTaskBusy)

				sessions := resultFor(t, rep, "sessions")
				assert.True(t, sessions.Skipped)
				require.ErrorIs(t, sessions.Err, context.Canceled)
				assert.NotErrorIs(t, sessions.Err, expiry.ErrTaskBusy)

				entries := e.logs.entriesFor("sessions")
				require.Len(t, entries, 1)
				assert.Equal(t, "cancelled", entries[0].attrs["reason"])

				finish(t, e)
			},
		},
		{
			name:  "done context on a busy task reports the context error",
			first: runTaskFirst,
			assert: func(t *testing.T, e *busyEnv) {
				ctx, cancel := context.WithCancel(e.ctx)
				cancel()

				res, err := e.r.RunTask(ctx, "sessions")
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, expiry.ErrTaskBusy)
				assert.True(t, res.Skipped)

				finish(t, e)
			},
		},
		{
			name:  "free again once the first run returns",
			first: runTaskFirst,
			assert: func(t *testing.T, e *busyEnv) {
				e.release()
				<-e.first

				res, err := e.r.RunTask(e.ctx, "sessions")
				require.NoError(t, err)
				assert.False(t, res.Skipped)
				assert.Equal(t, 3, res.Removed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				ctx := t.Context()
				gate := make(chan struct{})
				var active atomic.Int32
				var hook func()
				sessions := expiry.Task{Name: "sessions", Run: func(context.Context) (int, error) {
					defer active.Add(-1)
					if active.Add(1) > 1 {
						return 0, errRanConcurrently
					}
					<-gate
					return 3, nil
				}}
				other := expiry.Task{Name: "login-attempts", Run: func(context.Context) (int, error) {
					if hook != nil {
						hook()
					}
					return 7, nil
				}}

				logs := &recorder{}
				r, err := expiry.NewRunner([]expiry.Task{other, sessions},
					expiry.WithLogger(slog.New(logs)),
					expiry.WithObserver(func(res expiry.Result) { logs.note("observe:" + res.Task) }))
				require.NoError(t, err)

				first := make(chan busyOutcome, 1)
				go func() { first <- tc.first(ctx, r) }()
				synctest.Wait() // the first run is now blocked inside sessions
				// A first RunOnce also ran login-attempts before blocking.
				logs.reset()

				var once bool
				release := func() {
					if !once {
						once = true
						close(gate)
					}
				}
				defer release()

				tc.assert(t, &busyEnv{
					r: r, ctx: ctx, logs: logs, release: release, first: first, onLoginAttempts: &hook,
				})
			})
		})
	}
}

// A panic in a task must not leave the task marked as running, or every later
// run of it would be refused as busy for the life of the runner.
//
// It sits beside the TestRunner_Busy table because it needs a different task
// set and run sequence (a panicking task run twice), not the table's
// blocked-task rig.
func TestRunner_Busy_ReleasedAfterPanic(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(ctx context.Context, r *expiry.Runner) (expiry.Result, error)
		assert func(t *testing.T, res expiry.Result, err error)
	}

	cases := []testCase{
		{
			name: "busy mark released after a panic in RunTask",
			run: func(ctx context.Context, r *expiry.Runner) (expiry.Result, error) {
				return r.RunTask(ctx, "sessions")
			},
			assert: func(t *testing.T, res expiry.Result, err error) {
				require.NoError(t, err)
				assert.False(t, res.Skipped)
				assert.Equal(t, 2, res.Removed)
			},
		},
		{
			name: "busy mark released after a panic in RunOnce",
			run: func(ctx context.Context, r *expiry.Runner) (expiry.Result, error) {
				rep, err := r.RunOnce(ctx)
				if len(rep.Results) != 1 {
					return expiry.Result{}, err
				}
				return rep.Results[0], err
			},
			assert: func(t *testing.T, res expiry.Result, err error) {
				require.NoError(t, err)
				assert.False(t, res.Skipped)
				assert.Equal(t, 2, res.Removed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			calls := 0
			task := expiry.Task{Name: "sessions", Run: func(context.Context) (int, error) {
				calls++
				if calls == 1 {
					panic("nil store")
				}
				return 2, nil
			}}
			r, err := expiry.NewRunner([]expiry.Task{task}, expiry.WithLogger(slog.New(slog.DiscardHandler)))
			require.NoError(t, err)

			_, err = tc.run(t.Context(), r)
			require.ErrorIs(t, err, expiry.ErrTaskPanicked)

			res, err := tc.run(t.Context(), r)
			tc.assert(t, res, err)
		})
	}
}

func TestRunner_Reporting(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// observe registers an observer; without it the runner has none.
		observe bool
		run     func(ctx context.Context, r *expiry.Runner) error
		ctx     func(ctx context.Context) context.Context
		assert  func(t *testing.T, logs *recorder, observed []expiry.Result, err error)
	}

	runSessions := func(ctx context.Context, r *expiry.Runner) error {
		_, err := r.RunTask(ctx, "sessions")
		return err
	}

	cases := []testCase{
		{
			name:    "observer sees counts",
			observe: true,
			run:     runSessions,
			assert: func(t *testing.T, logs *recorder, observed []expiry.Result, err error) {
				require.NoError(t, err)
				assert.Equal(t, []expiry.Result{{Task: "sessions", Removed: 3, Elapsed: time.Second}}, observed)

				entries := logs.entriesFor("sessions")
				require.Len(t, entries, 1)
				assert.Equal(t, slog.LevelDebug, entries[0].level)
				assert.Equal(t, int64(3), entries[0].attrs["removed"])

				_, events := logs.snapshot()
				assert.Equal(t, []string{"log:DEBUG:sessions", "observe:sessions"}, events)
			},
		},
		{
			name:    "failure is logged at error, then observed",
			observe: true,
			run: func(ctx context.Context, r *expiry.Runner) error {
				_, err := r.RunTask(ctx, "audit")
				return err
			},
			assert: func(t *testing.T, logs *recorder, observed []expiry.Result, err error) {
				require.ErrorIs(t, err, errDB)
				require.Len(t, observed, 1)
				assert.Equal(t, "audit", observed[0].Task)
				require.ErrorIs(t, observed[0].Err, errDB)

				_, events := logs.snapshot()
				assert.Equal(t, []string{"log:ERROR:audit", "observe:audit"}, events)
			},
		},
		{
			name: "default logging names the task and the error",
			run: func(ctx context.Context, r *expiry.Runner) error {
				_, err := r.RunTask(ctx, "audit")
				return err
			},
			assert: func(t *testing.T, logs *recorder, observed []expiry.Result, err error) {
				require.ErrorIs(t, err, errDB)
				assert.Empty(t, observed)

				entries := logs.entriesFor("audit")
				require.Len(t, entries, 1)
				assert.Equal(t, slog.LevelError, entries[0].level)
				assert.Equal(t, "audit", entries[0].attrs["task"])
				assert.Equal(t, "purge", entries[0].attrs["reason"])
				assert.Equal(t, "*errors.errorString", entries[0].attrs["error_type"])
				// The store's own error text never reaches the record.
				for k, v := range entries[0].attrs {
					assert.NotContains(t, fmt.Sprint(v), "connection refused", k)
				}
			},
		},
		{
			name: "a panic is logged with its own reason",
			run: func(ctx context.Context, r *expiry.Runner) error {
				_, err := r.RunTask(ctx, "panics")
				return err
			},
			assert: func(t *testing.T, logs *recorder, _ []expiry.Result, err error) {
				require.ErrorIs(t, err, expiry.ErrTaskPanicked)
				entries := logs.entriesFor("panics")
				require.Len(t, entries, 1)
				assert.Equal(t, slog.LevelError, entries[0].level)
				assert.Equal(t, "panic", entries[0].attrs["reason"])
				for k, v := range entries[0].attrs {
					assert.NotContains(t, fmt.Sprint(v), "secret column", k)
				}
			},
		},
		{
			name: "purge-unsupported is logged with its own reason",
			run: func(ctx context.Context, r *expiry.Runner) error {
				_, err := r.RunTask(ctx, "unsupported")
				return err
			},
			assert: func(t *testing.T, logs *recorder, _ []expiry.Result, err error) {
				require.ErrorIs(t, err, expiry.ErrPurgeUnsupported)
				entries := logs.entriesFor("unsupported")
				require.Len(t, entries, 1)
				assert.Equal(t, slog.LevelError, entries[0].level)
				assert.Equal(t, "purge-unsupported", entries[0].attrs["reason"])
			},
		},
		{
			name:    "every result of a manual run is observed in order",
			observe: true,
			run: func(ctx context.Context, r *expiry.Runner) error {
				_, err := r.RunOnce(ctx)
				return err
			},
			assert: func(t *testing.T, logs *recorder, observed []expiry.Result, err error) {
				require.ErrorIs(t, err, errDB)
				require.ErrorIs(t, err, expiry.ErrTaskPanicked)
				require.ErrorIs(t, err, expiry.ErrPurgeUnsupported)
				require.Len(t, observed, 4)

				_, events := logs.snapshot()
				assert.Equal(t, []string{
					"log:DEBUG:sessions", "observe:sessions",
					"log:ERROR:audit", "observe:audit",
					"log:ERROR:panics", "observe:panics",
					"log:ERROR:unsupported", "observe:unsupported",
				}, events)
			},
		},
		{
			name:    "a skipped result is observed",
			observe: true,
			run:     runSessions,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			assert: func(t *testing.T, logs *recorder, observed []expiry.Result, err error) {
				require.ErrorIs(t, err, context.Canceled)
				require.Len(t, observed, 1)
				assert.True(t, observed[0].Skipped)
				assert.Zero(t, observed[0].Elapsed, "a skipped result did not run, so it took no time")
				require.ErrorIs(t, observed[0].Err, context.Canceled)

				_, events := logs.snapshot()
				assert.Equal(t, []string{"log:WARN:sessions", "observe:sessions"}, events)

				entries := logs.entriesFor("sessions")
				require.Len(t, entries, 1)
				assert.Equal(t, "cancelled", entries[0].attrs["reason"])
				assert.Equal(t, true, entries[0].attrs["cancelled"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			logs := &recorder{}
			var observed []expiry.Result
			opts := []expiry.Option{
				expiry.WithLogger(slog.New(logs)),
				expiry.WithClock(&steppingClock{now: time.Unix(0, 0), step: time.Second}),
			}
			if tc.observe {
				opts = append(opts, expiry.WithObserver(func(res expiry.Result) {
					logs.note("observe:" + res.Task)
					observed = append(observed, res)
				}))
			}

			r, err := expiry.NewRunner([]expiry.Task{
				{Name: "sessions", Run: func(context.Context) (int, error) { return 3, nil }},
				{Name: "audit", Run: func(context.Context) (int, error) { return 0, errDB }},
				{Name: "panics", Run: func(context.Context) (int, error) { panic("secret column") }},
				{Name: "unsupported", Run: func(context.Context) (int, error) {
					return 0, fmt.Errorf("owner: %w", expiry.ErrPurgeUnsupported)
				}},
			}, opts...)
			require.NoError(t, err)

			err = tc.run(ctx, r)
			tc.assert(t, logs, observed, err)
		})
	}
}
