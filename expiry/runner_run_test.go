package expiry_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/expiry"
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
