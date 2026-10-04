// Standalone tests here sit beside the TestRunner_Busy table because each needs a
// different task set and run sequence (a panicking task run twice), not the
// table's blocked-task rig.

package expiry_test

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/expiry"
)

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
