package expiry_test

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/expiry"
)

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
