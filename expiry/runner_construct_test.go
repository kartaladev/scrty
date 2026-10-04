// TestNewRunner_CopiesTasks stands apart from the TestNewRunner table because it
// mutates the caller's slice after construction and then inspects the runner,
// a different sequence from the table's build-and-assert shape.

package expiry_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/pkg/clock"
)

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
