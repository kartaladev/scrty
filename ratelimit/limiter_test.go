// Each table here has a call shape of its own — a mode's declarations, its
// String, a task over a fake pruner, and tasks run through an expiry.Runner — so
// they stay separate tables.
package ratelimit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/ratelimit"
)

// TestUnavailableMode_Declarations pins the two facts the public declarations
// carry on their own: the zero mode is the fail-closed one, so a consumer who
// configures nothing refuses during an outage, and the unavailable sentinel is
// its own error rather than an alias of a refusal or a wiring mistake.
func TestUnavailableMode_Declarations(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	cases := []testCase{
		{
			name: "the zero mode refuses",
			assert: func(t *testing.T) {
				var zero ratelimit.UnavailableMode
				assert.Equal(t, ratelimit.UnavailableRefuse, zero)
			},
		},
		{
			name: "the three modes are distinct",
			assert: func(t *testing.T) {
				assert.NotEqual(t, ratelimit.UnavailableRefuse, ratelimit.UnavailableFallbackToLocal)
				assert.NotEqual(t, ratelimit.UnavailableRefuse, ratelimit.UnavailableAllow)
				assert.NotEqual(t, ratelimit.UnavailableFallbackToLocal, ratelimit.UnavailableAllow)
			},
		},
		{
			name: "backend unavailable is its own sentinel",
			assert: func(t *testing.T) {
				assert.False(t, errors.Is(ratelimit.ErrBackendUnavailable, ratelimit.ErrConfig))
				assert.False(t, errors.Is(ratelimit.ErrBackendUnavailable, ratelimit.ErrThrottled))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t)
		})
	}
}

// TestUnavailableMode_String pins the names a log record or error message
// prints for each mode, and the stable form of a value that names none.
func TestUnavailableMode_String(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		mode   ratelimit.UnavailableMode
		assert func(t *testing.T, got string)
	}

	is := func(want string) func(t *testing.T, got string) {
		return func(t *testing.T, got string) { assert.Equal(t, want, got) }
	}

	cases := []testCase{
		{name: "refuse", mode: ratelimit.UnavailableRefuse, assert: is("refuse")},
		{name: "fall back to local", mode: ratelimit.UnavailableFallbackToLocal, assert: is("fall-back")},
		{name: "allow", mode: ratelimit.UnavailableAllow, assert: is("allow")},
		{name: "an unknown value prints its number", mode: ratelimit.UnavailableMode(7), assert: is("UnavailableMode(7)")},
		{name: "a negative value prints its number", mode: ratelimit.UnavailableMode(-1), assert: is("UnavailableMode(-1)")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.mode.String())
		})
	}
}

type fakePruner struct {
	removed int
	err     error
}

func (f fakePruner) Prune(context.Context) (int, error) { return f.removed, f.err }

// TestExpiryTask_ReportsPruner pins that the task reports what its pruner
// reports, count and error alike.
//
// It stands apart from TestExpiryTask: it runs the task directly over a fake pruner.
func TestExpiryTask_ReportsPruner(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")
	type testCase struct {
		name   string
		p      ratelimit.Pruner
		assert func(t *testing.T, removed int, err error)
	}
	cases := []testCase{
		{
			name: "count reaches the result",
			p:    fakePruner{removed: 7},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 7, removed)
			},
		},
		{
			name: "error reaches the result",
			p:    fakePruner{err: boom},
			assert: func(t *testing.T, _ int, err error) {
				assert.ErrorIs(t, err, boom)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			task := ratelimit.ExpiryTask(tc.p)
			assert.Equal(t, "ratelimit", task.Name)
			assert.Zero(t, task.Interval)
			removed, err := task.Run(t.Context())
			tc.assert(t, removed, err)
		})
	}
}

// TestExpiryTask pins the task's identity and what it reports through a runner.
//
// It stands apart from TestExpiryTask_ReportsPruner: it runs a real limiter through a runner.
func TestExpiryTask(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	cases := []testCase{
		{
			name: "name is ratelimit and interval is zero",
			assert: func(t *testing.T) {
				l, _ := newExpiryLimiter(t)
				task := ratelimit.ExpiryTask(l)
				assert.Equal(t, "ratelimit", task.Name)
				assert.Zero(t, task.Interval)
				assert.NotNil(t, task.Run)
			},
		},
		{
			name: "quiet limiter with three expired keys reports three removed",
			assert: func(t *testing.T) {
				l, clk := newExpiryLimiter(t)
				recordFor(t, l, "a", "b", "c")
				clk.Advance(testWindow + time.Second)

				r, err := expiry.NewRunner([]expiry.Task{ratelimit.ExpiryTask(l)})
				require.NoError(t, err)
				rep, err := r.RunOnce(t.Context())
				require.NoError(t, err)

				require.Len(t, rep.Results, 1)
				assert.Equal(t, "ratelimit", rep.Results[0].Task)
				assert.Equal(t, 3, rep.Results[0].Removed)
			},
		},
		{
			name: "two renamed limiters report under their own names",
			assert: func(t *testing.T) {
				apikey, clkA := newExpiryLimiter(t)
				magic, clkM := newExpiryLimiter(t)
				recordFor(t, apikey, "a", "b")
				recordFor(t, magic, "x")
				clkA.Advance(testWindow + time.Second)
				clkM.Advance(testWindow + time.Second)

				ta := ratelimit.ExpiryTask(apikey)
				ta.Name = "ratelimit:apikey"
				tm := ratelimit.ExpiryTask(magic)
				tm.Name = "ratelimit:magic-link"

				r, err := expiry.NewRunner([]expiry.Task{ta, tm})
				require.NoError(t, err)
				rep, err := r.RunOnce(t.Context())
				require.NoError(t, err)

				require.Len(t, rep.Results, 2)
				assert.Equal(t, "ratelimit:apikey", rep.Results[0].Task)
				assert.Equal(t, 2, rep.Results[0].Removed)
				assert.Equal(t, "ratelimit:magic-link", rep.Results[1].Task)
				assert.Equal(t, 1, rep.Results[1].Removed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t)
		})
	}
}
