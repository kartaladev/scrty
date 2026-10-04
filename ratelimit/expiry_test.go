package ratelimit_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/ratelimit"
)

func newExpiryLimiter(t *testing.T) (*ratelimit.MemoryLimiter, *clockwork.FakeClock) {
	t.Helper()

	clk := clockwork.NewFakeClock()
	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterClock(clk),
		ratelimit.WithMemoryLimiterLogger(discardLogger()))
	require.NoError(t, err)

	return l, clk
}

func recordFor(t *testing.T, l *ratelimit.MemoryLimiter, keys ...string) {
	t.Helper()

	for _, key := range keys {
		require.NoError(t, l.RecordFailure(t.Context(), key))
	}
}

// TestMemoryLimiter_Prune pins the count Prune returns and that it removes only
// keys the window no longer counts.
func TestMemoryLimiter_Prune(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock)
		assert func(t *testing.T, l *ratelimit.MemoryLimiter, removed int)
	}

	cases := []testCase{
		{
			name: "quiet limiter with three expired keys removes three",
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock) {
				recordFor(t, l, "a", "b", "c")
				clk.Advance(testWindow + time.Second)
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, removed int) {
				assert.Equal(t, 3, removed)
				for _, key := range []string{"a", "b", "c"} {
					assert.Zero(t, l.StampsFor(key))
				}
			},
		},
		{
			name: "key with a stamp inside the window survives with its count",
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock) {
				recordFor(t, l, "old", "live")
				clk.Advance(testWindow / 2)
				recordFor(t, l, "live")
				clk.Advance(testWindow/2 + time.Second) // old expired, live's newest stamp has not
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, removed int) {
				assert.Equal(t, 1, removed)
				assert.Equal(t, 2, l.StampsFor("live"))
				exceeded, err := l.Exceeded(t.Context(), "live")
				require.NoError(t, err)
				assert.False(t, exceeded)
				assert.Zero(t, l.StampsFor("old"))
			},
		},
		{
			name: "nothing expired removes nothing",
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				recordFor(t, l, "a", "b")
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, removed int) {
				assert.Zero(t, removed)
				assert.Equal(t, 1, l.StampsFor("a"))
				assert.Equal(t, 1, l.StampsFor("b"))
			},
		},
		{
			name: "a second prune removes nothing",
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock) {
				recordFor(t, l, "a", "b")
				clk.Advance(testWindow + time.Second)
				require.Equal(t, 2, l.Prune())
			},
			assert: func(t *testing.T, _ *ratelimit.MemoryLimiter, removed int) {
				assert.Zero(t, removed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, clk := newExpiryLimiter(t)
			tc.setup(t, l, clk)
			tc.assert(t, l, l.Prune())
		})
	}
}

// TestExpiryTask pins the task's identity and what it reports through a runner.
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
