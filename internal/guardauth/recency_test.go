package guardauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/guardauth"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/session"
)

// now is the judge's clock in every Judge case.
var now = time.Date(2026, time.March, 1, 9, 0, 0, 0, time.UTC)

// authenticatedAt is a time source reporting at.
func authenticatedAt(at time.Time) func(context.Context) (time.Time, bool) {
	return func(context.Context) (time.Time, bool) { return at, true }
}

func TestRecency_Judge(t *testing.T) {
	t.Parallel()

	const guardsWindow = 15 * time.Minute

	type testCase struct {
		name     string
		authTime func(ctx context.Context) (time.Time, bool)
		window   time.Duration // the route's window; zero means the guards'
		assert   func(t *testing.T, recent bool, judged time.Duration)
	}

	recentAgainst := func(want time.Duration) func(*testing.T, bool, time.Duration) {
		return func(t *testing.T, recent bool, judged time.Duration) {
			t.Helper()
			assert.True(t, recent, "the caller is recent")
			assert.Equal(t, want, judged)
		}
	}

	staleAgainst := func(want time.Duration) func(*testing.T, bool, time.Duration) {
		return func(t *testing.T, recent bool, judged time.Duration) {
			t.Helper()
			assert.False(t, recent, "the caller is not recent")
			assert.Equal(t, want, judged)
		}
	}

	cases := []testCase{
		{
			name:     "fresh within the guards' window",
			authTime: authenticatedAt(now.Add(-5 * time.Minute)),
			assert:   recentAgainst(guardsWindow),
		},
		{
			name:     "exactly at the window's end is recent",
			authTime: authenticatedAt(now.Add(-guardsWindow)),
			assert:   recentAgainst(guardsWindow),
		},
		{
			name:     "a nanosecond past the window's end is stale",
			authTime: authenticatedAt(now.Add(-guardsWindow - time.Nanosecond)),
			assert:   staleAgainst(guardsWindow),
		},
		{
			name:     "a zero authentication time is never recent",
			authTime: authenticatedAt(time.Time{}),
			assert:   staleAgainst(guardsWindow),
		},
		{
			name:     "a source reporting none is not recent",
			authTime: func(context.Context) (time.Time, bool) { return now, false },
			assert:   staleAgainst(guardsWindow),
		},
		{
			name:     "a per-route window shorter than the guards' refuses with the route's",
			authTime: authenticatedAt(now.Add(-6 * time.Minute)),
			window:   5 * time.Minute,
			assert:   staleAgainst(5 * time.Minute),
		},
		{
			name:     "a per-route window longer than the guards' wins",
			authTime: authenticatedAt(now.Add(-45 * time.Minute)),
			window:   time.Hour,
			assert:   recentAgainst(time.Hour),
		},
		{
			name:     "an authentication time ahead of the clock is recent",
			authTime: authenticatedAt(now.Add(time.Hour)),
			assert:   recentAgainst(guardsWindow),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, reason := guardauth.NewRecency(guardsWindow, clockwork.NewFakeClockAt(now), tc.authTime)
			require.Empty(t, reason)
			require.NotNil(t, r)

			recent, judged := r.Judge(t.Context(), tc.window)
			tc.assert(t, recent, judged)
		})
	}
}

func TestRecency_JudgePassesTheRequestContext(t *testing.T) {
	t.Parallel()

	type key struct{}

	var seen any

	r, reason := guardauth.NewRecency(time.Minute, clockwork.NewFakeClockAt(now),
		func(ctx context.Context) (time.Time, bool) {
			seen = ctx.Value(key{})
			return now, true
		})
	require.Empty(t, reason)

	recent, _ := r.Judge(context.WithValue(t.Context(), key{}, "request"), 0)

	assert.True(t, recent)
	assert.Equal(t, "request", seen, "the time source reads the request's context")
}

func TestNewRecency(t *testing.T) {
	t.Parallel()

	var typedNilClock *clockwork.FakeClock

	source := authenticatedAt(now)

	type testCase struct {
		name     string
		window   time.Duration
		clk      clock.Clock
		authTime func(ctx context.Context) (time.Time, bool)
		assert   func(t *testing.T, r *guardauth.Recency, reason string)
	}

	refused := func(want string) func(*testing.T, *guardauth.Recency, string) {
		return func(t *testing.T, r *guardauth.Recency, reason string) {
			t.Helper()
			assert.Nil(t, r)
			assert.Equal(t, want, reason)
		}
	}

	cases := []testCase{
		{
			name:     "a positive window, a clock and a source build a judge",
			window:   time.Minute,
			clk:      clockwork.NewFakeClockAt(now),
			authTime: source,
			assert: func(t *testing.T, r *guardauth.Recency, reason string) {
				assert.Empty(t, reason)
				assert.NotNil(t, r)
			},
		},
		{
			name:     "a zero window is refused",
			window:   0,
			clk:      clockwork.NewFakeClockAt(now),
			authTime: source,
			assert:   refused("WithRecentAuthenticationWindow needs a window above zero, got 0s"),
		},
		{
			name:     "a negative window is refused",
			window:   -time.Second,
			clk:      clockwork.NewFakeClockAt(now),
			authTime: source,
			assert:   refused("WithRecentAuthenticationWindow needs a window above zero, got -1s"),
		},
		{
			name:     "a nil clock is refused",
			window:   time.Minute,
			clk:      nil,
			authTime: source,
			assert:   refused("WithGuardClock was given no clock; omit the option to use the system clock"),
		},
		{
			name:     "a typed nil clock is refused",
			window:   time.Minute,
			clk:      typedNilClock,
			authTime: source,
			assert:   refused("WithGuardClock was given no clock; omit the option to use the system clock"),
		},
		{
			name:     "a nil time source is refused",
			window:   time.Minute,
			clk:      clockwork.NewFakeClockAt(now),
			authTime: nil,
			assert: refused(
				"WithAuthenticationTime was given no function; omit the option to read the session's"),
		},
		{
			name:     "the window is judged before the clock",
			window:   0,
			clk:      nil,
			authTime: nil,
			assert:   refused("WithRecentAuthenticationWindow needs a window above zero, got 0s"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, reason := guardauth.NewRecency(tc.window, tc.clk, tc.authTime)
			tc.assert(t, r, reason)
		})
	}
}

func TestSessionAuthenticationTime(t *testing.T) {
	t.Parallel()

	at := now.Add(-time.Minute)

	type testCase struct {
		name   string
		lookup func(ctx context.Context) (*session.Session, bool)
		assert func(t *testing.T, got time.Time, ok bool)
	}

	cases := []testCase{
		{
			name: "a request's session reports its authentication time",
			lookup: func(context.Context) (*session.Session, bool) {
				return &session.Session{AuthenticatedAt: at}, true
			},
			assert: func(t *testing.T, got time.Time, ok bool) {
				assert.True(t, ok)
				assert.Equal(t, at, got)
			},
		},
		{
			name:   "a request with no session reports none",
			lookup: func(context.Context) (*session.Session, bool) { return nil, false },
			assert: func(t *testing.T, got time.Time, ok bool) {
				assert.False(t, ok)
				assert.True(t, got.IsZero())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := guardauth.SessionAuthenticationTime(tc.lookup)(t.Context())
			tc.assert(t, got, ok)
		})
	}
}
