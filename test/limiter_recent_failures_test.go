package test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/ratelimit/redisstore"
)

// recentWindow and recentLimit are the policy every limiter in this file is
// built with: three failures in a minute, so that one failure is far below
// the limit.
const (
	recentLimit  = 3
	recentWindow = time.Minute
)

// recentBackend builds one durable limiter over a real store. unreachable asks
// for a limiter over a handle that cannot reach its store.
type recentBackend struct {
	name  string
	build func(t *testing.T, clk clock.Clock, unreachable bool) ratelimit.Limiter
}

// redisRecentBackend builds the Redis limiter over a server of the calling
// test's own, in application-clock mode. The unreachable limiter's client is
// closed.
func redisRecentBackend(t *testing.T) recentBackend {
	t.Helper()

	conn := RunTestRedis(t)

	return recentBackend{
		name: "redis",
		build: func(t *testing.T, clk clock.Clock, unreachable bool) ratelimit.Limiter {
			t.Helper()

			client := conn.Client
			if unreachable {
				client = redis.NewClient(conn.Client.Options())
				require.NoError(t, client.Close())
			}

			l, err := redisstore.NewLimiter(client, "recent", recentLimit, recentWindow,
				redisstore.WithKeyPrefix(scopePrefix(t)),
				redisstore.WithClock(clk),
				redisstore.WithOperationTimeout(redisTestTimeout),
				redisstore.WithLogger(slog.New(slog.DiscardHandler)))
			require.NoError(t, err)

			return l
		},
	}
}

// pgRecentBackend builds b's limiter over a migrated database of the calling
// test's own, in application-clock mode. The unreachable limiter's database
// handle is closed, and its pool's address refuses every connection.
func pgRecentBackend(t *testing.T, b pgBackend) recentBackend {
	t.Helper()

	conn := migratedLimiterDB(t)

	return recentBackend{
		name: b.name,
		build: func(t *testing.T, clk clock.Clock, unreachable bool) ratelimit.Limiter {
			t.Helper()

			db, dsn := conn.DB, conn.DSN
			if unreachable {
				var err error
				db, err = openPostgresDB(dsn, nil, false)
				require.NoError(t, err)
				require.NoError(t, db.Close())
				dsn = "postgres://nobody@127.0.0.1:1/none"
			}

			return b.limiter(t, db, dsn, pgScopedNamespace(t, "recent"), recentLimit, recentWindow, clk)
		},
	}
}

// TestLimiter_HasRecentFailures runs the durable limiters, each over its real
// store, through the question an automation challenge asks of a source: is
// there any failure in the window, however far below the limit. A store that
// cannot answer reads as having failures.
func TestLimiter_HasRecentFailures(t *testing.T) {
	t.Parallel()

	const key = "form-login:203.0.113.7"

	type testCase struct {
		name        string
		unreachable bool
		arrange     func(t *testing.T, l ratelimit.Limiter, clk *clockwork.FakeClock)
		assert      func(t *testing.T, l ratelimit.Limiter, has bool, err error)
	}

	fail := func(t *testing.T, l ratelimit.Limiter, key string, n int) {
		t.Helper()

		for range n {
			require.NoError(t, l.RecordFailure(t.Context(), key))
		}
	}
	answered := func(want bool) func(t *testing.T, l ratelimit.Limiter, has bool, err error) {
		return func(t *testing.T, _ ratelimit.Limiter, has bool, err error) {
			t.Helper()

			require.NoError(t, err)
			assert.Equal(t, want, has)
		}
	}

	cases := []testCase{
		{name: "a clean key", assert: answered(false)},
		{
			name: "one failure, far below the limit",
			arrange: func(t *testing.T, l ratelimit.Limiter, _ *clockwork.FakeClock) {
				fail(t, l, key, 1)
			},
			assert: answered(true),
		},
		{
			name: "a failure still inside the window",
			arrange: func(t *testing.T, l ratelimit.Limiter, clk *clockwork.FakeClock) {
				fail(t, l, key, 1)
				clk.Advance(recentWindow - time.Second)
			},
			assert: answered(true),
		},
		{
			name: "failures at the limit",
			arrange: func(t *testing.T, l ratelimit.Limiter, _ *clockwork.FakeClock) {
				fail(t, l, key, recentLimit)
			},
			assert: answered(true),
		},
		{
			name: "failures that have left the window",
			arrange: func(t *testing.T, l ratelimit.Limiter, clk *clockwork.FakeClock) {
				fail(t, l, key, 2)
				clk.Advance(recentWindow)
			},
			assert: answered(false),
		},
		{
			name: "another key's failure is not this key's",
			arrange: func(t *testing.T, l ratelimit.Limiter, _ *clockwork.FakeClock) {
				fail(t, l, "form-login:198.51.100.9", 1)
			},
			assert: answered(false),
		},
		{
			name: "asking records nothing",
			arrange: func(t *testing.T, l ratelimit.Limiter, _ *clockwork.FakeClock) {
				r := l.(ratelimit.RecentFailureReporter)
				for range recentLimit + 1 {
					_, err := r.HasRecentFailures(t.Context(), key)
					require.NoError(t, err)
				}
			},
			assert: func(t *testing.T, l ratelimit.Limiter, has bool, err error) {
				require.NoError(t, err)
				assert.False(t, has, "asking left a failure behind")
				exceeded, err := l.Exceeded(t.Context(), key)
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			name: "a store that cannot be reached", unreachable: true,
			assert: func(t *testing.T, _ ratelimit.Limiter, has bool, err error) {
				require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
				assert.True(t, has, "a key that could not be checked must read as having failures")
			},
		},
	}

	backends := map[string]func(t *testing.T) recentBackend{
		"redis":              redisRecentBackend,
		sqlstoreBackend.name: func(t *testing.T) recentBackend { return pgRecentBackend(t, sqlstoreBackend) },
		pgxBackend.name:      func(t *testing.T) recentBackend { return pgRecentBackend(t, pgxBackend) },
	}

	for name, newBackend := range backends {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			backend := newBackend(t)

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					// Whole seconds, so the clock reads on whole
					// microseconds however a row advances it.
					clk := clockwork.NewFakeClockAt(time.Unix(1_700_000_000, 0))
					l := backend.build(t, clk, tc.unreachable)

					if tc.arrange != nil {
						tc.arrange(t, l, clk)
					}

					reporter, ok := l.(ratelimit.RecentFailureReporter)
					require.True(t, ok, "the limiter does not implement ratelimit.RecentFailureReporter")

					has, err := reporter.HasRecentFailures(t.Context(), key)
					tc.assert(t, l, has, err)
				})
			}
		})
	}
}
