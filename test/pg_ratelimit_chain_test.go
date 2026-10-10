package test_test

import (
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/migrate"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test"
)

// capturingFactory records each limiter a factory builds, with the limit it
// was asked for, so a test can drive the limiter a chain built.
type capturingFactory struct {
	ratelimit.LimiterFactory

	mu    sync.Mutex
	built map[string]capturedLimiter
}

type capturedLimiter struct {
	limit   int
	limiter ratelimit.Limiter
}

func (f *capturingFactory) NewLimiter(ns string, limit int, window time.Duration) (ratelimit.Limiter, error) {
	l, err := f.LimiterFactory.NewLimiter(ns, limit, window)
	if err == nil {
		f.mu.Lock()
		f.built[ns] = capturedLimiter{limit: limit, limiter: l}
		f.mu.Unlock()
	}
	return l, err
}

// TestPGLimiter_DefaultChainBuilds pins that the default chain, password
// login and its default IPv6 aggregate included, builds over either
// PostgreSQL factory, and that the aggregate counts to its full limit.
func TestPGLimiter_DefaultChainBuilds(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		factory func(t *testing.T, conn test.PostgresConn) ratelimit.LimiterFactory
		assert  func(t *testing.T, f *capturingFactory, err error)
	}

	countsTo200 := func(t *testing.T, f *capturingFactory, err error) {
		t.Helper()
		require.NoError(t, err)
		var agg *capturedLimiter
		f.mu.Lock()
		for _, c := range f.built {
			if c.limit == 200 {
				agg = &c
			}
		}
		f.mu.Unlock()
		require.NotNil(t, agg, "the chain built no limiter with a limit of 200")
		for range 199 {
			require.NoError(t, agg.limiter.RecordFailure(t.Context(), "2001:db8::/64"))
		}
		got, err := agg.limiter.Exceeded(t.Context(), "2001:db8::/64")
		require.NoError(t, err)
		assert.False(t, got, "exceeded after 199 of 200")
		require.NoError(t, agg.limiter.RecordFailure(t.Context(), "2001:db8::/64"))
		got, err = agg.limiter.Exceeded(t.Context(), "2001:db8::/64")
		require.NoError(t, err)
		assert.True(t, got, "not exceeded at 200 of 200")
	}

	cases := []testCase{
		{
			name: "sqlstore",
			factory: func(t *testing.T, conn test.PostgresConn) ratelimit.LimiterFactory {
				f, err := sqlstore.NewLimiterFactory(conn.DB)
				require.NoError(t, err)
				return f
			},
			assert: countsTo200,
		},
		{
			name: "pgx",
			factory: func(t *testing.T, conn test.PostgresConn) ratelimit.LimiterFactory {
				pool, err := pgxpool.New(t.Context(), conn.DSN)
				require.NoError(t, err)
				t.Cleanup(pool.Close)
				f, err := pgxstore.NewLimiterFactory(pool)
				require.NoError(t, err)
				return f
			},
			assert: countsTo200,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := migrate.SecurityState()
			conn := test.RunTestPostgres(t, test.WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))
			f := &capturingFactory{LimiterFactory: tc.factory(t, conn), built: map[string]capturedLimiter{}}

			sessions, err := session.NewManager(session.WithStore(session.NewMemoryStore()))
			require.NoError(t, err)
			_, err = httpsec.New(
				httpsec.WithRateLimiterFactory(f),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: refusingAuthenticator{},
					Sessions:      sessions,
					Tokens:        fixedTokens{},
					Attempts:      policy.NewMemoryAttemptStore(),
				}),
			)
			tc.assert(t, f, err)
		})
	}
}
