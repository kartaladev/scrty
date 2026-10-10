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

// chainTestTimeout is the generous operation timeout the chain test gives
// both factories, in place of the production default.
const chainTestTimeout = 5 * time.Second

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
		if c, ok := f.built["password-login-ipv6-aggregate"]; ok && c.limit == 200 {
			agg = &c
		}
		f.mu.Unlock()
		require.NotNil(t, agg, "the chain built no password-login-ipv6-aggregate limiter with a limit of 200")
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
				// The test is about the chain building and counting, not the operation
				// timeout: a slow first dial under -race would exceed the 250ms default
				// and open the breaker mid-count.
				f, err := sqlstore.NewLimiterFactory(conn.DB, sqlstore.WithLimiterOperationTimeout(chainTestTimeout))
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
				// The test is about the chain building and counting, not the operation
				// timeout: a slow first dial under -race would exceed the 250ms default
				// and open the breaker mid-count.
				f, err := pgxstore.NewLimiterFactory(pool, pgxstore.WithLimiterOperationTimeout(chainTestTimeout))
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
