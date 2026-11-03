package test

//go:generate mockgen -destination=challenge_durable_mock_test.go -package=test -typed -mock_names=ChallengeVerifier=MockDurableChallengeVerifier github.com/kartaladev/scrty/httpsec ChallengeVerifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/ratelimit/redisstore"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/store/sqlstore"
	"github.com/kartaladev/scrty/token"
)

// durableRefusingAuthenticator fails every login, so each attempt a test posts
// is a failed one the source limiter records.
type durableRefusingAuthenticator struct{}

func (durableRefusingAuthenticator) Authenticate(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
	return nil, authenticate.ErrAuthenticationFailed
}

// durableTokens issues a fixed token; a failed login never reaches it.
type durableTokens struct{}

func (durableTokens) Generate(context.Context, string, *identity.Principal) (string, error) {
	return "tok", nil
}

func (durableTokens) Verify(context.Context, string) (*token.Claims, error) {
	return nil, token.ErrInvalid
}

func (durableTokens) SubjectMode() token.SubjectMode { return token.SubjectUserID }

var _ token.Generator = durableTokens{}

// durableChain builds a chain whose limits are kept by factory, with form login
// and an automation challenge whose verifier is v.
func durableChain(t *testing.T, factory ratelimit.LimiterFactory, v httpsec.ChallengeVerifier) *httpsec.Chain {
	t.Helper()

	sessions, err := session.New(session.WithStore(must.Must(session.NewMemoryStore())))
	require.NoError(t, err)

	chain, err := httpsec.New(
		httpsec.WithRateLimiterFactory(factory),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: durableRefusingAuthenticator{},
			Sessions:      sessions,
			Tokens:        durableTokens{},
			Attempts:      must.Must(lockout.NewMemoryAttemptStore()),
		}),
		httpsec.EnableAutomationChallenge(v),
	)
	require.NoError(t, err)

	return chain
}

// postLogin posts a wrong password from addr through chain, and returns the
// response's status.
func postLogin(t *testing.T, chain *httpsec.Chain, addr string) int {
	t.Helper()

	body := url.Values{
		httpsec.DefaultLoginUsernameParam: {"alice"},
		httpsec.DefaultLoginPasswordParam: {"wrong"},
	}.Encode()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultLoginPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = addr

	rec := httptest.NewRecorder()
	handler := chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(rec, req)

	return rec.Code
}

// TestChallenge_DurableLimiterReportsRecentFailures covers the automation
// challenge's "Durable limiter" scenario: with the chain's source limit kept
// by the Redis, the SQL or the pgx limiter, a source with no recorded failure
// is told to the verifier as clean, and the same source after one failed login,
// far below the limit, as having failures.
func TestChallenge_DurableLimiterReportsRecentFailures(t *testing.T) {
	t.Parallel()

	const (
		clean   = "203.0.113.7:40000"
		another = "198.51.100.9:40000"
	)

	type testCase struct {
		name    string
		factory func(t *testing.T) ratelimit.LimiterFactory
	}

	cases := []testCase{
		{
			name: "redis",
			factory: func(t *testing.T) ratelimit.LimiterFactory {
				t.Helper()

				f, err := redisstore.NewLimiterFactory(RunTestRedis(t).Client,
					redisstore.WithOperationTimeout(redisTestTimeout))
				require.NoError(t, err)

				return f
			},
		},
		{
			name: "sqlstore",
			factory: func(t *testing.T) ratelimit.LimiterFactory {
				t.Helper()

				f, err := sqlstore.NewLimiterFactory(migratedLimiterDB(t).DB,
					sqlstore.WithLimiterOperationTimeout(pgTestTimeout))
				require.NoError(t, err)

				return f
			},
		},
		{
			name: "pgx",
			factory: func(t *testing.T) ratelimit.LimiterFactory {
				t.Helper()

				f, err := pgxstore.NewLimiterFactory(pgxTestPool(t, migratedLimiterDB(t).DSN),
					pgxstore.WithLimiterOperationTimeout(pgTestTimeout))
				require.NoError(t, err)

				return f
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Every question the verifier is asked, in order.
			var asked []httpsec.ChallengeSignals

			v := NewMockDurableChallengeVerifier(gomock.NewController(t))
			v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, _ httpsec.Request, s httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
					asked = append(asked, s)

					return httpsec.ChallengeNotNeeded, nil
				}).Times(3)

			chain := durableChain(t, tc.factory(t), v)

			// A clean source posts a login; the attempt itself fails, which the
			// source limiter records after the verifier has been asked.
			postLogin(t, chain, clean)
			// The same source again, and a source that has never failed.
			postLogin(t, chain, clean)
			postLogin(t, chain, another)

			require.Len(t, asked, 3)
			assert.False(t, asked[0].SourceHasFailures, "a source with no recorded failure was reported as having failures")
			assert.True(t, asked[1].SourceHasFailures, "a source with one failed login was reported as clean")
			assert.False(t, asked[2].SourceHasFailures, "one source's failure leaked into another's")
		})
	}
}
