package test_test

import (
	"context"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	scrtyredis "github.com/kartaladev/scrty/redis"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// refusingAuthenticator and fixedTokens satisfy the login deps so a chain can
// be built; construction never calls either.
type refusingAuthenticator struct{}

func (refusingAuthenticator) Authenticate(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
	return nil, authenticate.ErrAuthenticationFailed
}

type fixedTokens struct{}

func (fixedTokens) Generate(context.Context, string, *identity.Principal) (string, error) {
	return "tok", nil
}

func (fixedTokens) Verify(context.Context, string) (*token.Claims, error) {
	return nil, token.ErrTokenInvalid
}

var _ token.Generator = fixedTokens{}

// TestLoginOwnLimiterUnderRedisFactory pins that an endpoint given its own
// limiter still builds under the Redis limiter factory, which refuses a
// namespace containing a colon: the flow names the login guard derives its
// IPv6 aggregate namespaces from must be colon-free.
//
// The client is never dialled; constructing the factory and the chain does no
// I/O, so no container is needed.
func TestLoginOwnLimiterUnderRedisFactory(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		loginOpts func(t *testing.T) []httpsec.LoginOption
		basicOpts func(t *testing.T) []httpsec.BasicAuthOption
		assert    func(t *testing.T, c *httpsec.Chain, err error)
	}

	own := func(t *testing.T) ratelimit.Limiter {
		t.Helper()

		l, err := ratelimit.NewMemoryLimiter(10, time.Minute)
		require.NoError(t, err)

		return l
	}

	built := func(t *testing.T, c *httpsec.Chain, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	cases := []testCase{
		{
			name: "own login limiter",
			loginOpts: func(t *testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{httpsec.WithLoginLimiter(own(t))}
			},
			assert: built,
		},
		{
			name: "own Basic limiter",
			basicOpts: func(t *testing.T) []httpsec.BasicAuthOption {
				return []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter(own(t))}
			},
			assert: built,
		},
		{
			name: "both own limiters",
			loginOpts: func(t *testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{httpsec.WithLoginLimiter(own(t))}
			},
			basicOpts: func(t *testing.T) []httpsec.BasicAuthOption {
				return []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter(own(t))}
			},
			assert: built,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:0", ContextTimeoutEnabled: true})
			t.Cleanup(func() { _ = client.Close() })

			factory, err := scrtyredis.NewLimiterFactory(client)
			require.NoError(t, err)

			sessions, err := session.NewManager(session.WithStore(session.NewMemoryStore()))
			require.NoError(t, err)

			attempts := policy.NewMemoryAttemptStore()

			var (
				loginOpts []httpsec.LoginOption
				basicOpts []httpsec.BasicAuthOption
			)

			if tc.loginOpts != nil {
				loginOpts = tc.loginOpts(t)
			}

			if tc.basicOpts != nil {
				basicOpts = tc.basicOpts(t)
			}

			c, err := httpsec.New(
				httpsec.WithRateLimiterFactory(factory),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: refusingAuthenticator{},
					Sessions:      sessions,
					Tokens:        fixedTokens{},
					Attempts:      attempts,
				}, loginOpts...),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{
					Authenticator: refusingAuthenticator{},
					Attempts:      attempts,
				}, basicOpts...),
			)
			tc.assert(t, c, err)
		})
	}
}
