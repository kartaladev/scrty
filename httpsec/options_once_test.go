package httpsec_test

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
)

func TestNew_SingleValueOptionGivenTwice(t *testing.T) {
	t.Parallel()

	newLogger := func() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
	newEngine := func(t *testing.T) *policy.Engine {
		t.Helper()

		e, err := policy.NewEngine()
		require.NoError(t, err)

		return e
	}
	handler := func(http.ResponseWriter, *http.Request, error) {}

	type testCase struct {
		name   string
		opts   func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, err error)
	}

	refused := func(option, thing string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), option+" was given twice; one chain has one "+thing)
		}
	}

	cases := []testCase{
		{
			name: "WithLogger, same value",
			opts: func(*testing.T) []httpsec.Option {
				l := newLogger()
				return []httpsec.Option{httpsec.WithLogger(l), httpsec.WithLogger(l)}
			},
			assert: refused("WithLogger", "logger"),
		},
		{
			name: "WithLogger, two values",
			opts: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithLogger(newLogger()), httpsec.WithLogger(newLogger())}
			},
			assert: refused("WithLogger", "logger"),
		},
		{
			name: "WithClock, same value",
			opts: func(*testing.T) []httpsec.Option {
				c := clock.System()
				return []httpsec.Option{httpsec.WithClock(c), httpsec.WithClock(c)}
			},
			assert: refused("WithClock", "time source"),
		},
		{
			name: "WithClock, two values",
			opts: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithClock(clock.System()), httpsec.WithClock(clock.System())}
			},
			assert: refused("WithClock", "time source"),
		},
		{
			name: "WithPolicyEngine, same value",
			opts: func(t *testing.T) []httpsec.Option {
				e := newEngine(t)
				return []httpsec.Option{httpsec.WithPolicyEngine(e), httpsec.WithPolicyEngine(e)}
			},
			assert: refused("WithPolicyEngine", "policy engine"),
		},
		{
			name: "WithPolicyEngine, two values",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithPolicyEngine(newEngine(t)), httpsec.WithPolicyEngine(newEngine(t))}
			},
			assert: refused("WithPolicyEngine", "policy engine"),
		},
		{
			name: "WithRateLimiterFactory, same value",
			opts: func(*testing.T) []httpsec.Option {
				f := ratelimit.MemoryLimiterFactory()
				return []httpsec.Option{httpsec.WithRateLimiterFactory(f), httpsec.WithRateLimiterFactory(f)}
			},
			assert: refused("WithRateLimiterFactory", "rate-limiter factory"),
		},
		{
			name: "WithRateLimiterFactory, two values",
			opts: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithRateLimiterFactory(ratelimit.MemoryLimiterFactory()),
					httpsec.WithRateLimiterFactory(ratelimit.MemoryLimiterFactory()),
				}
			},
			assert: refused("WithRateLimiterFactory", "rate-limiter factory"),
		},
		{
			name: "WithErrorHandler, same value",
			opts: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithErrorHandler(handler), httpsec.WithErrorHandler(handler)}
			},
			assert: refused("WithErrorHandler", "error handler"),
		},
		{
			name: "WithErrorHandler, two values",
			opts: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithErrorHandler(handler),
					httpsec.WithErrorHandler(func(http.ResponseWriter, *http.Request, error) {}),
				}
			},
			assert: refused("WithErrorHandler", "error handler"),
		},
		{
			name: "each option once is accepted",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithLogger(newLogger()),
					httpsec.WithClock(clock.System()),
					httpsec.WithPolicyEngine(newEngine(t)),
					httpsec.WithRateLimiterFactory(ratelimit.MemoryLimiterFactory()),
					httpsec.WithErrorHandler(handler),
				}
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(tc.opts(t)...)
			tc.assert(t, err)
		})
	}
}

func TestEnableAuthorization_ChecksEveryAuthorizer(t *testing.T) {
	t.Parallel()

	adminOnly := authorize.Rule[httpsec.Request]{
		Match:   func(r httpsec.Request) bool { return strings.HasPrefix(r.Path(), "/admin/") },
		Require: authorize.HasAnyRole("ADMIN"),
	}
	permitAll := authorize.Rule[httpsec.Request]{
		Match:   func(httpsec.Request) bool { return true },
		Require: authorize.PermitAll(),
	}

	type testCase struct {
		name   string
		opts   func(t *testing.T, az authorize.Authorizer) []httpsec.Option
		assert func(t *testing.T, az authorize.Authorizer, chain *httpsec.Chain, err error)
	}

	cases := []testCase{
		{
			name: "a nil authorizer in an earlier call is refused",
			opts: func(_ *testing.T, az authorize.Authorizer) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableAuthorization(nil, adminOnly),
					httpsec.EnableAuthorization(az, permitAll),
				}
			},
			assert: func(t *testing.T, _ authorize.Authorizer, _ *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "EnableAuthorization")
				assert.Contains(t, err.Error(), "authorizer")
			},
		},
		{
			name: "a nil authorizer in a later call is refused",
			opts: func(_ *testing.T, az authorize.Authorizer) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableAuthorization(az, adminOnly),
					httpsec.EnableAuthorization(nil, permitAll),
				}
			},
			assert: func(t *testing.T, _ authorize.Authorizer, _ *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "EnableAuthorization")
				assert.Contains(t, err.Error(), "authorizer")
			},
		},
		{
			name: "two valid authorizers: the last judges, the rules append in order",
			opts: func(t *testing.T, az authorize.Authorizer) []httpsec.Option {
				first := NewMockAuthorizer(gomock.NewController(t))

				return []httpsec.Option{
					httpsec.EnableAuthorization(first, adminOnly),
					httpsec.EnableAuthorization(az, permitAll),
				}
			},
			assert: func(t *testing.T, az authorize.Authorizer, chain *httpsec.Chain, err error) {
				require.NoError(t, err)

				s := serveAs(t, chain, testPrincipal(), "/admin/users")
				require.ErrorIs(t, s.err, authorize.ErrAccessDenied, "the first call's rule still decides first")

				s = serveAs(t, chain, testPrincipal(), "/public")
				require.NoError(t, s.err)

				seen, ok := authorizerSeenBy(s)
				require.True(t, ok)
				assert.Same(t, az, seen, "the last call's authorizer is the one the chain judges by")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			az := NewMockAuthorizer(gomock.NewController(t))

			chain, err := httpsec.New(tc.opts(t, az)...)
			tc.assert(t, az, chain, err)
		})
	}
}
