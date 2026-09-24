package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// adminPrincipal is a caller acting under the role the admin rule requires.
func adminPrincipal() *identity.Principal {
	p := testPrincipal()
	p.ActiveRole = &identity.AssignedRole{ID: "r-1", Name: "ADMIN"}

	return p
}

// serveAs runs a GET of path through chain as p, or anonymously when p is nil.
//
// It seeds the exchange from a context carrying the principal, which is what an
// authenticating interceptor would have published by the time the
// authorization stage runs.
func serveAs(t *testing.T, chain *httpsec.Chain, p *identity.Principal, path string) served {
	t.Helper()

	ctx := t.Context()
	if p != nil {
		ctx = identity.WithPrincipal(ctx, p)
	}

	out := served{rec: httptest.NewRecorder()}
	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true
		out.handled = ex

		return nil
	})

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	ex := httpsec.NewExchange(ctx,
		httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec))
	out.err = run(ex)

	return out
}

// authorizerSeenBy reports the authorizer the downstream handler could read,
// which is how a test pins that the stage published one for the guards on the
// route it reached.
func authorizerSeenBy(s served) (authorize.Authorizer, bool) {
	if s.handled == nil {
		return nil, false
	}

	return authorize.AuthorizerFromContext(s.handled.Context())
}

// TestAuthorizationStage pins the half of the stage that runs whatever the
// consumer configured: the authorizer reaches the route, so a guard there has
// one to judge by.
func TestAuthorizationStage(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(az authorize.Authorizer) []httpsec.Option
		assert func(t *testing.T, s served, az authorize.Authorizer)
	}

	cases := []testCase{
		{
			name: "with no rules every request reaches its route and reads the authorizer",
			opts: func(az authorize.Authorizer) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAuthorization(az)}
			},
			assert: func(t *testing.T, s served, az authorize.Authorizer) {
				require.NoError(t, s.err)
				require.True(t, s.handlerRan, "authorization is then the guards' business")

				seen, ok := authorizerSeenBy(s)
				require.True(t, ok, "a guard on the route must find the chain's authorizer")
				assert.Same(t, az, seen)
			},
		},
		{
			name: "authorization not enabled at all publishes no authorizer",
			opts: func(authorize.Authorizer) []httpsec.Option { return nil },
			assert: func(t *testing.T, s served, _ authorize.Authorizer) {
				require.NoError(t, s.err)
				require.True(t, s.handlerRan)

				_, ok := authorizerSeenBy(s)
				assert.False(t, ok,
					"a guard must fail closed rather than judge by an authorizer nobody wired")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			az := NewMockAuthorizer(gomock.NewController(t))

			chain, err := httpsec.New(tc.opts(az)...)
			require.NoError(t, err)

			tc.assert(t, serveAs(t, chain, testPrincipal(), "/anything"), az)
		})
	}
}

// TestAuthorizationRules pins what the centralized rule set decides: the first
// matching rule and nothing after it, a closed default for what no rule
// covers, and a refusal an anonymous caller can act on.
func TestAuthorizationRules(t *testing.T) {
	t.Parallel()

	adminRule := authorize.Rule[httpsec.Request]{
		Match:   func(r httpsec.Request) bool { return strings.HasPrefix(r.Path(), "/admin/") },
		Require: authorize.HasAnyRole("ADMIN"),
	}
	permitAll := authorize.Rule[httpsec.Request]{
		Match:   func(httpsec.Request) bool { return true },
		Require: authorize.PermitAll(),
	}
	apiRule := authorize.Rule[httpsec.Request]{
		Match:   func(r httpsec.Request) bool { return strings.HasPrefix(r.Path(), "/api/") },
		Require: authorize.PermitAll(),
	}

	type testCase struct {
		name   string
		opts   func(az authorize.Authorizer) []httpsec.Option
		path   string
		as     *identity.Principal // nil means anonymous
		assert func(t *testing.T, s served)
	}

	cases := []testCase{
		{
			name: "the first matching rule decides",
			opts: func(az authorize.Authorizer) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAuthorization(az, adminRule, permitAll)}
			},
			path: "/admin/users",
			as:   testPrincipal(),
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, authorize.ErrAccessDenied,
					"a later permit-all must not rescue what an earlier rule refused")
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "a matching rule that permits reaches the route",
			opts: func(az authorize.Authorizer) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAuthorization(az, adminRule, permitAll)}
			},
			path: "/admin/users",
			as:   adminPrincipal(),
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan)
			},
		},
		{
			name: "a request no rule matches is denied",
			opts: func(az authorize.Authorizer) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAuthorization(az, apiRule)}
			},
			path: "/other",
			as:   testPrincipal(),
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, authorize.ErrAccessDenied,
					"an endpoint added without a rule is closed, not open")
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "an anonymous request to a protected rule",
			opts: func(az authorize.Authorizer) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAuthorization(az, adminRule, permitAll)}
			},
			path: "/admin/users",
			as:   nil,
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
				require.ErrorIs(t, s.err, authorize.ErrAuthenticationRequired,
					"the stage wraps the core's sentinel, so either identity matches")
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "two calls give one ordered rule set",
			opts: func(az authorize.Authorizer) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableAuthorization(az, adminRule),
					httpsec.EnableAuthorization(az, permitAll),
				}
			},
			path: "/public",
			as:   testPrincipal(),
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err,
					"the second call appended a rule rather than replacing the first")
				assert.True(t, s.handlerRan)
			},
		},
		{
			name: "the appended rule set keeps the order the calls arrived in",
			opts: func(az authorize.Authorizer) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableAuthorization(az, adminRule),
					httpsec.EnableAuthorization(az, permitAll),
				}
			},
			path: "/admin/users",
			as:   testPrincipal(),
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, authorize.ErrAccessDenied,
					"the rule registered first still decides the requests it matches")
				assert.False(t, s.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			az := NewMockAuthorizer(gomock.NewController(t))

			chain, err := httpsec.New(tc.opts(az)...)
			require.NoError(t, err)

			tc.assert(t, serveAs(t, chain, tc.as, tc.path))
		})
	}
}
