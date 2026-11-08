package httpsec

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/recovery"
)

// TestCheckStaleRoutes pins the comparison itself, over hand-made inventories:
// each match kind, the cool-down's normal form, the exemption's wildcards and
// methods, and what is never judged.
func TestCheckStaleRoutes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		base      string
		endpoints []Endpoint
		options   []Option
		assert    func(t *testing.T, err error)
	}

	at := func(path string, match PathMatch, methods ...string) Endpoint {
		return declare("EnableTest", "WithTestPath", "scrty.test.op", path, match, PassThrough, RequiresNothing, methods...)
	}

	cooldown := func(routes ...Route) []Option {
		return []Option{EnableRecoveryCooldown(recovery.NewMemoryRecordStore(), time.Hour, routes...)}
	}

	exempt := func(method, pattern string) []Option {
		return []Option{EnableCSRFProtection(WithCSRFExemption(method, pattern))}
	}

	refused := func(parts ...string) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			require.ErrorIs(t, err, ErrConfig)

			for _, p := range parts {
				assert.ErrorContains(t, err, p)
			}
		}
	}

	accepted := func(t *testing.T, err error) { require.NoError(t, err) }

	exact := at("/auth/reauth/password", MatchExact, http.MethodPost)
	segment := at("/auth/sso/login/{provider}", MatchSegment, http.MethodGet)
	subtree := at("/auth/sessions", MatchSubtree, http.MethodGet, http.MethodDelete)

	cases := []testCase{
		{
			name: "cool-down: exact route at the old path", base: "/auth", endpoints: []Endpoint{exact},
			options: cooldown(Route{http.MethodPost, "/reauth/password"}),
			assert:  refused("EnableRecoveryCooldown", "POST /reauth/password", "scrty.test.op", "/auth/reauth/password"),
		},
		{
			name: "cool-down: case and trailing slash", base: "/auth", endpoints: []Endpoint{exact},
			options: cooldown(Route{"post", "/Reauth/Password/"}),
			assert:  refused("/auth/reauth/password"),
		},
		{
			name: "cool-down: route written with the base", base: "/auth", endpoints: []Endpoint{exact},
			options: cooldown(Route{http.MethodPost, "/auth/reauth/password"}),
			assert:  accepted,
		},
		{
			name: "cool-down: exact endpoint is not hit by a path beneath it", base: "/auth", endpoints: []Endpoint{exact},
			options: cooldown(Route{http.MethodPost, "/reauth/password/extra"}),
			assert:  accepted,
		},
		{
			name: "cool-down: another method on the path", base: "/auth", endpoints: []Endpoint{exact},
			options: cooldown(Route{http.MethodPut, "/reauth/password"}),
			assert:  accepted,
		},
		{
			name: "cool-down: HEAD counts as GET", base: "/auth", endpoints: []Endpoint{segment},
			options: cooldown(Route{http.MethodHead, "/sso/login/corp"}),
			assert:  refused("/auth/sso/login/{provider}"),
		},
		{
			name: "cool-down: segment endpoint, the prefix alone is not matched", base: "/auth", endpoints: []Endpoint{segment},
			options: cooldown(Route{http.MethodGet, "/sso/login"}),
			assert:  accepted,
		},
		{
			name: "cool-down: segment endpoint, two segments are not matched", base: "/auth", endpoints: []Endpoint{segment},
			options: cooldown(Route{http.MethodGet, "/sso/login/a/b"}),
			assert:  accepted,
		},
		{
			name: "cool-down: subtree beneath", base: "/auth", endpoints: []Endpoint{subtree},
			options: cooldown(Route{http.MethodDelete, "/Sessions/abc"}),
			assert:  refused("/auth/sessions"),
		},
		{
			name: "cool-down: subtree root", base: "/auth", endpoints: []Endpoint{subtree},
			options: cooldown(Route{http.MethodGet, "/sessions"}),
			assert:  refused("/auth/sessions"),
		},
		{
			name: "cool-down: subtree is not a longer name", base: "/auth", endpoints: []Endpoint{subtree},
			options: cooldown(Route{http.MethodGet, "/sessionsx"}),
			assert:  accepted,
		},
		{
			name: "cool-down: unrelated path", base: "/auth", endpoints: []Endpoint{exact},
			options: cooldown(Route{http.MethodPost, "/account/email"}),
			assert:  accepted,
		},
		{
			name: "cool-down: no base path checks nothing", base: "", endpoints: []Endpoint{at("/reauth/password", MatchExact, http.MethodPost)},
			options: cooldown(Route{http.MethodPost, "/reauth/password"}),
			assert:  accepted,
		},
		{
			name: "cool-down: an endpoint the base path did not move", base: "/auth",
			endpoints: []Endpoint{at("/.well-known/oauth-authorization-server/auth", MatchExact, http.MethodGet)},
			options:   cooldown(Route{http.MethodGet, "/.well-known/oauth-authorization-server/auth"}),
			assert:    accepted,
		},
		{
			name: "cool-down: a discovery document the issuer places", base: "/auth",
			endpoints: []Endpoint{declare("EnableOIDCProvider", "EnableOIDCProvider", "scrty.provider.discovery",
				"/auth/.well-known/openid-configuration", MatchExact, PassThrough, RequiresNothing, http.MethodGet)},
			options: cooldown(Route{http.MethodGet, "/.well-known/openid-configuration"}),
			assert:  accepted,
		},
		{
			name: "cool-down: waived", base: "/auth", endpoints: []Endpoint{exact},
			options: append(cooldown(Route{http.MethodPost, "/reauth/password"}), WithoutBasePathRouteCheck()),
			assert:  accepted,
		},
		{
			name: "exemption: exact route at the old path", base: "/auth", endpoints: []Endpoint{exact},
			options: exempt(http.MethodPost, "/reauth/password"),
			assert:  refused("WithCSRFExemption", "POST /reauth/password", "/auth/reauth/password"),
		},
		{
			name: "exemption: case differs, which it compares exactly", base: "/auth", endpoints: []Endpoint{exact},
			options: exempt(http.MethodPost, "/Reauth/Password"),
			assert:  accepted,
		},
		{
			name: "exemption: wildcard over a segment endpoint's name", base: "/auth", endpoints: []Endpoint{at("/auth/sso/login/{provider}", MatchSegment, http.MethodPost)},
			options: exempt(http.MethodPost, "/sso/*/x"),
			assert:  refused("WithCSRFExemption", "/sso/*/x", "/auth/sso/login/{provider}"),
		},
		{
			name: "exemption: wildcard that cannot reach the endpoint", base: "/auth", endpoints: []Endpoint{at("/auth/sso/login/{provider}", MatchSegment, http.MethodPost)},
			options: exempt(http.MethodPost, "/other/*/x"),
			assert:  accepted,
		},
		{
			name: "exemption: wildcard for the whole segment name", base: "/auth", endpoints: []Endpoint{at("/auth/sso/login/{provider}", MatchSegment, http.MethodPost)},
			options: exempt(http.MethodPost, "/sso/login/*"),
			assert:  refused("/auth/sso/login/{provider}"),
		},
		{
			name: "exemption: wildcard of the wrong depth for an exact endpoint", base: "/auth", endpoints: []Endpoint{exact},
			options: exempt(http.MethodPost, "/reauth/*/x"),
			assert:  accepted,
		},
		{
			name: "exemption: wildcard in place of an exact endpoint's segment", base: "/auth", endpoints: []Endpoint{exact},
			options: exempt(http.MethodPost, "/reauth/*"),
			assert:  refused("/auth/reauth/password"),
		},
		{
			name: "exemption: beneath a subtree", base: "/auth", endpoints: []Endpoint{at("/auth/sessions", MatchSubtree, http.MethodDelete)},
			options: exempt(http.MethodDelete, "/sessions/*"),
			assert:  refused("/auth/sessions"),
		},
		{
			name: "exemption: another method", base: "/auth", endpoints: []Endpoint{exact},
			options: exempt(http.MethodDelete, "/reauth/password"),
			assert:  accepted,
		},
		{
			name: "exemption: written with the base", base: "/auth", endpoints: []Endpoint{exact},
			options: exempt(http.MethodPost, "/auth/reauth/password"),
			assert:  accepted,
		},
		{
			name: "exemption: no base path checks nothing", base: "", endpoints: []Endpoint{at("/reauth/password", MatchExact, http.MethodPost)},
			options: exempt(http.MethodPost, "/reauth/password"),
			assert:  accepted,
		},
		{
			name: "exemption: waived", base: "/auth", endpoints: []Endpoint{exact},
			options: append(exempt(http.MethodPost, "/reauth/password"), WithoutBasePathRouteCheck()),
			assert:  accepted,
		},
		{
			name: "cool-down: a route at another endpoint's current path", base: "/reauth",
			endpoints: []Endpoint{
				at("/reauth/reauth/password", MatchExact, http.MethodPost),
				at("/reauth/verify/x", MatchExact, http.MethodPost),
			},
			options: cooldown(Route{http.MethodPost, "/Reauth/Verify/x/"}),
			assert:  accepted,
		},
		{
			name: "exemption: a route at another endpoint's current path", base: "/reauth",
			endpoints: []Endpoint{
				at("/reauth/reauth/password", MatchExact, http.MethodPost),
				at("/reauth/verify/x", MatchExact, http.MethodPost),
			},
			options: exempt(http.MethodPost, "/reauth/verify/x"),
			assert:  accepted,
		},
		{
			name: "exemption: trailing slash on an exact endpoint is stale", base: "/auth",
			endpoints: []Endpoint{at("/auth/signin/", MatchExact, http.MethodPost)},
			options:   exempt(http.MethodPost, "/signin/"),
			assert:    refused("WithCSRFExemption", "POST /signin/", "/auth/signin/"),
		},
		{
			name: "exemption: no trailing slash never matched an exact endpoint with one", base: "/auth",
			endpoints: []Endpoint{at("/auth/signin/", MatchExact, http.MethodPost)},
			options:   exempt(http.MethodPost, "/signin"),
			assert:    accepted,
		},
		{
			name: "exemption: trailing slash never matched an exact endpoint without one", base: "/auth",
			endpoints: []Endpoint{at("/auth/signin", MatchExact, http.MethodPost)},
			options:   exempt(http.MethodPost, "/signin/"),
			assert:    accepted,
		},
		{
			name: "exemption: empty segment after a segment endpoint's prefix", base: "/auth",
			endpoints: []Endpoint{at("/auth/sso/login/{provider}", MatchSegment, http.MethodPost)},
			options:   exempt(http.MethodPost, "/sso/login/"),
			assert:    accepted,
		},
		{
			name: "no routes at all", base: "/auth", endpoints: []Endpoint{exact},
			assert: accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := &config{basePath: tc.base}

			for _, opt := range tc.options {
				require.NoError(t, opt(c))
			}

			tc.assert(t, checkStaleRoutes(c, tc.endpoints))
		})
	}
}
