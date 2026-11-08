package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// TestBasePathRouteCheck pins what New does with the routes the consumer gives
// the chain once a base path moves the built-in endpoints: a route left at an
// endpoint's old path is refused, naming the route, its setting and the moved
// endpoint, and the waiver and a route written with the base build. The
// comparison itself is pinned over hand-made inventories beside the check.
func TestBasePathRouteCheck(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) (*httpsec.Chain, error)
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	// reauthWith builds a chain with password sign-in and re-authentication
	// under base, plus the options given.
	reauthWith := func(base string, extra ...httpsec.Option) func(t *testing.T) (*httpsec.Chain, error) {
		return func(t *testing.T) (*httpsec.Chain, error) {
			h := newLoginGuardHarness(t)

			opts := []httpsec.Option{
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
				}),
				httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(h.tokens)),
			}

			if base != "" {
				opts = append(opts, httpsec.WithBasePath(base))
			}

			return httpsec.New(append(opts, extra...)...)
		}
	}

	cooldown := func(r httpsec.Route) httpsec.Option {
		return httpsec.EnableRecoveryCooldown(recovery.NewMemoryRecordStore(), time.Hour, r)
	}

	refused := func(parts ...string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, c *httpsec.Chain, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, c, "a refused build returns no chain")

			for _, part := range parts {
				assert.ErrorContains(t, err, part)
			}
		}
	}

	built := func(t *testing.T, c *httpsec.Chain, err error) {
		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	cases := []testCase{
		{
			name:   "cool-down route left behind",
			build:  reauthWith("/auth", cooldown(httpsec.Route{Method: http.MethodPost, Path: "/reauth/password"})),
			assert: refused("EnableRecoveryCooldown", "POST /reauth/password", "scrty.reauth.password", "/auth/reauth/password"),
		},
		{
			name:   "route differing only in case and trailing slash",
			build:  reauthWith("/auth", cooldown(httpsec.Route{Method: http.MethodPost, Path: "/Reauth/Password/"})),
			assert: refused("POST /Reauth/Password/", "/auth/reauth/password"),
		},
		{
			name:   "route written with the base",
			build:  reauthWith("/auth", cooldown(httpsec.Route{Method: http.MethodPost, Path: "/auth/reauth/password"})),
			assert: built,
		},
		{
			name:   "route at an unrelated path",
			build:  reauthWith("/auth", cooldown(httpsec.Route{Method: http.MethodPost, Path: "/account/email"})),
			assert: built,
		},
		{
			name:   "no base path checks nothing",
			build:  reauthWith("", cooldown(httpsec.Route{Method: http.MethodPost, Path: "/reauth/password"})),
			assert: built,
		},
		{
			name: "cross-site exemption left behind",
			build: reauthWith("/auth", httpsec.EnableCSRFProtection(
				httpsec.WithCSRFExemption(http.MethodPost, "/sign-in/password"))),
			assert: refused("WithCSRFExemption", "POST /sign-in/password", "/auth/sign-in/password"),
		},
		{
			name: "cool-down route at another endpoint's current path",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				h := newLoginGuardHarness(t)

				return httpsec.New(
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
					}, httpsec.WithLoginRequestPath("/verify/x")),
					httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(h.tokens)),
					httpsec.WithBasePath("/reauth"),
					cooldown(httpsec.Route{Method: http.MethodPost, Path: "/reauth/verify/x"}),
				)
			},
			assert: built,
		},
		{
			name: "exemption at another endpoint's current path",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				h := newLoginGuardHarness(t)

				return httpsec.New(
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
					}, httpsec.WithLoginRequestPath("/verify/x")),
					httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(h.tokens)),
					httpsec.WithBasePath("/reauth"),
					httpsec.EnableCSRFProtection(httpsec.WithCSRFExemption(http.MethodPost, "/reauth/verify/x")),
				)
			},
			assert: built,
		},
		{
			name: "exemption left at an exact endpoint's old path with a trailing slash",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				h := newLoginGuardHarness(t)

				return httpsec.New(
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
					}, httpsec.WithLoginRequestPath("/signin/")),
					httpsec.WithBasePath("/auth"),
					httpsec.EnableCSRFProtection(httpsec.WithCSRFExemption(http.MethodPost, "/signin/")),
				)
			},
			assert: refused("WithCSRFExemption", "POST /signin/", "/auth/signin/"),
		},
		{
			name: "consumer waives the check",
			build: reauthWith("/auth", httpsec.WithoutBasePathRouteCheck(), httpsec.EnableCSRFProtection(
				httpsec.WithCSRFExemption(http.MethodPost, "/sign-in/password"))),
			assert: built,
		},
		{
			name:   "the waiver without a base path is refused",
			build:  reauthWith("", httpsec.WithoutBasePathRouteCheck()),
			assert: refused("WithoutBasePathRouteCheck", "WithBasePath"),
		},
		{
			name: "the waiver given before the base path builds",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				h := newLoginGuardHarness(t)

				return httpsec.New(
					httpsec.WithoutBasePathRouteCheck(),
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
					}),
					httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(h.tokens)),
					httpsec.EnableCSRFProtection(httpsec.WithCSRFExemption(http.MethodPost, "/sign-in/password")),
					httpsec.WithBasePath("/auth"),
				)
			},
			assert: built,
		},
		{
			name: "wildcard exemption over the back-channel logout's provider segment",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				// The redirect URL of the shared fixture is not under the base path;
				// that check is waived so this row judges the route alone.
				opts := append(oidcLoginOptions(t, httpsec.WithoutOIDCRedirectPathCheck()),
					httpsec.WithBasePath("/auth"),
					httpsec.EnableCSRFProtection(httpsec.WithCSRFExemption(http.MethodPost, "/sso/*/x")),
				)

				return httpsec.New(opts...)
			},
			assert: refused("WithCSRFExemption", "/sso/*/x", "/auth/sso/backchannel-logout/{provider}"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := tc.build(t)
			tc.assert(t, c, err)
		})
	}
}

// TestBasePathRouteCheck_RouteWrittenWithBaseIsEnforced pins that a cool-down
// route written with the base path, which the build accepts, is the route the
// guard then refuses during the cool-down, and that another endpoint of the
// chain is not caught by it.
func TestBasePathRouteCheck_RouteWrittenWithBaseIsEnforced(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		method string
		path   string
		assert func(t *testing.T, out served)
	}

	cases := []testCase{
		{
			name:   "the route written with the base is refused during the cool-down",
			method: http.MethodPost,
			path:   "/auth/reauth/password",
			assert: func(t *testing.T, out served) {
				require.ErrorIs(t, out.err, recovery.ErrCooldown)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)
			},
		},
		{
			name:   "another endpoint under the base is not refused by the cool-down",
			method: http.MethodPost,
			path:   "/auth/sign-in/password",
			assert: func(t *testing.T, out served) {
				assert.NotErrorIs(t, out.err, recovery.ErrCooldown)
			},
		},
		{
			name:   "an application path beside the marked one reaches the handler",
			method: http.MethodPost,
			path:   "/auth/reauth/other",
			assert: func(t *testing.T, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t)

			chain, err := httpsec.New(
				httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: h.tokens, Sessions: h.sessions, Users: h.users}),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
				}),
				httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(h.tokens)),
				httpsec.WithBasePath("/auth"),
				httpsec.EnableRecoveryCooldown(completedRecoveryAgo(t, 3*time.Hour), recoveryCooldown,
					httpsec.Route{Method: http.MethodPost, Path: "/auth/reauth/password"}),
			)
			require.NoError(t, err)

			s, err := h.sessions.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil)
			req.RemoteAddr = e2eSource + ":51000"
			req.Header.Set("Authorization", "Bearer "+mfaTokenFor(s.ID))

			tc.assert(t, serve(t, chain, req))
		})
	}
}
