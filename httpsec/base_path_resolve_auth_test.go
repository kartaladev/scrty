package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// probe is one request an endpoint group answers, with the path given
// relative to the group's prefix.
type probe struct {
	method string
	suffix string
}

// authEndpoint is a group of built-in endpoints answered under one setting: the
// re-authentication prefix, or one of the four federated-login paths.
type authEndpoint struct {
	name string

	// defaultPrefix is where the group answers with no path of the consumer's.
	defaultPrefix string

	// consumerPath is what the consumer sets, without the base, and served is
	// where it answers without a base.
	consumerPath string
	served       string

	// probes are the requests the group answers under its prefix.
	probes []probe

	// option is the name of the option that sets the path.
	option string

	// options enables the group, with the path given when it is not "".
	options func(t *testing.T, path string) []httpsec.Option
}

// oidcLoginOptions enables federated login with a handoff, over a registry
// holding the provider "corp", with the OIDC options given.
func oidcLoginOptions(t *testing.T, opts ...httpsec.OIDCOption) []httpsec.Option {
	t.Helper()

	flows, err := oidc.NewMemoryFlowStore()
	require.NoError(t, err)

	handoffs, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(gomock.NewController(t)))
	require.NoError(t, err)

	sessions, err := session.New()
	require.NoError(t, err)

	all := append([]httpsec.OIDCOption{
		httpsec.WithOIDCSessions(sessions),
		httpsec.WithOIDCTokens(newMockGenerator(gomock.NewController(t))),
	}, opts...)

	return []httpsec.Option{httpsec.EnableOIDCLogin(
		httpsec.OIDCDeps{RelyingParty: oidcManagerOver(t, flows), Handoff: handoffs}, all...)}
}

func authEndpoints() []authEndpoint {
	return []authEndpoint{
		{
			name:          "re-authentication",
			defaultPrefix: httpsec.DefaultReauthenticationPrefix,
			consumerPath:  "/confirm/",
			served:        "/confirm",
			option:        "WithReauthenticationPrefix",
			probes: []probe{
				{http.MethodGet, "/methods"},
				{http.MethodPost, "/challenge/totp"},
				{http.MethodPost, "/verify/totp"},
				{http.MethodPost, "/password"},
			},
			options: func(t *testing.T, path string) []httpsec.Option {
				h := newLoginGuardHarness(t)

				var opts []httpsec.ReauthenticationOption
				opts = append(opts, httpsec.WithReauthenticationTokens(h.tokens))
				if path != "" {
					opts = append(opts, httpsec.WithReauthenticationPrefix(path))
				}

				return []httpsec.Option{
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
					}),
					httpsec.EnableReauthentication(opts...),
				}
			},
		},
		{
			name:          "OIDC authorize",
			defaultPrefix: "/sso/login",
			consumerPath:  "/start/",
			served:        "/start",
			option:        "WithOIDCAuthorizePath",
			probes:        []probe{{http.MethodGet, "/" + testOIDCProvider}},
			options: func(t *testing.T, path string) []httpsec.Option {
				if path == "" {
					return oidcLoginOptions(t)
				}

				return oidcLoginOptions(t, httpsec.WithOIDCAuthorizePath(path))
			},
		},
		{
			name:          "OIDC callback",
			defaultPrefix: "/sso/callback",
			consumerPath:  "/back/",
			served:        "/back",
			option:        "WithOIDCCallbackPath",
			probes:        []probe{{http.MethodGet, "/" + testOIDCProvider}},
			options: func(t *testing.T, path string) []httpsec.Option {
				if path == "" {
					return oidcLoginOptions(t)
				}

				return oidcLoginOptions(t, httpsec.WithOIDCCallbackPath(path))
			},
		},
		{
			name:          "OIDC handoff",
			defaultPrefix: httpsec.DefaultOIDCHandoffPath,
			consumerPath:  "/handoff-code",
			served:        "/handoff-code",
			option:        "WithOIDCHandoffPath",
			probes:        []probe{{http.MethodPost, ""}},
			options: func(t *testing.T, path string) []httpsec.Option {
				if path == "" {
					return oidcLoginOptions(t)
				}

				return oidcLoginOptions(t, httpsec.WithOIDCHandoffPath(path))
			},
		},
		{
			name:          "OIDC back-channel logout",
			defaultPrefix: "/sso/backchannel-logout",
			consumerPath:  "/bc-out/",
			served:        "/bc-out",
			option:        "WithOIDCBackchannelLogoutPath",
			probes:        []probe{{http.MethodPost, "/" + testOIDCProvider}},
			options: func(t *testing.T, path string) []httpsec.Option {
				if path == "" {
					return oidcLoginOptions(t)
				}

				return oidcLoginOptions(t, httpsec.WithOIDCBackchannelLogoutPath(path))
			},
		},
	}
}

// TestBasePath_ResolvesAuthEndpoints pins where the re-authentication endpoints
// and the four federated-login endpoints answer under a base path: at the base
// followed by their own path, the default or the consumer's, wherever the base
// path option stands, and never at the path without the base. Every
// re-authentication sub-path is moved once, not twice.
func TestBasePath_ResolvesAuthEndpoints(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		endpoint authEndpoint
		path     string

		before, after []httpsec.Option

		assert func(t *testing.T, e authEndpoint, c *httpsec.Chain, err error)
	}

	answersUnder := func(prefix string, passesPrefixes ...string) func(*testing.T, authEndpoint, *httpsec.Chain, error) {
		return func(t *testing.T, e authEndpoint, c *httpsec.Chain, err error) {
			require.NoError(t, err)
			require.NotNil(t, c)

			for _, p := range e.probes {
				assert.True(t, answered(t, c, p.method, prefix+p.suffix), "%s %s is answered", p.method, prefix+p.suffix)

				for _, other := range passesPrefixes {
					assert.False(t, answered(t, c, p.method, other+p.suffix), "%s %s passes through", p.method, other+p.suffix)
				}
			}
		}
	}

	var cases []testCase

	for _, e := range authEndpoints() {
		cases = append(cases,
			testCase{
				name:     e.name + ": no base path leaves the default where it was",
				endpoint: e,
				assert:   answersUnder(e.defaultPrefix, "/auth"+e.defaultPrefix),
			},
			testCase{
				name:     e.name + ": the base path given first moves the default",
				endpoint: e,
				before:   []httpsec.Option{httpsec.WithBasePath("/auth")},
				assert:   answersUnder("/auth"+e.defaultPrefix, e.defaultPrefix, "/auth/auth"+e.defaultPrefix),
			},
			testCase{
				name:     e.name + ": the base path given last moves the default the same",
				endpoint: e,
				after:    []httpsec.Option{httpsec.WithBasePath("/auth")},
				assert:   answersUnder("/auth"+e.defaultPrefix, e.defaultPrefix, "/auth/auth"+e.defaultPrefix),
			},
			testCase{
				name:     e.name + ": the consumer's path answers within the base",
				endpoint: e,
				path:     e.consumerPath,
				before:   []httpsec.Option{httpsec.WithBasePath("/auth")},
				assert:   answersUnder("/auth"+e.served, e.served, "/auth"+e.defaultPrefix),
			},
			testCase{
				name:     e.name + ": the consumer's path answers within the base given last",
				endpoint: e,
				path:     e.consumerPath,
				after:    []httpsec.Option{httpsec.WithBasePath("/auth")},
				assert:   answersUnder("/auth"+e.served, e.served, "/auth"+e.defaultPrefix),
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := append([]httpsec.Option{}, tc.before...)
			opts = append(opts, tc.endpoint.options(t, tc.path)...)
			opts = append(opts, tc.after...)

			c, err := httpsec.New(opts...)
			tc.assert(t, tc.endpoint, c, err)
		})
	}
}

// TestBasePath_OIDCCallbackProvider pins the callback of provider "corp" under
// a base path at /auth/sso/callback/corp, and nowhere else.
func TestBasePath_OIDCCallbackProvider(t *testing.T) {
	t.Parallel()

	c, err := httpsec.New(append(oidcLoginOptions(t), httpsec.WithBasePath("/auth"))...)
	require.NoError(t, err)

	assert.True(t, answered(t, c, http.MethodGet, "/auth/sso/callback/corp"))
	assert.False(t, answered(t, c, http.MethodGet, "/sso/callback/corp"))
	assert.False(t, answered(t, c, http.MethodGet, "/auth/auth/sso/callback/corp"))
}

// TestBasePath_AuthorizationRulesKeepConsumerPaths pins that the base path does
// not move an authorization rule: a rule for GET /projects/{id} judges
// /projects/42 under the base /auth, and never matches /auth/projects/42.
func TestBasePath_AuthorizationRulesKeepConsumerPaths(t *testing.T) {
	t.Parallel()

	rule := authorize.Rule[httpsec.Request]{
		Match: func(r httpsec.Request) bool {
			return r.Method() == http.MethodGet && len(r.Path()) > len("/projects/") && r.Path()[:len("/projects/")] == "/projects/"
		},
		Require: authorize.PermitAll(),
	}

	for _, e := range authEndpoints() {
		t.Run(e.name, func(t *testing.T) {
			t.Parallel()

			opts := append(e.options(t, ""), httpsec.WithBasePath("/auth"),
				httpsec.EnableAuthorization(permittingAuthorizer(t), rule))

			c, err := httpsec.New(opts...)
			require.NoError(t, err)

			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(nextHandlerHeader, "1")
			})

			reached := func(path string) bool {
				rec := httptest.NewRecorder()
				c.Middleware()(next).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))

				return rec.Header().Get(nextHandlerHeader) != ""
			}

			assert.True(t, reached("/projects/42"), "the rule judges /projects/42")
			assert.False(t, reached("/auth/projects/42"), "the rule never matches /auth/projects/42")
		})
	}
}

// TestBasePath_RefusesDoubledAuthPath pins that a path the consumer set which
// repeats the base path is refused, naming the option and the doubled path.
func TestBasePath_RefusesDoubledAuthPath(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		endpoint authEndpoint
		path     string
		doubled  string
	}

	var cases []testCase

	for i, doubled := range []string{"/auth/auth/reauth", "/auth/auth/sso/login/", "/auth/auth/sso/callback/", "/auth/auth/sso/handoff", "/auth/auth/sso/backchannel-logout/"} {
		e := authEndpoints()[i]
		path := doubled[len("/auth"):]

		cases = append(cases, testCase{name: e.name, endpoint: e, path: path, doubled: doubled})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := append(tc.endpoint.options(t, tc.path), httpsec.WithBasePath("/auth"))

			c, err := httpsec.New(opts...)
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, c)
			assert.ErrorContains(t, err, tc.endpoint.option)
			assert.ErrorContains(t, err, tc.doubled)
		})
	}
}
