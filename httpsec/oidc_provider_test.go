package httpsec_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

const opIssuer = "https://id.example.com"

// opFixture holds what every chain in these tests is built from. The signing
// keys are shared, because generating them is the slow part and nothing here
// signs: the tests read only who holds which.
type opFixture struct {
	keys, otherKeys *signingkey.Keys
}

func newOPFixture(t *testing.T) *opFixture {
	t.Helper()

	return &opFixture{
		keys:      must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))),
		otherKeys: must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))),
	}
}

// provider builds a provider over the fixture's keys.
func (f *opFixture) provider(t *testing.T, opts ...oidcprovider.Option) *oidcprovider.Provider {
	t.Helper()

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: opIssuer,
		Clients: []oidcprovider.Client{{
			ID:           "billing-web",
			Type:         oidcprovider.Confidential,
			Secret:       []byte("0123456789abcdef0123456789abcdef"),
			RedirectURIs: []string{"https://rp.example.com/cb"},
		}},
		Keys:         f.keys,
		Users:        NewMockUserLoader(gomock.NewController(t)),
		LoginURL:     opIssuer + "/login",
		ConsentURL:   opIssuer + "/consent",
		LogoutURL:    opIssuer + "/logout-page",
		LoggedOutURL: opIssuer + "/bye",
	}, opts...)
	require.NoError(t, err)

	return p
}

// reporting is a session manager that reports each sign-in's end to p.
func reporting(t *testing.T, p *oidcprovider.Provider) *session.Sessions {
	t.Helper()

	return must.Must(session.New(session.WithEndObserver(p)))
}

func (f *opFixture) bearer(t *testing.T, m *session.Sessions) httpsec.Option {
	t.Helper()

	return httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{
		Sessions: m,
		Users:    NewMockUserLoader(gomock.NewController(t)),
	})
}

// wired is every option a provider needs beside itself, over the provider's own
// keys and a manager that reports to it.
func (f *opFixture) wired(t *testing.T, p *oidcprovider.Provider) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{
		f.bearer(t, reporting(t, p)),
		httpsec.EnableJWKSEndpoint(f.keys),
		httpsec.EnableSecurityHeaders(),
	}
}

func TestOIDCProvider_Construction(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		build  func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, chain *httpsec.Chain, err error)
	}

	refused := func(names ...string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, chain)
			for _, name := range names {
				assert.ErrorContains(t, err, name)
			}
		}
	}

	built := func(t *testing.T, chain *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, chain)
	}

	// opts is a provider on an otherwise complete chain, with the provider's
	// own options.
	withOptions := func(t *testing.T, popts []oidcprovider.Option, opts ...httpsec.OIDCProviderOption) []httpsec.Option {
		t.Helper()

		p := f.provider(t, popts...)

		return append(f.wired(t, p), httpsec.EnableOIDCProvider(p, opts...))
	}

	// formLogin issues the session reference, as a chain under the session
	// bearer must; a chain with no bearer mode still needs a generator to build.
	formLogin := func(t *testing.T, m *session.Sessions, tokens token.Generator) httpsec.Option {
		t.Helper()

		return httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: NewMockAuthenticator(gomock.NewController(t)),
			Sessions:      m,
			Tokens:        tokens,
			Attempts:      must.Must(lockout.NewMemoryAttemptStore()),
		})
	}

	const endpointAudience = oidcprovider.AudienceIssuerOrTokenEndpoint

	cases := []testCase{
		{
			name:   "a fully wired provider builds",
			build:  func(t *testing.T) []httpsec.Option { t.Helper(); return withOptions(t, nil) },
			assert: built,
		},
		{
			name: "no provider",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return append(f.wired(t, f.provider(t)), httpsec.EnableOIDCProvider(nil))
			},
			assert: refused("EnableOIDCProvider"),
		},
		{
			name: "form login and no bearer mode",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					formLogin(t, reporting(t, p), newMockGenerator(gomock.NewController(t))),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: refused("EnableOIDCProvider", "bearer"),
		},
		{
			name: "no JWKS endpoint",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: refused("EnableOIDCProvider", "EnableJWKSEndpoint"),
		},
		{
			name: "enabled twice",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(f.wired(t, p), httpsec.EnableOIDCProvider(p), httpsec.EnableOIDCProvider(p))
			},
			assert: refused("EnableOIDCProvider", "twice"),
		},
		{
			name: "the end-session path set to the chain's logout path",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(f.wired(t, p),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: reporting(t, p)}),
					httpsec.EnableOIDCProvider(p, httpsec.WithOIDCProviderPath(httpsec.OIDCEndSession, httpsec.DefaultLogoutPath)))
			},
			assert: refused("EnableOIDCProvider", httpsec.DefaultLogoutPath),
		},
		{
			name: "the token path set to the JWKS path, whichever came first",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPath(httpsec.OIDCToken, httpsec.DefaultJWKSPath))
			},
			assert: refused("EnableOIDCProvider", httpsec.DefaultJWKSPath),
		},
		{
			name: "two provider paths equal",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPath(httpsec.OIDCRevoke, "/oauth2/token"))
			},
			assert: refused("EnableOIDCProvider", "/oauth2/token"),
		},
		{
			name: "a prefix naming no path",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPrefix("op"))
			},
			assert: refused("WithOIDCProviderPrefix"),
		},
		{
			name: "an empty prefix",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPrefix(""))
			},
			assert: refused("WithOIDCProviderPrefix"),
		},
		{
			name: "a prefix ending in a slash",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPrefix("/op/"))
			},
			assert: refused("WithOIDCProviderPrefix"),
		},
		{
			name: "a path naming no path",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "token"))
			},
			assert: refused("WithOIDCProviderPath"),
		},
		{
			name: "a path for an endpoint that does not exist",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPath(httpsec.OIDCEndpoint(200), "/x"))
			},
			assert: refused("WithOIDCProviderPath"),
		},
		{
			name: "the bearer's session manager does not report to the provider",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					f.bearer(t, must.Must(session.New())),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableOIDCProvider(f.provider(t)),
				}
			},
			assert: refused("EnableOIDCProvider", "session.WithEndObserver"),
		},
		{
			name: "the logout's session manager does not report to the provider",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(f.wired(t, p),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: must.Must(session.New())}),
					httpsec.EnableOIDCProvider(p))
			},
			assert: refused("EnableOIDCProvider", "session.WithEndObserver"),
		},
		{
			name: "form login's session manager does not report to the provider",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(f.wired(t, p), formLogin(t, must.Must(session.New()), nil), httpsec.EnableOIDCProvider(p))
			},
			assert: refused("EnableOIDCProvider", "session.WithEndObserver"),
		},
		{
			name: "a renewal over the bearer's reporting manager builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)
				m := reporting(t, p)

				return []httpsec.Option{
					f.bearer(t, m),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Sessions: m, Users: NewMockUserLoader(gomock.NewController(t))}),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: built,
		},
		{
			name: "reporting is judged after the chain's wiring, wherever the step stands",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				var wired bool

				t.Cleanup(func() { assert.True(t, wired, "the wiring step had not run when the chain was refused") })

				return []httpsec.Option{
					f.bearer(t, must.Must(session.New())),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableOIDCProvider(f.provider(t)),
					httpsec.WiredStep(func() { wired = true }),
				}
			},
			assert: refused("EnableOIDCProvider", "session.WithEndObserver"),
		},
		{
			name: "the provider says DPoP is on and the chain has no EnableDPoP",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, []oidcprovider.Option{oidcprovider.WithDPoP()})
			},
			assert: refused("EnableOIDCProvider", "WithDPoP"),
		},
		{
			name: "the chain has EnableDPoP and the provider does not say so",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return append(withOptions(t, nil), httpsec.EnableDPoP(httpsec.DPoP{PublicURL: opIssuer}))
			},
			assert: refused("EnableOIDCProvider", "WithDPoP"),
		},
		{
			name: "a provider-only chain enables DPoP",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return append(withOptions(t, []oidcprovider.Option{oidcprovider.WithDPoP()}),
					httpsec.EnableDPoP(httpsec.DPoP{PublicURL: opIssuer}))
			},
			assert: built,
		},
		{
			// EnableDPoP's own check runs first here, as it came first. Were the
			// provider not among the features verifying bound credentials, it
			// would report having none, and hide the provider's real fault.
			name: "the provider counts as verifying bound credentials, so DPoP does not report having none",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t, oidcprovider.WithDPoP())

				return []httpsec.Option{
					httpsec.EnableDPoP(httpsec.DPoP{PublicURL: opIssuer}),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: refused("EnableOIDCProvider", "bearer"),
		},
		{
			name: "an assertion endpoint the prefix moved away from",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(endpointAudience)},
					httpsec.WithOIDCProviderPrefix("/op"))
			},
			assert: refused("EnableOIDCProvider", "WithAssertionTokenEndpoint"),
		},
		{
			name: "an assertion endpoint a per-path option moved away from",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(endpointAudience)},
					httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/tokens"))
			},
			assert: refused("EnableOIDCProvider", "WithAssertionTokenEndpoint"),
		},
		{
			name: "an assertion endpoint stating the moved path builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, []oidcprovider.Option{
					oidcprovider.WithClientAssertionAudience(endpointAudience),
					oidcprovider.WithAssertionTokenEndpoint(opIssuer + "/op/token"),
				}, httpsec.WithOIDCProviderPrefix("/op"))
			},
			assert: built,
		},
		{
			name: "an assertion endpoint on the default path builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(endpointAudience)})
			},
			assert: built,
		},
		{
			name: "no assertion endpoint, under the issuer-only rule, is free of the path",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPrefix("/op"))
			},
			assert: built,
		},
		{
			name: "a JWKS endpoint publishing another signing-key manager",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(f.otherKeys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: refused("EnableOIDCProvider", "EnableJWKSEndpoint"),
		},
		{
			name: "no security headers",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: refused("EnableOIDCProvider", "EnableSecurityHeaders", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "no security headers, the consumer stating its pages carry frame-ancestors",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableOIDCProvider(p, httpsec.WithOIDCPagesCarryFrameAncestors()),
				}
			},
			assert: built,
		},
		{
			name: "a wrapped JWKS provider, which cannot be compared, builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(NewMockKeySetProvider(gomock.NewController(t))),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: built,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.build(t)...)
			tc.assert(t, chain, err)
		})
	}
}

// opAnswer is what a chain made of a request, and whether the request reached the
// application behind the chain.
type opAnswer struct {
	status   int
	passedOn bool
}

// serveOP runs one request through a chain with the application behind it.
func serveOP(t *testing.T, chain *httpsec.Chain, r *http.Request) opAnswer {
	t.Helper()

	var passedOn bool

	h := chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { passedOn = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	return opAnswer{status: rec.Code, passedOn: passedOn}
}

func TestOIDCProvider_Routes(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		opts   []httpsec.OIDCProviderOption
		method string
		path   string
		assert func(t *testing.T, a opAnswer)
	}

	passesThrough := func(t *testing.T, a opAnswer) {
		t.Helper()
		assert.True(t, a.passedOn, "the request should have reached the application")
	}

	// answered holds whichever handler serves the endpoint, a stub or a real one,
	// so it says only that the provider took the request.
	answered := func(t *testing.T, a opAnswer) {
		t.Helper()
		assert.False(t, a.passedOn, "the request should have been answered by the provider")
	}

	prefix := []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/op")}
	moved := []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/tokens")}

	cases := []testCase{
		{name: "another path passes through", method: http.MethodGet, path: "/api/orders", assert: passesThrough},
		{name: "a path under the prefix naming no endpoint passes through", method: http.MethodGet, path: "/oauth2/other", assert: passesThrough},
		{name: "a path below an endpoint passes through", method: http.MethodGet, path: "/oauth2/token/x", assert: passesThrough},

		{name: "authorization", method: http.MethodGet, path: "/oauth2/authorize", assert: answered},
		{name: "resume", method: http.MethodPost, path: "/oauth2/authorize/resume", assert: answered},
		{name: "token", method: http.MethodPost, path: "/oauth2/token", assert: answered},
		{name: "UserInfo", method: http.MethodGet, path: "/oauth2/userinfo", assert: answered},
		{name: "revocation", method: http.MethodPost, path: "/oauth2/revoke", assert: answered},
		{name: "introspection", method: http.MethodPost, path: "/oauth2/introspect", assert: answered},
		{name: "end-session", method: http.MethodGet, path: "/oauth2/logout", assert: answered},
		{name: "logout confirmation", method: http.MethodPost, path: "/oauth2/logout/confirm", assert: answered},
		{name: "consents", method: http.MethodGet, path: "/oauth2/consents", assert: answered},

		{name: "a prefix moves the token endpoint", opts: prefix, method: http.MethodPost, path: "/op/token", assert: answered},
		{name: "a prefix moves the resume endpoint", opts: prefix, method: http.MethodPost, path: "/op/authorize/resume", assert: answered},
		{name: "the default path passes through under a prefix", opts: prefix, method: http.MethodPost, path: "/oauth2/token", assert: passesThrough},

		{name: "a per-path option moves one endpoint", opts: moved, method: http.MethodPost, path: "/tokens", assert: answered},
		{name: "the moved endpoint's default passes through", opts: moved, method: http.MethodPost, path: "/oauth2/token", assert: passesThrough},
		{name: "a per-path option leaves the others", opts: moved, method: http.MethodPost, path: "/oauth2/revoke", assert: answered},
		{
			name:   "a per-path option holds under a prefix, whichever came first",
			opts:   []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/tokens"), httpsec.WithOIDCProviderPrefix("/op")},
			method: http.MethodPost, path: "/tokens", assert: answered,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := f.provider(t)
			chain, err := httpsec.New(append(f.wired(t, p), httpsec.EnableOIDCProvider(p, tc.opts...))...)
			require.NoError(t, err)

			r := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil)
			tc.assert(t, serveOP(t, chain, r))
		})
	}
}

// TestOIDCProvider_Routes_Groups pins the seam each endpoint group plugs into,
// with a group of the test's own, so it holds when the stubs are gone.
func TestOIDCProvider_Routes_Groups(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	errSettle := errors.New("settling failed")
	errFlush := errors.New("flushing failed")

	type testCase struct {
		name   string
		group  *httpsec.TestOIDCGroup
		header string
		assert func(t *testing.T, g *httpsec.TestOIDCGroup, chain *httpsec.Chain, err error, r *http.Request)
	}

	cases := []testCase{
		{
			name:   "an outer route is answered ahead of the bearer, whatever credential it carries",
			group:  &httpsec.TestOIDCGroup{Path: "/g"},
			header: "Bearer not-a-session",
			assert: func(t *testing.T, g *httpsec.TestOIDCGroup, chain *httpsec.Chain, err error, r *http.Request) {
				t.Helper()
				require.NoError(t, err)

				a := serveOP(t, chain, r)
				assert.False(t, a.passedOn)
				assert.Equal(t, 1, g.Calls())
			},
		},
		{
			name:   "an inner route sits behind the bearer, which refuses a bad credential",
			group:  &httpsec.TestOIDCGroup{Path: "/g", Inner: true},
			header: "Bearer not-a-session",
			assert: func(t *testing.T, g *httpsec.TestOIDCGroup, chain *httpsec.Chain, err error, r *http.Request) {
				t.Helper()
				require.NoError(t, err)

				a := serveOP(t, chain, r)
				assert.Equal(t, http.StatusUnauthorized, a.status)
				assert.Zero(t, g.Calls())
			},
		},
		{
			name:  "an inner route is answered with no credential at all",
			group: &httpsec.TestOIDCGroup{Path: "/g", Inner: true},
			assert: func(t *testing.T, g *httpsec.TestOIDCGroup, chain *httpsec.Chain, err error, r *http.Request) {
				t.Helper()
				require.NoError(t, err)

				a := serveOP(t, chain, r)
				assert.False(t, a.passedOn)
				assert.Equal(t, 1, g.Calls())
			},
		},
		{
			name:  "a route another group holds is refused",
			group: &httpsec.TestOIDCGroup{Path: "/oauth2/token"},
			assert: func(t *testing.T, _ *httpsec.TestOIDCGroup, chain *httpsec.Chain, err error, _ *http.Request) {
				t.Helper()
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "/oauth2/token")
				assert.Nil(t, chain)
			},
		},
		{
			name:  "a group that cannot settle refuses the chain",
			group: &httpsec.TestOIDCGroup{Path: "/g", SettleErr: errSettle},
			assert: func(t *testing.T, _ *httpsec.TestOIDCGroup, chain *httpsec.Chain, err error, _ *http.Request) {
				t.Helper()
				require.ErrorIs(t, err, errSettle)
				assert.Nil(t, chain)
			},
		},
		{
			name:  "a group settles with the bearer's manager to hand, and is wired with the chain",
			group: &httpsec.TestOIDCGroup{Path: "/g"},
			assert: func(t *testing.T, g *httpsec.TestOIDCGroup, _ *httpsec.Chain, err error, _ *http.Request) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, g.SettledWithManager())
				assert.True(t, g.WiredWithLogger())
			},
		},
		{
			name:  "a group's refusal logs are flushed with the chain's",
			group: &httpsec.TestOIDCGroup{Path: "/g", FlushErr: errFlush},
			assert: func(t *testing.T, _ *httpsec.TestOIDCGroup, chain *httpsec.Chain, err error, _ *http.Request) {
				t.Helper()
				require.NoError(t, err)
				assert.ErrorIs(t, chain.FlushRefusalLogs(), errFlush)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := f.provider(t)
			chain, err := httpsec.New(append(f.wired(t, p),
				httpsec.EnableOIDCProvider(p, httpsec.WithTestOIDCGroup(tc.group)))...)

			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tc.group.Path, nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}

			tc.assert(t, tc.group, chain, err, r)
		})
	}
}
