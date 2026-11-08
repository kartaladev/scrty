package httpsec_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
)

const (
	// bpIssuer is the provider's issuer in every chain here: it covers the base
	// path, as a provider under a base path must.
	bpIssuer = "https://id.example.com/auth"

	// bpLoginPage is the consumer's login page. It is on the issuer's origin, as the
	// provider requires, and outside the base path, which must not move it.
	bpLoginPage = "https://id.example.com/signin"

	bpBase = "/auth"
)

// bpChain builds a chain with the provider at bpIssuer under bpBase. With
// baseFirst, WithBasePath is the first option, ahead of the provider and its
// options; otherwise it is the last.
func bpChain(t *testing.T, f *opFixture, baseFirst bool, opts ...httpsec.OIDCProviderOption) (*httpsec.Chain, error) {
	t.Helper()

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: bpIssuer,
		Clients: []oidcprovider.Client{{
			ID:           "billing-web",
			Type:         oidcprovider.Confidential,
			Secret:       []byte("0123456789abcdef0123456789abcdef"),
			RedirectURIs: []string{rpCallback},
			Scopes:       []string{"openid", "profile"},
		}},
		Keys:         f.keys,
		Users:        NewMockUserLoader(gomock.NewController(t)),
		LoginURL:     bpLoginPage,
		ConsentURL:   "https://id.example.com/consent",
		LogoutURL:    "https://id.example.com/logout-page",
		LoggedOutURL: "https://id.example.com/bye",
	})
	require.NoError(t, err)

	chainOpts := append(f.wired(t, p), httpsec.EnableOIDCProvider(p, opts...))
	if baseFirst {
		chainOpts = append([]httpsec.Option{httpsec.WithBasePath(bpBase)}, chainOpts...)
	} else {
		chainOpts = append(chainOpts, httpsec.WithBasePath(bpBase))
	}

	return httpsec.New(chainOpts...)
}

// bpServe sends one request through chain, with the application behind it.
func bpServe(t *testing.T, chain *httpsec.Chain, method, target string) mdAnswer {
	t.Helper()

	var passedOn bool

	h := chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { passedOn = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, target, nil))

	return mdAnswer{status: rec.Code, header: rec.Header(), body: rec.Body.Bytes(), passedOn: passedOn}
}

// bpOpenIDConfiguration is the OpenID configuration chain serves under the base.
func bpOpenIDConfiguration(t *testing.T, chain *httpsec.Chain) map[string]any {
	t.Helper()

	return bpServe(t, chain, http.MethodGet, bpBase+mdOIDCPath).doc(t)
}

// TestOIDCProvider_BasePath pins where the provider answers under a base path:
// its prefix and its per-endpoint paths within the base, the metadata documents
// where the issuer places them, the published URLs naming the paths served, and
// the consumer's pages left where they are. Every row runs with WithBasePath
// both before and after the provider, which must make no difference.
func TestOIDCProvider_BasePath(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		opts   []httpsec.OIDCProviderOption
		assert func(t *testing.T, chain *httpsec.Chain)
	}

	answersAt := func(method string, served string, passing ...string) func(*testing.T, *httpsec.Chain) {
		return func(t *testing.T, chain *httpsec.Chain) {
			t.Helper()

			assert.False(t, bpServe(t, chain, method, served).passedOn, "%s %s should be answered by the provider", method, served)

			for _, p := range passing {
				assert.True(t, bpServe(t, chain, method, p).passedOn, "%s %s should pass through", method, p)
			}
		}
	}

	cases := []testCase{
		{
			name:   "the token endpoint answers under the base, and its unbased path passes through",
			assert: answersAt(http.MethodPost, "/auth/oauth2/token", "/oauth2/token", "/auth/auth/oauth2/token"),
		},
		{
			name:   "an endpoint's own path is within the base",
			opts:   []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/tokens")},
			assert: answersAt(http.MethodPost, "/auth/tokens", "/tokens", "/oauth2/token", "/auth/oauth2/token"),
		},
		{
			name:   "the prefix is within the base",
			opts:   []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/op")},
			assert: answersAt(http.MethodPost, "/auth/op/token", "/op/token", "/auth/oauth2/token"),
		},
		{
			name: "an endpoint's own path holds under a prefix, both within the base",
			opts: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/tokens"), httpsec.WithOIDCProviderPrefix("/op"),
			},
			assert: func(t *testing.T, chain *httpsec.Chain) {
				t.Helper()

				answersAt(http.MethodPost, "/auth/tokens", "/auth/op/token")(t, chain)
				answersAt(http.MethodPost, "/auth/op/revoke", "/op/revoke")(t, chain)
			},
		},
		{
			name: "the OpenID configuration answers at the issuer's path, and not at the root",
			assert: func(t *testing.T, chain *httpsec.Chain) {
				t.Helper()

				assert.Equal(t, http.StatusOK, bpServe(t, chain, http.MethodGet, "/auth"+mdOIDCPath).status)
				assert.True(t, bpServe(t, chain, http.MethodGet, mdOIDCPath).passedOn, "the root path passes through")
				assert.True(t, bpServe(t, chain, http.MethodGet, "/auth/auth"+mdOIDCPath).passedOn, "a doubled base passes through")
			},
		},
		{
			name: "the authorization server metadata answers at the host root, with the issuer's path inserted",
			assert: func(t *testing.T, chain *httpsec.Chain) {
				t.Helper()

				a := bpServe(t, chain, http.MethodGet, mdOAuthPath+"/auth")
				assert.Equal(t, http.StatusOK, a.status, string(a.body))
				assert.True(t, bpServe(t, chain, http.MethodGet, "/auth"+mdOAuthPath+"/auth").passedOn,
					"the metadata is not moved under the base")
			},
		},
		{
			name: "the documents name the endpoints where they answer",
			assert: func(t *testing.T, chain *httpsec.Chain) {
				t.Helper()

				doc := bpOpenIDConfiguration(t, chain)
				assert.Equal(t, bpIssuer, doc["issuer"])
				assert.Equal(t, "https://id.example.com/auth/oauth2/token", doc["token_endpoint"])
				assert.Equal(t, "https://id.example.com/auth/.well-known/jwks.json", doc["jwks_uri"])

				oauth := bpServe(t, chain, http.MethodGet, mdOAuthPath+"/auth").doc(t)
				assert.Equal(t, doc["token_endpoint"], oauth["token_endpoint"])
				assert.Equal(t, doc["jwks_uri"], oauth["jwks_uri"])

				for _, member := range []string{
					"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri",
					"revocation_endpoint", "introspection_endpoint", "end_session_endpoint",
				} {
					raw, ok := doc[member].(string)
					require.True(t, ok, "%s is published", member)
					assert.True(t, strings.HasPrefix(raw, bpIssuer+"/"), "%s is %q, outside the issuer", member, raw)
					assert.NotContains(t, raw, "/auth/auth", "%s doubles the base", member)

					u, err := url.Parse(raw)
					require.NoError(t, err)

					method := http.MethodPost
					if member == "jwks_uri" || member == "userinfo_endpoint" || member == "authorization_endpoint" || member == "end_session_endpoint" {
						method = http.MethodGet
					}

					assert.False(t, bpServe(t, chain, method, u.Path).passedOn, "%s names %s, which the chain does not answer", member, u.Path)
				}
			},
		},
		{
			name: "a published endpoint path within the base is named as served",
			opts: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/tokens")},
			assert: func(t *testing.T, chain *httpsec.Chain) {
				t.Helper()

				assert.Equal(t, "https://id.example.com/auth/tokens", bpOpenIDConfiguration(t, chain)["token_endpoint"])
			},
		},
		{
			name: "the key set is served under the base",
			assert: func(t *testing.T, chain *httpsec.Chain) {
				t.Helper()

				a := bpServe(t, chain, http.MethodGet, "/auth/.well-known/jwks.json")
				require.Equal(t, http.StatusOK, a.status)

				var set map[string]any
				require.NoError(t, json.Unmarshal(a.body, &set))
				assert.Contains(t, set, "keys")

				assert.True(t, bpServe(t, chain, http.MethodGet, "/.well-known/jwks.json").passedOn, "the unbased key set passes through")
			},
		},
		{
			name: "an authorization request needing a sign-in goes to the consumer's login page, unmoved",
			assert: func(t *testing.T, chain *httpsec.Chain) {
				t.Helper()

				params := url.Values{
					"response_type":         {"code"},
					"client_id":             {"billing-web"},
					"redirect_uri":          {rpCallback},
					"scope":                 {"openid profile"},
					"state":                 {"xyz"},
					"code_challenge":        {pkceChallengeS256},
					"code_challenge_method": {"S256"},
				}

				a := bpServe(t, chain, http.MethodGet, bpIssuer+"/oauth2/authorize?"+params.Encode())
				require.Equal(t, http.StatusSeeOther, a.status, string(a.body))

				at, err := url.Parse(a.header.Get("Location"))
				require.NoError(t, err)
				assert.Equal(t, bpLoginPage, at.Scheme+"://"+at.Host+at.Path)
			},
		},
	}

	for _, tc := range cases {
		for _, baseFirst := range []bool{false, true} {
			name := tc.name + "/base path after the provider"
			if baseFirst {
				name = tc.name + "/base path before the provider"
			}

			t.Run(name, func(t *testing.T) {
				t.Parallel()

				chain, err := bpChain(t, f, baseFirst, tc.opts...)
				require.NoError(t, err)

				tc.assert(t, chain)
			})
		}
	}
}

// TestOIDCProvider_BasePathRepeat pins that a provider path the consumer set at
// or under the base path, which would answer with the base doubled, is refused,
// naming the option and the doubled path, wherever WithBasePath stands.
func TestOIDCProvider_BasePathRepeat(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		opts   []httpsec.OIDCProviderOption
		assert func(t *testing.T, chain *httpsec.Chain, err error)
	}

	refused := func(fragments ...string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, chain)

			for _, fragment := range fragments {
				assert.Contains(t, err.Error(), fragment)
			}
		}
	}

	cases := []testCase{
		{
			name:   "a prefix under the base",
			opts:   []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/auth/oauth2")},
			assert: refused("WithOIDCProviderPrefix", `"/auth/auth/oauth2"`),
		},
		{
			name:   "a prefix that is the base",
			opts:   []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/auth/")},
			assert: refused("WithOIDCProviderPrefix", `"/auth/auth/"`),
		},
		{
			name:   "an endpoint path under the base",
			opts:   []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/auth/token")},
			assert: refused("WithOIDCProviderPath for OIDCToken", `"/auth/auth/token"`),
		},
		{
			name: "a prefix sharing only the base's leading characters is no repeat",
			opts: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/authz")},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, bpServe(t, chain, http.MethodPost, "/auth/authz/token").passedOn)
			},
		},
	}

	for _, tc := range cases {
		for _, baseFirst := range []bool{false, true} {
			name := tc.name + "/base path after the provider"
			if baseFirst {
				name = tc.name + "/base path before the provider"
			}

			t.Run(name, func(t *testing.T) {
				t.Parallel()

				chain, err := bpChain(t, f, baseFirst, tc.opts...)
				tc.assert(t, chain, err)
			})
		}
	}
}
