package httpsec_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/token/signingkey"
)

const (
	mdOIDCPath  = "/.well-known/openid-configuration"
	mdOAuthPath = "/.well-known/oauth-authorization-server"

	mdPathIssuer = "https://id.example.com/auth"
)

// mdSetup is what one chain serving the metadata is built from.
type mdSetup struct {
	issuer  string
	clients []oidcprovider.Client
	popts   []oidcprovider.Option
	chain   []httpsec.Option
	jwks    []httpsec.JWKSOption
	oidc    []httpsec.OIDCProviderOption
}

// build makes the chain, over the fixture's keys.
func (s mdSetup) build(t *testing.T, f *opFixture) (*httpsec.Chain, error) {
	t.Helper()

	if s.issuer == "" {
		s.issuer = opIssuer
	}

	p := f.providerOver(t, s.issuer, f.keys, s.clients, s.popts...)

	opts := []httpsec.Option{
		f.bearer(t, reporting(t, p)),
		httpsec.EnableJWKSEndpoint(f.keys, s.jwks...),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableOIDCProvider(p, s.oidc...),
	}

	return httpsec.New(append(opts, s.chain...)...)
}

// mdAnswer is what a request to the chain got.
type mdAnswer struct {
	status   int
	header   http.Header
	body     []byte
	passedOn bool
}

func (a mdAnswer) doc(t *testing.T) map[string]any {
	t.Helper()

	require.Equal(t, http.StatusOK, a.status, string(a.body))

	var doc map[string]any
	require.NoError(t, json.Unmarshal(a.body, &doc))

	return doc
}

// mdGet sends one request through the chain, with the application behind it.
func mdGet(t *testing.T, chain *httpsec.Chain, method, path string) mdAnswer {
	t.Helper()

	var passedOn bool

	h := chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { passedOn = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, path, nil))

	return mdAnswer{status: rec.Code, header: rec.Header(), body: rec.Body.Bytes(), passedOn: passedOn}
}

func dpopOn(algs ...jwa.SignatureAlgorithm) mdSetup {
	return mdSetup{
		popts: []oidcprovider.Option{oidcprovider.WithDPoP()},
		chain: []httpsec.Option{httpsec.EnableDPoP(httpsec.DPoP{PublicURL: opIssuer, Algorithms: algs})},
	}
}

func TestOIDCMetadata(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		setup  mdSetup
		path   string
		assert func(t *testing.T, doc map[string]any)
	}

	list := func(values ...string) []any {
		out := make([]any, len(values))
		for i, v := range values {
			out[i] = v
		}

		return out
	}

	offering := oidcprovider.Client{
		ID: "mobile", Type: oidcprovider.Public, ApplicationType: oidcprovider.Native,
		RedirectURIs: []string{"https://rp.example.com/cb"},
		Scopes:       []string{"openid", "offline_access"},
		GrantTypes:   []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
	}

	cases := []testCase{
		{
			name: "the required and supported members of a provider with defaults",
			assert: func(t *testing.T, doc map[string]any) {
				assert.Equal(t, opIssuer, doc["issuer"])
				assert.Equal(t, opIssuer+"/oauth2/authorize", doc["authorization_endpoint"])
				assert.Equal(t, opIssuer+"/oauth2/token", doc["token_endpoint"])
				assert.Equal(t, opIssuer+"/oauth2/userinfo", doc["userinfo_endpoint"])
				assert.Equal(t, opIssuer+"/.well-known/jwks.json", doc["jwks_uri"])
				assert.Equal(t, list("code"), doc["response_types_supported"])
				assert.Equal(t, list("query"), doc["response_modes_supported"])
				assert.Equal(t, list("authorization_code", "refresh_token"), doc["grant_types_supported"])
				assert.Equal(t, list("public"), doc["subject_types_supported"])
				assert.Equal(t, list("S256"), doc["code_challenge_methods_supported"])
				assert.Equal(t, list("RS256"), doc["id_token_signing_alg_values_supported"])
				assert.Equal(t, list("openid", "profile", "email"), doc["scopes_supported"])
				assert.Contains(t, doc["claims_supported"], "sub")
			},
		},
		{
			name: "endpoints follow the prefix and the paths in use",
			setup: mdSetup{oidc: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCProviderPrefix("/op"),
				httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/tokens"),
			}},
			assert: func(t *testing.T, doc map[string]any) {
				assert.Equal(t, opIssuer+"/op/authorize", doc["authorization_endpoint"])
				assert.Equal(t, opIssuer+"/tokens", doc["token_endpoint"])
				assert.Equal(t, opIssuer+"/op/userinfo", doc["userinfo_endpoint"])
				assert.Equal(t, opIssuer+"/op/revoke", doc["revocation_endpoint"])
				assert.Equal(t, opIssuer+"/op/introspect", doc["introspection_endpoint"])
				assert.Equal(t, opIssuer+"/op/logout", doc["end_session_endpoint"])
			},
		},
		{
			name:  "a prefix given with one trailing slash is the trimmed prefix",
			setup: mdSetup{oidc: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/op/")}},
			assert: func(t *testing.T, doc map[string]any) {
				assert.Equal(t, opIssuer+"/op/authorize", doc["authorization_endpoint"])
				assert.Equal(t, opIssuer+"/op/token", doc["token_endpoint"])
			},
		},
		{
			name: "the revocation and introspection methods, the latter without none, and the assertion algorithms without none",
			assert: func(t *testing.T, doc map[string]any) {
				all := list("client_secret_basic", "client_secret_post", "private_key_jwt", "none")
				assert.Equal(t, all, doc["token_endpoint_auth_methods_supported"])
				assert.Equal(t, all, doc["revocation_endpoint_auth_methods_supported"])
				assert.Equal(t, list("client_secret_basic", "client_secret_post", "private_key_jwt"),
					doc["introspection_endpoint_auth_methods_supported"])

				for _, member := range []string{
					"token_endpoint_auth_signing_alg_values_supported",
					"revocation_endpoint_auth_signing_alg_values_supported",
					"introspection_endpoint_auth_signing_alg_values_supported",
				} {
					assert.Contains(t, doc[member], "RS256", member)
					assert.Contains(t, doc[member], "ES256", member)
					assert.NotContains(t, doc[member], "none", member)
				}
			},
		},
		{
			name: "what the provider refuses is false, and what it does is true",
			assert: func(t *testing.T, doc map[string]any) {
				for _, member := range []string{"request_parameter_supported", "request_uri_parameter_supported", "claims_parameter_supported"} {
					assert.Equal(t, false, doc[member], member)
				}

				for _, member := range []string{
					"authorization_response_iss_parameter_supported", "backchannel_logout_supported", "backchannel_logout_session_supported",
				} {
					assert.Equal(t, true, doc[member], member)
				}
			},
		},
		{
			name:  "DPoP on names its proof algorithm, and no certificate member appears",
			setup: dpopOn(),
			assert: func(t *testing.T, doc map[string]any) {
				assert.Equal(t, list("ES256"), doc["dpop_signing_alg_values_supported"])
				assert.NotContains(t, doc, "tls_client_certificate_bound_access_tokens")
			},
		},
		{
			name:  "DPoP on with several algorithms names each, sorted",
			setup: dpopOn(jwa.PS256(), jwa.ES256()),
			assert: func(t *testing.T, doc map[string]any) {
				assert.Equal(t, list("ES256", "PS256"), doc["dpop_signing_alg_values_supported"])
			},
		},
		{
			name:  "certificate binding on says so, and no DPoP member appears",
			setup: mdSetup{chain: []httpsec.Option{httpsec.EnableCertificateBinding()}},
			assert: func(t *testing.T, doc map[string]any) {
				assert.Equal(t, true, doc["tls_client_certificate_bound_access_tokens"])
				assert.NotContains(t, doc, "dpop_signing_alg_values_supported")
			},
		},
		{
			name: "with neither enabled, neither member appears",
			assert: func(t *testing.T, doc map[string]any) {
				assert.NotContains(t, doc, "dpop_signing_alg_values_supported")
				assert.NotContains(t, doc, "tls_client_certificate_bound_access_tokens")
			},
		},
		{
			name: "a consumer's member is published beside the provider's",
			setup: mdSetup{oidc: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCMetadataMember("service_documentation", "https://docs.example.com"),
				httpsec.WithOIDCMetadataMember("ui_locales_supported", []string{"en", "id"}),
			}},
			assert: func(t *testing.T, doc map[string]any) {
				assert.Equal(t, "https://docs.example.com", doc["service_documentation"])
				assert.Equal(t, list("en", "id"), doc["ui_locales_supported"])
				assert.Equal(t, opIssuer, doc["issuer"])
			},
		},
		{
			name:  "offline_access is listed when a client may ask for it",
			setup: mdSetup{clients: []oidcprovider.Client{offering}},
			assert: func(t *testing.T, doc map[string]any) {
				assert.Equal(t, list("openid", "profile", "email", "offline_access"), doc["scopes_supported"])
			},
		},
		{
			name:  "an issuer with a path, behind a router that strips it: published URLs carry the path",
			setup: mdSetup{issuer: mdPathIssuer},
			assert: func(t *testing.T, doc map[string]any) {
				assert.Equal(t, mdPathIssuer, doc["issuer"])
				assert.Equal(t, mdPathIssuer+"/oauth2/authorize", doc["authorization_endpoint"])
				assert.Equal(t, mdPathIssuer+"/oauth2/token", doc["token_endpoint"])
				assert.Equal(t, mdPathIssuer+"/oauth2/userinfo", doc["userinfo_endpoint"])
				assert.Equal(t, mdPathIssuer+"/oauth2/revoke", doc["revocation_endpoint"])
				assert.Equal(t, mdPathIssuer+"/oauth2/introspect", doc["introspection_endpoint"])
				assert.Equal(t, mdPathIssuer+"/oauth2/logout", doc["end_session_endpoint"])
				assert.Equal(t, mdPathIssuer+"/.well-known/jwks.json", doc["jwks_uri"])
			},
		},
		{
			name: "an issuer with a path, on a chain that is not stripped: the same URLs",
			setup: mdSetup{
				issuer: mdPathIssuer,
				jwks:   []httpsec.JWKSOption{httpsec.WithJWKSEndpointPath("/auth/.well-known/jwks.json")},
				oidc:   []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/auth/oauth2")},
			},
			path: "/auth" + mdOIDCPath,
			assert: func(t *testing.T, doc map[string]any) {
				assert.Equal(t, mdPathIssuer, doc["issuer"])
				assert.Equal(t, mdPathIssuer+"/oauth2/authorize", doc["authorization_endpoint"])
				assert.Equal(t, mdPathIssuer+"/oauth2/token", doc["token_endpoint"])
				assert.Equal(t, mdPathIssuer+"/oauth2/logout", doc["end_session_endpoint"])
				assert.Equal(t, mdPathIssuer+"/.well-known/jwks.json", doc["jwks_uri"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := tc.setup.build(t, f)
			require.NoError(t, err)

			path := tc.path
			if path == "" {
				path = mdOIDCPath
			}

			a := mdGet(t, chain, http.MethodGet, path)
			tc.assert(t, a.doc(t))
		})
	}
}

// TestOIDCMetadata_TwoDocuments pins that the OAuth document is the OpenID one's content.
func TestOIDCMetadata_TwoDocuments(t *testing.T) {
	t.Parallel()

	chain, err := mdSetup{}.build(t, newOPFixture(t))
	require.NoError(t, err)

	oidc := mdGet(t, chain, http.MethodGet, mdOIDCPath)
	oauth := mdGet(t, chain, http.MethodGet, mdOAuthPath)

	require.Equal(t, http.StatusOK, oidc.status)
	require.Equal(t, http.StatusOK, oauth.status)
	assert.JSONEq(t, string(oidc.body), string(oauth.body))
}

// TestOIDCMetadata_Paths pins where each form is served for an issuer with and without a
// path: OpenID Connect Discovery 1.0 section 4 appends the well-known suffix to the issuer,
// RFC 8414 section 3 inserts it between the host and the path.
func TestOIDCMetadata_Paths(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	stripped := mdSetup{issuer: mdPathIssuer}
	unstripped := mdSetup{
		issuer: mdPathIssuer,
		jwks:   []httpsec.JWKSOption{httpsec.WithJWKSEndpointPath("/auth/.well-known/jwks.json")},
		oidc:   []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/auth/oauth2")},
	}

	slashed := mdSetup{issuer: mdPathIssuer + "/"}

	type testCase struct {
		name   string
		setup  mdSetup
		path   string
		served bool
	}

	cases := []testCase{
		{name: "no path: the OpenID document at the root", path: mdOIDCPath, served: true},
		{name: "no path: the OAuth document at the root", path: mdOAuthPath, served: true},
		{name: "no path: nothing under the prefix", path: "/oauth2" + mdOIDCPath},

		{name: "stripped: the OpenID document as the router leaves it", setup: stripped, path: mdOIDCPath, served: true},
		{name: "stripped: the OAuth document inserted before the path", setup: stripped, path: mdOAuthPath + "/auth", served: true},
		{name: "stripped: the OAuth document at the root belongs to no issuer here", setup: stripped, path: mdOAuthPath},
		{name: "stripped: the appended form is not the stripped chain's", setup: stripped, path: "/auth" + mdOIDCPath},

		{name: "trailing slash: the OpenID document with the slash trimmed", setup: slashed, path: mdOIDCPath, served: true},
		{name: "trailing slash: the OAuth document inserted without the slash", setup: slashed, path: mdOAuthPath + "/auth", served: true},
		{name: "trailing slash: the slash is not part of the served path", setup: slashed, path: mdOAuthPath + "/auth/"},

		{name: "unstripped: the OpenID document appended to the issuer", setup: unstripped, path: "/auth" + mdOIDCPath, served: true},
		{name: "unstripped: the OAuth document inserted before the path", setup: unstripped, path: mdOAuthPath + "/auth", served: true},
		{name: "unstripped: the root OpenID path belongs to no issuer here", setup: unstripped, path: mdOIDCPath},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := tc.setup.build(t, f)
			require.NoError(t, err)

			a := mdGet(t, chain, http.MethodGet, tc.path)
			assert.Equal(t, !tc.served, a.passedOn, "whether the request reached the application")

			if tc.served {
				want := opIssuer
				if tc.setup.issuer != "" {
					want = tc.setup.issuer
				}

				assert.Equal(t, want, a.doc(t)["issuer"])
			}
		})
	}
}

// TestOIDCMetadata_WellKnownPaths pins that the CORS layer treats the documents as the
// provider's client endpoints, on every path they are served.
func TestOIDCMetadata_WellKnownPaths(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name  string
		setup mdSetup
		path  string
	}

	cors := httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}, AllowCredentials: true})

	cases := []testCase{
		{name: "the OpenID document", path: mdOIDCPath},
		{name: "the OAuth document", path: mdOAuthPath},
		{name: "the OAuth document of an issuer with a path", setup: mdSetup{issuer: mdPathIssuer}, path: mdOAuthPath + "/auth"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.setup.chain = append(tc.setup.chain, cors)

			chain, err := tc.setup.build(t, f)
			require.NoError(t, err)

			h := chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, nil)
			req.Header.Set("Origin", allowedOrigin)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, allowedOrigin, rec.Header().Get("Access-Control-Allow-Origin"))
			assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"), "the client endpoints allow no credentials")
		})
	}
}

func TestOIDCMetadata_Construction(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		setup  mdSetup
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, httpsec.ErrConfig)
	}

	member := func(name string, value any) mdSetup {
		return mdSetup{oidc: []httpsec.OIDCProviderOption{httpsec.WithOIDCMetadataMember(name, value)}}
	}

	cases := []testCase{
		{name: "a member the provider sets, the token endpoint", setup: member("token_endpoint", "https://evil.example.com/token"), assert: refused},
		{name: "the issuer", setup: member("issuer", "https://evil.example.com"), assert: refused},
		{
			name:   "a member the provider sets only when a feature is on, while it is off",
			setup:  member("dpop_signing_alg_values_supported", []string{"ES256"}),
			assert: refused,
		},
		{
			name:   "certificate-bound tokens, which the provider sets only when bound, while they are off",
			setup:  member("tls_client_certificate_bound_access_tokens", true),
			assert: refused,
		},
		{name: "a member with no name", setup: member("", "x"), assert: refused},
		{name: "a member no JSON can hold", setup: member("service_documentation", make(chan int)), assert: refused},
		{
			name: "the same member twice",
			setup: mdSetup{oidc: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCMetadataMember("service_documentation", "a"),
				httpsec.WithOIDCMetadataMember("service_documentation", "b"),
			}},
			assert: refused,
		},
		{
			name:   "a negative cache lifetime",
			setup:  mdSetup{oidc: []httpsec.OIDCProviderOption{httpsec.WithOIDCMetadataCacheLifetime(-time.Minute)}},
			assert: refused,
		},
		{
			name:   "a cache lifetime under a second, which would read as none",
			setup:  mdSetup{oidc: []httpsec.OIDCProviderOption{httpsec.WithOIDCMetadataCacheLifetime(time.Millisecond)}},
			assert: refused,
		},
		{
			name:  "a consumer's own member that is not the provider's",
			setup: member("service_documentation", "https://docs.example.com"),
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := tc.setup.build(t, f)
			tc.assert(t, err)
		})
	}
}

func TestOIDCMetadata_Serving(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		setup  mdSetup
		method string
		path   string
		assert func(t *testing.T, a mdAnswer)
	}

	cacheOf := func(d time.Duration) mdSetup {
		return mdSetup{oidc: []httpsec.OIDCProviderOption{httpsec.WithOIDCMetadataCacheLifetime(d)}}
	}

	hasCache := func(want string) func(*testing.T, mdAnswer) {
		return func(t *testing.T, a mdAnswer) {
			t.Helper()
			require.Equal(t, http.StatusOK, a.status)
			assert.Equal(t, want, a.header.Get("Cache-Control"))
			assert.Equal(t, "application/json", a.header.Get("Content-Type"))
		}
	}

	cases := []testCase{
		{name: "the OpenID document is public and cached an hour by default", path: mdOIDCPath, assert: hasCache("public, max-age=3600")},
		{name: "the OAuth document is cached the same", path: mdOAuthPath, assert: hasCache("public, max-age=3600")},
		{name: "the consumer shortens the cache to 5 minutes", setup: cacheOf(5 * time.Minute), path: mdOIDCPath, assert: hasCache("public, max-age=300")},
		{name: "the shorter cache holds for the OAuth document", setup: cacheOf(5 * time.Minute), path: mdOAuthPath, assert: hasCache("public, max-age=300")},
		{name: "a lifetime of zero asks caches to revalidate", setup: cacheOf(0), path: mdOIDCPath, assert: hasCache("public, no-cache")},
		{
			name:   "HEAD is answered with the headers",
			method: http.MethodHead, path: mdOIDCPath,
			assert: hasCache("public, max-age=3600"),
		},
		{
			name:   "HEAD has an empty body",
			method: http.MethodHead, path: mdOIDCPath,
			assert: func(t *testing.T, a mdAnswer) {
				t.Helper()
				require.Equal(t, http.StatusOK, a.status)
				assert.Empty(t, a.body)
			},
		},
		{
			name:   "another method is refused here, not passed on",
			method: http.MethodPost, path: mdOIDCPath,
			assert: func(t *testing.T, a mdAnswer) {
				t.Helper()
				assert.Equal(t, http.StatusMethodNotAllowed, a.status)
				assert.Equal(t, "GET, HEAD", a.header.Get("Allow"))
				assert.False(t, a.passedOn)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := tc.setup.build(t, f)
			require.NoError(t, err)

			method := tc.method
			if method == "" {
				method = http.MethodGet
			}

			tc.assert(t, mdGet(t, chain, method, tc.path))
		})
	}
}

// TestOIDCMetadata_Serving_JWKSKeepsItsOwnBehaviour proves that the key set endpoint, which
// jwks_uri names, is not touched by the documents: it carries no cache lifetime of theirs,
// and it keeps publishing the previous key after a rotation, so a token signed before the
// rotation still verifies.
func TestOIDCMetadata_Serving_JWKSKeepsItsOwnBehaviour(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClock()
	keys := must.Must(signingkey.New(t.Context(),
		signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
		signingkey.WithClock(clk),
		signingkey.WithRotateInterval(6*time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(time.Hour),
		signingkey.WithKeyLifetime(24*time.Hour),
	))

	f := newOPFixture(t)
	p := f.providerOver(t, opIssuer, keys, nil)

	chain, err := httpsec.New(
		f.bearer(t, reporting(t, p)),
		httpsec.EnableJWKSEndpoint(keys),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableOIDCProvider(p),
	)
	require.NoError(t, err)

	// kids returns an error rather than failing the test, because Eventually runs it off
	// the test goroutine.
	kids := func() ([]string, mdAnswer, error) {
		a := mdGet(t, chain, http.MethodGet, "/.well-known/jwks.json")
		if a.status != http.StatusOK {
			return nil, a, fmt.Errorf("the key set answered %d: %s", a.status, a.body)
		}

		var set struct {
			Keys []struct {
				Kid string `json:"kid"`
			} `json:"keys"`
		}
		if err := json.Unmarshal(a.body, &set); err != nil {
			return nil, a, err
		}

		out := make([]string, 0, len(set.Keys))
		for _, k := range set.Keys {
			out = append(out, k.Kid)
		}

		return out, a, nil
	}

	before, answer, err := kids()
	require.NoError(t, err)
	require.Len(t, before, 1)
	assert.Empty(t, answer.header.Get("Cache-Control"), "the key set does not take the documents' cache lifetime")

	require.NoError(t, keys.Start(t.Context()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()

		require.NoError(t, keys.Shutdown(ctx))
	})

	require.NoError(t, clk.BlockUntilContext(t.Context(), 3))
	clk.Advance(6 * time.Hour)

	require.Eventually(t, func() bool {
		after, _, err := kids()

		return err == nil && len(after) == 2
	}, 5*time.Second, 10*time.Millisecond, "the key rotated")

	after, answer, err := kids()
	require.NoError(t, err)
	assert.Contains(t, after, before[0], "the previous key is still published")
	assert.Empty(t, answer.header.Get("Cache-Control"))
}

// TestOIDCMetadata_ScopesFollowTheRegistry pins that scopes_supported is read at the
// request, so a client added to the in-memory registry after the chain was built is
// reflected in both documents, while the other members stay as built.
func TestOIDCMetadata_ScopesFollowTheRegistry(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	reg, err := oidcprovider.NewMemoryRegistry([]oidcprovider.Client{{
		ID: "billing-web", Type: oidcprovider.Confidential,
		Secret:       []byte("0123456789abcdef0123456789abcdef"),
		RedirectURIs: []string{"https://rp.example.com/cb"},
	}})
	require.NoError(t, err)

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: opIssuer, Registry: reg, Keys: f.keys, Users: NewMockUserLoader(gomock.NewController(t)),
		LoginURL: opIssuer + "/login", ConsentURL: opIssuer + "/consent",
		LogoutURL: opIssuer + "/logout-page", LoggedOutURL: opIssuer + "/bye",
	})
	require.NoError(t, err)

	chain, err := httpsec.New(f.bearer(t, reporting(t, p)), httpsec.EnableJWKSEndpoint(f.keys),
		httpsec.EnableSecurityHeaders(), httpsec.EnableCSRFProtection(), httpsec.EnableOIDCProvider(p))
	require.NoError(t, err)

	for _, path := range []string{mdOIDCPath, mdOAuthPath} {
		assert.NotContains(t, mdGet(t, chain, http.MethodGet, path).doc(t)["scopes_supported"], "offline_access", path)
	}

	require.NoError(t, reg.Put(t.Context(), oidcprovider.Client{
		ID: "mobile", Type: oidcprovider.Public, ApplicationType: oidcprovider.Native,
		RedirectURIs: []string{"https://rp.example.com/cb"},
		Scopes:       []string{"openid", "offline_access"},
		GrantTypes:   []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
	}))

	for _, path := range []string{mdOIDCPath, mdOAuthPath} {
		doc := mdGet(t, chain, http.MethodGet, path).doc(t)
		assert.Contains(t, doc["scopes_supported"], "offline_access", path)
		assert.Equal(t, opIssuer+"/oauth2/token", doc["token_endpoint"], path)
	}
}
