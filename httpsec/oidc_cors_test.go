package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// metadataPath is where the issuer's discovery document is served once task 10.1 lands.
const metadataPath = "/.well-known/openid-configuration"

// TestCORS_OIDCProvider pins how the CORS layer treats the provider's endpoints: the five that
// browser clients call follow the consumer's allowlist, on terms the protocol sets, and the four
// that carry a user's browser never carry a CORS header, whatever the allowlist says.
//
// Every row's policy allows credentials, so a provider endpoint that sent them would show.
func TestCORS_OIDCProvider(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		cors   []httpsec.CORSOption
		policy func(p *httpsec.CORSPolicy)
		oidc   []httpsec.OIDCProviderOption
		req    func(t *testing.T) *http.Request

		// served names a row that holds only once the endpoint exists: until then the request
		// passes through to the consumer's handler, and the row is skipped.
		served string
		assert func(t *testing.T, a tokenAnswer)
	}

	preflight := func(path string, asks ...string) func(t *testing.T) *http.Request {
		return func(t *testing.T) *http.Request {
			t.Helper()

			r := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, opIssuer+path, nil)
			r.Header.Set("Origin", allowedOrigin)
			r.Header.Set("Access-Control-Request-Method", http.MethodPost)
			if len(asks) > 0 {
				r.Header.Set("Access-Control-Request-Headers", strings.Join(asks, ", "))
			}

			return r
		}
	}

	call := func(method, path string) func(t *testing.T) *http.Request {
		return func(t *testing.T) *http.Request {
			t.Helper()

			var body *strings.Reader
			if method == http.MethodPost {
				body = strings.NewReader(url.Values{"grant_type": {"refresh_token"}}.Encode())
			} else {
				body = strings.NewReader("")
			}

			r := httptest.NewRequestWithContext(t.Context(), method, opIssuer+path, body)
			r.Header.Set("Origin", allowedOrigin)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.RemoteAddr = tokenAddr

			return r
		}
	}

	noAccessControl := func(t *testing.T, a tokenAnswer) {
		t.Helper()

		for name := range a.header {
			assert.False(t, strings.HasPrefix(http.CanonicalHeaderKey(name), "Access-Control-"), "%s is set", name)
		}
	}

	allowed := func(t *testing.T, a tokenAnswer) {
		t.Helper()

		assert.Equal(t, http.StatusNoContent, a.status)
		assert.Equal(t, allowedOrigin, a.header.Get("Access-Control-Allow-Origin"))
		assert.Empty(t, a.header.Get("Access-Control-Allow-Credentials"), "a provider endpoint allows no credentials")
	}

	// Endpoints that take a browser client's call.
	callable := []struct{ name, path, served string }{
		{name: "token", path: "/oauth2/token"},
		{name: "userinfo", path: "/oauth2/userinfo"},
		{name: "revocation", path: "/oauth2/revoke"},
		{name: "introspection", path: "/oauth2/introspect"},
		{name: "metadata", path: metadataPath, served: "the metadata documents (task 10.1)"},
	}

	// Endpoints that carry a user's browser, and so never a CORS header.
	browser := []struct{ name, path string }{
		{name: "authorization", path: "/oauth2/authorize"},
		{name: "resume", path: "/oauth2/authorize/resume"},
		{name: "end-session", path: "/oauth2/logout"},
		{name: "logout confirmation", path: "/oauth2/logout/confirm"},
	}

	var cases []testCase

	for _, ep := range callable {
		cases = append(cases,
			testCase{
				name:   ep.name + ": a preflight from an allowed origin is allowed, with no credentials",
				req:    preflight(ep.path),
				served: ep.served,
				assert: allowed,
			},
			testCase{
				name:   ep.name + ": a preflight asking for DPoP and Authorization is allowed, though the chain has no DPoP",
				req:    preflight(ep.path, "dpop", "Authorization"),
				served: ep.served,
				assert: func(t *testing.T, a tokenAnswer) {
					t.Helper()

					allowed(t, a)
					assert.Equal(t, "DPoP, Authorization", a.header.Get("Access-Control-Allow-Headers"))
				},
			},
			testCase{
				name:   ep.name + ": a call from an allowed origin exposes DPoP-Nonce and WWW-Authenticate, with no credentials",
				req:    call(http.MethodGet, ep.path),
				served: ep.served,
				assert: func(t *testing.T, a tokenAnswer) {
					t.Helper()

					assert.Equal(t, allowedOrigin, a.header.Get("Access-Control-Allow-Origin"))
					assert.Empty(t, a.header.Get("Access-Control-Allow-Credentials"))
					assert.Equal(t, "DPoP-Nonce, WWW-Authenticate", a.header.Get("Access-Control-Expose-Headers"))
				},
			},
			testCase{
				name: ep.name + ": an origin outside the allowlist gets no CORS header",
				req: func(t *testing.T) *http.Request {
					r := call(http.MethodGet, ep.path)(t)
					r.Header.Set("Origin", "https://evil.example.net")
					return r
				},
				served: ep.served,
				assert: noAccessControl,
			},
		)
	}

	for _, ep := range browser {
		cases = append(cases,
			testCase{
				name:   ep.name + ": a call from an allowed origin carries no Access-Control header",
				req:    call(http.MethodGet, ep.path),
				assert: noAccessControl,
			},
			testCase{
				name: ep.name + ": a preflight from an allowed origin is not answered as one",
				req:  preflight(ep.path, "Authorization"),
				assert: func(t *testing.T, a tokenAnswer) {
					t.Helper()
					noAccessControl(t, a)
					assert.NotEqual(t, http.StatusNoContent, a.status)
				},
			},
		)
	}

	cases = append(cases,
		testCase{
			name: "the consumer's own routes keep the whole policy, credentials included",
			req:  func(t *testing.T) *http.Request { r := preflight("/api/orders", "Authorization")(t); return r },
			policy: func(p *httpsec.CORSPolicy) {
				p.AllowedHeaders = []string{"Authorization"}
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()

				assert.Equal(t, allowedOrigin, a.header.Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "true", a.header.Get("Access-Control-Allow-Credentials"))
			},
		},
		testCase{
			name: "the consumer's own routes do not gain the provider's headers",
			req:  preflight("/api/orders", "DPoP"),
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()

				assert.Empty(t, a.header.Get("Access-Control-Allow-Origin"), "DPoP is not on the consumer's list")
			},
		},
		testCase{
			name: "a path the consumer moved an endpoint to is the one excluded, and the old path is not",
			oidc: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(httpsec.OIDCAuthorize, "/sso/start")},
			req:  call(http.MethodGet, "/sso/start"),
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				noAccessControl(t, a)
			},
		},
		testCase{
			name: "the old authorization path, now the consumer's own, follows the policy",
			oidc: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(httpsec.OIDCAuthorize, "/sso/start")},
			req:  call(http.MethodGet, "/oauth2/authorize"),
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()

				assert.Equal(t, allowedOrigin, a.header.Get("Access-Control-Allow-Origin"))
			},
		},
		testCase{
			name: "a moved prefix moves the exclusion and the provider rules with it",
			oidc: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/idp")},
			req:  preflight("/idp/token", "DPoP"),
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				allowed(t, a)
			},
		},
		testCase{
			name: "WithoutAutomaticCORSHeaders leaves the consumer's lists alone: DPoP is refused at the token endpoint",
			cors: []httpsec.CORSOption{httpsec.WithoutAutomaticCORSHeaders()},
			req:  preflight("/oauth2/token", "DPoP"),
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()

				assert.Empty(t, a.header.Get("Access-Control-Allow-Origin"))
			},
		},
		testCase{
			name: "the consumer's own exposed header is kept beside the provider's",
			policy: func(p *httpsec.CORSPolicy) {
				p.ExposedHeaders = []string{"X-Request-Id", "www-authenticate"}
			},
			req: call(http.MethodGet, "/oauth2/userinfo"),
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()

				assert.Equal(t, "X-Request-Id, www-authenticate, DPoP-Nonce", a.header.Get("Access-Control-Expose-Headers"))
			},
		},
		testCase{
			name: "authorization still refuses the allowed origin's preflight when CORS allows every origin",
			policy: func(p *httpsec.CORSPolicy) {
				p.AllowedOrigins = []string{"*"}
				p.AllowCredentials = false
			},
			req:    preflight("/oauth2/authorize"),
			assert: noAccessControl,
		},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			policy := httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}, AllowCredentials: true}
			if tc.policy != nil {
				tc.policy(&policy)
			}

			e := newTokenEndpoint(t, tokenSetup{
				cert:     true,
				chain:    []httpsec.Option{httpsec.EnableCORS(policy, tc.cors...)},
				endpoint: func(*testing.T) []httpsec.OIDCProviderOption { return tc.oidc },
			})

			req := tc.req(t)
			if tc.served != "" {
				probe := httptest.NewRequestWithContext(t.Context(), http.MethodGet, req.URL.String(), nil)
				if e.serve(t, probe).passedOn {
					t.Skipf("holds once %s is served: a plain GET still reaches the consumer's handler", tc.served)
				}
			}

			a := e.serve(t, req)
			tc.assert(t, a)
			assert.Contains(t, strings.Join(a.header.Values("Vary"), ", "), "Origin", "every answer varies by Origin")
		})
	}
}

// TestCORS_OIDCProvider_TokenEndpointAnswers pins that the headers the layer sets before the
// token endpoint survive its own answer, on a real exchange.
func TestCORS_OIDCProvider_TokenEndpointAnswers(t *testing.T) {
	t.Parallel()

	e := newTokenEndpoint(t, tokenSetup{
		cert: true,
		chain: []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{
			AllowedOrigins: []string{allowedOrigin}, AllowCredentials: true,
		})},
	})

	a := e.send(t, exchangeOf(e.issue(t, tokenWeb, nil)), asClient(tokenWeb), func(r *http.Request) {
		r.Header.Set("Origin", allowedOrigin)
	})

	require.Equal(t, http.StatusOK, a.status, a.body)
	assert.Equal(t, allowedOrigin, a.header.Get("Access-Control-Allow-Origin"))
	assert.Empty(t, a.header.Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "DPoP-Nonce, WWW-Authenticate", a.header.Get("Access-Control-Expose-Headers"))
	assert.Contains(t, strings.Join(a.header.Values("Vary"), ", "), "Origin")
	assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
}
