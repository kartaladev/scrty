package httpsec_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

const rsIssuer = "https://sso.example.com"

// rsJWT builds a JWT-shaped token for the routing read: a header naming typ (none when empty), a
// payload naming iss, and the audience in place of a signature. Nothing verifies the signature:
// the stub sources read the audience from the last segment, so a test can tell which resource the
// token was minted for.
func rsJWT(typ, iss, aud string) string {
	header := `{"alg":"ES256"}`
	if typ != "" {
		header = `{"alg":"ES256","typ":"` + typ + `"}`
	}

	enc := base64.RawURLEncoding

	return enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString([]byte(`{"iss":"`+iss+`"}`)) + "." + aud
}

// forAudience is a stub verification that accepts a token minted for aud, and refuses any other
// as the resource server refuses an invalid token.
func forAudience(aud string) func(context.Context, string) (*identity.Principal, map[string]string, error) {
	return func(_ context.Context, raw string) (*identity.Principal, map[string]string, error) {
		if !strings.HasSuffix(raw, "."+aud) {
			return nil, nil, httpsec.ErrInvalidAccessToken
		}

		return &identity.Principal{ID: "u-1"}, nil, nil
	}
}

// rsRoute is one request through a routing chain, and what it observed.
type rsRoute struct {
	served

	// laterRan says the credential mode after the resource server saw the request.
	laterRan bool
}

// TestResourceServer_Routing pins how a token is routed: by the path's resource server first, then
// to the one source it belongs to there; what is refused and never handed on; and what passes on to
// the chain's later modes.
func TestResourceServer_Routing(t *testing.T) {
	t.Parallel()

	type sources struct{ orders, billing, intro *httpsec.StubSource }

	type testCase struct {
		name   string
		path   string
		header string
		assert func(t *testing.T, out rsRoute, s sources)
	}

	accepted := func(t *testing.T, out rsRoute) {
		t.Helper()
		require.NoError(t, out.err)
		assert.True(t, out.handlerRan)
		assert.True(t, out.laterRan, "an accepted token continues down the chain")
	}

	refused := func(t *testing.T, out rsRoute) {
		t.Helper()
		require.ErrorIs(t, out.err, httpsec.ErrInvalidAccessToken)
		assert.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
		assert.False(t, out.laterRan, "a refused access token is never handed on")
	}

	passedOn := func(t *testing.T, out rsRoute, s sources) {
		t.Helper()
		require.NoError(t, out.err)
		assert.True(t, out.laterRan, "an unrecognised token passes to the next mode")
		assert.Zero(t, s.orders.Offered()+s.billing.Offered()+s.intro.Offered(), "no source was offered it")
	}

	ordersToken := rsJWT("at+jwt", rsIssuer, "urn:orders")

	cases := []testCase{
		{
			name:   "a token for the covering resource server is accepted by its source",
			path:   "/orders/1",
			header: "Bearer " + ordersToken,
			assert: func(t *testing.T, out rsRoute, s sources) {
				accepted(t, out)
				assert.Equal(t, 1, s.orders.Offered())
				assert.Zero(t, s.billing.Offered(), "the other resource server never sees it")
			},
		},
		{
			name:   "the same token at another resource server trusting the same issuer is refused there",
			path:   "/billing/1",
			header: "Bearer " + ordersToken,
			assert: func(t *testing.T, out rsRoute, s sources) {
				refused(t, out)
				assert.Equal(t, 1, s.billing.Offered())
				assert.Zero(t, s.orders.Offered())
			},
		},
		{
			name:   "the type is compared without regard to case",
			path:   "/orders/1",
			header: "Bearer " + rsJWT("application/AT+JWT", rsIssuer, "urn:orders"),
			assert: func(t *testing.T, out rsRoute, s sources) {
				accepted(t, out)
				assert.Equal(t, 1, s.orders.Offered())
			},
		},
		{
			name:   "an at+jwt from an issuer no source names is refused on a covered path",
			path:   "/orders/1",
			header: "Bearer " + rsJWT("AT+JWT", "https://other.example.com", "urn:orders"),
			assert: func(t *testing.T, out rsRoute, s sources) {
				refused(t, out)
				assert.Zero(t, s.orders.Offered())
			},
		},
		{
			name:   "a provider-format token on a resource server with no provider source is refused",
			path:   "/orders/1",
			header: "Bearer at.0123456789",
			assert: func(t *testing.T, out rsRoute, _ sources) { refused(t, out) },
		},
		{
			name:   "a refresh token is refused, never sent to an introspection source",
			path:   "/billing/1",
			header: "Bearer rt.0123456789",
			assert: func(t *testing.T, out rsRoute, s sources) {
				refused(t, out)
				assert.Zero(t, s.intro.Offered())
			},
		},
		{
			name:   "an unrecognised opaque token passes on from a covered path",
			path:   "/orders/1",
			header: "Bearer an-api-key",
			assert: passedOn,
		},
		{
			name:   "an unrecognised JWT of another type passes on from a covered path",
			path:   "/orders/1",
			header: "Bearer " + rsJWT("JWT", "https://other.example.com", "urn:orders"),
			assert: passedOn,
		},
		{
			name:   "a session token from a source's issuer is never offered to a source",
			path:   "/orders/1",
			header: "Bearer " + rsJWT("scrty+jwt", rsIssuer, "urn:orders"),
			assert: passedOn,
		},
		{
			name:   "an opaque token with an introspection prefix goes to that source",
			path:   "/billing/1",
			header: "Bearer kc_abc",
			assert: func(t *testing.T, out rsRoute, s sources) {
				accepted(t, out)
				assert.Equal(t, 1, s.intro.Offered())
			},
		},
		{
			name:   "a prefix covers whole segments only",
			path:   "/orders-v2/1",
			header: "Bearer " + ordersToken,
			assert: func(t *testing.T, out rsRoute, s sources) {
				refused(t, out)
				assert.Zero(t, s.orders.Offered(), "no resource server covers the path")
			},
		},
		{
			name:   "repeated slashes do not leave the covering resource server",
			path:   "//orders//1",
			header: "Bearer " + ordersToken,
			assert: func(t *testing.T, out rsRoute, s sources) {
				accepted(t, out)
				assert.Equal(t, 1, s.orders.Offered())
			},
		},
		{
			name:   "a provider token off every prefix is refused",
			path:   "/admin/report",
			header: "Bearer at.0123456789",
			assert: func(t *testing.T, out rsRoute, _ sources) { refused(t, out) },
		},
		{
			name:   "an at+jwt off every prefix is refused",
			path:   "/admin/report",
			header: "Bearer " + rsJWT("at+jwt", "https://other.example.com", "urn:x"),
			assert: func(t *testing.T, out rsRoute, _ sources) { refused(t, out) },
		},
		{
			name:   "a JWT naming a source's issuer off every prefix is refused",
			path:   "/admin/report",
			header: "Bearer " + rsJWT("JWT", rsIssuer, "urn:x"),
			assert: func(t *testing.T, out rsRoute, _ sources) { refused(t, out) },
		},
		{
			name:   "an opaque token with an introspection prefix off every prefix is refused",
			path:   "/internal/x",
			header: "Bearer kc_abc",
			assert: func(t *testing.T, out rsRoute, s sources) {
				refused(t, out)
				assert.Zero(t, s.intro.Offered())
			},
		},
		{
			name:   "an unprefixed opaque token off every prefix passes on",
			path:   "/internal/x",
			header: "Bearer some-session-reference",
			assert: passedOn,
		},
		{
			name:   "a JWT from no source's issuer off every prefix passes on",
			path:   "/internal/x",
			header: "Bearer " + rsJWT("JWT", "https://other.example.com", "urn:x"),
			assert: passedOn,
		},
		{
			name:   "a session token off every prefix passes on",
			path:   "/internal/x",
			header: "Bearer " + rsJWT("scrty+jwt", rsIssuer, "urn:x"),
			assert: passedOn,
		},
		{
			name:   "a token over the size bound is refused before it is read",
			path:   "/orders/1",
			header: "Bearer " + rsJWT("at+jwt", rsIssuer, "urn:orders"+strings.Repeat("A", 64<<10)),
			assert: func(t *testing.T, out rsRoute, s sources) {
				refused(t, out)
				assert.Zero(t, s.orders.Offered())
			},
		},
		{
			name:   "a token at the size bound is read",
			path:   "/billing/1",
			header: "Bearer kc_" + strings.Repeat("A", 8<<10-len("kc_")),
			assert: func(t *testing.T, out rsRoute, s sources) {
				accepted(t, out)
				assert.Equal(t, 1, s.intro.Offered())
			},
		},
		{
			name:   "another scheme is no token",
			path:   "/orders/1",
			header: "Basic YWRhOnB3",
			assert: passedOn,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := sources{
				orders: &httpsec.StubSource{
					Name: "orders-sso", Issuer: rsIssuer, Unbound: true, Verify: forAudience("urn:orders"),
				},
				billing: &httpsec.StubSource{
					Name: "billing-sso", Issuer: rsIssuer, Unbound: true, Verify: forAudience("urn:billing"),
				},
				intro: &httpsec.StubSource{Name: "billing-introspection", Prefix: "kc_", Unbound: true},
			}

			out := routeThrough(t, tc.path, tc.header,
				httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/orders/"),
					httpsec.WithStubSource(s.orders)),
				httpsec.EnableResourceServer("urn:billing", httpsec.WithPathPrefix("/billing/"),
					httpsec.WithStubSource(s.billing), httpsec.WithStubSource(s.intro)),
			)

			tc.assert(t, out, s)
		})
	}
}

// routeThrough serves one request to path with the Authorization header header through a chain of
// opts, with a credential mode at OrderBearerToken that records whether the request reached it.
func routeThrough(t *testing.T, path, header string, opts ...httpsec.Option) rsRoute {
	t.Helper()

	var later bool

	c, err := httpsec.New(append(opts, httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
		func(ex *httpsec.Exchange, next httpsec.Next) error {
			later = true

			return next(ex)
		}), httpsec.OrderBearerToken))...)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.example.com/", nil)
	req.URL.Path = path
	if header != "" {
		req.Header.Set("Authorization", header)
	}

	out := serve(t, c, req)

	return rsRoute{served: out, laterRan: later}
}

// TestResourceServer_ProviderBound pins that a token as large as the chain's provider can issue is
// read, and that the provider's own endpoints still judge their tokens before any resource server.
func TestResourceServer_ProviderBound(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		path   string
		token  string
		assert func(t *testing.T, out rsRoute, src *httpsec.StubSource)
	}

	cases := []testCase{
		{
			name:  "a provider token at the provider's own bound is read",
			path:  "/api/orders",
			token: "at." + strings.Repeat("A", 2*(4096+10*2048)+8<<10-len("at.")),
			assert: func(t *testing.T, out rsRoute, src *httpsec.StubSource) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
				assert.Equal(t, 1, src.Offered())
			},
		},
		{
			name:  "a provider token over the provider's bound is refused",
			path:  "/api/orders",
			token: "at." + strings.Repeat("A", 2*(4096+10*2048)+8<<10),
			assert: func(t *testing.T, out rsRoute, src *httpsec.StubSource) {
				require.ErrorIs(t, out.err, httpsec.ErrInvalidAccessToken)
				assert.Zero(t, src.Offered())
			},
		},
		{
			name:  "UserInfo judges a provider token off every prefix, as before",
			path:  "/oauth2/userinfo",
			token: "at.not-a-token-the-provider-issued",
			assert: func(t *testing.T, out rsRoute, src *httpsec.StubSource) {
				require.NoError(t, out.err, "UserInfo answers the request itself")
				assert.Equal(t, http.StatusUnauthorized, out.rec.Code)
				assert.Contains(t, out.rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
				assert.False(t, out.laterRan)
				assert.Zero(t, src.Offered())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := f.provider(t)
			src := &httpsec.StubSource{Name: "provider", Provider: true, Unbound: true}

			opts := append(f.wired(t, p),
				httpsec.EnableOIDCProvider(p),
				httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"), httpsec.WithStubSource(src)))

			tc.assert(t, routeThrough(t, tc.path, "Bearer "+tc.token, opts...), src)
		})
	}
}

// TestResourceServer_SourceRefusalNotHandedOn pins that a token a source recognised and refused, for
// whatever reason it gives, is refused, and the later modes never judge it; and that a source's
// dependency failure is returned as it is, never as a refusal.
func TestResourceServer_SourceRefusalNotHandedOn(t *testing.T) {
	t.Parallel()

	errStoreDown := errors.New("grant store down")

	type testCase struct {
		name   string
		verify func(context.Context, string) (*identity.Principal, map[string]string, error)
		assert func(t *testing.T, out rsRoute)
	}

	cases := []testCase{
		{
			name: "an expired provider token is refused and the signed bearer never judges it",
			verify: func(context.Context, string) (*identity.Principal, map[string]string, error) {
				return nil, nil, httpsec.ErrInvalidAccessToken
			},
			assert: func(t *testing.T, out rsRoute) {
				require.ErrorIs(t, out.err, httpsec.ErrInvalidAccessToken)
				assert.False(t, out.laterRan)
			},
		},
		{
			name: "a dependency failure is not a refusal",
			verify: func(context.Context, string) (*identity.Principal, map[string]string, error) {
				return nil, nil, errStoreDown
			},
			assert: func(t *testing.T, out rsRoute) {
				require.ErrorIs(t, out.err, errStoreDown)
				assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				assert.False(t, out.laterRan)
			},
		},
		{
			name: "a source that verifies no caller is a refusal",
			verify: func(context.Context, string) (*identity.Principal, map[string]string, error) {
				return nil, nil, nil
			},
			assert: func(t *testing.T, out rsRoute) {
				require.ErrorIs(t, out.err, httpsec.ErrInvalidAccessToken)
				assert.False(t, out.laterRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := &httpsec.StubSource{Name: "provider", Provider: true, Unbound: true, Verify: tc.verify}

			tc.assert(t, routeThrough(t, "/api/orders", "Bearer at.0123456789",
				httpsec.EnableResourceServer("urn:orders", httpsec.WithStubSource(src))))
		})
	}
}

// TestResourceServer_Binding pins how the resource server holds a verified token to its binding,
// through the shared binding check: an unbound token is refused unless its source accepts one, and
// a confirmation the chain cannot check is refused even then.
func TestResourceServer_Binding(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		unbound bool
		cnf     map[string]string
		assert  func(t *testing.T, out rsRoute)
	}

	cases := []testCase{
		{
			name:   "an unbound token is refused by default",
			assert: func(t *testing.T, out rsRoute) { require.ErrorIs(t, out.err, httpsec.ErrInvalidAccessToken) },
		},
		{
			name:    "an unbound token is accepted by a source that accepts unbound tokens",
			unbound: true,
			assert: func(t *testing.T, out rsRoute) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
			},
		},
		{
			name:    "a confirmation the chain cannot check is refused, never taken for unbound",
			unbound: true,
			cnf:     map[string]string{"other": "x"},
			assert:  func(t *testing.T, out rsRoute) { require.ErrorIs(t, out.err, httpsec.ErrInvalidAccessToken) },
		},
		{
			name: "a certificate-bound token without its certificate is the certificate-binding refusal",
			cnf:  map[string]string{"x5t#S256": "AAAA"},
			assert: func(t *testing.T, out rsRoute) {
				require.ErrorIs(t, out.err, httpsec.ErrCertificateBinding)
				assert.False(t, out.laterRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := &httpsec.StubSource{
				Name: "provider", Provider: true, Unbound: tc.unbound,
				Verify: func(context.Context, string) (*identity.Principal, map[string]string, error) {
					return &identity.Principal{ID: "u-1"}, tc.cnf, nil
				},
			}

			tc.assert(t, routeThrough(t, "/api/orders", "Bearer at.0123456789",
				httpsec.EnableCertificateBinding(),
				httpsec.EnableResourceServer("urn:orders", httpsec.WithStubSource(src))))
		})
	}
}

// TestResourceServer_AcceptedClaimsTheCredential pins that a token the resource server accepted is
// the request's credential: the chain's bearer modes, which read the same Authorization header
// later, do not judge it again.
func TestResourceServer_AcceptedClaimsTheCredential(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		bearer func(t *testing.T) httpsec.Option
	}

	cases := []testCase{
		{
			name:   "beside the session-reference bearer",
			bearer: func(t *testing.T) httpsec.Option { return f.bearer(t, must.Must(session.New())) },
		},
		{
			name: "beside the signed bearer",
			bearer: func(t *testing.T) httpsec.Option {
				return f.signedBearer(t, must.Must(session.New()), httpsec.DefaultBearerScheme)
			},
		},
		{
			name: "beside API keys read under the Bearer scheme",
			bearer: func(t *testing.T) httpsec.Option {
				return httpsec.EnableAPIKey(newAPIKeyHarness(t).keys, httpsec.WithAPIKeyScheme("Bearer "))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := &httpsec.StubSource{Name: "provider", Provider: true, Unbound: true}

			out := routeThrough(t, "/api/orders", "Bearer at.0123456789",
				tc.bearer(t),
				httpsec.EnableResourceServer("urn:orders", httpsec.WithStubSource(src)))

			require.NoError(t, out.err)
			assert.True(t, out.handlerRan)
			assert.Equal(t, 1, src.Offered())
		})
	}
}
