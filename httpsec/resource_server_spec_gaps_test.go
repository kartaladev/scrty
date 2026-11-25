package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy/lockout"
)

// grantingRoleLoader grants the one privilege "read" on sales/order to every role.
type grantingRoleLoader struct{}

func (grantingRoleLoader) LoadPrivileges(context.Context, string) ([]*identity.ResourcePrivileges, error) {
	return []*identity.ResourcePrivileges{{
		Group: "sales", Resource: "order", Privileges: []identity.Privilege{{Name: "read", Granted: true}},
	}}, nil
}

// callThrough calls the API with tok bound to k, through the chain and then next.
func (w *psWorld) callThrough(t *testing.T, tok string, k dpopKey, jti string, next http.Handler) *httptest.ResponseRecorder {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, psAPIURL, nil)
	r.RemoteAddr = tokenAddr
	r.Header.Set("Authorization", "DPoP "+tok)
	r.Header.Set("DPoP", k.validProof(jti).with(map[string]any{
		"htu": psAPIURL, "iat": w.clk.Now().Unix(), "ath": tokenHash(tok),
	}).sign(t))

	rec := httptest.NewRecorder()
	w.chain.Middleware()(next).ServeHTTP(rec, r)

	return rec
}

// TestResourceServer_PrivilegeGuard pins that a privilege guard judges a caller a resource server
// authenticated by the role its user holds, with no session: the route is called when the active
// role grants the privilege, and refused as an access denial when the user holds no role.
func TestResourceServer_PrivilegeGuard(t *testing.T) {
	t.Parallel()

	k := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name   string
		admin  bool
		assert func(t *testing.T, rec *httptest.ResponseRecorder, ran bool, err error)
	}

	cases := []testCase{
		{
			name:  "a user whose active role grants the privilege reaches the route",
			admin: true,
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, ran bool, err error) {
				require.NoError(t, err)
				assert.True(t, ran)
				assert.Equal(t, http.StatusNoContent, rec.Code)
			},
		},
		{
			name: "a user with no active role is denied",
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, ran bool, err error) {
				require.ErrorIs(t, err, authorize.ErrAccessDenied)
				assert.False(t, ran)
				assert.Equal(t, http.StatusForbidden, rec.Code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newPSWorld(t, psSetup{})
			w.admin.Store(tc.admin)

			var guardErr error

			az, err := authorize.NewPrivilegeAuthorizer(grantingRoleLoader{})
			require.NoError(t, err)

			guards, err := httpsec.NewGuards(az, httpsec.WithGuardErrorHandler(
				func(rw http.ResponseWriter, _ *http.Request, err error) {
					guardErr = err
					rw.WriteHeader(httpsec.StatusForError(err))
				}))
			require.NoError(t, err)

			var ran bool

			route := guards.ResourcePrivileges("sales", "order").RequireAny("read")(
				http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
					ran = true

					rw.WriteHeader(http.StatusNoContent)
				}))

			tok := w.token(t, psJWTClient, &k, forAPI)
			rec := w.callThrough(t, tok, k, "j-priv", route)

			tc.assert(t, rec, ran, guardErr)
		})
	}
}

// TestSessionAuthentication_PrincipalCarriesNoScopes pins that a user a session authenticates, by
// its token or by its reference, carries no scopes: scopes belong to access tokens alone.
func TestSessionAuthentication_PrincipalCarriesNoScopes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		build func(t *testing.T, b *issuingBase) (*httpsec.Chain, string)
	}

	cases := []testCase{
		{
			name: "a session token",
			build: func(t *testing.T, b *issuingBase) (*httpsec.Chain, string) {
				t.Helper()

				chain, err := httpsec.New(b.bearer())
				require.NoError(t, err)

				return chain, b.signedIn(t, "", nil)
			},
		},
		{
			name: "a session reference",
			build: func(t *testing.T, b *issuingBase) (*httpsec.Chain, string) {
				t.Helper()

				chain, err := httpsec.New(httpsec.EnableSessionBearer(
					httpsec.SessionBearerDeps{Sessions: b.sessions, Users: b.users}))
				require.NoError(t, err)

				s, err := b.sessions.Create(t.Context(), e2eUser)
				require.NoError(t, err)

				return chain, s.ID
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, credential := tc.build(t, newIssuingBase(t))

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/api/orders", nil)
			req.Header.Set("Authorization", "Bearer "+credential)

			out := serve(t, chain, req)

			require.NoError(t, out.err)
			require.True(t, out.handlerRan)
			require.NotNil(t, out.handled.Authentication)
			require.NotNil(t, out.handled.Authentication.Principal)
			assert.Equal(t, e2eUser, out.handled.Authentication.Principal.ID)
			assert.Empty(t, out.handled.Authentication.Principal.Scopes)
		})
	}
}

// TestResourceServer_BindingDoesNotTouchSignIn pins that a resource server requiring bound access
// tokens does not make form login ask for a proof: a login with none is judged on its credentials,
// and the token and session it issues are unbound. Only the chain's own DPoP requirement refuses it.
func TestResourceServer_BindingDoesNotTouchSignIn(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		require bool
		assert  func(t *testing.T, f *issuingFixture, out served)
	}

	cases := []testCase{
		{
			name: "form login with no proof issues an unbound token and session",
			assert: func(t *testing.T, f *issuingFixture, out served) {
				jkt, s := f.issued(t, out)
				assert.Empty(t, jkt, "the token carries no cnf")
				assert.True(t, s.KeyBinding.IsZero(), "the stored session is unbound")
			},
		},
		{
			name:    "with DPoP required of the chain the same login is refused",
			require: true,
			assert: func(t *testing.T, _ *issuingFixture, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
				assert.False(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := newIssuingBase(t)
			attempts := must.Must(lockout.NewMemoryAttemptStore())
			src := &httpsec.StubSource{Name: "provider", Provider: true}

			f := b.fixture(t, httpsec.DPoP{PublicURL: dpopPublicURL, Require: tc.require},
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: b.authn, Sessions: b.sessions, Tokens: b.gen, Attempts: attempts,
				}),
				httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"), httpsec.WithStubSource(src)))

			req := postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
				httpsec.DefaultLoginUsernameParam: {e2eAddress},
				httpsec.DefaultLoginPasswordParam: {e2ePassword},
			})

			out := serve(t, f.chain, req)

			tc.assert(t, &f, out)
			assert.Zero(t, src.Offered(), "the sign-in is none of the source's business")
		})
	}
}

// TestResourceServer_OneReplayStore pins that the resource server and the provider's endpoints share
// one replay store: a proof's jti a resource server accepted is refused at UserInfo, and a fresh jti
// is not.
func TestResourceServer_OneReplayStore(t *testing.T) {
	t.Parallel()

	k := newDPoPKey(t, elliptic.P256())
	userInfoURL := opIssuer + "/oauth2/userinfo"

	type testCase struct {
		name   string
		jti    string
		assert func(t *testing.T, rec *httptest.ResponseRecorder)
	}

	cases := []testCase{
		{
			name: "the jti the resource server accepted is refused at UserInfo",
			jti:  "shared-1",
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
				assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)
			},
		},
		{
			name: "a fresh jti is answered",
			jti:  "fresh-1",
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, rec.Code, rec.Header().Get("WWW-Authenticate")+rec.Body.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newPSWorld(t, psSetup{})
			// The API token is audienced for the resource server; UserInfo answers a token audienced
			// for the provider itself, so the replayed proof rides beside the grant's other token.
			apiTok := w.token(t, psJWTClient, &k, forAPI)
			tok := w.token(t, psOpaqueClient, &k, func(v url.Values) { v.Set("scope", "openid profile") })

			first := w.call(t, apiTok, &k, "shared-1")
			require.Equal(t, http.StatusOK, first.status, first.body)

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, userInfoURL, nil)
			r.RemoteAddr = tokenAddr
			r.Header.Set("Authorization", "DPoP "+tok)
			r.Header.Set("DPoP", k.validProof(tc.jti).with(map[string]any{
				"htu": userInfoURL, "iat": w.clk.Now().Unix(), "ath": tokenHash(tok),
			}).sign(t))

			rec := httptest.NewRecorder()
			w.chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, r)

			tc.assert(t, rec)
		})
	}
}

// TestResourceServer_SessionTokenBesideResourceServer pins that a valid session token on a chain
// with signed bearer tokens and a resource server is authenticated by the signed bearer, and that no
// source is offered it.
func TestResourceServer_SessionTokenBesideResourceServer(t *testing.T) {
	t.Parallel()

	b := newIssuingBase(t)
	src := &httpsec.StubSource{Name: "any", Provider: true, Fallback: true, Unbound: true}

	chain, err := httpsec.New(b.bearer(),
		httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"), httpsec.WithStubSource(src)))
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/api/orders", nil)
	req.Header.Set("Authorization", "Bearer "+b.signedIn(t, "", nil))

	out := serve(t, chain, req)

	require.NoError(t, out.err)
	require.True(t, out.handlerRan)
	require.NotNil(t, out.handled.Authentication)
	assert.Equal(t, e2eUser, out.handled.Authentication.Principal.ID)
	assert.Zero(t, src.Offered(), "no source is consulted for a session token")
}

// TestResourceServer_NoSessionNeeded pins that a token a resource server accepts needs no session:
// the route is called, no session is created for the caller, and no cookie is set.
func TestResourceServer_NoSessionNeeded(t *testing.T) {
	t.Parallel()

	b := newIssuingBase(t)
	src := &httpsec.StubSource{Name: "provider", Provider: true, Unbound: true}

	f := b.fixture(t, httpsec.DPoP{PublicURL: dpopPublicURL},
		httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"), httpsec.WithStubSource(src)))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/api/orders", nil)
	req.Header.Set("Authorization", "Bearer at.0123456789")

	out := serve(t, f.chain, req)

	require.NoError(t, out.err)
	require.True(t, out.handlerRan)
	assert.Equal(t, 1, src.Offered())
	assert.Empty(t, out.rec.Header().Values("Set-Cookie"))

	for _, user := range []identity.UserID{"u-1", e2eUser} {
		n, err := b.sessions.CountActiveByUser(t.Context(), user)
		require.NoError(t, err)
		assert.Zero(t, n, "no session for %s", user)
	}
}

// TestResourceServer_BindingOptOutIsPerSource pins that a source opting out of binding accepts an
// unbound token for itself alone: a default source of the same resource server still refuses one.
func TestResourceServer_BindingOptOutIsPerSource(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		header string
		assert func(t *testing.T, out rsRoute)
	}

	cases := []testCase{
		{
			name:   "an unbound token is accepted from the source that opted out",
			header: "Bearer opt.1",
			assert: func(t *testing.T, out rsRoute) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
			},
		},
		{
			name:   "an unbound token is refused from the source that did not",
			header: "Bearer bnd.1",
			assert: func(t *testing.T, out rsRoute) {
				require.ErrorIs(t, out.err, httpsec.ErrInvalidToken)
				assert.False(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out := routeThrough(t, "/api/orders", tc.header,
				httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}),
				httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"),
					httpsec.WithStubSource(&httpsec.StubSource{Name: "optout", Prefix: "opt.", Unbound: true}),
					httpsec.WithStubSource(&httpsec.StubSource{Name: "default", Prefix: "bnd."})))

			tc.assert(t, out)
		})
	}
}

// TestResourceServer_QualifiedIdentifier pins that two issuers' tokens with the same subject yield
// two callers with different identifiers, neither of them the bare subject.
func TestResourceServer_QualifiedIdentifier(t *testing.T) {
	t.Parallel()

	w := newRIWorld(t, riSetup{second: true})

	first := w.call(t, w.token(t, w.issuers[0], w.issuers[0].keys[0], nil), nil)
	second := w.call(t, w.token(t, w.issuers[1], w.issuers[1].keys[0], nil), nil)

	require.Equal(t, http.StatusOK, first.status, first.body)
	require.Equal(t, http.StatusOK, second.status, second.body)
	require.NotNil(t, first.caller)
	require.NotNil(t, second.caller)

	assert.NotEqual(t, first.caller.ID, second.caller.ID)
	assert.NotEqual(t, identity.UserID("42"), first.caller.ID)
	assert.NotEqual(t, identity.UserID("42"), second.caller.ID)
	assert.True(t, strings.Contains(string(first.caller.ID), w.issuers[0].iss))
	assert.True(t, strings.Contains(string(second.caller.ID), w.issuers[1].iss))
}

// TestResourceServer_OpaqueIntrospectionOverHTTP pins what the provider's introspection endpoint
// answers the client holding an opaque access token: active, with its subject, scope, client and
// expiry.
func TestResourceServer_OpaqueIntrospectionOverHTTP(t *testing.T) {
	t.Parallel()

	k := newDPoPKey(t, elliptic.P256())
	w := newPSWorld(t, psSetup{})
	tok := w.token(t, psOpaqueClient, &k, forAPI)

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, opIssuer+"/oauth2/introspect",
		strings.NewReader(url.Values{"token": {tok}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = tokenAddr
	asClient(psOpaqueClient)(r)

	got := w.serve(t, r)

	require.Equal(t, http.StatusOK, got.status, got.body)

	doc := got.document(t)
	assert.Equal(t, true, doc["active"])
	assert.Equal(t, psOpaqueClient, doc["client_id"])
	assert.NotEmpty(t, doc["sub"])
	assert.NotEmpty(t, doc["scope"])
	assert.Contains(t, doc, "exp")
}
