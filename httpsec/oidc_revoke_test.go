package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
)

const (
	revokeURL     = opIssuer + "/oauth2/revoke"
	introspectURL = opIssuer + "/oauth2/introspect"

	opOtherClient    = "other"
	opOpaqueClient   = "opaque"
	opResourceClient = "resource-server"
	opAudience       = "https://api.example.com"

	opInactive = `{"active":false}`
)

// opWorldSetup is what a row of these endpoints' tests asks of its provider and chain, beyond what
// tokenSetup carries.
type opWorldSetup struct {
	tokenSetup

	// issuer replaces opIssuer.
	issuer string
	// provider adds options to the provider, built for the row's test.
	provider func(t *testing.T) []oidcprovider.Option
}

// opWorld is a provider on a chain, with the clients these endpoints need. Its outage fails the
// client registry and the user store together; disabled and gone change what the user store says.
type opWorld struct {
	*tokenEndpoint

	disabled, gone *atomic.Bool

	// lookups counts the clients read from the registry, which is one for each time a client
	// authenticates.
	lookups *atomic.Int32
}

func newOPWorld(t *testing.T, setup opWorldSetup) *opWorld {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Now())
	consents := must.Must(oidcprovider.NewMemoryConsentStore())
	w := &opWorld{disabled: &atomic.Bool{}, gone: &atomic.Bool{}, lookups: &atomic.Int32{}}
	outage := &atomic.Bool{}

	ctrl := gomock.NewController(t)

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			switch {
			case outage.Load():
				return nil, errors.New("user store secret text")
			case w.gone.Load():
				return nil, identity.ErrUserNotFound
			}

			return &identity.Details{
				ID: user, Active: !w.disabled.Load(), Name: "Ada Lovelace", Username: "ada@example.com",
			}, nil
		},
	).AnyTimes()

	secret := []byte(tokenSecret)
	scopes := []string{"openid", "profile", "email", "org", "offline_access"}
	both := []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken}
	confidential := func(id string) oidcprovider.Client {
		return oidcprovider.Client{
			ID: id, Type: oidcprovider.Confidential, Secret: secret, RedirectURIs: []string{rpCallback},
			Scopes: scopes, GrantTypes: both, Resources: []string{opAudience},
		}
	}

	opaque := confidential(opOpaqueClient)
	opaque.OpaqueAccessTokens = true
	resource := confidential(opResourceClient)
	resource.ResourceIdentifier = opAudience

	memory := must.Must(oidcprovider.NewMemoryRegistry([]oidcprovider.Client{
		confidential(tokenWeb),
		confidential(opOtherClient),
		opaque,
		resource,
		{
			ID: tokenPublic, Type: oidcprovider.Public, ApplicationType: oidcprovider.Native,
			RedirectURIs: []string{rpCallback}, Scopes: scopes, GrantTypes: both,
		},
	}))

	registry := NewMockClientRegistry(ctrl)
	registry.EXPECT().Client(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, id string) (*oidcprovider.RegisteredClient, error) {
			w.lookups.Add(1)

			if outage.Load() {
				return nil, errors.New("registry secret text")
			}

			return memory.Client(ctx, id)
		},
	).AnyTimes()

	popts := []oidcprovider.Option{
		oidcprovider.WithClock(clk),
		oidcprovider.WithConsentStore(consents),
		oidcprovider.WithoutBrowserSessions(),
	}
	if setup.provider != nil {
		popts = append(popts, setup.provider(t)...)
	}

	chainOpts := []httpsec.Option{httpsec.WithClock(clk)}
	if setup.dpop != nil {
		popts = append(popts, oidcprovider.WithDPoP())
		chainOpts = append(chainOpts, httpsec.EnableDPoP(*setup.dpop(t)))
	}
	if setup.cert {
		chainOpts = append(chainOpts, httpsec.EnableCertificateBinding())
	}

	issuer := setup.issuer
	if issuer == "" {
		issuer = opIssuer
	}

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     registry,
		Keys:         tokenKeys(),
		Users:        users,
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout-page",
		LoggedOutURL: issuer + "/bye",
	}, popts...)
	require.NoError(t, err)

	var endpoint []httpsec.OIDCProviderOption
	if setup.endpoint != nil {
		endpoint = setup.endpoint(t)
	}

	f := &opFixture{keys: tokenKeys()}
	chainOpts = append(chainOpts, f.wired(t, p)...)
	chainOpts = append(chainOpts, setup.chain...)
	chainOpts = append(chainOpts, httpsec.EnableOIDCProvider(p, endpoint...))

	chain, err := httpsec.New(chainOpts...)
	require.NoError(t, err)

	w.tokenEndpoint = &tokenEndpoint{p: p, chain: chain, clk: clk, consents: consents, outage: outage}

	return w
}

// post sends form to target.
func (w *opWorld) post(t *testing.T, target string, form url.Values, change ...tokenChange) tokenAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = tokenAddr
	for _, c := range change {
		c(r)
	}

	return w.serve(t, r)
}

// issued is the token response clientID gets for a fresh code, with change applied to the
// authorization request, and more applied to the token request.
func (w *opWorld) issued(t *testing.T, clientID string, change func(url.Values), more ...tokenChange) map[string]any {
	t.Helper()

	code := w.issue(t, clientID, change)

	form := exchangeOf(code)
	if clientID == tokenPublic {
		form.Set("client_id", clientID)
	} else {
		more = append([]tokenChange{asClient(clientID)}, more...)
	}

	a := w.send(t, form, more...)
	require.Equal(t, http.StatusOK, a.status, a.body)

	return a.document(t)
}

// issuedToken is one member of the token response clientID gets for a fresh code.
func (w *opWorld) issuedToken(t *testing.T, clientID, member string) string {
	t.Helper()

	raw, _ := w.issued(t, clientID, nil)[member].(string)
	require.NotEmpty(t, raw, "the token response holds no %s", member)

	return raw
}

// refresh presents raw as clientID, and answers what the token endpoint says.
func (w *opWorld) refresh(t *testing.T, clientID, raw string) tokenAnswer {
	t.Helper()

	return w.send(t, refreshOf(raw), asClient(clientID))
}

func tokenForm(raw string, extra ...string) url.Values {
	form := url.Values{"token": {raw}}
	addPairs(form, extra)

	return form
}

// forgedSecret is raw with a secret never issued, under the same family.
func forgedSecret(raw string) string {
	cut := strings.LastIndexByte(raw, '.') + 1

	first := byte('A')
	if raw[cut] == 'A' {
		first = 'B'
	}

	return raw[:cut] + string(first) + raw[cut+1:]
}

// overTLSLess takes the request off TLS, as the chain would report the connection.
func overTLSLess(r *http.Request) { r.TLS = nil }

// assertAnswered pins an answer of 200: nothing passed on, and nothing a cache may keep.
func assertAnswered(t *testing.T, a tokenAnswer) {
	t.Helper()

	assertTokenHeaders(t, a)
	assert.Equal(t, http.StatusOK, a.status, a.body)
}

// assertInactive pins the whole of what is said of a token that is not active.
func assertInactive(t *testing.T, a tokenAnswer) {
	t.Helper()

	assertAnswered(t, a)
	assert.Equal(t, "application/json", a.header.Get("Content-Type"))
	assert.Equal(t, opInactive, a.body)
}

// wrongMethod pins that a method the endpoint does not serve is answered, not passed on.
func wrongMethod(t *testing.T, a tokenAnswer, allow string) {
	t.Helper()

	assertTokenHeaders(t, a)
	assert.Equal(t, http.StatusMethodNotAllowed, a.status)
	assert.Equal(t, allow, a.header.Get("Allow"))
	assert.Empty(t, a.body)
}

// TestOIDCRevoke pins the revocation endpoint: RFC 7009 over a chain. A row proves "nothing was
// revoked" by a refresh that works afterwards, and "the grant ended" by one that does not.
func TestOIDCRevoke(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  opWorldSetup
		send   func(t *testing.T, w *opWorld) tokenAnswer
		assert func(t *testing.T, a tokenAnswer)
	}

	refused := func(code string) func(*testing.T, tokenAnswer) {
		return func(t *testing.T, a tokenAnswer) {
			t.Helper()
			assertTokenRefused(t, a, code)
		}
	}
	issued := func(t *testing.T, a tokenAnswer) {
		t.Helper()
		assertTokenIssued(t, a, "Bearer")
	}
	empty200 := func(t *testing.T, a tokenAnswer) {
		t.Helper()
		assertAnswered(t, a)
		assert.Empty(t, a.body)
	}

	// revokes and then refreshes the same client's token, so the row's assert says what the
	// revocation left.
	thenRefresh := func(form func(raw string) url.Values) func(*testing.T, *opWorld) tokenAnswer {
		return func(t *testing.T, w *opWorld) tokenAnswer {
			t.Helper()

			raw := w.issuedToken(t, tokenWeb, "refresh_token")
			empty200(t, w.post(t, revokeURL, form(raw), asClient(tokenWeb)))

			return w.refresh(t, tokenWeb, raw)
		}
	}

	cases := []testCase{
		{
			name:   "a client's refresh token ends its grant",
			send:   thenRefresh(func(raw string) url.Values { return tokenForm(raw) }),
			assert: refused(oidcprovider.CodeInvalidGrant),
		},
		{
			name:   "any hint is ignored, the lookup going by the token's own shape",
			send:   thenRefresh(func(raw string) url.Values { return tokenForm(raw, "token_type_hint", "access_token") }),
			assert: refused(oidcprovider.CodeInvalidGrant),
		},
		{
			name: "a public client names its client_id",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				raw := w.issuedToken(t, tokenPublic, "refresh_token")
				empty200(t, w.post(t, revokeURL, tokenForm(raw, "client_id", tokenPublic)))

				return w.send(t, refreshOf(raw, "client_id", tokenPublic))
			},
			assert: refused(oidcprovider.CodeInvalidGrant),
		},
		{
			name: "every refresh token of the grant ends, the newest included, and a superseded one is no reuse",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				first := w.issuedToken(t, tokenWeb, "refresh_token")
				a := w.refresh(t, tokenWeb, first)
				require.Equal(t, http.StatusOK, a.status, a.body)
				newest, _ := a.document(t)["refresh_token"].(string)
				w.clk.Advance(tokenPastGrace)

				empty200(t, w.post(t, revokeURL, tokenForm(first), asClient(tokenWeb)))

				return w.refresh(t, tokenWeb, newest)
			},
			assert: refused(oidcprovider.CodeInvalidGrant),
		},
		{
			name: "an opaque access token ends itself, and no other of its grant",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				doc := w.issued(t, opOpaqueClient, nil)
				at, _ := doc["access_token"].(string)
				rt, _ := doc["refresh_token"].(string)
				require.True(t, strings.HasPrefix(at, "at."), "the client takes opaque tokens")

				empty200(t, w.post(t, revokeURL, tokenForm(at), asClient(opOpaqueClient)))
				_, err := w.p.VerifyAccessToken(t.Context(), at)
				var refusal *oidcprovider.Error
				require.ErrorAs(t, err, &refusal)
				assert.Equal(t, oidcprovider.CodeInvalidToken, refusal.Code)

				return w.refresh(t, opOpaqueClient, rt)
			},
			assert: issued,
		},
		{
			name: "a JWT access token is success with nothing revoked",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				doc := w.issued(t, tokenWeb, nil)
				at, _ := doc["access_token"].(string)
				rt, _ := doc["refresh_token"].(string)
				empty200(t, w.post(t, revokeURL, tokenForm(at), asClient(tokenWeb)))

				return w.refresh(t, tokenWeb, rt)
			},
			assert: issued,
		},
		{
			name: "a value that is no token is success",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, revokeURL, tokenForm("no-such-token"), asClient(tokenWeb))
			},
			assert: empty200,
		},
		{
			name: "a real family beside a secret never issued is success with nothing revoked",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				raw := w.issuedToken(t, tokenWeb, "refresh_token")
				empty200(t, w.post(t, revokeURL, tokenForm(forgedSecret(raw)), asClient(tokenWeb)))

				return w.refresh(t, tokenWeb, raw)
			},
			assert: issued,
		},
		{
			name: "an expired token is success",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				raw := w.issuedToken(t, tokenWeb, "refresh_token")
				w.clk.Advance(91 * 24 * time.Hour)

				return w.post(t, revokeURL, tokenForm(raw), asClient(tokenWeb))
			},
			assert: empty200,
		},
		{
			name: "another client's token is invalid_grant, revoking nothing",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				raw := w.issuedToken(t, tokenWeb, "refresh_token")
				assertTokenRefused(t, w.post(t, revokeURL, tokenForm(raw), asClient(opOtherClient)), oidcprovider.CodeInvalidGrant)

				return w.refresh(t, tokenWeb, raw)
			},
			assert: issued,
		},
		{
			name: "no token is invalid_request",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, revokeURL, url.Values{}, asClient(tokenWeb))
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "a token in the query is no token, and is not read",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				raw := w.issuedToken(t, tokenWeb, "refresh_token")
				a := w.post(t, revokeURL+"?token="+url.QueryEscape(raw), url.Values{}, asClient(tokenWeb))
				assertTokenRefused(t, a, oidcprovider.CodeInvalidRequest)

				return w.refresh(t, tokenWeb, raw)
			},
			assert: issued,
		},
		{
			name: "a repeated token is invalid_request",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, revokeURL, tokenForm("one", "token", "two"), asClient(tokenWeb))
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "a body that is no form is invalid_request",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, revokeURL, tokenForm("x"), asClient(tokenWeb), func(r *http.Request) {
					r.Header.Set("Content-Type", "application/json")
				})
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "no client authentication is invalid_client",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, revokeURL, tokenForm("x"))
			},
			assert: refused(oidcprovider.CodeInvalidClient),
		},
		{
			name: "a wrong secret is invalid_client, revoking nothing",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				raw := w.issuedToken(t, tokenWeb, "refresh_token")
				a := w.post(t, revokeURL, tokenForm(raw), withSecret(tokenWeb, "wrong"))
				assertTokenRefused(t, a, oidcprovider.CodeInvalidClient)

				return w.refresh(t, tokenWeb, raw)
			},
			assert: issued,
		},
		{
			name: "GET is answered, not passed on",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.serve(t, httptest.NewRequestWithContext(t.Context(), http.MethodGet, revokeURL, nil))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				wrongMethod(t, a, http.MethodPost)
			},
		},
		{
			name: "a request not made over TLS is refused, revoking nothing",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				raw := w.issuedToken(t, tokenWeb, "refresh_token")
				a := w.post(t, revokeURL, tokenForm(raw), asClient(tokenWeb), overTLSLess)
				assertTokenRefused(t, a, oidcprovider.CodeInvalidRequest)

				return w.refresh(t, tokenWeb, raw)
			},
			assert: issued,
		},
		{
			name: "the loopback issuer answers plain http",
			setup: opWorldSetup{
				issuer: "http://127.0.0.1:8080",
				provider: func(*testing.T) []oidcprovider.Option {
					return []oidcprovider.Option{oidcprovider.WithLoopbackHTTPIssuer()}
				},
			},
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, revokeURL, tokenForm("no-such-token"), asClient(tokenWeb), overTLSLess)
			},
			assert: empty200,
		},
		{
			name: "a dependency that fails is no verdict: 500 with no text",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				w.outage.Store(true)

				return w.post(t, revokeURL, tokenForm("x"), asClient(tokenWeb))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				assertTokenFailed(t, a)
				assert.Empty(t, a.body)
			},
		},
		{
			name: "a request elsewhere passes through",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, revokeURL+"/below", tokenForm("x"))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				assert.True(t, a.passedOn)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPWorld(t, tc.setup)
			tc.assert(t, tc.send(t, w))
		})
	}
}

// TestOIDCIntrospect pins the introspection endpoint: RFC 7662 over a chain. Only a token the client
// may see is described, and everything else reads alike.
func TestOIDCIntrospect(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  opWorldSetup
		send   func(t *testing.T, w *opWorld) tokenAnswer
		assert func(t *testing.T, a tokenAnswer)
	}

	refused := func(code string) func(*testing.T, tokenAnswer) {
		return func(t *testing.T, a tokenAnswer) {
			t.Helper()
			assertTokenRefused(t, a, code)
		}
	}
	active := func(t *testing.T, a tokenAnswer) {
		t.Helper()
		assertAnswered(t, a)
		assert.Equal(t, true, a.document(t)["active"])
	}
	issued := func(t *testing.T, a tokenAnswer) {
		t.Helper()
		assertTokenIssued(t, a, "Bearer")
	}

	cases := []testCase{
		{
			name: "a client's own JWT access token is described",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := w.issuedToken(t, tokenWeb, "access_token")

				return w.post(t, introspectURL, tokenForm(at), asClient(tokenWeb))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				active(t, a)
				doc := a.document(t)
				assert.Equal(t, tokenWeb, doc["client_id"])
				assert.Equal(t, "u-1", doc["sub"])
				assert.Equal(t, "Bearer", doc["token_type"])
				assert.Equal(t, opIssuer, doc["iss"])
				assert.Contains(t, doc["scope"], "openid")
				assert.NotContains(t, doc, "cnf")
			},
		},
		{
			name: "a client's own opaque access token is described, under any hint",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := w.issuedToken(t, opOpaqueClient, "access_token")

				return w.post(t, introspectURL, tokenForm(at, "token_type_hint", "refresh_token"), asClient(opOpaqueClient))
			},
			assert: active,
		},
		{
			name:  "a bound token's confirmation is described",
			setup: opWorldSetup{tokenSetup: tokenSetup{dpop: plainDPoP}},
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				k := newDPoPKey(t, elliptic.P256())
				doc := w.issued(t, tokenWeb, nil, w.withProof(t, k, "j1", nil))
				at, _ := doc["access_token"].(string)

				return w.post(t, introspectURL, tokenForm(at), asClient(tokenWeb))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				active(t, a)
				doc := a.document(t)
				assert.Equal(t, "DPoP", doc["token_type"])
				assert.Contains(t, doc, "cnf")
			},
		},
		{
			name: "a refresh token is described, and is not rotated by that",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				raw := w.issuedToken(t, tokenWeb, "refresh_token")
				a := w.post(t, introspectURL, tokenForm(raw), asClient(tokenWeb))
				active(t, a)
				assert.Equal(t, "refresh_token", a.document(t)["token_type"])
				w.clk.Advance(tokenPastGrace)

				return w.refresh(t, tokenWeb, raw)
			},
			assert: issued,
		},
		{
			name: "a superseded refresh token past its grace is inactive, and is no reuse",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				first := w.issuedToken(t, tokenWeb, "refresh_token")
				a := w.refresh(t, tokenWeb, first)
				require.Equal(t, http.StatusOK, a.status, a.body)
				newest, _ := a.document(t)["refresh_token"].(string)
				w.clk.Advance(tokenPastGrace)

				assertInactive(t, w.post(t, introspectURL, tokenForm(first), asClient(tokenWeb)))

				return w.refresh(t, tokenWeb, newest)
			},
			assert: issued,
		},
		{
			name: "a JWT of a grant since revoked is inactive",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				doc := w.issued(t, tokenWeb, nil)
				at, _ := doc["access_token"].(string)
				rt, _ := doc["refresh_token"].(string)
				require.Equal(t, http.StatusOK, w.post(t, revokeURL, tokenForm(rt), asClient(tokenWeb)).status)

				return w.post(t, introspectURL, tokenForm(at), asClient(tokenWeb))
			},
			assert: assertInactive,
		},
		{
			name: "an expired token is inactive",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := w.issuedToken(t, tokenWeb, "access_token")
				w.clk.Advance(6 * time.Minute)

				return w.post(t, introspectURL, tokenForm(at), asClient(tokenWeb))
			},
			assert: assertInactive,
		},
		{
			name: "a value that is no token is inactive",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, introspectURL, tokenForm("no-such-token"), asClient(tokenWeb))
			},
			assert: assertInactive,
		},
		{
			name: "another client's token reads as inactive",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := w.issuedToken(t, tokenWeb, "access_token")

				return w.post(t, introspectURL, tokenForm(at), asClient(opOtherClient))
			},
			assert: assertInactive,
		},
		{
			name: "a resource server sees a token for its resource",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				doc := w.issued(t, tokenWeb, func(params url.Values) { params.Set("resource", opAudience) })
				at, _ := doc["access_token"].(string)

				return w.post(t, introspectURL, tokenForm(at), asClient(opResourceClient))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				active(t, a)
				assert.Equal(t, []any{opAudience}, a.document(t)["aud"])
			},
		},
		{
			name: "a public client is invalid_client, whatever it names",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				raw := w.issuedToken(t, tokenPublic, "access_token")

				return w.post(t, introspectURL, tokenForm(raw, "client_id", tokenPublic))
			},
			assert: refused(oidcprovider.CodeInvalidClient),
		},
		{
			name: "no client authentication is invalid_client",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, introspectURL, tokenForm("x"))
			},
			assert: refused(oidcprovider.CodeInvalidClient),
		},
		{
			name: "no token is invalid_request",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, introspectURL, url.Values{}, asClient(tokenWeb))
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "a token in the query is not read",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := w.issuedToken(t, tokenWeb, "access_token")

				return w.post(t, introspectURL+"?token="+url.QueryEscape(at), url.Values{}, asClient(tokenWeb))
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "GET is answered, not passed on",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.serve(t, httptest.NewRequestWithContext(t.Context(), http.MethodGet, introspectURL, nil))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				wrongMethod(t, a, http.MethodPost)
			},
		},
		{
			name: "a request not made over TLS is refused",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, introspectURL, tokenForm("x"), asClient(tokenWeb), overTLSLess)
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "the loopback issuer answers plain http",
			setup: opWorldSetup{
				issuer: "http://127.0.0.1:8080",
				provider: func(*testing.T) []oidcprovider.Option {
					return []oidcprovider.Option{oidcprovider.WithLoopbackHTTPIssuer()}
				},
			},
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, introspectURL, tokenForm("no-such-token"), asClient(tokenWeb), overTLSLess)
			},
			assert: assertInactive,
		},
		{
			name: "a dependency that fails is no verdict: 500 with no text",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				w.outage.Store(true)

				return w.post(t, introspectURL, tokenForm("x"), asClient(tokenWeb))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				assertTokenFailed(t, a)
				assert.Empty(t, a.body)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPWorld(t, tc.setup)
			tc.assert(t, tc.send(t, w))
		})
	}
}

// opClientEndpoint is one of the endpoints that share a client's authentication and its throttling.
type opClientEndpoint struct {
	name, url string
	limiter   func(ratelimit.Limiter) httpsec.OIDCProviderOption
	bound     func(int64) httpsec.OIDCProviderOption
}

// oidcClientEndpoints are the endpoints these tests run at.
var oidcClientEndpoints = []opClientEndpoint{
	{name: "revocation", url: revokeURL, limiter: httpsec.WithOIDCRevokeLimiter, bound: httpsec.WithOIDCRevokeBodyLimit},
	{name: "introspection", url: introspectURL, limiter: httpsec.WithOIDCIntrospectLimiter, bound: httpsec.WithOIDCIntrospectBodyLimit},
}

// TestOIDCRevoke_Throttle pins what both endpoints charge a source for, and what they ask of it first,
// each row run at each endpoint.
func TestOIDCRevoke_Throttle(t *testing.T) {
	t.Parallel()

	type endpoint = opClientEndpoint

	limitedAt := func(ep endpoint, limit int) []httpsec.OIDCProviderOption {
		l := must.Must(ratelimit.NewMemoryLimiter(limit, time.Hour))

		return []httpsec.OIDCProviderOption{ep.limiter(l)}
	}

	type testCase struct {
		name string
		opts func(t *testing.T, ep endpoint) []httpsec.OIDCProviderOption
		run  func(t *testing.T, w *opWorld, ep endpoint)
	}

	cases := []testCase{
		{
			name: "a wrong secret is charged, and a source past the limit is refused unchecked",
			opts: func(_ *testing.T, ep endpoint) []httpsec.OIDCProviderOption { return limitedAt(ep, 1) },
			run: func(t *testing.T, w *opWorld, ep endpoint) {
				t.Helper()

				assertTokenRefused(t, w.post(t, ep.url, tokenForm("x"), withSecret(tokenWeb, "wrong")), oidcprovider.CodeInvalidClient)

				w.lookups.Store(0)
				assertTokenRefused(t, w.post(t, ep.url, tokenForm("x"), asClient(tokenWeb)), oidcprovider.CodeInvalidClient)
				assert.Zero(t, w.lookups.Load(), "a throttled source reaches no client lookup")

				a := w.post(t, ep.url, tokenForm("x"), asClient(tokenWeb), fromAddr(tokenOtherAddr))
				assertAnswered(t, a)
			},
		},
		{
			name: "by default a source has ten failures",
			run: func(t *testing.T, w *opWorld, ep endpoint) {
				t.Helper()

				for range 9 {
					assertTokenRefused(t, w.post(t, ep.url, tokenForm("x"), withSecret(tokenWeb, "wrong")), oidcprovider.CodeInvalidClient)
				}
				assertAnswered(t, w.post(t, ep.url, tokenForm("x"), asClient(tokenWeb)))

				assertTokenRefused(t, w.post(t, ep.url, tokenForm("x"), withSecret(tokenWeb, "wrong")), oidcprovider.CodeInvalidClient)
				assertTokenRefused(t, w.post(t, ep.url, tokenForm("x"), asClient(tokenWeb)), oidcprovider.CodeInvalidClient)
			},
		},
		{
			name: "failures at one endpoint do not throttle the other",
			opts: func(_ *testing.T, ep endpoint) []httpsec.OIDCProviderOption { return limitedAt(ep, 1) },
			run: func(t *testing.T, w *opWorld, ep endpoint) {
				t.Helper()

				other := revokeURL
				if ep.url == revokeURL {
					other = introspectURL
				}

				assertTokenRefused(t, w.post(t, ep.url, tokenForm("x"), withSecret(tokenWeb, "wrong")), oidcprovider.CodeInvalidClient)
				assertAnswered(t, w.post(t, other, tokenForm("x"), asClient(tokenWeb)))
			},
		},
		{
			name: "a malformed request is not charged",
			opts: func(_ *testing.T, ep endpoint) []httpsec.OIDCProviderOption { return limitedAt(ep, 1) },
			run: func(t *testing.T, w *opWorld, ep endpoint) {
				t.Helper()

				assertTokenRefused(t, w.post(t, ep.url, url.Values{}, asClient(tokenWeb)), oidcprovider.CodeInvalidRequest)
				assertAnswered(t, w.post(t, ep.url, tokenForm("x"), asClient(tokenWeb)))
			},
		},
		{
			name: "a failure is not charged",
			opts: func(_ *testing.T, ep endpoint) []httpsec.OIDCProviderOption { return limitedAt(ep, 1) },
			run: func(t *testing.T, w *opWorld, ep endpoint) {
				t.Helper()

				w.outage.Store(true)
				assertTokenFailed(t, w.post(t, ep.url, tokenForm("x"), asClient(tokenWeb)))
				w.outage.Store(false)

				assertAnswered(t, w.post(t, ep.url, tokenForm("x"), asClient(tokenWeb)))
			},
		},
		{
			name: "a limiter that cannot answer fails closed",
			opts: func(t *testing.T, ep endpoint) []httpsec.OIDCProviderOption {
				t.Helper()

				limiter := NewMockLimiter(gomock.NewController(t))
				limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, errors.New("limiter secret text")).Times(1)

				return []httpsec.OIDCProviderOption{ep.limiter(limiter)}
			},
			run: func(t *testing.T, w *opWorld, ep endpoint) {
				t.Helper()

				assertTokenRefused(t, w.post(t, ep.url, tokenForm("x"), asClient(tokenWeb)), oidcprovider.CodeInvalidClient)
			},
		},
		{
			name: "a client authenticates once, because an assertion is single-use",
			run: func(t *testing.T, w *opWorld, ep endpoint) {
				t.Helper()

				w.lookups.Store(0)
				assertAnswered(t, w.post(t, ep.url, tokenForm("x"), asClient(tokenWeb)))
				assert.EqualValues(t, 1, w.lookups.Load())
			},
		},
		{
			name: "a body over the bound is refused, with nothing authenticated",
			opts: func(_ *testing.T, ep endpoint) []httpsec.OIDCProviderOption {
				return []httpsec.OIDCProviderOption{ep.bound(4)}
			},
			run: func(t *testing.T, w *opWorld, ep endpoint) {
				t.Helper()

				w.lookups.Store(0)
				a := w.post(t, ep.url, tokenForm("longer-than-the-bound"), asClient(tokenWeb))
				assertTokenHeaders(t, a)
				assert.Equal(t, http.StatusRequestEntityTooLarge, a.status)
				assert.Zero(t, w.lookups.Load())
			},
		},
		{
			name: "by default a body is bound by DefaultLoginBodyLimit",
			run: func(t *testing.T, w *opWorld, ep endpoint) {
				t.Helper()

				padded := tokenForm("x", "padding", strings.Repeat("p", int(httpsec.DefaultLoginBodyLimit)-64))
				assertAnswered(t, w.post(t, ep.url, padded, asClient(tokenWeb)))

				over := tokenForm("x", "padding", strings.Repeat("p", int(httpsec.DefaultLoginBodyLimit)))
				assert.Equal(t, http.StatusRequestEntityTooLarge, w.post(t, ep.url, over, asClient(tokenWeb)).status)
			},
		},
	}

	for _, ep := range oidcClientEndpoints {
		for _, tc := range cases {
			t.Run(ep.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				var setup opWorldSetup
				if tc.opts != nil {
					setup.endpoint = func(t *testing.T) []httpsec.OIDCProviderOption {
						t.Helper()

						return tc.opts(t, ep)
					}
				}

				tc.run(t, newOPWorld(t, setup), ep)
			})
		}
	}
}

// TestOIDCIntrospect_PublicRefusalIsCharged pins that a public client refused at introspection is
// charged to its source like any other failed client authentication, so a source cannot probe the
// endpoint through a client that never authenticates.
func TestOIDCIntrospect_PublicRefusalIsCharged(t *testing.T) {
	t.Parallel()

	w := newOPWorld(t, opWorldSetup{})
	for range 10 {
		assertTokenRefused(t, w.post(t, introspectURL, tokenForm("x", "client_id", tokenPublic)), oidcprovider.CodeInvalidClient)
	}

	w.lookups.Store(0)
	assertTokenRefused(t, w.post(t, introspectURL, tokenForm("x"), asClient(tokenWeb)), oidcprovider.CodeInvalidClient)
	assert.Zero(t, w.lookups.Load(), "the source is throttled by what the public client's refusals charged")
}

// TestOIDCRevoke_RefusalLogs pins that each endpoint's throttle reaches the chain's sampling: what
// it logs about a source it cannot attribute goes through the chain's sampler, and a chain's flush
// reports what its guard held back, each at each endpoint.
func TestOIDCRevoke_RefusalLogs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// drive sends requests until the row's component holds suppressed records.
		drive func(t *testing.T, w *opWorld, ep opClientEndpoint)
		// key says whether a reported key is the row's component's, for the flow.
		key func(key, flow string) bool
	}

	cases := []testCase{
		{
			name: "the chain's sampler is the throttle's",
			drive: func(t *testing.T, w *opWorld, ep opClientEndpoint) {
				t.Helper()

				for range 3 {
					w.post(t, ep.url, tokenForm("x"), asClient(tokenWeb), fromAddr(""))
				}
			},
			key: func(key, flow string) bool { return strings.HasPrefix(key, flow+"|") },
		},
		{
			name: "a chain's flush reaches the throttle's guard",
			drive: func(t *testing.T, w *opWorld, ep opClientEndpoint) {
				t.Helper()

				for range 4 {
					w.post(t, ep.url, tokenForm("x"), withSecret(tokenWeb, "wrong"))
				}
			},
			key: func(key, flow string) bool { return strings.Contains(key, ":"+flow+":") },
		},
	}

	for _, ep := range oidcClientEndpoints {
		for _, tc := range cases {
			t.Run(ep.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				var (
					mu         sync.Mutex
					suppressed = map[string]int{}
				)

				flow := map[string]string{"revocation": "oidc-revoke", "introspection": "oidc-introspect"}[ep.name]
				w := newOPWorld(t, opWorldSetup{
					tokenSetup: tokenSetup{
						endpoint: func(*testing.T) []httpsec.OIDCProviderOption {
							l := must.Must(ratelimit.NewMemoryLimiter(1, time.Hour))

							return []httpsec.OIDCProviderOption{ep.limiter(l)}
						},
						chain: []httpsec.Option{
							httpsec.WithLogger(slog.New(slog.DiscardHandler)),
							httpsec.WithRefusalLogReporter(func(key string, n int) {
								mu.Lock()
								defer mu.Unlock()

								suppressed[key] += n
							}),
						},
					},
				})

				tc.drive(t, w, ep)
				require.NoError(t, w.chain.FlushRefusalLogs())

				mu.Lock()
				defer mu.Unlock()

				var total int
				for key, n := range suppressed {
					if tc.key(key, flow) {
						total += n
					}
				}
				assert.Positive(t, total, "the component's suppressed records are reported: %v", suppressed)
			})
		}
	}
}

// TestOIDCRevoke_Options pins what the endpoints' options refuse at construction.
func TestOIDCRevoke_Options(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opt    httpsec.OIDCProviderOption
		assert func(t *testing.T, err error)
	}

	refused := func(option string) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.ErrorContains(t, err, option)
		}
	}

	accepted := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err)
	}

	var typedNil *ratelimit.MemoryLimiter

	cases := []testCase{
		{name: "a nil revocation limiter", opt: httpsec.WithOIDCRevokeLimiter(nil), assert: refused("WithOIDCRevokeLimiter")},
		{name: "a typed nil revocation limiter", opt: httpsec.WithOIDCRevokeLimiter(typedNil), assert: refused("WithOIDCRevokeLimiter")},
		{name: "a nil introspection limiter", opt: httpsec.WithOIDCIntrospectLimiter(nil), assert: refused("WithOIDCIntrospectLimiter")},
		{name: "a typed nil introspection limiter", opt: httpsec.WithOIDCIntrospectLimiter(typedNil), assert: refused("WithOIDCIntrospectLimiter")},
		{name: "a revocation bound of zero", opt: httpsec.WithOIDCRevokeBodyLimit(0), assert: refused("WithOIDCRevokeBodyLimit")},
		{name: "a negative revocation bound", opt: httpsec.WithOIDCRevokeBodyLimit(-1), assert: refused("WithOIDCRevokeBodyLimit")},
		{name: "an introspection bound of zero", opt: httpsec.WithOIDCIntrospectBodyLimit(0), assert: refused("WithOIDCIntrospectBodyLimit")},
		{name: "a negative introspection bound", opt: httpsec.WithOIDCIntrospectBodyLimit(-1), assert: refused("WithOIDCIntrospectBodyLimit")},
		{name: "a positive revocation bound", opt: httpsec.WithOIDCRevokeBodyLimit(1), assert: accepted},
		{name: "a positive introspection bound", opt: httpsec.WithOIDCIntrospectBodyLimit(1), assert: accepted},
	}

	f := &opFixture{keys: tokenKeys()}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := f.provider(t)
			_, err := httpsec.New(append(f.wired(t, p), httpsec.EnableOIDCProvider(p, tc.opt))...)
			tc.assert(t, err)
		})
	}
}
