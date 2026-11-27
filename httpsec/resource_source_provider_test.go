package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
)

// The resource server the provider-source cases call, and the clients they hold tokens of.
const (
	psAPI          = opAudience
	psAPIURL       = opIssuer + "/api/orders"
	psJWTClient    = "orders-web"
	psOpaqueClient = "orders-opaque"
)

// psWorld is a provider on a chain that serves it and runs a resource server trusting it, with a
// user store whose answers a case changes.
type psWorld struct {
	*tokenEndpoint

	// inactive, gone, down and admin change what the user store says of every user.
	inactive, gone, down, admin *atomic.Bool

	// wrongID makes the user store answer another user's details, nilDetails answers no details
	// and no error, and hangup has the request's caller leave while the user loads.
	wrongID, nilDetails, hangup *atomic.Bool

	// leave ends the request of the call in flight.
	leave atomic.Pointer[context.CancelFunc]
}

// psSetup is what a case asks of its world.
type psSetup struct {
	// rs replaces the resource server: it is handed the world's provider.
	rs func(p *oidcprovider.Provider) httpsec.Option

	// failure, when set, receives the error the chain answers a request with, which then is written
	// as its status alone.
	failure *atomic.Pointer[error]

	// events, when set, receives the chain's security events.
	events *eventRecorder

	// provider adds options to the provider.
	provider []oidcprovider.Option

	// chain adds options to the chain, ahead of the provider and the resource server.
	chain []httpsec.Option

	// buildErr, when set, receives the chain's construction error, and the world is not built.
	buildErr *error
}

func newPSWorld(t *testing.T, setup psSetup) *psWorld {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Now())
	consents := must.Must(oidcprovider.NewMemoryConsentStore())
	w := &psWorld{
		inactive: &atomic.Bool{}, gone: &atomic.Bool{}, down: &atomic.Bool{}, admin: &atomic.Bool{},
		wrongID: &atomic.Bool{}, nilDetails: &atomic.Bool{}, hangup: &atomic.Bool{},
	}

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			switch {
			case w.hangup.Load():
				if leave := w.leave.Load(); leave != nil {
					(*leave)()
				}

				return nil, context.Canceled
			case w.nilDetails.Load():
				return nil, nil
			case w.wrongID.Load():
				return &identity.Details{ID: user + "-other", Active: true, Username: "eve@example.com"}, nil
			case w.down.Load():
				return nil, errors.New("user store secret text")
			case w.gone.Load():
				return nil, identity.ErrUserNotFound
			}

			d := &identity.Details{ID: user, Active: !w.inactive.Load(), Username: "ada@example.com"}
			if w.admin.Load() {
				d.Roles = []*identity.AssignedRole{{ID: "admin", Name: "admin", Primary: true}}
			}

			return d, nil
		},
	).AnyTimes()

	secret := []byte(tokenSecret)
	scopes := []string{"openid", "profile", "orders:read"}
	client := func(id string) oidcprovider.Client {
		return oidcprovider.Client{
			ID: id, Type: oidcprovider.Confidential, Secret: secret, RedirectURIs: []string{rpCallback},
			Scopes: scopes, Resources: []string{psAPI},
		}
	}
	opaque := client(psOpaqueClient)
	opaque.OpaqueAccessTokens = true

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       opIssuer,
		Clients:      []oidcprovider.Client{client(psJWTClient), opaque},
		Keys:         tokenKeys(),
		Users:        users,
		LoginURL:     opIssuer + "/login",
		ConsentURL:   opIssuer + "/consent",
		LogoutURL:    opIssuer + "/logout-page",
		LoggedOutURL: opIssuer + "/bye",
	}, append([]oidcprovider.Option{oidcprovider.WithClock(clk), oidcprovider.WithConsentStore(consents),
		oidcprovider.WithoutBrowserSessions(), oidcprovider.WithDPoP()}, setup.provider...)...)
	require.NoError(t, err)

	rs := httpsec.EnableResourceServer(psAPI, httpsec.WithPathPrefix("/api/"), httpsec.FromProvider(p))
	if setup.rs != nil {
		rs = setup.rs(p)
	}

	f := &opFixture{keys: tokenKeys()}
	opts := append([]httpsec.Option{httpsec.WithClock(clk), httpsec.EnableDPoP(httpsec.DPoP{PublicURL: opIssuer})},
		f.wired(t, p)...)
	if setup.failure != nil {
		opts = append(opts, httpsec.WithErrorHandler(func(rw http.ResponseWriter, _ *http.Request, err error) {
			setup.failure.Store(&err)
			rw.WriteHeader(httpsec.StatusForError(err))
		}))
	}

	if setup.events != nil {
		opts = append(opts, httpsec.EnableSecurityEvents(setup.events.sink))
	}

	opts = append(opts, setup.chain...)
	opts = append(opts, httpsec.EnableOIDCProvider(p), rs)

	chain, err := httpsec.New(opts...)
	if setup.buildErr != nil {
		*setup.buildErr = err

		return w
	}

	require.NoError(t, err)

	w.tokenEndpoint = &tokenEndpoint{p: p, chain: chain, clk: clk, consents: consents, outage: &atomic.Bool{}}

	return w
}

// forAPI asks for the resource server's identifier in an authorization request.
func forAPI(params url.Values) { params.Set("resource", psAPI) }

// token is an access token for clientID, bound to k when k is not nil, with change applied to the
// authorization request.
func (w *psWorld) token(t *testing.T, clientID string, k *dpopKey, change func(url.Values)) string {
	t.Helper()

	var more []tokenChange
	if k != nil {
		more = append(more, w.withProof(t, *k, "issuing-"+clientID, nil))
	}

	code := w.issue(t, clientID, change)
	a := w.send(t, exchangeOf(code), append([]tokenChange{asClient(clientID)}, more...)...)
	require.Equal(t, http.StatusOK, a.status, a.body)

	at, _ := a.document(t)["access_token"].(string)
	require.NotEmpty(t, at)

	return at
}

// psCall is one call of the API, and what the handler behind the chain saw.
type psCall struct {
	tokenAnswer

	// caller is the principal published for the handler, nil when it was never called.
	caller *identity.Principal
}

// call calls the API with tok under scheme, beside a proof from k when k is not nil.
func (w *psWorld) call(t *testing.T, tok string, k *dpopKey, jti string) psCall {
	t.Helper()

	return w.callOn(t, w.chain, tok, k, jti)
}

// callOn calls the API through chain, which need not be the one serving the provider, as call
// does.
func (w *psWorld) callOn(t *testing.T, chain *httpsec.Chain, tok string, k *dpopKey, jti string) psCall {
	t.Helper()

	return w.callAt(t, chain, psAPIURL, tok, k, jti)
}

// callAt calls target through chain, as callOn does the API.
func (w *psWorld) callAt(t *testing.T, chain *httpsec.Chain, target, tok string, k *dpopKey, jti string) psCall {
	t.Helper()

	ctx, leave := context.WithCancel(t.Context())
	defer leave()

	w.leave.Store(&leave)

	r := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	r.RemoteAddr = tokenAddr

	if k == nil {
		r.Header.Set("Authorization", "Bearer "+tok)
	} else {
		proof := k.validProof(jti).with(map[string]any{
			"htu": target, "iat": w.clk.Now().Unix(), "ath": tokenHash(tok),
		}).sign(t)
		r.Header.Set("Authorization", "DPoP "+tok)
		r.Header.Set("DPoP", proof)
	}

	var out psCall

	h := chain.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		out.passedOn = true
		out.caller, _ = identity.PrincipalFromContext(r.Context())
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	out.status, out.header, out.body = rec.Code, rec.Header(), rec.Body.String()

	return out
}

// holdsRole says p holds a grant of the role named name.
func holdsRole(p *identity.Principal, name string) bool {
	for _, r := range p.Roles {
		if r != nil && r.Name == name {
			return true
		}
	}

	return false
}

// TestResourceServer_FromProvider pins the provider source: the grant read on every request, the
// audience naming the resource, the provider's own type, and the local user loaded each request.
func TestResourceServer_FromProvider(t *testing.T) {
	t.Parallel()

	k := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name   string
		setup  psSetup
		act    func(t *testing.T, w *psWorld) psCall
		assert func(t *testing.T, w *psWorld, out psCall)
	}

	accepted := func(t *testing.T, _ *psWorld, out psCall) {
		t.Helper()
		require.Equal(t, http.StatusOK, out.status, out.body)
		require.True(t, out.passedOn)
		require.NotNil(t, out.caller)
		assert.Equal(t, identity.UserID("u-1"), out.caller.ID)
	}

	invalidToken := func(t *testing.T, _ *psWorld, out psCall) {
		t.Helper()
		assert.Equal(t, http.StatusUnauthorized, out.status)
		assert.False(t, out.passedOn)
		assert.Equal(t, []string{`DPoP error="invalid_token", algs="ES256"`}, out.header.Values("WWW-Authenticate"))
	}

	// hungUp receives the error of the case where the caller leaves.
	hungUp := &atomic.Pointer[error]{}

	// outage receives the events of the case where the user store is down.
	outage := &eventRecorder{}

	cases := []testCase{
		{
			name: "a bound JWT for the resource is accepted as its local user",
			act: func(t *testing.T, w *psWorld) psCall {
				return w.call(t, w.token(t, psJWTClient, &k, forAPI), &k, "j-1")
			},
			assert: accepted,
		},
		{
			name: "an opaque token is verified through the provider's store and accepted",
			act: func(t *testing.T, w *psWorld) psCall {
				return w.call(t, w.token(t, psOpaqueClient, &k, forAPI), &k, "j-1")
			},
			assert: accepted,
		},
		{
			name: "a token whose audience names no resource is refused as an invalid token",
			act: func(t *testing.T, w *psWorld) psCall {
				return w.call(t, w.token(t, psJWTClient, &k, nil), &k, "j-1")
			},
			assert: invalidToken,
		},
		{
			name: "a token for the resource's alias is accepted",
			setup: psSetup{rs: func(p *oidcprovider.Provider) httpsec.Option {
				return httpsec.EnableResourceServer("urn:orders", httpsec.WithResourceAliases(psAPI),
					httpsec.WithPathPrefix("/api/"), httpsec.FromProvider(p))
			}},
			act: func(t *testing.T, w *psWorld) psCall {
				return w.call(t, w.token(t, psJWTClient, &k, forAPI), &k, "j-1")
			},
			assert: accepted,
		},
		{
			name: "a token whose grant was revoked is refused on the next request",
			act: func(t *testing.T, w *psWorld) psCall {
				tok := w.token(t, psJWTClient, &k, forAPI)
				first := w.call(t, tok, &k, "j-1")
				require.Equal(t, http.StatusOK, first.status, first.body)

				require.NoError(t, w.p.RevokeUserGrants(t.Context(), "u-1", "test"))

				return w.call(t, tok, &k, "j-2")
			},
			assert: invalidToken,
		},
		{
			name: "an opaque token whose grant was revoked is refused on the next request",
			act: func(t *testing.T, w *psWorld) psCall {
				tok := w.token(t, psOpaqueClient, &k, forAPI)
				require.Equal(t, http.StatusOK, w.call(t, tok, &k, "j-1").status)

				require.NoError(t, w.p.RevokeUserGrants(t.Context(), "u-1", "test"))

				return w.call(t, tok, &k, "j-2")
			},
			assert: invalidToken,
		},
		{
			name: "an unbound token is refused by default",
			act: func(t *testing.T, w *psWorld) psCall {
				return w.call(t, w.token(t, psJWTClient, nil, forAPI), nil, "")
			},
			assert: invalidToken,
		},
		{
			name: "an ID token of the provider is refused as an invalid token",
			act: func(t *testing.T, w *psWorld) psCall {
				code := w.issue(t, psJWTClient, forAPI)
				a := w.send(t, exchangeOf(code), asClient(psJWTClient), w.withProof(t, k, "issuing", nil))
				require.Equal(t, http.StatusOK, a.status, a.body)

				idToken, _ := a.document(t)["id_token"].(string)
				require.NotEmpty(t, idToken)

				return w.call(t, idToken, &k, "j-1")
			},
			assert: invalidToken,
		},
		{
			name: "an inactive local user is refused as an invalid token",
			act: func(t *testing.T, w *psWorld) psCall {
				tok := w.token(t, psJWTClient, &k, forAPI)
				w.inactive.Store(true)

				return w.call(t, tok, &k, "j-1")
			},
			assert: invalidToken,
		},
		{
			name: "a local user no longer in the store is refused as an invalid token",
			act: func(t *testing.T, w *psWorld) psCall {
				tok := w.token(t, psJWTClient, &k, forAPI)
				w.gone.Store(true)

				return w.call(t, tok, &k, "j-1")
			},
			assert: invalidToken,
		},
		{
			name: "a loader that answers another user's details is refused as an invalid token",
			act: func(t *testing.T, w *psWorld) psCall {
				tok := w.token(t, psJWTClient, &k, forAPI)
				w.wrongID.Store(true)

				return w.call(t, tok, &k, "j-1")
			},
			assert: invalidToken,
		},
		{
			name: "a loader that answers no details and no error is refused as an invalid token",
			act: func(t *testing.T, w *psWorld) psCall {
				tok := w.token(t, psJWTClient, &k, forAPI)
				w.nilDetails.Store(true)

				return w.call(t, tok, &k, "j-1")
			},
			assert: invalidToken,
		},
		{
			name:  "a caller who leaves while the user loads is neither refused nor an outage",
			setup: psSetup{failure: hungUp},
			act: func(t *testing.T, w *psWorld) psCall {
				tok := w.token(t, psJWTClient, &k, forAPI)
				w.hangup.Store(true)

				return w.call(t, tok, &k, "j-1")
			},
			assert: func(t *testing.T, _ *psWorld, out psCall) {
				assert.False(t, out.passedOn)

				failure := hungUp.Load()
				require.NotNil(t, failure)
				require.ErrorIs(t, *failure, context.Canceled)
				assert.NotErrorIs(t, *failure, httpsec.ErrInvalidToken, "a hang-up is not a refusal")
				assert.NotContains(t, (*failure).Error(), "could not be loaded", "a hang-up is not an outage")
			},
		},
		{
			name:  "a user store that fails is a dependency failure, not a refusal",
			setup: psSetup{events: outage},
			act: func(t *testing.T, w *psWorld) psCall {
				tok := w.token(t, psJWTClient, &k, forAPI)
				w.down.Store(true)

				return w.call(t, tok, &k, "j-1")
			},
			assert: func(t *testing.T, _ *psWorld, out psCall) {
				assert.Equal(t, http.StatusInternalServerError, out.status)
				assert.Empty(t, out.header.Values("WWW-Authenticate"))
				assert.NotContains(t, out.body, "secret text")

				for _, e := range outage.all() {
					assert.NotEqual(t, event.OutcomeFailure, e.Outcome, "the outage was recorded as a refused credential: %s", e.Name)
				}
			},
		},
		{
			name: "a role removed after the token was issued is not held",
			act: func(t *testing.T, w *psWorld) psCall {
				w.admin.Store(true)
				tok := w.token(t, psJWTClient, &k, forAPI)

				first := w.call(t, tok, &k, "j-1")
				require.NotNil(t, first.caller)
				require.True(t, holdsRole(first.caller, "admin"), "the role is held while it is granted")

				w.admin.Store(false)

				return w.call(t, tok, &k, "j-2")
			},
			assert: func(t *testing.T, w *psWorld, out psCall) {
				accepted(t, w, out)
				assert.False(t, holdsRole(out.caller, "admin"))
			},
		},
		{
			name: "the caller carries the token's scopes",
			act: func(t *testing.T, w *psWorld) psCall {
				return w.call(t, w.token(t, psJWTClient, &k, func(v url.Values) {
					forAPI(v)
					v.Set("scope", "openid orders:read")
				}), &k, "j-1")
			},
			assert: func(t *testing.T, w *psWorld, out psCall) {
				accepted(t, w, out)
				assert.ElementsMatch(t, []string{"openid", "orders:read"}, out.caller.Scopes)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newPSWorld(t, tc.setup)
			tc.assert(t, w, tc.act(t, w))
		})
	}
}

// TestResourceServer_FromProviderConstruction pins the provider source's wiring mistakes.
func TestResourceServer_FromProviderConstruction(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		build  func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, err error)
	}

	refused := func(names ...string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)
			for _, name := range names {
				assert.Contains(t, err.Error(), name)
			}
		}
	}

	cases := []testCase{
		{
			name: "the chain's own provider",
			build: func(t *testing.T) []httpsec.Option {
				p := f.provider(t)

				return append(f.wired(t, p), httpsec.EnableCertificateBinding(), httpsec.EnableOIDCProvider(p),
					httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(p)))
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "a nil provider",
			build: func(t *testing.T) []httpsec.Option {
				p := f.provider(t)

				return append(f.wired(t, p), httpsec.EnableCertificateBinding(), httpsec.EnableOIDCProvider(p),
					httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(nil)))
			},
			assert: refused("FromProvider", "nil"),
		},
		{
			name: "a provider that is not the chain's",
			build: func(t *testing.T) []httpsec.Option {
				p := f.provider(t)

				return append(f.wired(t, p), httpsec.EnableCertificateBinding(), httpsec.EnableOIDCProvider(p),
					httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(f.provider(t))))
			},
			assert: refused("FromProvider", "EnableOIDCProvider"),
		},
		{
			name: "a chain with no provider trusts a provider another chain serves",
			build: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCertificateBinding(),
					httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(f.provider(t)))}
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "a nil provider on a chain with no provider",
			build: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCertificateBinding(),
					httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(nil))}
			},
			assert: refused("FromProvider", "nil"),
		},
		{
			name: "the provider twice in one resource server",
			build: func(t *testing.T) []httpsec.Option {
				p := f.provider(t)

				return append(f.wired(t, p), httpsec.EnableCertificateBinding(), httpsec.EnableOIDCProvider(p),
					httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(p), httpsec.FromProvider(p)))
			},
			assert: refused(opIssuer),
		},
		{
			name: "the chain's own issuer as a remote issuer",
			build: func(t *testing.T) []httpsec.Option {
				p := f.provider(t)

				return append(f.wired(t, p), httpsec.EnableCertificateBinding(), httpsec.EnableOIDCProvider(p),
					httpsec.EnableResourceServer("urn:orders", httpsec.FromIssuer(p.Issuer())))
			},
			assert: refused("FromIssuer", opIssuer, "only FromProvider may trust"),
		},
		{
			name: "the chain's own issuer as an introspection source",
			build: func(t *testing.T) []httpsec.Option {
				p := f.provider(t)

				return append(f.wired(t, p), httpsec.EnableCertificateBinding(), httpsec.EnableOIDCProvider(p),
					httpsec.EnableResourceServer("urn:orders", httpsec.FromIntrospection(p.Issuer(),
						p.Issuer()+"/introspect", "orders-api", httpsec.WithIntrospectionSecret("s"), httpsec.WithOpaquePrefix("op."))))
			},
			assert: refused("FromIntrospection", opIssuer, "only FromProvider may trust"),
		},
		{
			name: "a nil source option is skipped",
			build: func(t *testing.T) []httpsec.Option {
				p := f.provider(t)

				return append(f.wired(t, p), httpsec.EnableCertificateBinding(), httpsec.EnableOIDCProvider(p),
					httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(p, nil)))
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(tc.build(t)...)
			tc.assert(t, err)
		})
	}
}

// TestResourceServer_FromProviderRefusalIdentity pins that a provider token the source refuses is
// the invalid-token refusal, which is the authentication failure too.
func TestResourceServer_FromProviderRefusalIdentity(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)
	p := f.provider(t)

	c, err := httpsec.New(append(f.wired(t, p), httpsec.EnableCertificateBinding(), httpsec.EnableOIDCProvider(p),
		httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"), httpsec.FromProvider(p)))...)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.example.com/api/orders", nil)
	req.Header.Set("Authorization", "Bearer at.not-a-token-the-provider-issued")

	out := serve(t, c, req)

	require.ErrorIs(t, out.err, httpsec.ErrInvalidToken)
	assert.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
	assert.False(t, out.handlerRan)
	assert.NotContains(t, out.err.Error(), "not-a-token")
}

// TestResourceServer_AudienceNamed pins that a token's audience must name the resource server or
// an alias by exact match, and that an empty audience names nothing.
func TestResourceServer_AudienceNamed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		audience []string
		assert   func(t *testing.T, named bool)
	}{
		{"no audience", nil, func(t *testing.T, named bool) { assert.False(t, named) }},
		{"an empty list", []string{}, func(t *testing.T, named bool) { assert.False(t, named) }},
		{"an empty string", []string{""}, func(t *testing.T, named bool) { assert.False(t, named) }},
		{"only the issuer", []string{opIssuer}, func(t *testing.T, named bool) { assert.False(t, named) }},
		{"the identifier in another case", []string{"URN:ORDERS"}, func(t *testing.T, named bool) { assert.False(t, named) }},
		{"the identifier", []string{"urn:orders"}, func(t *testing.T, named bool) { assert.True(t, named) }},
		{"an alias beside another audience", []string{opIssuer, "urn:legacy"}, func(t *testing.T, named bool) { assert.True(t, named) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, httpsec.AudienceNamedBy("urn:orders", []string{"urn:legacy"}, tc.audience))
		})
	}
}

// apiChain is a token chain covering /api/ that runs no provider and trusts p through FromProvider:
// the API of a binary whose provider another chain serves.
func apiChain(t *testing.T, w *psWorld, p *oidcprovider.Provider) *httpsec.Chain {
	t.Helper()

	c, err := httpsec.New(httpsec.WithClock(w.clk),
		httpsec.EnableDPoP(httpsec.DPoP{PublicURL: opIssuer}),
		httpsec.EnableResourceServer(psAPI, httpsec.WithPathPrefix("/api/"), httpsec.FromProvider(p)))
	require.NoError(t, err)

	return c
}

// TestFromProvider_OtherChain pins that a provider source trusts a provider another chain serves,
// verifying its tokens as on the provider's own chain, and that on a chain running a provider it
// trusts only that one.
func TestFromProvider_OtherChain(t *testing.T) {
	t.Parallel()

	k := newDPoPKey(t, elliptic.P256())
	f := newOPFixture(t)

	// noRS leaves the provider's own chain without a resource server, so only the token chain
	// judges the API's tokens.
	noRS := psSetup{rs: func(*oidcprovider.Provider) httpsec.Option { return nil }}

	type testCase struct {
		name   string
		act    func(t *testing.T) (psCall, error)
		assert func(t *testing.T, out psCall, err error)
	}

	accepted := func(t *testing.T, out psCall, err error) {
		t.Helper()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, out.status, out.body)
		require.True(t, out.passedOn)
		require.NotNil(t, out.caller)
		assert.Equal(t, identity.UserID("u-1"), out.caller.ID)
	}

	refused := func(names ...string) func(t *testing.T, _ psCall, err error) {
		return func(t *testing.T, _ psCall, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)
			for _, name := range names {
				assert.ErrorContains(t, err, name)
			}
		}
	}

	cases := []testCase{
		{
			name: "a bound JWT the other chain's provider issued is accepted as its local user",
			act: func(t *testing.T) (psCall, error) {
				w := newPSWorld(t, noRS)

				return w.callOn(t, apiChain(t, w, w.p), w.token(t, psJWTClient, &k, forAPI), &k, "j-1"), nil
			},
			assert: accepted,
		},
		{
			name: "a bound opaque token the other chain's provider issued is accepted as its local user",
			act: func(t *testing.T) (psCall, error) {
				w := newPSWorld(t, noRS)

				return w.callOn(t, apiChain(t, w, w.p), w.token(t, psOpaqueClient, &k, forAPI), &k, "j-1"), nil
			},
			assert: accepted,
		},
		{
			name: "a token whose grant was revoked through the provider is refused on the next request",
			act: func(t *testing.T) (psCall, error) {
				w := newPSWorld(t, noRS)
				api := apiChain(t, w, w.p)

				tok := w.token(t, psJWTClient, &k, forAPI)
				first := w.callOn(t, api, tok, &k, "j-1")
				require.Equal(t, http.StatusOK, first.status, first.body)

				require.NoError(t, w.p.RevokeUserGrants(t.Context(), "u-1", "test"))

				return w.callOn(t, api, tok, &k, "j-2"), nil
			},
			assert: func(t *testing.T, out psCall, err error) {
				require.NoError(t, err)
				assert.Equal(t, http.StatusUnauthorized, out.status)
				assert.False(t, out.passedOn)
				assert.Equal(t, []string{`DPoP error="invalid_token", algs="ES256"`}, out.header.Values("WWW-Authenticate"))
			},
		},
		{
			name: "a chain running one provider refuses a source trusting another",
			act: func(t *testing.T) (psCall, error) {
				p := f.provider(t)
				_, err := httpsec.New(append(f.wired(t, p), httpsec.EnableCertificateBinding(), httpsec.EnableOIDCProvider(p),
					httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(f.provider(t))))...)

				return psCall{}, err
			},
			assert: refused("FromProvider", "EnableOIDCProvider"),
		},
		{
			name: "a nil provider is refused on a chain running none",
			act: func(*testing.T) (psCall, error) {
				_, err := httpsec.New(httpsec.EnableCertificateBinding(),
					httpsec.EnableResourceServer(psAPI, httpsec.FromProvider(nil)))

				return psCall{}, err
			},
			assert: refused("FromProvider", "nil"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out, err := tc.act(t)
			tc.assert(t, out, err)
		})
	}
}

// trustedOutcome is what a case of TestResourceServer_TrustedProviderRules observed: the chain's
// construction error, or the request it served and what its sources saw.
type trustedOutcome struct {
	err error

	route rsRoute

	// offered is how many tokens the stub source was offered; hits how many requests the
	// introspection endpoint received.
	offered, hits int

	// calls are the API calls a case made, in the order it made them.
	calls []psCall
}

// TestResourceServer_TrustedProviderRules pins that the rules naming the chain's provider hold for
// a provider a provider source trusts on a chain that runs none: its issuer is no resource
// identifier and no remote source's, its largest token is read, and its own formats never reach an
// introspection endpoint.
func TestResourceServer_TrustedProviderRules(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		act    func(t *testing.T, p *oidcprovider.Provider) trustedOutcome
		assert func(t *testing.T, out trustedOutcome)
	}

	build := func(opts ...httpsec.Option) trustedOutcome {
		_, err := httpsec.New(append([]httpsec.Option{httpsec.EnableCertificateBinding()}, opts...)...)

		return trustedOutcome{err: err}
	}

	issuerRefused := func(t *testing.T, out trustedOutcome) {
		t.Helper()
		require.ErrorIs(t, out.err, httpsec.ErrConfig)
		assert.ErrorContains(t, out.err, opIssuer)
		assert.ErrorContains(t, out.err, "UserInfo")
	}

	remoteRefused := func(option string) func(t *testing.T, out trustedOutcome) {
		return func(t *testing.T, out trustedOutcome) {
			t.Helper()
			require.ErrorIs(t, out.err, httpsec.ErrConfig)
			assert.ErrorContains(t, out.err, option)
			assert.ErrorContains(t, out.err, opIssuer)
			assert.ErrorContains(t, out.err, "only FromProvider may trust")
		}
	}

	// buildOn builds a chain with only the options given, so a case states the chain's binding.
	buildOn := func(opts ...httpsec.Option) trustedOutcome {
		_, err := httpsec.New(opts...)

		return trustedOutcome{err: err}
	}

	built := func(t *testing.T, out trustedOutcome) {
		t.Helper()
		require.NoError(t, out.err)
	}

	refusedNaming := func(names ...string) func(t *testing.T, out trustedOutcome) {
		return func(t *testing.T, out trustedOutcome) {
			t.Helper()
			require.ErrorIs(t, out.err, httpsec.ErrConfig)
			for _, name := range names {
				assert.ErrorContains(t, out.err, name)
			}
		}
	}

	// bindingRefused is refusedNaming for a source's binding, whose message names the resource
	// server and FromProvider rather than EnableOIDCProvider, which the chain does not run.
	bindingRefused := func(names ...string) func(t *testing.T, out trustedOutcome) {
		return func(t *testing.T, out trustedOutcome) {
			t.Helper()
			refusedNaming(names...)(t, out)
			assert.NotContains(t, out.err.Error(), "EnableOIDCProvider")
		}
	}

	dpopChain := httpsec.EnableDPoP(httpsec.DPoP{PublicURL: opIssuer})

	cases := []testCase{
		{
			name: "two provider sources naming different providers in one resource server",
			act: func(t *testing.T, p *oidcprovider.Provider) trustedOutcome {
				other := f.providerOver(t, opIssuer+"/tenant-b", f.keys, nil)

				return build(httpsec.EnableResourceServer("urn:orders",
					httpsec.FromProvider(other), httpsec.FromProvider(p)))
			},
			assert: refusedNaming("urn:orders", "FromProvider more than once", "one provider"),
		},
		{
			name: "two resource servers each trusting its own provider route each one's opaque token to it",
			act: func(t *testing.T, _ *oidcprovider.Provider) trustedOutcome {
				k := newDPoPKey(t, elliptic.P256())
				noRS := psSetup{rs: func(*oidcprovider.Provider) httpsec.Option { return nil }}
				a, b := newPSWorld(t, noRS), newPSWorld(t, noRS)

				api, err := httpsec.New(httpsec.WithClock(a.clk), dpopChain,
					httpsec.EnableResourceServer(psAPI, httpsec.WithPathPrefix("/api/"), httpsec.FromProvider(a.p)),
					httpsec.EnableResourceServer("urn:billing", httpsec.WithResourceAliases(psAPI),
						httpsec.WithPathPrefix("/billing/"), httpsec.FromProvider(b.p)))
				if err != nil {
					return trustedOutcome{err: err}
				}

				billing := opIssuer + "/billing/invoices"
				tokA := a.token(t, psOpaqueClient, &k, forAPI)
				tokB := b.token(t, psOpaqueClient, &k, forAPI)

				return trustedOutcome{calls: []psCall{
					a.callAt(t, api, psAPIURL, tokA, &k, "j-1"),
					b.callAt(t, api, billing, tokB, &k, "j-2"),
					b.callAt(t, api, psAPIURL, tokB, &k, "j-3"),
				}}
			},
			assert: func(t *testing.T, out trustedOutcome) {
				require.NoError(t, out.err)
				require.Len(t, out.calls, 3)
				assert.Equal(t, http.StatusOK, out.calls[0].status, "first provider's token on its own prefix: %s",
					out.calls[0].body)
				assert.Equal(t, http.StatusOK, out.calls[1].status, "second provider's token on its own prefix: %s",
					out.calls[1].body)
				assert.Equal(t, http.StatusUnauthorized, out.calls[2].status,
					"second provider's token on the first's prefix")
				assert.False(t, out.calls[2].passedOn)
			},
		},
		{
			name: "a provider binding to DPoP trusted by a chain checking only certificates",
			act: func(t *testing.T, _ *oidcprovider.Provider) trustedOutcome {
				p := f.providerFor(t, []oidcprovider.Client{requiring("dpop-app", oidcprovider.BindingDPoP)},
					oidcprovider.WithDPoP())

				return buildOn(httpsec.EnableCertificateBinding(),
					httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(p)))
			},
			assert: bindingRefused("urn:orders", "FromProvider", "DPoP", "EnableDPoP"),
		},
		{
			name: "a provider binding to certificates trusted by a chain checking only DPoP",
			act: func(t *testing.T, _ *oidcprovider.Provider) trustedOutcome {
				p := f.providerFor(t, []oidcprovider.Client{requiring("mtls-app", oidcprovider.BindingMTLS)})

				return buildOn(dpopChain, httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(p)))
			},
			assert: bindingRefused("urn:orders", "FromProvider", "certificate", "EnableCertificateBinding"),
		},
		{
			name: "a provider binding to DPoP trusted by a chain checking DPoP",
			act: func(t *testing.T, _ *oidcprovider.Provider) trustedOutcome {
				p := f.providerFor(t, []oidcprovider.Client{requiring("dpop-app", oidcprovider.BindingDPoP)},
					oidcprovider.WithDPoP())

				return buildOn(dpopChain, httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(p)))
			},
			assert: built,
		},
		{
			name: "a provider binding to certificates trusted by a chain checking certificates",
			act: func(t *testing.T, _ *oidcprovider.Provider) trustedOutcome {
				p := f.providerFor(t, []oidcprovider.Client{requiring("mtls-app", oidcprovider.BindingMTLS)})

				return buildOn(httpsec.EnableCertificateBinding(),
					httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(p)))
			},
			assert: built,
		},
		{
			name: "a provider built with DPoP and no client requiring it, trusted by a chain checking only certificates",
			act: func(t *testing.T, _ *oidcprovider.Provider) trustedOutcome {
				p := f.provider(t, oidcprovider.WithDPoP())

				return buildOn(httpsec.EnableCertificateBinding(),
					httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(p)))
			},
			assert: bindingRefused("urn:orders", "FromProvider", "DPoP", "WithDPoP", "EnableDPoP"),
		},
		{
			name: "a provider built with DPoP trusted by a chain enabling DPoP",
			act: func(t *testing.T, _ *oidcprovider.Provider) trustedOutcome {
				p := f.provider(t, oidcprovider.WithDPoP())

				return buildOn(dpopChain, httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(p)))
			},
			assert: built,
		},
		{
			name: "a resource identifier equal to the trusted provider's issuer",
			act: func(_ *testing.T, p *oidcprovider.Provider) trustedOutcome {
				return build(httpsec.EnableResourceServer(opIssuer, httpsec.FromProvider(p)))
			},
			assert: issuerRefused,
		},
		{
			name: "an alias equal to the trusted provider's issuer",
			act: func(_ *testing.T, p *oidcprovider.Provider) trustedOutcome {
				return build(httpsec.EnableResourceServer("urn:orders", httpsec.WithResourceAliases(opIssuer),
					httpsec.FromProvider(p)))
			},
			assert: issuerRefused,
		},
		{
			name: "another resource server's identifier equal to the trusted provider's issuer",
			act: func(_ *testing.T, p *oidcprovider.Provider) trustedOutcome {
				return build(
					httpsec.EnableResourceServer(opIssuer, httpsec.WithPathPrefix("/other/"),
						httpsec.WithStubSource(&httpsec.StubSource{Name: "other", Issuer: "https://other.example.com"})),
					httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"), httpsec.FromProvider(p)))
			},
			assert: issuerRefused,
		},
		{
			name: "a remote issuer naming the trusted provider beside it",
			act: func(_ *testing.T, p *oidcprovider.Provider) trustedOutcome {
				return build(httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(p),
					httpsec.FromIssuer(p.Issuer())))
			},
			assert: remoteRefused("FromIssuer"),
		},
		{
			name: "a remote issuer naming the trusted provider in another resource server, listed first",
			act: func(_ *testing.T, p *oidcprovider.Provider) trustedOutcome {
				return build(
					httpsec.EnableResourceServer("urn:partner", httpsec.WithPathPrefix("/partner/"),
						httpsec.FromIssuer(p.Issuer())),
					httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"), httpsec.FromProvider(p)))
			},
			assert: remoteRefused("FromIssuer"),
		},
		{
			name: "an introspection source naming the trusted provider in another resource server",
			act: func(_ *testing.T, p *oidcprovider.Provider) trustedOutcome {
				return build(
					httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"), httpsec.FromProvider(p)),
					httpsec.EnableResourceServer("urn:partner", httpsec.WithPathPrefix("/partner/"),
						httpsec.FromIntrospection(p.Issuer(), p.Issuer()+"/introspect", "orders-api",
							httpsec.WithIntrospectionSecret("s"), httpsec.WithOpaquePrefix("op."))))
			},
			assert: remoteRefused("FromIntrospection"),
		},
		{
			name: "a token as large as the trusted provider issues is not refused for its size",
			act: func(t *testing.T, p *oidcprovider.Provider) trustedOutcome {
				require.Greater(t, p.MaxAccessTokenSize(), 8<<10, "the provider's bound must exceed the default")

				src := &httpsec.StubSource{Name: "stub", Provider: true, Unbound: true}
				tok := "at." + strings.Repeat("A", p.MaxAccessTokenSize()-len("at."))

				route := routeThrough(t, "/stub/x", "Bearer "+tok, httpsec.EnableCertificateBinding(),
					httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"), httpsec.FromProvider(p)),
					httpsec.EnableResourceServer("urn:stub", httpsec.WithPathPrefix("/stub/"), httpsec.WithStubSource(src)))

				return trustedOutcome{route: route, offered: src.Offered()}
			},
			assert: func(t *testing.T, out trustedOutcome) {
				require.NoError(t, out.route.err)
				assert.True(t, out.route.handlerRan)
				assert.Equal(t, 1, out.offered)
			},
		},
		{
			name: "the trusted provider's refresh token at an introspection-only path never reaches the endpoint",
			act: func(t *testing.T, p *oidcprovider.Provider) trustedOutcome {
				ep := newISEndpoint(t)
				ep.set(nil)

				transport, ok := ep.srv.Client().Transport.(*http.Transport)
				require.True(t, ok)

				oc, err := outbound.New(outbound.WithHTTPClient(&http.Client{Transport: transport}))
				require.NoError(t, err)

				route := routeThrough(t, "/partner/x", "Bearer rt.a-refresh-token-of-the-provider",
					httpsec.EnableCertificateBinding(),
					httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"), httpsec.FromProvider(p)),
					httpsec.EnableResourceServer("urn:partner", httpsec.WithPathPrefix("/partner/"),
						httpsec.FromIntrospection(ep.srv.URL, ep.srv.URL+"/introspect", "partner-api",
							httpsec.WithIntrospectionSecret("rs-secret"), httpsec.WithOutboundClient(oc),
							httpsec.WithUnboundTokens())))

				return trustedOutcome{route: route, hits: int(ep.hits.Load())}
			},
			assert: func(t *testing.T, out trustedOutcome) {
				require.ErrorIs(t, out.route.err, httpsec.ErrInvalidToken)
				assert.False(t, out.route.handlerRan)
				assert.False(t, out.route.laterRan)
				assert.Zero(t, out.hits, "the provider's token was sent to the introspection endpoint")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.act(t, f.provider(t)))
		})
	}
}
