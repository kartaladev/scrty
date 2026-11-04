package oidcprovider_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

const (
	billingBackChannel = "https://billing.example.com/backchannel"
	weekBackChannel    = "https://week.example.com/backchannel"
	logoutEventName    = "http://schemas.openid.net/event/backchannel-logout"
)

// handedOver is one token a consumer's delivery received.
type handedOver struct {
	uri, raw string
}

// logoutRecorder is a consumer's delivery that keeps what it is handed.
type logoutRecorder struct {
	mu   sync.Mutex
	seen []handedOver
}

// Deliver implements oidcprovider.LogoutDelivery.
func (r *logoutRecorder) Deliver(_ context.Context, uri, raw string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, handedOver{uri: uri, raw: raw})

	return nil
}

func (r *logoutRecorder) handed() []handedOver {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]handedOver(nil), r.seen...)
}

// listening gives clientID a back-channel logout URI, keeping the rest of how the exchange fixtures
// register it. change alters it further.
func listening(t *testing.T, e *endFixture, clientID, redirect, uri string, change func(*oidcprovider.Client)) {
	t.Helper()

	c := oidcprovider.Client{
		ID: clientID, Type: oidcprovider.Confidential, Secret: []byte(exchangeSecret), RedirectURIs: []string{redirect},
		Scopes:               []string{"openid", "profile", "offline_access"},
		GrantTypes:           []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
		BackChannelLogoutURI: uri,
	}
	if change != nil {
		change(&c)
	}
	require.NoError(t, e.registry.Put(t.Context(), c))
}

// drained waits until what was handed on has been dealt with.
func drained(t *testing.T, p *oidcprovider.Provider) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
	defer cancel()
	require.NoError(t, p.Shutdown(ctx))
}

// rawClaims reads a compact JWS's claims without decoding their values.
func rawClaims(t *testing.T, raw string) map[string]json.RawMessage {
	t.Helper()

	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3, "a compact JWS")
	text, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(text, &claims))

	return claims
}

// TestProvider_LogoutToken pins what one client is sent when a sign-in holding its grant ends.
func TestProvider_LogoutToken(t *testing.T) {
	t.Parallel()

	type result struct {
		e      *endFixture
		scene  *refreshScene
		signIn oidcprovider.SignIn
		raw    string
		// renewedIDToken is the ID token of a refresh made before the sign-in ended.
		renewedIDToken string
	}

	type testCase struct {
		name string
		// client alters how billing-web is registered.
		client func(*oidcprovider.Client)
		assert func(t *testing.T, r result)
	}

	cases := []testCase{
		{
			name: "its header says what it is, and that it is signed with the default algorithm",
			assert: func(t *testing.T, r result) {
				header, _ := decodeJWT(t, r.raw)
				assert.Equal(t, token.TypeLogoutToken, header["typ"])
				assert.Equal(t, "logout+jwt", header["typ"])
				assert.Equal(t, string(signingkey.RS256), header["alg"])
			},
		},
		{
			name:   "it is signed with the client's ID token algorithm",
			client: func(c *oidcprovider.Client) { c.IDTokenAlg = signingkey.ES256 },
			assert: func(t *testing.T, r result) {
				header, _ := decodeJWT(t, r.raw)
				assert.Equal(t, string(signingkey.ES256), header["alg"])
				_, err := verifyAs(t, r.e.exchangeFixture, token.TypeLogoutToken, r.raw)
				assert.NoError(t, err)
			},
		},
		{
			name: "it verifies under the provider's keys as a logout token, and as nothing else",
			assert: func(t *testing.T, r result) {
				_, err := verifyAs(t, r.e.exchangeFixture, token.TypeLogoutToken, r.raw)
				require.NoError(t, err)
				_, err = verifyAs(t, r.e.exchangeFixture, token.TypeIDToken, r.raw)
				assert.Error(t, err, "it cannot pass for an ID token")
			},
		},
		{
			name: "it is no access token",
			assert: func(t *testing.T, r result) {
				_, err := r.e.p.VerifyAccessToken(t.Context(), r.raw)
				var refusal *oidcprovider.Error
				require.ErrorAs(t, err, &refusal)
				assert.Equal(t, oidcprovider.CodeInvalidToken, refusal.Code)
			},
		},
		{
			name: "it names the issuer, and the client as its one audience",
			assert: func(t *testing.T, r result) {
				_, claims := decodeJWT(t, r.raw)
				assert.Equal(t, issuer, claims["iss"])
				assert.Contains(t, []any{"billing-web", []any{"billing-web"}}, claims["aud"])
			},
		},
		{
			name: "it lasts no more than two minutes from now",
			assert: func(t *testing.T, r result) {
				_, claims := decodeJWT(t, r.raw)
				iat, exp := claims["iat"].(float64), claims["exp"].(float64)
				assert.Equal(t, unixOf(r.e.clk.Now()), iat)
				assert.Greater(t, exp, iat)
				assert.LessOrEqual(t, exp-iat, float64(120))
			},
		},
		{
			name: "its events hold the logout event with an empty object, and nothing else",
			assert: func(t *testing.T, r result) {
				assert.Equal(t, `{"`+logoutEventName+`":{}}`, string(rawClaims(t, r.raw)["events"]))
			},
		},
		{
			name: "it names the sign-in's user and family, and no nonce",
			assert: func(t *testing.T, r result) {
				_, claims := decodeJWT(t, r.raw)
				assert.Equal(t, string(r.signIn.User), claims["sub"])
				assert.Equal(t, r.signIn.Family.String(), claims["sid"])
				assert.NotContains(t, claims, "nonce")
			},
		},
		{
			name: "its sid is that of the ID tokens from the sign-in, a refreshed one included",
			assert: func(t *testing.T, r result) {
				_, logout := decodeJWT(t, r.raw)
				_, first := decodeJWT(t, r.scene.first.IDToken)
				_, renewed := decodeJWT(t, r.renewedIDToken)
				assert.NotEmpty(t, logout["sid"])
				assert.Equal(t, first["sid"], logout["sid"])
				assert.Equal(t, renewed["sid"], logout["sid"])
			},
		},
		{
			name: "it has a jti",
			assert: func(t *testing.T, r result) {
				_, claims := decodeJWT(t, r.raw)
				assert.NotEmpty(t, claims["jti"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			recorder := &logoutRecorder{}
			e := newEndFixture(t, oidcprovider.WithLogoutDelivery(recorder))
			listening(t, e, "billing-web", authzRedirect, billingBackChannel, tc.client)
			signIn := e.signInOf("u-1", "", "")
			scene := e.online(t, signIn)
			renewed, err := e.p.Token(t.Context(), scene.again(scene.first.RefreshToken))
			require.NoError(t, err)

			_, err = e.p.EndSignIn(t.Context(), oidcprovider.SignInSelector{Family: signIn.Family})
			require.NoError(t, err)
			drained(t, e.p)

			handed := recorder.handed()
			require.Len(t, handed, 1)
			assert.Equal(t, billingBackChannel, handed[0].uri)
			tc.assert(t, result{e: e, scene: scene, signIn: signIn, raw: handed[0].raw, renewedIDToken: renewed.IDToken})
		})
	}
}

// TestProvider_LogoutToken_Fresh pins that no two tokens share a jti, for two clients of one end.
func TestProvider_LogoutToken_Fresh(t *testing.T) {
	t.Parallel()

	recorder := &logoutRecorder{}
	e := newEndFixture(t, oidcprovider.WithLogoutDelivery(recorder))
	listening(t, e, "billing-web", authzRedirect, billingBackChannel, nil)
	listening(t, e, weekClient, weekRedirect, weekBackChannel, nil)
	signIn := e.signInOf("u-1", "", "")
	e.online(t, signIn)
	e.grantFrom(t, signIn, weekClient, weekRedirect, "openid", "profile")

	_, err := e.p.EndSignIn(t.Context(), oidcprovider.SignInSelector{Family: signIn.Family})
	require.NoError(t, err)
	drained(t, e.p)

	handed := recorder.handed()
	require.Len(t, handed, 2)
	_, first := decodeJWT(t, handed[0].raw)
	_, second := decodeJWT(t, handed[1].raw)
	assert.NotEqual(t, first["jti"], second["jti"])
}

// TestProvider_LogoutToken_ShortKeyWindow pins that keys with a usable window under two minutes, which
// New accepts when every client fits them, can still sign a logout token: the token lasts the window.
func TestProvider_LogoutToken_ShortKeyWindow(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		keys   func(t *testing.T) signingkey.KeySource
		assert func(t *testing.T, lifetime float64)
	}

	cases := []testCase{
		{
			name: "a minute's window gives a minute",
			keys: func(t *testing.T) signingkey.KeySource {
				return reportingKeys{KeySource: newExchangeKeys(t), lifetime: 2 * time.Hour, rotate: 2*time.Hour - time.Minute}
			},
			assert: func(t *testing.T, lifetime float64) { assert.Equal(t, float64(60), lifetime) },
		},
		{
			name: "a window of more than two minutes gives two",
			keys: func(t *testing.T) signingkey.KeySource {
				return reportingKeys{KeySource: newExchangeKeys(t), lifetime: 2 * time.Hour, rotate: time.Hour}
			},
			assert: func(t *testing.T, lifetime float64) { assert.Equal(t, float64(120), lifetime) },
		},
		{
			name:   "keys reporting no window give two",
			keys:   func(t *testing.T) signingkey.KeySource { return newExchangeKeys(t) },
			assert: func(t *testing.T, lifetime float64) { assert.Equal(t, float64(120), lifetime) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			deps := validDeps(t)
			deps.Keys = tc.keys(t)
			client := webClient()
			client.IDTokenLifetime, client.AccessTokenLifetime = time.Minute, time.Minute
			deps.Clients = []oidcprovider.Client{client}
			p, err := oidcprovider.New(deps)
			require.NoError(t, err)
			rc, err := p.ClientForTest(t.Context(), client.ID)
			require.NoError(t, err)
			family, err := id.NewV7Generator().NewID()
			require.NoError(t, err)

			raw, err := p.LogoutTokenForTest(t.Context(), oidcprovider.ClientToNotify{ClientID: client.ID, User: "u-1", SignInFamily: family}, rc)
			require.NoError(t, err)

			_, claims := decodeJWT(t, raw)
			tc.assert(t, claims["exp"].(float64)-claims["iat"].(float64))
		})
	}
}

// endingGrants is a real grant store whose ends report what a row names, so that a row about delivery
// needs no authorization flow to have a grant.
type endingGrants struct {
	oidcprovider.GrantStore

	mu    sync.Mutex
	ended map[id.ID][]oidcprovider.Grant
}

// push names what the end of family reports.
func (g *endingGrants) push(family id.ID, ended []oidcprovider.Grant) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ended == nil {
		g.ended = map[id.ID][]oidcprovider.Grant{}
	}
	g.ended[family] = ended
}

// EndSignIns implements oidcprovider.GrantStore.
func (g *endingGrants) EndSignIns(_ context.Context, sel oidcprovider.SignInSelector, _ time.Time) ([]oidcprovider.Grant, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ended := g.ended[sel.Family]
	delete(g.ended, sel.Family)

	return ended, nil
}

// lockedBuffer is a log destination read while deliveries may still write.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// ending is a provider over a registry of its own, whose sign-ins end at a row's request.
type ending struct {
	p      *oidcprovider.Provider
	grants *endingGrants
	keys   *exchangeKeys
	logs   *lockedBuffer

	// reentrant runs inside the next report.
	reentrant atomic.Pointer[func()]
	// handed counts the clients handed on.
	handed atomic.Int64

	mu       sync.Mutex
	failures []oidcprovider.LogoutFailure
}

// failed is what the seam for a failed delivery has been told.
func (x *ending) failed() []oidcprovider.LogoutFailure {
	x.mu.Lock()
	defer x.mu.Unlock()

	return append([]oidcprovider.LogoutFailure(nil), x.failures...)
}

// reasons is why each delivery failed, in the order they did.
func (x *ending) reasons() []string {
	reasons := []string{}
	for _, f := range x.failed() {
		reasons = append(reasons, f.Reason)
	}

	return reasons
}

// end ends one sign-in, of which each named client holds a grant.
func (x *ending) end(ctx context.Context, t *testing.T, clients ...string) {
	t.Helper()

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	ended := make([]oidcprovider.Grant, 0, len(clients))
	for _, c := range clients {
		ended = append(ended, oidcprovider.Grant{ClientID: c, User: "u-1", SignInFamily: family})
	}
	x.grants.push(family, ended)

	_, err = x.p.EndSignIn(ctx, oidcprovider.SignInSelector{Family: family})
	require.NoError(t, err, "whatever becomes of its delivery, an end succeeds")
}

// report is a session manager's report of an end whose clients are those named.
func (x *ending) report(t *testing.T, clients ...string) session.EndReport {
	t.Helper()

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	ended := make([]oidcprovider.Grant, 0, len(clients))
	for _, c := range clients {
		ended = append(ended, oidcprovider.Grant{ClientID: c, User: "u-1", SignInFamily: family})
	}
	x.handed.Add(int64(len(ended)))
	x.grants.push(family, ended)

	return session.EndReport{Cause: session.EndFamilyRevoked, User: "u-1", Family: family}
}

// listeningClient is a client registered to be told at uri.
func listeningClient(clientID, uri string) oidcprovider.Client {
	return oidcprovider.Client{
		ID: clientID, Type: oidcprovider.Confidential, Secret: []byte(exchangeSecret),
		RedirectURIs: []string{"https://rp.example.com/cb"}, Scopes: []string{"openid"},
		BackChannelLogoutURI: uri,
	}
}

// newEnding builds a provider whose registry holds clients, or registry when one is given in opts.
func newEnding(t *testing.T, clients []oidcprovider.Client, registry oidcprovider.ClientRegistry, opts ...oidcprovider.Option) *ending {
	t.Helper()

	store, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)
	x := &ending{grants: &endingGrants{GrantStore: store}, keys: newExchangeKeys(t), logs: &lockedBuffer{}}

	deps := validDeps(t)
	deps.Keys = x.keys
	deps.Clients, deps.Registry = clients, registry
	base := []oidcprovider.Option{
		oidcprovider.WithGrantStore(x.grants),
		oidcprovider.WithLogger(slog.New(slog.NewTextHandler(x.logs, nil))),
		oidcprovider.WithLogoutFailuresForTest(func(_ context.Context, f oidcprovider.LogoutFailure) {
			x.mu.Lock()
			x.failures = append(x.failures, f)
			x.mu.Unlock()
			if run := x.reentrant.Swap(nil); run != nil {
				(*run)()
			}
		}),
	}
	x.p, err = oidcprovider.New(deps, append(base, opts...)...)
	require.NoError(t, err)

	return x
}

// post is one request a relying party's server received.
type post struct {
	method, path, contentType, token string
}

// relyingParty is a relying party's TLS server, which keeps what it receives.
type relyingParty struct {
	srv *httptest.Server

	mu    sync.Mutex
	posts []post
}

func newRelyingParty(t *testing.T, answer func(w http.ResponseWriter, r *http.Request)) *relyingParty {
	t.Helper()

	rp := &relyingParty{}
	rp.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		rp.mu.Lock()
		rp.posts = append(rp.posts, post{method: r.Method, path: r.URL.Path, contentType: r.Header.Get("Content-Type"), token: r.PostForm.Get("logout_token")})
		rp.mu.Unlock()
		answer(w, r)
	}))
	t.Cleanup(rp.srv.Close)

	return rp
}

func (rp *relyingParty) received() []post {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	return append([]post(nil), rp.posts...)
}

// TestProvider_BackChannelDelivery pins the default delivery, against a real server over TLS.
func TestProvider_BackChannelDelivery(t *testing.T) {
	t.Parallel()

	answering := func(status int) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }
	}
	redirecting := func(status int) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/moved" {
				return
			}
			w.Header().Set("Location", "/moved")
			w.WriteHeader(status)
		}
	}
	trusting := func(rp *relyingParty) []oidcprovider.Option {
		return []oidcprovider.Option{oidcprovider.WithLogoutOutbound(outbound.WithHTTPClient(rp.srv.Client()))}
	}
	throughOutbound := func(t *testing.T, rp *relyingParty, opts ...outbound.Option) []oidcprovider.Option {
		t.Helper()
		out, err := outbound.New(append([]outbound.Option{outbound.WithHTTPClient(rp.srv.Client())}, opts...)...)
		require.NoError(t, err)

		return []oidcprovider.Option{oidcprovider.WithOutbound(out)}
	}
	delivered := func(t *testing.T, rp *relyingParty, x *ending) {
		t.Helper()
		require.Len(t, rp.received(), 1)
		assert.Empty(t, x.failed())
	}
	failedAs := func(reason string, hits int) func(*testing.T, *relyingParty, *ending) {
		return func(t *testing.T, rp *relyingParty, x *ending) {
			t.Helper()
			assert.Len(t, rp.received(), hits, "one attempt, and nowhere else")
			assert.Equal(t, []string{reason}, x.reasons())
		}
	}

	type testCase struct {
		name   string
		answer func(http.ResponseWriter, *http.Request)
		opts   func(t *testing.T, rp *relyingParty) []oidcprovider.Option
		assert func(t *testing.T, rp *relyingParty, x *ending)
	}

	cases := []testCase{
		{
			name:   "a 200 is a success, after one form POST of logout_token",
			answer: answering(http.StatusOK),
			assert: func(t *testing.T, rp *relyingParty, x *ending) {
				t.Helper()
				delivered(t, rp, x)
				got := rp.received()[0]
				assert.Equal(t, http.MethodPost, got.method)
				assert.Equal(t, "application/x-www-form-urlencoded", got.contentType)
				header, _ := decodeJWT(t, got.token)
				assert.Equal(t, token.TypeLogoutToken, header["typ"])
			},
		},
		{name: "a 204 is a success", answer: answering(http.StatusNoContent), assert: delivered},
		{name: "a 201 is not", answer: answering(http.StatusCreated), assert: failedAs("status", 1)},
		{name: "a 500 is not, and is not tried again", answer: answering(http.StatusInternalServerError), assert: failedAs("status", 1)},
		{name: "a 400 is not, and is not tried again", answer: answering(http.StatusBadRequest), assert: failedAs("status", 1)},
		{name: "a 302 is not followed, and is no success", answer: redirecting(http.StatusFound), assert: failedAs("post", 1)},
		{name: "a 307 is not followed, so nothing is sent again", answer: redirecting(http.StatusTemporaryRedirect), assert: failedAs("post", 1)},
		{name: "a 308 is not followed, so nothing is sent again", answer: redirecting(http.StatusPermanentRedirect), assert: failedAs("post", 1)},
		{
			name:   "options given for delivery cannot bring redirects back",
			answer: redirecting(http.StatusFound),
			opts: func(_ *testing.T, rp *relyingParty) []oidcprovider.Option {
				return []oidcprovider.Option{oidcprovider.WithLogoutOutbound(outbound.WithHTTPClient(rp.srv.Client()), outbound.WithMaxRedirects(5))}
			},
			assert: failedAs("post", 1),
		},
		{
			name:   "options given for delivery confine it",
			answer: answering(http.StatusOK),
			opts: func(_ *testing.T, rp *relyingParty) []oidcprovider.Option {
				return []oidcprovider.Option{oidcprovider.WithLogoutOutbound(outbound.WithHTTPClient(rp.srv.Client()), outbound.WithAllowedOrigins("https://elsewhere.example.com"))}
			},
			assert: failedAs("post", 0),
		},
		{
			name:   "a client given for the provider's fetches carries delivery too, with no options of its own",
			answer: answering(http.StatusOK),
			opts:   func(t *testing.T, rp *relyingParty) []oidcprovider.Option { return throughOutbound(t, rp) },
			assert: delivered,
		},
		{
			name:   "and confines it",
			answer: answering(http.StatusOK),
			opts: func(t *testing.T, rp *relyingParty) []oidcprovider.Option {
				return throughOutbound(t, rp, outbound.WithAllowedOrigins("https://elsewhere.example.com"))
			},
			assert: failedAs("post", 0),
		},
		{
			name:   "and, capped at no redirects, follows none",
			answer: redirecting(http.StatusFound),
			opts: func(t *testing.T, rp *relyingParty) []oidcprovider.Option {
				return throughOutbound(t, rp, outbound.WithMaxRedirects(0))
			},
			assert: failedAs("post", 1),
		},
		{
			name:   "the stated limit: such a client that may redirect does, on its origin, as WithOutbound says",
			answer: redirecting(http.StatusFound),
			opts:   func(t *testing.T, rp *relyingParty) []oidcprovider.Option { return throughOutbound(t, rp) },
			assert: func(t *testing.T, rp *relyingParty, x *ending) {
				t.Helper()
				assert.Len(t, rp.received(), 2)
				assert.Empty(t, x.failed())
			},
		},
		{
			name:   "options given for delivery win over such a client",
			answer: redirecting(http.StatusFound),
			opts: func(t *testing.T, rp *relyingParty) []oidcprovider.Option {
				return append(throughOutbound(t, rp), trusting(rp)...)
			},
			assert: failedAs("post", 1),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rp := newRelyingParty(t, tc.answer)
			opts := trusting(rp)
			if tc.opts != nil {
				opts = tc.opts(t, rp)
			}
			x := newEnding(t, []oidcprovider.Client{listeningClient("billing-web", rp.srv.URL+"/logout")}, nil, opts...)

			x.end(t.Context(), t, "billing-web")
			drained(t, x.p)

			tc.assert(t, rp, x)
		})
	}
}

// TestProvider_BackChannelDelivery_Failures pins what becomes of each way a delivery fails: it is
// logged and reported with no text of its cause, and costs the end nothing.
func TestProvider_BackChannelDelivery_Failures(t *testing.T) {
	t.Parallel()

	const secretText = "a cause quoting something private"
	errPrivate := errors.New(secretText)

	type testCase struct {
		name    string
		arrange func(t *testing.T, x *ending)
		// delivery answers in place of the default, and nil leaves a delivery that succeeds.
		delivery oidcprovider.LogoutDeliveryFunc
		// registry replaces the clients, and nil keeps them.
		registry func(t *testing.T) oidcprovider.ClientRegistry
		assert   func(t *testing.T, x *ending, tokens []string)
	}

	cases := []testCase{
		{
			name: "a registry that cannot answer",
			registry: func(t *testing.T) oidcprovider.ClientRegistry {
				t.Helper()
				registry := NewMockClientRegistry(gomock.NewController(t))
				registry.EXPECT().Client(gomock.Any(), "billing-web").Return(nil, errPrivate).AnyTimes()

				return registry
			},
			assert: func(t *testing.T, x *ending, tokens []string) {
				assert.Equal(t, []string{"client"}, x.reasons())
				assert.Empty(t, tokens)
			},
		},
		{
			name: "a client the registry no longer holds is no failure, as there is no one to tell",
			registry: func(t *testing.T) oidcprovider.ClientRegistry {
				t.Helper()
				registry := NewMockClientRegistry(gomock.NewController(t))
				registry.EXPECT().Client(gomock.Any(), "billing-web").Return(nil, oidcprovider.ErrClientNotFound).AnyTimes()

				return registry
			},
			assert: func(t *testing.T, x *ending, tokens []string) {
				assert.Empty(t, x.reasons())
				assert.Empty(t, tokens)
			},
		},
		{
			name:    "keys that cannot sign",
			arrange: func(_ *testing.T, x *ending) { x.keys.failSigning(func(context.Context) error { return errPrivate }) },
			assert: func(t *testing.T, x *ending, tokens []string) {
				assert.Equal(t, []string{"sign"}, x.reasons())
				assert.Empty(t, tokens)
			},
		},
		{
			name:     "a consumer's delivery answering an error",
			delivery: func(context.Context, string, string) error { return errPrivate },
			assert: func(t *testing.T, x *ending, tokens []string) {
				assert.Equal(t, []string{"delivery"}, x.reasons())
				assert.Len(t, tokens, 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var mu sync.Mutex
			var tokens []string
			delivery := oidcprovider.LogoutDeliveryFunc(func(ctx context.Context, uri, raw string) error {
				mu.Lock()
				tokens = append(tokens, raw)
				mu.Unlock()
				if tc.delivery != nil {
					return tc.delivery(ctx, uri, raw)
				}

				return nil
			})
			var registry oidcprovider.ClientRegistry
			clients := []oidcprovider.Client{listeningClient("billing-web", billingBackChannel)}
			if tc.registry != nil {
				registry, clients = tc.registry(t), nil
			}
			x := newEnding(t, clients, registry, oidcprovider.WithLogoutDelivery(delivery))
			if tc.arrange != nil {
				tc.arrange(t, x)
			}

			x.end(t.Context(), t, "billing-web")
			drained(t, x.p)

			mu.Lock()
			defer mu.Unlock()
			tc.assert(t, x, tokens)
			logged := x.logs.String()
			assert.NotContains(t, logged, secretText, "no cause's text reaches a log")
			for _, raw := range tokens {
				assert.NotContains(t, logged, raw, "and no token does")
			}
			if len(x.failed()) > 0 {
				assert.Contains(t, logged, "billing-web", "a failure is logged, naming its client")
				assert.Contains(t, logged, "reason="+x.failed()[0].Reason, "and what failed")
			}
		})
	}
}

// TestProvider_BackChannelDelivery_NoSecretInStatusFailure pins that a failing answer's log holds
// neither the token nor what the relying party answered.
func TestProvider_BackChannelDelivery_NoSecretInStatusFailure(t *testing.T) {
	t.Parallel()

	const answered = "a body quoting something private"
	rp := newRelyingParty(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(answered))
	})
	x := newEnding(t, []oidcprovider.Client{listeningClient("billing-web", rp.srv.URL+"/logout?secret=in-the-uri")}, nil,
		oidcprovider.WithLogoutOutbound(outbound.WithHTTPClient(rp.srv.Client())))

	x.end(t.Context(), t, "billing-web")
	drained(t, x.p)

	logged := x.logs.String()
	require.Len(t, rp.received(), 1)
	assert.NotContains(t, logged, rp.received()[0].token)
	assert.NotContains(t, logged, answered)
	assert.NotContains(t, logged, "in-the-uri")
	assert.Contains(t, logged, "status=500")
}

// TestProvider_BackChannelDelivery_Who pins who is told of an end, once each, with the back-channel URI
// read when a token is delivered, not when its end was asked for.
func TestProvider_BackChannelDelivery_Who(t *testing.T) {
	t.Parallel()

	const (
		hrClient   = "hr-web"
		hrRedirect = "https://hr.example.com/cb"
		hrChannel  = "https://hr.example.com/backchannel"
	)

	type testCase struct {
		name string
		// run sets things up on e, whose billing-web, week-app and hr-web all listen, and ends something.
		run    func(t *testing.T, e *endFixture)
		assert func(t *testing.T, handed []handedOver)
	}

	toldOnce := func(t *testing.T, handed []handedOver) {
		t.Helper()
		require.Len(t, handed, 1)
		assert.Equal(t, billingBackChannel, handed[0].uri)
	}
	endFamily := func(t *testing.T, e *endFixture, signIn oidcprovider.SignIn) {
		t.Helper()
		_, err := e.p.EndSignIn(t.Context(), oidcprovider.SignInSelector{Family: signIn.Family})
		require.NoError(t, err)
	}

	cases := []testCase{
		{
			name: "two clients of one sign-in are told once each",
			run: func(t *testing.T, e *endFixture) {
				signIn := e.signInOf("u-1", "", "")
				e.online(t, signIn)
				e.grantFrom(t, signIn, weekClient, weekRedirect, "openid", "profile")
				endFamily(t, e, signIn)
			},
			assert: func(t *testing.T, handed []handedOver) {
				uris := []string{}
				for _, h := range handed {
					uris = append(uris, h.uri)
				}
				assert.ElementsMatch(t, []string{billingBackChannel, weekBackChannel}, uris)
			},
		},
		{
			name: "a client holding several grants of one sign-in is told once",
			run: func(t *testing.T, e *endFixture) {
				signIn := e.signInOf("u-1", "", "")
				e.online(t, signIn)
				e.online(t, signIn)
				e.offline(t, signIn)
				endFamily(t, e, signIn)
			},
			assert: toldOnce,
		},
		{
			name: "a second end of the sign-in tells no one again",
			run: func(t *testing.T, e *endFixture) {
				signIn := e.signInOf("u-1", "", "")
				e.online(t, signIn)
				endFamily(t, e, signIn)
				endFamily(t, e, signIn)
			},
			assert: toldOnce,
		},
		{
			name: "nor does a session manager's report of the same end",
			run: func(t *testing.T, e *endFixture) {
				signIn := e.signInOf("u-1", "", "")
				e.online(t, signIn)
				endFamily(t, e, signIn)
				e.p.SignInsEnded(t.Context(), session.EndReport{Cause: session.EndFamilyRevoked, User: signIn.User, Family: signIn.Family})
			},
			assert: toldOnce,
		},
		{
			name: "a session manager's report tells the client",
			run: func(t *testing.T, e *endFixture) {
				signIn := e.signInOf("u-1", "", "")
				e.online(t, signIn)
				e.p.SignInsEnded(t.Context(), session.EndReport{Cause: session.EndFamilyRevoked, User: signIn.User, Family: signIn.Family})
			},
			assert: toldOnce,
		},
		{
			name: "a client holding grants of two ended sign-ins is told of each, under each one's sid",
			run: func(t *testing.T, e *endFixture) {
				e.online(t, e.signInOf("u-1", "", ""))
				e.online(t, e.signInOf("u-1", "", ""))
				_, err := e.p.EndSignIn(t.Context(), oidcprovider.SignInSelector{User: "u-1"})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, handed []handedOver) {
				require.Len(t, handed, 2)
				_, first := decodeJWT(t, handed[0].raw)
				_, second := decodeJWT(t, handed[1].raw)
				assert.NotEqual(t, first["sid"], second["sid"])
			},
		},
		{
			name: "a client holding grants only of another sign-in is not told",
			run: func(t *testing.T, e *endFixture) {
				ended := e.signInOf("u-1", "", "")
				e.online(t, ended)
				e.grantFrom(t, e.signInOf("u-1", "", ""), hrClient, hrRedirect, "openid", "profile")
				endFamily(t, e, ended)
			},
			assert: toldOnce,
		},
		{
			name: "a client whose grant outlives the sign-in is told all the same",
			run: func(t *testing.T, e *endFixture) {
				signIn := e.signInOf("u-1", "", "")
				e.offline(t, signIn)
				endFamily(t, e, signIn)
			},
			assert: toldOnce,
		},
		{
			name: "a client that registered no URI is not told",
			run: func(t *testing.T, e *endFixture) {
				signIn := e.signInOf("u-1", "", "")
				e.online(t, signIn)
				listening(t, e, "billing-web", authzRedirect, "", nil)
				endFamily(t, e, signIn)
			},
			assert: func(t *testing.T, handed []handedOver) { assert.Empty(t, handed) },
		},
		{
			name: "a URI registered after the grant is the one told",
			run: func(t *testing.T, e *endFixture) {
				signIn := e.signInOf("u-1", "", "")
				e.online(t, signIn)
				listening(t, e, "billing-web", authzRedirect, "https://moved.example.com/backchannel", nil)
				endFamily(t, e, signIn)
			},
			assert: func(t *testing.T, handed []handedOver) {
				require.Len(t, handed, 1)
				assert.Equal(t, "https://moved.example.com/backchannel", handed[0].uri)
			},
		},
		{
			name: "a client deleted since the grant is not told",
			run: func(t *testing.T, e *endFixture) {
				signIn := e.signInOf("u-1", "", "")
				e.online(t, signIn)
				require.NoError(t, e.registry.Delete(t.Context(), "billing-web"))
				endFamily(t, e, signIn)
			},
			assert: func(t *testing.T, handed []handedOver) { assert.Empty(t, handed) },
		},
		{
			name: "revoking a user's grants ends no sign-in, so no one is told",
			run: func(t *testing.T, e *endFixture) {
				e.online(t, e.signInOf("u-1", "", ""))
				require.NoError(t, e.p.RevokeUserGrants(t.Context(), identity.UserID("u-1"), "mfa-reset"))
			},
			assert: func(t *testing.T, handed []handedOver) { assert.Empty(t, handed) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			recorder := &logoutRecorder{}
			e := newEndFixture(t, oidcprovider.WithLogoutDelivery(recorder))
			listening(t, e, "billing-web", authzRedirect, billingBackChannel, nil)
			listening(t, e, weekClient, weekRedirect, weekBackChannel, nil)
			require.NoError(t, e.registry.Put(t.Context(), oidcprovider.Client{
				ID: hrClient, Type: oidcprovider.Confidential, Secret: []byte(exchangeSecret), RedirectURIs: []string{hrRedirect},
				Scopes:               []string{"openid", "profile"},
				GrantTypes:           []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
				BackChannelLogoutURI: hrChannel,
			}))

			tc.run(t, e)
			drained(t, e.p)

			tc.assert(t, recorder.handed())
		})
	}
}

// contextKey marks a caller's context.
type contextKey struct{}

// TestProvider_BackChannelDelivery_Context pins what of the caller's context a delivery keeps: its
// values and not its end, under a bound of its own.
func TestProvider_BackChannelDelivery_Context(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		ctx  func(ctx context.Context) context.Context
	}

	cases := []testCase{
		{name: "a caller still there", ctx: func(ctx context.Context) context.Context { return ctx }},
		{
			name: "a caller who hung up as the delivery starts",
			ctx: func(ctx context.Context) context.Context {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()

				return cancelled
			},
		},
		{
			name: "a caller about to run out of time",
			ctx: func(ctx context.Context) context.Context {
				expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Hour))
				cancel()

				return expired
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var ran atomic.Bool
			delivery := oidcprovider.LogoutDeliveryFunc(func(ctx context.Context, _, _ string) error {
				ran.Store(true)
				assert.NoError(t, ctx.Err(), "not the caller's end")
				assert.Equal(t, "kept", ctx.Value(contextKey{}), "but the caller's values")
				by, bounded := ctx.Deadline()
				assert.True(t, bounded, "under a bound of its own")
				assert.LessOrEqual(t, time.Until(by), 5*time.Second)

				return nil
			})
			x := newEnding(t, []oidcprovider.Client{listeningClient("billing-web", billingBackChannel)}, nil, oidcprovider.WithLogoutDelivery(delivery))

			x.end(tc.ctx(context.WithValue(t.Context(), contextKey{}, "kept")), t, "billing-web")
			drained(t, x.p)

			assert.True(t, ran.Load())
			assert.Empty(t, x.reasons())
		})
	}
}
