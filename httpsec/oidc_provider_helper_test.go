package httpsec_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/session"
)

// The external identity the test provider asserts, and the user it is linked
// to.
const (
	oidcTestSubject                   = "sub-1"
	oidcTestSessionID                 = "sid-1"
	oidcTestUserID    identity.UserID = "u-1"
)

// oidcTestProvider is an httptest TLS server acting as an OpenID provider
// with pinned endpoints, so a manager built on it never runs discovery. Its
// tokens are HS256 under the client secret, so no key set is ever consulted.
//
// The token endpoint echoes the authorization code it is given as the ID
// token's nonce. A test that wants a callback to verify therefore sends the
// nonce the authorize redirect carried as the code; any other code yields a
// token whose nonce does not match.
type oidcTestProvider struct {
	srv *httptest.Server

	// tokenDown makes the token endpoint answer 503, a provider outage.
	tokenDown atomic.Bool
}

// newOIDCTestProvider starts the provider; it is closed when the test ends.
func newOIDCTestProvider(t *testing.T) *oidcTestProvider {
	t.Helper()

	p := &oidcTestProvider{}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", p.serveToken)
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)

	return p
}

// provider is the registration of the test provider as testOIDCProvider.
func (p *oidcTestProvider) provider() oidc.Provider {
	return oidc.Provider{ //nolint:gosec // G101: a fixture, not a credential
		Name:                  testOIDCProvider,
		Issuer:                p.srv.URL,
		ClientID:              "app",
		ClientSecret:          "secret-" + testOIDCProvider + "-0123456789abcdef0123456789abcdef",
		RedirectURL:           "https://app.example.com" + httpsec.DefaultOIDCCallbackPath + testOIDCProvider,
		AuthorizationEndpoint: p.srv.URL + "/authorize",
		TokenEndpoint:         p.srv.URL + "/token",
		JWKSURI:               p.srv.URL + "/jwks",
		SigningAlgs:           []string{"HS256"},
	}
}

// serveToken answers a code exchange with an ID token for oidcTestSubject
// whose nonce is the code.
func (p *oidcTestProvider) serveToken(w http.ResponseWriter, r *http.Request) {
	if p.tokenDown.Load() {
		http.Error(w, `{"error":"temporarily_unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	reg := p.provider()
	now := time.Now()

	payload, err := json.Marshal(map[string]any{
		"iss":   reg.Issuer,
		"aud":   reg.ClientID,
		"sub":   oidcTestSubject,
		"sid":   oidcTestSessionID,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"nonce": r.PostForm.Get("code"),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), []byte(reg.ClientSecret)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token": "discarded",
		"token_type":   "Bearer",
		"id_token":     string(signed),
	})
}

// oidcHarness is what a federated-login chain is wired to: a real manager
// over the test provider, a real flow store, broker, handoff manager and
// session manager, with doubles only for the consumer's user store and token
// generator.
type oidcHarness struct {
	provider *oidcTestProvider
	flows    *oidc.MemoryFlowStore
	manager  *oidc.Manager
	handoffs *oidc.HandoffManager
	store    *oidc.MemoryHandoffStore
	sessions *session.Manager
	tokens   *MockGenerator
	logs     *syncBuffer

	// chainOpts are chain options a case adds beside EnableOIDCLogin: a
	// policy engine, EnableMFA.
	chainOpts []httpsec.Option

	// issued counts the access tokens the chain issued.
	issued atomic.Int64
}

// newOIDCHarness builds the harness, with managerOpts configuring the OIDC
// manager beside the flow store and outbound client it always gets.
func newOIDCHarness(t *testing.T, managerOpts ...oidc.ManagerOption) *oidcHarness {
	t.Helper()

	ctrl := gomock.NewController(t)
	p := newOIDCTestProvider(t)

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id identity.UserID) (*identity.Details, error) {
			if id != oidcTestUserID {
				return nil, identity.ErrUserNotFound
			}

			return &identity.Details{ID: oidcTestUserID, Username: "ada@example.com", Active: true}, nil
		})

	links := oidc.NewMemoryLinkStore()
	require.NoError(t, links.Insert(t.Context(), oidc.Link{
		Provider:  testOIDCProvider,
		Issuer:    p.srv.URL,
		Subject:   oidcTestSubject,
		UserID:    oidcTestUserID,
		CreatedAt: time.Now(),
	}))

	broker, err := oidc.NewBroker(links, users)
	require.NoError(t, err)

	registry, err := oidc.NewRegistry(p.provider())
	require.NoError(t, err)

	client, err := outbound.New(outbound.WithHTTPClient(p.srv.Client()))
	require.NoError(t, err)

	flows, err := oidc.NewMemoryFlowStore()
	require.NoError(t, err)

	opts := append([]oidc.ManagerOption{
		oidc.WithOutboundClient(client),
		oidc.WithFlowStore(flows),
	}, managerOpts...)

	manager, err := oidc.NewManager(registry, broker, opts...)
	require.NoError(t, err)

	store := oidc.NewMemoryHandoffStore()

	handoffs, err := oidc.NewHandoffManager(store, users)
	require.NoError(t, err)

	sessions, err := session.NewManager()
	require.NoError(t, err)

	return &oidcHarness{
		provider: p,
		flows:    flows,
		manager:  manager,
		handoffs: handoffs,
		store:    store,
		sessions: sessions,
		tokens:   NewMockGenerator(ctrl),
		logs:     &syncBuffer{},
	}
}

// chain builds a chain with the default conveyance and opts.
func (h *oidcHarness) chain(t *testing.T, opts ...httpsec.OIDCOption) *httpsec.Chain {
	t.Helper()

	return h.build(t, h.handoffs, append([]httpsec.OIDCOption{
		httpsec.WithOIDCTokens(h.tokens),
		httpsec.WithOIDCSessions(h.sessions),
	}, opts...)...)
}

// conveyedChain builds a chain whose callback success is fn, and so with no
// handoff manager.
func (h *oidcHarness) conveyedChain(
	t *testing.T, fn httpsec.CallbackSuccess, opts ...httpsec.OIDCOption,
) *httpsec.Chain {
	t.Helper()

	return h.build(t, nil, append([]httpsec.OIDCOption{
		httpsec.WithOIDCSessions(h.sessions),
		httpsec.WithCallbackSuccess(fn),
	}, opts...)...)
}

func (h *oidcHarness) build(
	t *testing.T, handoffs *oidc.HandoffManager, opts ...httpsec.OIDCOption,
) *httpsec.Chain {
	t.Helper()

	c, err := h.assemble(handoffs, opts...)
	require.NoError(t, err)

	return c
}

// assemble is build without the assertion, for the cases that are about the
// construction error itself.
func (h *oidcHarness) assemble(handoffs *oidc.HandoffManager, opts ...httpsec.OIDCOption) (*httpsec.Chain, error) {
	chainOpts := []httpsec.Option{
		httpsec.WithLogger(slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
		httpsec.WithRefusalLogInterval(0),
	}
	chainOpts = append(chainOpts, h.chainOpts...)
	chainOpts = append(chainOpts, httpsec.EnableOIDCLogin(h.manager, handoffs, opts...))

	return httpsec.New(chainOpts...)
}

// issueTokens lets the chain issue access tokens, counting each one.
func (h *oidcHarness) issueTokens() {
	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string, *identity.Principal) (string, error) {
			h.issued.Add(1)

			return "issued-token", nil
		})
}

// oidcTestIDToken is the raw ID token a test handoff carries. It is opaque to
// redemption, which only records it on the session.
const oidcTestIDToken = "raw.id.token" //nolint:gosec // G101: a fixture, not a credential

// handoffResult is the login a genuine callback for the linked user
// conveys, with no destination recorded.
func (h *oidcHarness) handoffResult() oidc.CallbackResult {
	return oidc.CallbackResult{
		Principal: &identity.Principal{ID: oidcTestUserID, Username: "ada@example.com"},
		Provider:  testOIDCProvider,
		Issuer:    h.provider.srv.URL,
		SessionID: oidcTestSessionID,
		IDToken:   oidcTestIDToken,
	}
}

// issueHandoff issues a handoff code for the linked user, as a genuine
// callback would, with next as the destination the login recorded.
func (h *oidcHarness) issueHandoff(t *testing.T, next string) string {
	t.Helper()

	res := h.handoffResult()
	res.Next = next

	return h.issueHandoffFor(t, res)
}

// issueHandoffFor issues a handoff code for res.
func (h *oidcHarness) issueHandoffFor(t *testing.T, res oidc.CallbackResult) string {
	t.Helper()

	code, err := h.handoffs.Issue(t.Context(), res)
	require.NoError(t, err)

	return code
}

// oidcTestSource is the address handoff redemptions come from unless a case
// names another.
const oidcTestSource = "203.0.113.7"

// handoffRequest posts code as the handoff form field from source.
func handoffRequest(ctx context.Context, source, code string) *http.Request {
	return postValues(ctx, httpsec.DefaultOIDCHandoffPath, source,
		url.Values{httpsec.DefaultOIDCHandoffParam: {code}})
}

// liveFlows counts the flows the store holds, by purging all of them: it is
// the last thing a case reads from the store.
func (h *oidcHarness) liveFlows(t *testing.T) int {
	t.Helper()

	n, err := h.flows.DeleteExpired(t.Context(), time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	return n
}

// storedHandoffs counts the handoff codes the store holds, by purging all of
// them: it is the last thing a case reads from the store.
func (h *oidcHarness) storedHandoffs(t *testing.T) int {
	t.Helper()

	n, err := h.store.DeleteExpired(t.Context(), time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	return n
}

// activeSessions counts the linked user's sessions.
func (h *oidcHarness) activeSessions(t *testing.T) int {
	t.Helper()

	n, err := h.sessions.CountActiveByUser(t.Context(), oidcTestUserID)
	require.NoError(t, err)

	return n
}

// oidcLogin is a login a browser started: the flow cookie it holds and the
// state and nonce the authorize redirect carried.
type oidcLogin struct {
	handle, state, nonce string
}

// startLogin starts a login for testOIDCProvider with next as the requested
// destination, and returns what the browser now holds.
func startLogin(t *testing.T, c *httpsec.Chain, next string) oidcLogin {
	t.Helper()

	target := httpsec.DefaultOIDCAuthorizePath + testOIDCProvider
	if next != "" {
		target += "?" + url.Values{httpsec.DefaultOIDCNextParam: {next}}.Encode()
	}

	out := serve(t, c, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))
	require.NoError(t, out.err)
	require.Equal(t, http.StatusFound, out.rec.Code)

	// The only cookie the endpoint sets, whatever the chain named it.
	cookies := out.rec.Result().Cookies() //nolint:bodyclose // the recorder's result has no body to close
	require.Len(t, cookies, 1, "the authorize response set no flow cookie")
	cookie := cookies[0]

	loc, err := url.Parse(out.rec.Header().Get("Location"))
	require.NoError(t, err)

	return oidcLogin{
		handle: cookie.Value,
		state:  loc.Query().Get("state"),
		nonce:  loc.Query().Get("nonce"),
	}
}

// callbackRequest is the provider's redirect back to the callback with
// rawQuery, carrying the flow cookie when handle is not empty.
func callbackRequest(ctx context.Context, rawQuery, handle string) *http.Request {
	target := httpsec.DefaultOIDCCallbackPath + testOIDCProvider
	if rawQuery != "" {
		target += "?" + rawQuery
	}

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if handle != "" {
		req.AddCookie(&http.Cookie{Name: httpsec.DefaultOIDCFlowCookieName, Value: handle}) //nolint:gosec // G124: a request cookie, never set
	}

	return req
}

// genuineCallback is the query the provider sends back for login l.
func (l oidcLogin) genuineCallback() string {
	return url.Values{"code": {l.nonce}, "state": {l.state}}.Encode()
}

// syncBuffer is a bytes.Buffer safe for the concurrent writes of a logger.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// logoutTokenSeq numbers the jti of every logout token the helpers sign, so no
// two tokens of one test run share one.
var logoutTokenSeq atomic.Int64

// logoutClaims are the claims of a valid back-channel logout token from the
// test provider, issued at iat, naming sub and sid; an empty sub or sid is
// left out.
func (p *oidcTestProvider) logoutClaims(iat time.Time, sub, sid string) map[string]any {
	reg := p.provider()

	claims := map[string]any{
		"iss":    reg.Issuer,
		"aud":    reg.ClientID,
		"iat":    iat.Unix(),
		"jti":    fmt.Sprintf("jti-%d", logoutTokenSeq.Add(1)),
		"events": map[string]any{oidc.BackchannelLogoutEvent: map[string]any{}},
	}
	if sub != "" {
		claims["sub"] = sub
	}
	if sid != "" {
		claims["sid"] = sid
	}

	return claims
}

// logoutToken signs a valid back-channel logout token naming sub and sid,
// issued now, as the test provider does: HS256 under the client secret.
func (p *oidcTestProvider) logoutToken(t *testing.T, sub, sid string) string {
	t.Helper()

	return p.signClaims(t, []byte(p.provider().ClientSecret), p.logoutClaims(time.Now(), sub, sid))
}

// signClaims signs claims with HS256 under key.
func (p *oidcTestProvider) signClaims(t *testing.T, key []byte, claims map[string]any) string {
	t.Helper()

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), key))
	require.NoError(t, err)

	return string(signed)
}

// managerWith builds a manager over the test provider, as edit leaves its
// registration (nil keeps it as it is), resolving identities through broker.
func (h *oidcHarness) managerWith(
	t *testing.T, broker oidc.IdentityBroker, edit func(*oidc.Provider), opts ...oidc.ManagerOption,
) *oidc.Manager {
	t.Helper()

	reg := h.provider.provider()
	if edit != nil {
		edit(&reg)
	}

	registry, err := oidc.NewRegistry(reg)
	require.NoError(t, err)

	client, err := outbound.New(outbound.WithHTTPClient(h.provider.srv.Client()))
	require.NoError(t, err)

	m, err := oidc.NewManager(registry, broker, append([]oidc.ManagerOption{
		oidc.WithOutboundClient(client),
		oidc.WithFlowStore(h.flows),
	}, opts...)...)
	require.NoError(t, err)

	return m
}
