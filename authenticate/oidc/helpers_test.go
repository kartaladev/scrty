package oidc_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/outbound"
)

// testTextLogger returns a text-handler logger writing to w at debug level,
// with the timestamp attribute stripped from every record.
//
// slog.NewTextHandler's default timestamp renders as decimal digits (e.g.
// "2026-09-25T18:52:31.842+07:00"), which can coincidentally contain a
// substring a test asserts is absent from the log (a claim value, a role
// name, ...). Dropping the timestamp removes that collision without
// weakening what the test actually checks.
func testTextLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))
}

// testProvider is an httptest TLS server acting as an OpenID provider: a
// discovery document, a key set and a token endpoint, with call counters and a
// signer for ID and logout tokens. It lives in a _test.go file because the core
// module never imports the test module.
//
// The key set publishes every key the provider has held, oldest first, so a
// token signed before a Rotate still verifies against a refetched set.
type testProvider struct {
	srv *httptest.Server

	mu            sync.Mutex
	key           jwk.Key   // current RS256 signing key (private), kid "k1" until rotated
	keys          []jwk.Key // every key published in the set, private halves included
	tokenResponse func(r *http.Request) (status int, body string)

	discoveryCalls, jwksCalls atomic.Int64
	tokenCalls                atomic.Int64
	failJWKS, failDiscovery   atomic.Bool

	// discoveryBody and jwksBody, when they hold a string, are served as the
	// discovery document or key set in place of the generated one, so a test
	// can craft a malformed or hostile answer.
	discoveryBody, jwksBody atomic.Value

	// jwksGate, when set, is called by the key-set handler before it answers,
	// so a test can hold a fetch in flight.
	jwksGate atomic.Pointer[func()]

	handler http.Handler
}

// newTestProvider starts a provider with one RS256 key, kid "k1", and a token
// endpoint that answers 500 until SetTokenResponse is called. The server is
// closed when the test ends.
func newTestProvider(t *testing.T) *testProvider {
	t.Helper()

	p := &testProvider{
		tokenResponse: func(*http.Request) (int, string) {
			return http.StatusInternalServerError, `{"error":"server_error"}`
		},
	}
	p.key = newRSAKey(t, "k1")
	p.keys = []jwk.Key{p.key}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.serveDiscovery)
	mux.HandleFunc("GET /jwks", p.serveJWKS)
	mux.HandleFunc("POST /token", p.serveToken)
	p.handler = mux
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)

	return p
}

// Issuer is the provider's issuer identifier, the server's base URL.
func (p *testProvider) Issuer() string { return p.srv.URL }

// Provider returns an unpinned provider configuration pointing at the server.
func (p *testProvider) Provider(name string) oidc.Provider {
	return oidc.Provider{
		Name:         name,
		Issuer:       p.Issuer(),
		ClientID:     "client-" + name,
		ClientSecret: "secret-" + name,
		RedirectURL:  "https://app.example/login/oauth2/callback/" + name,
	}
}

// Outbound returns a confined client that trusts the server's certificate.
func (p *testProvider) Outbound(t *testing.T) *outbound.Client {
	t.Helper()

	c, err := outbound.New(outbound.WithHTTPClient(p.srv.Client()))
	require.NoError(t, err)

	return c
}

// InMemoryOutbound returns a confined client whose requests to the provider
// are answered by its handler in the calling goroutine, with no network I/O.
// A testing/synctest bubble can then advance its fake clock while a request
// is in flight, which a socket read would prevent. Requests to any other host
// fail.
func (p *testProvider) InMemoryOutbound(t *testing.T) *outbound.Client {
	t.Helper()
	return inMemoryOutbound(t, p)
}

// inMemoryOutbound is InMemoryOutbound for several providers at once, each
// answering the requests addressed to its own host.
func inMemoryOutbound(t *testing.T, providers ...*testProvider) *outbound.Client {
	t.Helper()

	byHost := make(map[string]http.Handler, len(providers))
	for _, p := range providers {
		byHost[p.srv.Listener.Addr().String()] = p.handler
	}
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		h, ok := byHost[r.URL.Host]
		if !ok {
			return nil, errors.New("in-memory transport: unknown host " + r.URL.Host)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		res := rec.Result()
		res.Request = r
		return res, nil
	})}
	c, err := outbound.New(outbound.WithHTTPClient(hc))
	require.NoError(t, err)

	return c
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// SetTokenResponse replaces how the token endpoint answers.
func (p *testProvider) SetTokenResponse(fn func(r *http.Request) (status int, body string)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenResponse = fn
}

// Rotate makes a new RS256 key with the given kid current and publishes it
// beside the keys already published.
func (p *testProvider) Rotate(t *testing.T, kid string) {
	t.Helper()

	k := newRSAKey(t, kid)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key = k
	p.keys = append(p.keys, k)
}

// signConfig is what a signOption changes about one Sign call.
type signConfig struct {
	alg    jwa.SignatureAlgorithm
	kid    *string
	key    jwk.Key
	secret []byte
	none   bool
}

type signOption func(*signConfig)

// withAlg signs with alg instead of RS256, using the chosen key.
func withAlg(alg jwa.SignatureAlgorithm) signOption {
	return func(c *signConfig) { c.alg = alg }
}

// withKid writes kid into the header instead of the signing key's own; an
// empty kid leaves the header without one.
func withKid(kid string) signOption { return func(c *signConfig) { c.kid = &kid } }

// withKey signs with key, which need not be in the published set.
func withKey(key jwk.Key) signOption { return func(c *signConfig) { c.key = key } }

// withHS256Secret signs with HS256 under the given shared secret.
func withHS256Secret(secret string) signOption {
	return func(c *signConfig) { c.alg = jwa.HS256(); c.secret = []byte(secret) }
}

// withNoneAlg produces an unsigned token whose header says "alg":"none".
func withNoneAlg() signOption { return func(c *signConfig) { c.none = true } }

// Sign returns a compact JWS of claims, signed by default with the current
// RS256 key and naming its kid.
func (p *testProvider) Sign(t *testing.T, claims map[string]any, opts ...signOption) string {
	t.Helper()

	p.mu.Lock()
	cfg := signConfig{alg: jwa.RS256(), key: p.key}
	p.mu.Unlock()
	for _, o := range opts {
		o(&cfg)
	}

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	kid, _ := cfg.key.KeyID()
	if cfg.kid != nil {
		kid = *cfg.kid
	}

	if cfg.none {
		header := map[string]any{"alg": "none"}
		if kid != "" {
			header["kid"] = kid
		}
		h, err := json.Marshal(header)
		require.NoError(t, err)
		enc := base64.RawURLEncoding
		return enc.EncodeToString(h) + "." + enc.EncodeToString(payload) + "."
	}

	headers := jws.NewHeaders()
	if kid != "" {
		require.NoError(t, headers.Set(jws.KeyIDKey, kid))
	}

	var signingKey any
	if cfg.secret != nil {
		signingKey = cfg.secret
	} else {
		raw, err := jwk.Export[*rsa.PrivateKey](cfg.key)
		require.NoError(t, err)
		signingKey = raw
	}

	signed, err := jws.Sign(payload, jws.WithKey(cfg.alg, signingKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)

	return string(signed)
}

func (p *testProvider) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	p.discoveryCalls.Add(1)
	if p.failDiscovery.Load() {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if body, ok := p.discoveryBody.Load().(string); ok {
		_, _ = w.Write([]byte(body))
		return
	}
	writeJSON(w, map[string]any{
		"issuer":                                p.Issuer(),
		"authorization_endpoint":                p.Issuer() + "/authorize",
		"token_endpoint":                        p.Issuer() + "/token",
		"jwks_uri":                              p.Issuer() + "/jwks",
		"end_session_endpoint":                  p.Issuer() + "/logout",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (p *testProvider) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	p.jwksCalls.Add(1)
	if gate := p.jwksGate.Load(); gate != nil {
		(*gate)()
	}
	if p.failJWKS.Load() {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if body, ok := p.jwksBody.Load().(string); ok {
		_, _ = w.Write([]byte(body))
		return
	}

	p.mu.Lock()
	set := jwk.NewSet()
	var addErr error
	for _, k := range p.keys {
		if err := set.AddKey(k); err != nil {
			addErr = err
		}
	}
	p.mu.Unlock()

	public, err := jwk.PublicSetOf(set)
	if addErr != nil || err != nil {
		http.Error(w, "key set", http.StatusInternalServerError)
		return
	}
	writeJSON(w, public)
}

func (p *testProvider) serveToken(w http.ResponseWriter, r *http.Request) {
	p.tokenCalls.Add(1)

	p.mu.Lock()
	respond := p.tokenResponse
	p.mu.Unlock()

	status, body := respond(r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func writeJSON(w http.ResponseWriter, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "marshal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// newRSAKey returns a private RS256 JWK with the given kid.
func newRSAKey(t *testing.T, kid string) jwk.Key {
	t.Helper()

	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key, err := jwk.Import[jwk.Key](raw)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, kid))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.RS256()))
	require.NoError(t, key.Set(jwk.KeyUsageKey, string(jwk.ForSignature)))

	return key
}

// TestTestProvider pins the fixture every later oidc test stands on: what it
// serves, what it signs, and that its outbound client reaches it.
func TestTestProvider(t *testing.T) {
	t.Parallel()

	p := newTestProvider(t)
	out := p.Outbound(t)

	type testCase struct {
		name   string
		act    func(t *testing.T) (*outbound.Response, error)
		assert func(t *testing.T, resp *outbound.Response, err error)
	}

	cases := []testCase{
		{
			name: "discovery names the issuer and its endpoints",
			act: func(t *testing.T) (*outbound.Response, error) {
				return out.Get(t.Context(), p.Issuer()+"/.well-known/openid-configuration", nil)
			},
			assert: func(t *testing.T, resp *outbound.Response, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.Status)
				var doc map[string]any
				require.NoError(t, json.Unmarshal(resp.Body, &doc))
				require.Equal(t, p.Issuer(), doc["issuer"])
				require.Equal(t, p.Issuer()+"/jwks", doc["jwks_uri"])
				require.Equal(t, int64(1), p.discoveryCalls.Load())
			},
		},
		{
			name: "the key set verifies what Sign produces and carries no private key",
			act: func(t *testing.T) (*outbound.Response, error) {
				return out.Get(t.Context(), p.Issuer()+"/jwks", nil)
			},
			assert: func(t *testing.T, resp *outbound.Response, err error) {
				require.NoError(t, err)
				set, err := jwk.Parse(resp.Body)
				require.NoError(t, err)
				require.Equal(t, 1, set.Len())
				k, ok := set.Key(0)
				require.True(t, ok)
				private, err := jwk.IsPrivateKey(k)
				require.NoError(t, err)
				require.False(t, private)

				raw := p.Sign(t, map[string]any{"sub": "alice"})
				_, err = jws.Verify([]byte(raw), jws.WithKeySet(set))
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.act(t)
			tc.assert(t, resp, err)
		})
	}
}

// TestTestProviderSign pins what each signOption produces, so the malformed
// token rows of later tests stand on a signer that does what it says.
func TestTestProviderSign(t *testing.T) {
	t.Parallel()

	p := newTestProvider(t)
	published := func(t *testing.T) jwk.Set {
		t.Helper()
		resp, err := p.Outbound(t).Get(t.Context(), p.Issuer()+"/jwks", nil)
		require.NoError(t, err)
		set, err := jwk.Parse(resp.Body)
		require.NoError(t, err)
		return set
	}
	header := func(t *testing.T, raw string) jws.Headers {
		t.Helper()
		msg, err := jws.Parse([]byte(raw))
		require.NoError(t, err)
		require.Len(t, msg.Signatures(), 1)
		return msg.Signatures()[0].ProtectedHeaders()
	}
	claims := map[string]any{"sub": "alice"}

	type testCase struct {
		name   string
		opts   []signOption
		assert func(t *testing.T, raw string)
	}

	cases := []testCase{
		{name: "default is RS256 under the current kid",
			assert: func(t *testing.T, raw string) {
				h := header(t, raw)
				alg, _ := h.Algorithm()
				kid, _ := h.KeyID()
				require.Equal(t, jwa.RS256(), alg)
				require.Equal(t, "k1", kid)
				_, err := jws.Verify([]byte(raw), jws.WithKeySet(published(t)))
				require.NoError(t, err)
			}},
		{name: "withKid replaces the header kid",
			opts: []signOption{withKid("other")},
			assert: func(t *testing.T, raw string) {
				kid, _ := header(t, raw).KeyID()
				require.Equal(t, "other", kid)
			}},
		{name: "an empty withKid leaves no kid",
			opts: []signOption{withKid("")},
			assert: func(t *testing.T, raw string) {
				require.False(t, header(t, raw).Has(jws.KeyIDKey))
			}},
		{name: "withAlg signs under the named algorithm",
			opts: []signOption{withAlg(jwa.RS384())},
			assert: func(t *testing.T, raw string) {
				alg, _ := header(t, raw).Algorithm()
				require.Equal(t, jwa.RS384(), alg)
			}},
		{name: "withKey signs with a key the set does not hold",
			opts: []signOption{withKey(newRSAKey(t, "k1"))},
			assert: func(t *testing.T, raw string) {
				_, err := jws.Verify([]byte(raw), jws.WithKeySet(published(t)))
				require.Error(t, err)
			}},
		{name: "withHS256Secret signs with the shared secret",
			opts: []signOption{withHS256Secret("secret-corp")},
			assert: func(t *testing.T, raw string) {
				_, err := jws.Verify([]byte(raw), jws.WithKey(jwa.HS256(), []byte("secret-corp")))
				require.NoError(t, err)
			}},
		{name: "withNoneAlg is unsigned",
			opts: []signOption{withNoneAlg()},
			assert: func(t *testing.T, raw string) {
				require.Regexp(t, `^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.$`, raw)
				h, err := base64.RawURLEncoding.DecodeString(raw[:strings.IndexByte(raw, '.')])
				require.NoError(t, err)
				require.JSONEq(t, `{"alg":"none","kid":"k1"}`, string(h))
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, p.Sign(t, claims, tc.opts...))
		})
	}

	t.Run("a rotated key signs and both keys stay published", func(t *testing.T) {
		q := newTestProvider(t)
		before := q.Sign(t, claims)
		q.Rotate(t, "k2")
		after := q.Sign(t, claims)
		kid, _ := header(t, after).KeyID()
		require.Equal(t, "k2", kid)

		resp, err := q.Outbound(t).Get(t.Context(), q.Issuer()+"/jwks", nil)
		require.NoError(t, err)
		set, err := jwk.Parse(resp.Body)
		require.NoError(t, err)
		require.Equal(t, 2, set.Len())
		for _, raw := range []string{before, after} {
			_, err := jws.Verify([]byte(raw), jws.WithKeySet(set))
			require.NoError(t, err)
		}
	})
}

// stubBroker resolves every identity to one fixed principal. Where a test must
// verify calls, it uses the generated MockIdentityBroker instead.
type stubBroker struct{}

func (stubBroker) Broker(context.Context, oidc.ExternalIdentity) (*identity.Principal, error) {
	return &identity.Principal{ID: "user-1"}, nil
}

// nilClock is a consumer's clock type; (*nilClock)(nil) is the typed nil an
// unchecked constructor error hands over.
type nilClock struct{}

func (*nilClock) Now() time.Time { return time.Time{} }

// fixedClock is a consumer's own clock with only Now.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

// errFlowRandom is what errReader fails with.
var errFlowRandom = errors.New("random source failed")

// errReader is a random source that always fails.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errFlowRandom }

// errRedactionFixture is the dependency error every diagnostic-redaction
// reproduction in this change quotes: a username and a user reference the
// library never saw, which no record may carry.
var errRedactionFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// expiryT0 is when every flow and handoff in the expiry tests was issued.
var expiryT0 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

var errExpiryStore = errors.New("store unavailable")

// flushSummaries returns, in the order written, the suppressed count of every
// record in logs whose message is msg. It is how these tests read what a
// flush reported without depending on the sampling key's own text.
func flushSummaries(t *testing.T, logs, msg string) []int {
	t.Helper()

	var counts []int
	for _, line := range strings.Split(logs, "\n") {
		if line == "" || !strings.Contains(line, `msg="`+msg+`"`) {
			continue
		}

		idx := strings.Index(line, "suppressed=")
		require.GreaterOrEqual(t, idx, 0, "a summary record carried no suppressed attribute: %s", line)

		rest := line[idx+len("suppressed="):]
		if end := strings.IndexByte(rest, ' '); end >= 0 {
			rest = rest[:end]
		}
		n, err := strconv.Atoi(rest)
		require.NoError(t, err)
		counts = append(counts, n)
	}
	return counts
}

// flushFixedClock is a clock that never advances, so every refusal a test
// drives falls in the sampler's very first window.
func flushFixedClock() *clockwork.FakeClock {
	return clockwork.NewFakeClockAt(time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC))
}

// callbackEnv is one login in progress: a provider, a manager whose default
// store holds a flow begun by Authorize, and a token endpoint that answers
// that flow's code with a valid ID token.
type callbackEnv struct {
	m      *oidc.RelyingParty
	p      *testProvider
	broker *MockIdentityBroker
	auth   oidc.Authorization
	flow   oidc.Flow
	idTok  string
	logs   *bytes.Buffer
	now    time.Time
}

// genuine is the callback the provider's real redirect produces.
func (e *callbackEnv) genuine(t *testing.T) (oidc.CallbackResult, error) {
	t.Helper()
	return e.m.Callback(t.Context(), "corp", "the-code", e.flow.State, e.auth.Handle)
}

// expectBroker makes the broker resolve exactly one identity to alice.
func (e *callbackEnv) expectBroker(times int) {
	e.broker.EXPECT().Broker(gomock.Any(), gomock.Any()).Return(alice(), nil).Times(times)
}

// newCallbackEnv builds a manager for providers corp and partner at a fixed
// clock. With the default store it begins one flow at corp, and makes corp's
// token endpoint answer that flow's code with a valid ID token.
func newCallbackEnv(t *testing.T, now time.Time, flows func(t *testing.T) oidc.FlowStore) *callbackEnv {
	t.Helper()

	p := newTestProvider(t)
	reg, err := oidc.NewRegistry(p.Provider("corp"), p.Provider("partner"))
	require.NoError(t, err)

	e := &callbackEnv{p: p, broker: NewMockIdentityBroker(gomock.NewController(t)), logs: &bytes.Buffer{}, now: now}
	opts := []oidc.Option{
		oidc.WithOutboundClient(p.Outbound(t)),
		oidc.WithClock(clockwork.NewFakeClockAt(now)),
		oidc.WithLogger(testTextLogger(e.logs)),
	}
	if flows != nil {
		opts = append(opts, oidc.WithFlowStore(flows(t)))
	}
	e.m, err = oidc.NewRelyingParty(reg, e.broker, opts...)
	require.NoError(t, err)
	if flows != nil {
		return e
	}

	e.auth, err = e.m.Authorize(t.Context(), "corp", "/after")
	require.NoError(t, err)
	e.flow = authorizeFlow(t, e.m, e.auth.Handle)
	e.reissue(t, nil)

	return e
}

// reissue makes corp's token endpoint answer the flow's code with a valid ID
// token carrying extra claims beside the usual ones.
func (e *callbackEnv) reissue(t *testing.T, extra map[string]any) {
	t.Helper()

	claims := map[string]any{
		"iss": e.p.Issuer(), "aud": "client-corp", "sub": "subject-1",
		"exp": e.now.Add(5 * time.Minute).Unix(), "iat": e.now.Unix(),
		"nonce": e.flow.Nonce, "sid": "provider-session",
		"email": "alice@corp.example", "email_verified": true,
	}
	maps.Copy(claims, extra)
	idTok := e.p.Sign(t, claims)
	e.idTok = idTok
	verifier := e.flow.Verifier
	e.p.SetTokenResponse(func(r *http.Request) (int, string) {
		if r.ParseForm() != nil || r.PostForm.Get("code") != "the-code" || r.PostForm.Get("code_verifier") != verifier {
			return http.StatusBadRequest, `{"error":"invalid_grant"}`
		}
		return http.StatusOK, `{"access_token":"at","id_token":"` + idTok + `"}`
	})
}

// brokerCorpIdentity is the verified identity linked to u-1 in every
// linked-resolution row.
func brokerCorpIdentity() oidc.ExternalIdentity {
	return oidc.ExternalIdentity{
		Provider: "corp", Issuer: brokerCorpIssuer, Subject: "s-1",
		Email: "alice@corp.example", EmailVerified: true,
	}
}

// brokerSeededLinks returns a memory link store holding (corp, corp issuer,
// s-1) → u-1 / alice.
func brokerSeededLinks(t *testing.T) *oidc.MemoryLinkStore {
	t.Helper()

	s := oidc.NewMemoryLinkStore()
	require.NoError(t, s.Insert(t.Context(), oidc.Link{
		Provider: "corp", Issuer: brokerCorpIssuer, Subject: "s-1",
		UserID: "u-1", Username: "alice", Email: "alice@corp.example",
	}))
	return s
}

// errDBDown is a loader outage.
var errDBDown = errors.New("db down")

// provisionClock is the broker's clock in every provisioning row.
var provisionClock = time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)

// allProvisionFields is every field a Provision or Update option can name.
// The matcher loops over it rather than restating the list. A field listed
// here without a case in provisionFieldValue panics; a new identity.Field
// constant that is never added here is not compared at all, because the
// identity package exports no list of every field to check this one against.
var allProvisionFields = []identity.Field{
	identity.FieldName,
	identity.FieldEmail,
	identity.FieldRoles,
	identity.FieldOrganization,
	identity.FieldPassword,
	identity.FieldPasswordChangedAt,
}

// provisionFieldValue returns u's value for f, in the shape the matcher
// compares. Roles is clipped to a fresh backing array so two equal-content
// slices with different capacities still compare equal.
func provisionFieldValue(u *identity.UserChange, f identity.Field) any {
	switch f {
	case identity.FieldName:
		return u.Name
	case identity.FieldEmail:
		return u.Email
	case identity.FieldRoles:
		return slices.Clip(append([]string{}, u.Roles...))
	case identity.FieldOrganization:
		return u.Organization
	case identity.FieldPassword:
		return u.Password
	case identity.FieldPasswordChangedAt:
		return u.PasswordChangedAt
	default:
		panic(fmt.Sprintf("provisionFieldValue: unhandled field %d", f))
	}
}

// brokerUserOptionsMatcher matches the variadic options of a Provision call
// by what they name: it applies both sides with identity.ApplyUserOptions and
// compares every field's IsSet flag and, where set, its value.
type brokerUserOptionsMatcher struct{ want *identity.UserChange }

// provisionedWith matches Provision options naming exactly opts.
func provisionedWith(opts ...identity.UserOption) gomock.Matcher {
	return brokerUserOptionsMatcher{want: identity.ApplyUserOptions(opts...)}
}

func (m brokerUserOptionsMatcher) Matches(x any) bool {
	opts, ok := x.([]identity.UserOption)
	if !ok {
		return false
	}
	got := identity.ApplyUserOptions(opts...)
	for _, f := range allProvisionFields {
		if got.IsSet(f) != m.want.IsSet(f) {
			return false
		}
		if m.want.IsSet(f) && !reflect.DeepEqual(provisionFieldValue(got, f), provisionFieldValue(m.want, f)) {
			return false
		}
	}
	return true
}

func (m brokerUserOptionsMatcher) String() string {
	return fmt.Sprintf("names name=%q email=%q roles=%q (and only the fields set on %+v)",
		m.want.Name, m.want.Email, m.want.Roles, *m.want)
}

// provisionIdentity is an unlinked, verified identity from provider.
func provisionIdentity(provider, email string) oidc.ExternalIdentity {
	return oidc.ExternalIdentity{
		Provider: provider, Issuer: "https://" + provider + ".example", Subject: "s-new",
		Email: email, EmailVerified: true, Claims: map[string]any{},
	}
}

// bcryptShapedHash returns a well-formed bcrypt hash string at cost, whose
// 53-character salt-and-digest is fill repeated. bcrypt.Cost reads only the
// prefix, so the digest need not verify anything.
func bcryptShapedHash(cost string, fill byte) string {
	return "$2a$" + cost + "$" + strings.Repeat(string(fill), 53)
}

// Hashes the password-claim rows present. They are distinct so a row can tell
// which one reached a call or a log.
var (
	hashCost12 = bcryptShapedHash("12", 'a')
	hashCost04 = bcryptShapedHash("04", 'b')
	hashCost31 = bcryptShapedHash("31", 'c')
	hashCost13 = bcryptShapedHash("13", 'd')
)

// fastBcryptEncoder returns a real bcrypt encoder at the password package's
// floor, cost 10, which keeps the construction probe cheap.
func fastBcryptEncoder(t *testing.T) password.Encoder {
	t.Helper()
	enc, err := password.NewBcryptEncoder(password.WithBcryptCost(10))
	require.NoError(t, err)
	return enc
}

// passwordClaimIdentity is an unlinked, verified corp identity carrying hash
// at credentials.password_hash, or no such claim when hash is nil.
func passwordClaimIdentity(subject string, hash any) oidc.ExternalIdentity {
	ext := provisionIdentity("corp", "bob@corp.example")
	ext.Subject = subject
	if hash != nil {
		ext.Claims = map[string]any{"credentials": map[string]any{"password_hash": hash}}
	}
	return ext
}

// linesContaining returns the lines of logs that contain s.
func linesContaining(logs, s string) []string {
	var out []string
	for line := range strings.SplitSeq(logs, "\n") {
		if strings.Contains(line, s) {
			out = append(out, line)
		}
	}
	return out
}
