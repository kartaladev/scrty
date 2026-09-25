package oidc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/outbound"
)

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
