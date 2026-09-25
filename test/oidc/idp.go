package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/outbound"
)

// IdentityProvider is an in-process OpenID provider for tests: discovery, a
// key set and a token endpoint over TLS, rotatable keys, call counters, both
// client authentication methods, and a signer that emits valid and malformed
// ID and logout tokens.
//
// Build one with NewIdentityProvider. It is safe for concurrent use.
type IdentityProvider struct {
	srv *httptest.Server

	mu   sync.Mutex
	key  jwk.Key   // current RS256 signing key (private)
	keys []jwk.Key // every key ever published, oldest first, private halves included

	// clientSecrets maps a client id, as handed out by Provider, to the
	// secret registered beside it, so a token signed with
	// HS256WithClientSecret and the token endpoint's own credential check
	// use the same value Provider gave the caller.
	clientSecrets map[string]string

	// pending maps an issued authorization code to the ID token Login signed
	// for it. The token endpoint answers a code exactly once: redeeming it
	// removes the entry.
	pending map[string]string

	discoveryCalls atomic.Int64
	jwksCalls      atomic.Int64
	tokenCalls     atomic.Int64

	// lastTokenAuth is how the most recent token request authenticated the
	// client, so a test can assert not only that the configured method
	// worked, but that the client did not also carry credentials on the
	// channel it wasn't configured to use.
	lastTokenAuth TokenAuthObservation
}

// TokenAuthObservation records how one token request authenticated the
// client: which channel serveToken accepted its id and secret from, and
// whether the other channel carried anything at all.
type TokenAuthObservation struct {
	// Method is the channel serveToken accepted credentials from:
	// oidc.ClientSecretBasic when the Authorization header carried them,
	// oidc.ClientSecretPost otherwise.
	Method oidc.ClientAuthMethod

	// AuthorizationHeader reports whether the request carried an
	// Authorization header, regardless of which channel was accepted.
	AuthorizationHeader bool

	// FormClientSecret reports whether the request's form body carried a
	// client_secret field, regardless of which channel was accepted.
	FormClientSecret bool
}

// IdentityProviderOption configures an IdentityProvider. None are defined yet;
// the type exists so a future option needs no signature change at every call
// site that already passes none.
type IdentityProviderOption func(*IdentityProvider)

// NewIdentityProvider starts a provider with one RS256 key, kid "k1". The
// server is closed when the test ends.
func NewIdentityProvider(t *testing.T, opts ...IdentityProviderOption) *IdentityProvider {
	t.Helper()

	p := &IdentityProvider{
		clientSecrets: make(map[string]string),
		pending:       make(map[string]string),
	}
	p.key = newRSAKey(t, "k1")
	p.keys = []jwk.Key{p.key}

	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.serveDiscovery)
	mux.HandleFunc("GET /jwks", p.serveJWKS)
	mux.HandleFunc("POST /token", p.serveToken)

	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)

	return p
}

// Issuer is the provider's issuer identifier, the server's base URL.
func (p *IdentityProvider) Issuer() string { return p.srv.URL }

// Provider returns an unpinned registration for name, authenticating at the
// token endpoint with auth. Discovery, not a pinned endpoint, is what a
// caller's oidc.Manager uses to reach this provider.
//
// The client id and secret are deterministic from name, so a later call
// naming the same provider, and the token endpoint's own credential check,
// agree with what a caller was handed here.
func (p *IdentityProvider) Provider(name string, auth oidc.ClientAuthMethod) oidc.Provider {
	clientID := "client-" + name
	secret := "secret-" + name

	p.mu.Lock()
	p.clientSecrets[clientID] = secret
	p.mu.Unlock()

	return oidc.Provider{
		Name:         name,
		Issuer:       p.Issuer(),
		ClientID:     clientID,
		ClientSecret: secret,
		// The path a caller's httpsec chain answers a callback on by default;
		// Login hands back a callback target built from this URL.
		RedirectURL: "https://app.example" + httpsec.DefaultOIDCCallbackPath + name,
		ClientAuth:  auth,
	}
}

// Outbound returns a confined client that trusts the provider's certificate.
func (p *IdentityProvider) Outbound(t *testing.T) *outbound.Client {
	t.Helper()

	c, err := outbound.New(outbound.WithHTTPClient(p.srv.Client()))
	require.NoError(t, err)

	return c
}

// Rotate makes a new RS256 key with the given kid current and publishes it
// beside every key published before it, so a token signed under an earlier
// key still verifies against a refetched key set.
func (p *IdentityProvider) Rotate(t *testing.T, kid string) {
	t.Helper()

	k := newRSAKey(t, kid)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.key = k
	p.keys = append(p.keys, k)
}

// Calls reports how many times discovery, the key set and the token endpoint
// have each been requested.
func (p *IdentityProvider) Calls() (discovery, jwks, token int64) {
	return p.discoveryCalls.Load(), p.jwksCalls.Load(), p.tokenCalls.Load()
}

// LastTokenAuth reports how the most recent token request authenticated the
// client. Call it after a login has completed; before any token request it
// reports the zero value.
func (p *IdentityProvider) LastTokenAuth() TokenAuthObservation {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.lastTokenAuth
}

// Login simulates the user at the provider: given the authorization
// redirect (the Location of a GET on the authorize endpoint), it records the
// code the next token request will exchange for an ID token, and returns the
// callback path and query the browser would be sent to next.
//
// claims is what the token asserts. iss, the flow's own nonce and, unless
// opts overrides them, aud, iat and exp are filled in from the authorization
// redirect and the current time; claims wins over every filled-in default it
// also names. opts changes how the token is signed or lets a malformed-token
// constructor (WrongIssuer, BadSignature, ...) corrupt exactly what it names,
// so the same call that drives a genuine login can drive one that must fail.
func (p *IdentityProvider) Login(
	t *testing.T, authorizeURL string, claims map[string]any, opts ...TokenOption,
) (callbackPath string) {
	t.Helper()

	u, err := url.Parse(authorizeURL)
	require.NoError(t, err, "Login was given an unparsable authorization redirect: %q", authorizeURL)

	q := u.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	nonce := q.Get("nonce")
	require.NotEmpty(t, clientID, "the authorization redirect carried no client_id: %q", authorizeURL)
	require.NotEmpty(t, redirectURI, "the authorization redirect carried no redirect_uri: %q", authorizeURL)
	require.NotEmpty(t, state, "the authorization redirect carried no state: %q", authorizeURL)

	now := time.Now()
	final := map[string]any{
		"iss":   p.Issuer(),
		"aud":   clientID,
		"nonce": nonce,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range claims {
		final[k] = v
	}

	raw := p.sign(t, final, opts...)
	code := p.issueCode(t, raw)

	redirect, err := url.Parse(redirectURI)
	require.NoError(t, err, "the authorization redirect carried an unparsable redirect_uri: %q", redirectURI)

	redirect.RawQuery = url.Values{"code": {code}, "state": {state}}.Encode()

	return redirect.Path + "?" + redirect.RawQuery
}

// LogoutToken signs a back-channel logout token.
//
// Unlike Login, claims is used exactly as given beyond iss, iat, jti and the
// back-channel events claim, which are filled in only when claims does not
// already carry them: a caller names its own aud, sub and sid, since a logout
// token is not tied to any one login flow.
func (p *IdentityProvider) LogoutToken(t *testing.T, claims map[string]any, opts ...TokenOption) string {
	t.Helper()

	now := time.Now()
	final := map[string]any{
		"iss":    p.Issuer(),
		"iat":    now.Unix(),
		"jti":    randomHex(t, 8),
		"events": map[string]any{oidc.BackchannelLogoutEvent: map[string]any{}},
	}
	for k, v := range claims {
		final[k] = v
	}

	return p.sign(t, final, opts...)
}

// issueCode records raw under a fresh single-use code and returns it.
func (p *IdentityProvider) issueCode(t *testing.T, raw string) string {
	t.Helper()

	code := randomHex(t, 16)

	p.mu.Lock()
	p.pending[code] = raw
	p.mu.Unlock()

	return code
}

// secretFor returns the client secret registered for a client id, or "" for
// one Provider never handed out. aud is untyped because it is read straight
// out of a token's claims map, which a malformed-token option may have
// shaped into anything.
func (p *IdentityProvider) secretFor(aud any) string {
	clientID, _ := aud.(string)

	p.mu.Lock()
	defer p.mu.Unlock()

	return p.clientSecrets[clientID]
}

// currentKey returns the provider's current signing key and its kid.
func (p *IdentityProvider) currentKey() (jwk.Key, string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	kid, _ := p.key.KeyID()

	return p.key, kid
}

func (p *IdentityProvider) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	p.discoveryCalls.Add(1)

	writeJSON(w, map[string]any{
		"issuer":                                p.Issuer(),
		"authorization_endpoint":                p.Issuer() + "/authorize",
		"token_endpoint":                        p.Issuer() + "/token",
		"jwks_uri":                              p.Issuer() + "/jwks",
		"end_session_endpoint":                  p.Issuer() + "/logout",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"backchannel_logout_supported":          true,
		"backchannel_logout_session_supported":  true,
	})
}

func (p *IdentityProvider) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	p.jwksCalls.Add(1)

	p.mu.Lock()
	set := jwk.NewSet()
	var addErr error
	for _, k := range p.keys {
		if err := set.AddKey(k); err != nil {
			addErr = err
		}
	}
	p.mu.Unlock()

	if addErr != nil {
		http.Error(w, "key set", http.StatusInternalServerError)
		return
	}

	public, err := jwk.PublicSetOf(set)
	if err != nil {
		http.Error(w, "key set", http.StatusInternalServerError)
		return
	}

	writeJSON(w, public)
}

// serveToken answers a code exchange: both client authentication methods are
// checked against the secret Provider registered, and a code is honoured
// exactly once.
func (p *IdentityProvider) serveToken(w http.ResponseWriter, r *http.Request) {
	p.tokenCalls.Add(1)

	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	method, clientID, clientSecret, ok := clientCredentials(r)

	p.mu.Lock()
	p.lastTokenAuth = TokenAuthObservation{
		Method:              method,
		AuthorizationHeader: r.Header.Get("Authorization") != "",
		FormClientSecret:    r.PostForm.Get("client_secret") != "",
	}
	p.mu.Unlock()

	if !ok {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client")
		return
	}

	p.mu.Lock()
	want, known := p.clientSecrets[clientID]
	p.mu.Unlock()
	if !known || subtle.ConstantTimeCompare([]byte(want), []byte(clientSecret)) != 1 {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client")
		return
	}

	code := r.PostForm.Get("code")

	p.mu.Lock()
	raw, found := p.pending[code]
	if found {
		delete(p.pending, code)
	}
	p.mu.Unlock()

	if !found {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token": "discarded",
		"token_type":   "Bearer",
		"id_token":     raw,
	})
}

// clientCredentials reads the client's id and secret from an HTTP Basic
// header (client_secret_basic) or, failing that, the form body
// (client_secret_post), and reports which channel it read them from. ok is
// false when neither carried a client id.
func clientCredentials(r *http.Request) (method oidc.ClientAuthMethod, id, secret string, ok bool) {
	if u, pw, has := r.BasicAuth(); has {
		du, err1 := url.QueryUnescape(u)
		dp, err2 := url.QueryUnescape(pw)
		if err1 != nil || err2 != nil {
			return oidc.ClientSecretBasic, "", "", false
		}

		return oidc.ClientSecretBasic, du, dp, true
	}

	id = r.PostForm.Get("client_id")
	if id == "" {
		return oidc.ClientSecretPost, "", "", false
	}

	return oidc.ClientSecretPost, id, r.PostForm.Get("client_secret"), true
}

func writeTokenError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
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

// randomHex returns n random bytes, hex-encoded.
func randomHex(t *testing.T, n int) string {
	t.Helper()

	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)

	return hex.EncodeToString(b)
}

// tokenConfig is what a TokenOption changes about one token IdentityProvider
// signs: its claims, or how it is signed.
type tokenConfig struct {
	claims map[string]any

	// kid overrides the header key id Sign would otherwise use.
	kid *string

	// badSignature signs with a freshly generated key that shares the
	// current key's kid but not its key material, so the signature the
	// published key set verifies against does not match.
	badSignature bool

	// hs256WithClientSecret signs with HS256 under the client secret
	// registered for the claims' own aud, rather than the current RS256 key.
	hs256WithClientSecret bool

	// none produces an unsigned token whose header says "alg":"none".
	none bool
}

// TokenOption changes one token IdentityProvider signs, either a claim it
// asserts or how it is signed. Each malformed-token constructor
// (WrongIssuer, BadSignature, ...) returns one, and each corrupts exactly the
// one thing it names, leaving Login's and LogoutToken's other defaults alone.
type TokenOption func(*tokenConfig)

// WrongIssuer makes the token assert an issuer that is not this provider's.
func WrongIssuer() TokenOption {
	return func(c *tokenConfig) { c.claims["iss"] = "https://wrong-issuer.example" }
}

// WrongAudience makes the token assert an audience that names no registered
// client.
func WrongAudience() TokenOption {
	return func(c *tokenConfig) { c.claims["aud"] = "wrong-client-id" }
}

// Expired makes the token's exp two hours in the past, well beyond any clock
// skew a verifier would allow.
func Expired() TokenOption {
	return func(c *tokenConfig) { c.claims["exp"] = time.Now().Add(-2 * time.Hour).Unix() }
}

// FutureIssuedAt makes the token's iat two hours in the future, well beyond
// any clock skew a verifier would allow.
func FutureIssuedAt() TokenOption {
	return func(c *tokenConfig) { c.claims["iat"] = time.Now().Add(2 * time.Hour).Unix() }
}

// BadSignature signs the token with a key that shares the current signing
// key's kid but not its key material, so it names a real published key
// whose signature does not match.
func BadSignature() TokenOption {
	return func(c *tokenConfig) { c.badSignature = true }
}

// UnknownKid signs the token under a key id no published key set entry has
// ever used.
func UnknownKid() TokenOption {
	return func(c *tokenConfig) {
		kid := "unknown-kid"
		c.kid = &kid
	}
}

// AlgNone produces an unsigned token whose header claims "alg":"none".
func AlgNone() TokenOption {
	return func(c *tokenConfig) { c.none = true }
}

// HS256WithClientSecret signs the token with HS256 under the client secret
// registered for its own aud, instead of the provider's RS256 key: the
// attack a provider accepting a symmetric algorithm it never listed would
// fall for.
func HS256WithClientSecret() TokenOption {
	return func(c *tokenConfig) { c.hs256WithClientSecret = true }
}

// WrongNonce makes the token assert a nonce that does not match the flow
// that started the login.
func WrongNonce() TokenOption {
	return func(c *tokenConfig) { c.claims["nonce"] = "not-the-flow-nonce" }
}

// NoSubject removes the token's sub claim.
func NoSubject() TokenOption {
	return func(c *tokenConfig) { delete(c.claims, "sub") }
}

// MultipleAudiencesWithoutAZP makes the token name a second audience beside
// its own, and carries no azp naming which of them is the authorized party.
func MultipleAudiencesWithoutAZP() TokenOption {
	return func(c *tokenConfig) {
		aud, _ := c.claims["aud"].(string)
		c.claims["aud"] = []string{aud, "another-consumer"}
		delete(c.claims, "azp")
	}
}

// sign marshals claims as the payload of a compact JWS, applies opts, and
// returns the token: unsigned when an option asked for that, otherwise
// signed as the options and the provider's current key decide.
func (p *IdentityProvider) sign(t *testing.T, claims map[string]any, opts ...TokenOption) string {
	t.Helper()

	cfg := &tokenConfig{claims: claims}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}

	payload, err := json.Marshal(cfg.claims)
	require.NoError(t, err)

	if cfg.none {
		return unsignedJWS(t, headerKid(cfg, p), payload)
	}

	alg, signingKey, kid := p.signingMaterial(t, cfg)
	if cfg.kid != nil {
		kid = *cfg.kid
	}

	headers := jws.NewHeaders()
	if kid != "" {
		require.NoError(t, headers.Set(jws.KeyIDKey, kid))
	}

	signed, err := jws.Sign(payload, jws.WithKey(alg, signingKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)

	return string(signed)
}

// signingMaterial resolves what sign signs with, before a kid override.
func (p *IdentityProvider) signingMaterial(t *testing.T, cfg *tokenConfig) (alg jwa.SignatureAlgorithm, key any, kid string) {
	t.Helper()

	switch {
	case cfg.hs256WithClientSecret:
		return jwa.HS256(), []byte(p.secretFor(cfg.claims["aud"])), ""
	case cfg.badSignature:
		_, currentKid := p.currentKey()
		mismatched := newRSAKey(t, currentKid)

		return jwa.RS256(), exportRSAKey(t, mismatched), currentKid
	default:
		current, currentKid := p.currentKey()

		return jwa.RS256(), exportRSAKey(t, current), currentKid
	}
}

// exportRSAKey returns k's private key material, for signing.
func exportRSAKey(t *testing.T, k jwk.Key) *rsa.PrivateKey {
	t.Helper()

	raw, err := jwk.Export[*rsa.PrivateKey](k)
	require.NoError(t, err)

	return raw
}

// headerKid is the kid an unsigned (alg: none) token's header carries: the
// override an option named, or the provider's current kid.
func headerKid(cfg *tokenConfig, p *IdentityProvider) string {
	if cfg.kid != nil {
		return *cfg.kid
	}
	_, kid := p.currentKey()

	return kid
}

// unsignedJWS builds the compact form of an alg:none token: a header and a
// payload, base64url-encoded and joined by dots, with no signature segment.
func unsignedJWS(t *testing.T, kid string, payload []byte) string {
	t.Helper()

	header := map[string]any{"alg": "none"}
	if kid != "" {
		header["kid"] = kid
	}
	h, err := json.Marshal(header)
	require.NoError(t, err)

	enc := base64.RawURLEncoding
	return enc.EncodeToString(h) + "." + enc.EncodeToString(payload) + "."
}
