package httpsec_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// The resource server the remote-issuer cases call.
const (
	riAPI    = "urn:example:orders:api"
	riAPIURL = "https://api.example.com/api/orders"
)

// riKey is one signing key of a fake issuer.
type riKey struct {
	kid  string
	alg  jwa.SignatureAlgorithm
	priv crypto.Signer
	pub  jwk.Key
}

// newRIKey is a key named kid for alg, ES256 or RS256.
func newRIKey(t *testing.T, kid string, alg jwa.SignatureAlgorithm) riKey {
	t.Helper()

	var priv crypto.Signer

	var err error

	if alg == jwa.RS256() {
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}

	require.NoError(t, err)

	pub, err := jwk.PublicKeyOf(priv.Public())
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, kid))
	require.NoError(t, pub.Set(jwk.AlgorithmKey, alg))
	require.NoError(t, pub.Set(jwk.KeyUsageKey, "sig"))

	return riKey{kid: kid, alg: alg, priv: priv, pub: pub}
}

// riIssuer is a TLS issuer serving OpenID discovery, its key set and an introspection endpoint, whose
// answers a case changes.
type riIssuer struct {
	srv *httptest.Server
	iss string

	mu   sync.Mutex
	keys []riKey

	// metadataIssuer and jwksURI replace what the metadata states, when not empty.
	metadataIssuer, jwksURI atomic.Pointer[string]

	// down answers every key-set request 503; hangup has the request's caller leave while the key set
	// is fetched.
	down, hangup atomic.Bool

	// active is what the introspection endpoint says of every token; introspectionDown answers 503.
	active, introspectionDown atomic.Bool

	metadataHits, jwksHits, introspectionHits atomic.Int32

	// leave ends the request of the call in flight.
	leave atomic.Pointer[context.CancelFunc]
}

func newRIIssuer(t *testing.T, keys ...riKey) *riIssuer {
	t.Helper()

	i := &riIssuer{keys: keys}
	i.active.Store(true)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(rw http.ResponseWriter, _ *http.Request) {
		i.metadataHits.Add(1)

		doc := map[string]any{"issuer": i.iss, "jwks_uri": i.iss + "/jwks"}
		if v := i.metadataIssuer.Load(); v != nil {
			doc["issuer"] = *v
		}

		if v := i.jwksURI.Load(); v != nil {
			doc["jwks_uri"] = *v
		}

		writeJSON(rw, doc)
	})
	mux.HandleFunc("/jwks", func(rw http.ResponseWriter, r *http.Request) {
		i.jwksHits.Add(1)

		switch {
		case i.hangup.Load():
			if leave := i.leave.Load(); leave != nil {
				(*leave)()
			}

			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}

			return
		case i.down.Load():
			rw.WriteHeader(http.StatusServiceUnavailable)

			return
		}

		set := jwk.NewSet()

		i.mu.Lock()
		for _, k := range i.keys {
			_ = set.AddKey(k.pub)
		}
		i.mu.Unlock()

		b, _ := json.Marshal(set)
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write(b)
	})
	mux.HandleFunc("/introspect", func(rw http.ResponseWriter, _ *http.Request) {
		i.introspectionHits.Add(1)

		if i.introspectionDown.Load() {
			rw.WriteHeader(http.StatusServiceUnavailable)

			return
		}

		if !i.active.Load() {
			writeJSON(rw, map[string]any{"active": false})

			return
		}

		writeJSON(rw, map[string]any{"active": true, "sub": "42", "aud": riAPI,
			"exp": time.Now().Add(time.Hour).Unix(), "token_type": "access_token"})
	})

	i.srv = httptest.NewTLSServer(mux)
	t.Cleanup(i.srv.Close)
	i.iss = i.srv.URL

	return i
}

func writeJSON(rw http.ResponseWriter, v any) {
	b, _ := json.Marshal(v)
	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write(b)
}

// publish adds k to the key set the issuer serves.
func (i *riIssuer) publish(k riKey) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.keys = append(i.keys, k)
}

// countingTransport counts the requests it sends.
type countingTransport struct {
	next http.RoundTripper
	sent atomic.Int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.sent.Add(1)

	return c.next.RoundTrip(r)
}

// riWorld is a chain whose resource server trusts one or more fake issuers.
type riWorld struct {
	issuers []*riIssuer
	clk     *clockwork.FakeClock
	chain   *httpsec.Chain
	sent    *countingTransport
	logs    *capturingHandler
	failure atomic.Pointer[error]
}

// riSetup is what a case asks of its world.
type riSetup struct {
	// opts are the first issuer's source options, beside the outbound client and, unless bound,
	// WithUnboundTokens.
	opts func(w *riWorld) []httpsec.SourceOption

	// second adds a second issuer, with default options and unbound tokens.
	second bool

	// bound leaves WithUnboundTokens out, and enables DPoP on the chain.
	bound bool

	// keys are the first issuer's keys; a new ES256 key "k1" when empty.
	keys []riKey
}

func newRIWorld(t *testing.T, setup riSetup) *riWorld {
	t.Helper()

	keys := setup.keys
	if len(keys) == 0 {
		keys = []riKey{newRIKey(t, "k1", jwa.ES256())}
	}

	w := &riWorld{clk: clockwork.NewFakeClockAt(time.Now()), logs: &capturingHandler{}}
	w.issuers = append(w.issuers, newRIIssuer(t, keys...))

	if setup.second {
		w.issuers = append(w.issuers, newRIIssuer(t, newRIKey(t, "k2", jwa.ES256())))
	}

	transport, ok := w.issuers[0].srv.Client().Transport.(*http.Transport)
	require.True(t, ok)

	w.sent = &countingTransport{next: transport}
	oc, err := outbound.New(outbound.WithHTTPClient(&http.Client{Transport: w.sent}))
	require.NoError(t, err)

	first := []httpsec.SourceOption{httpsec.WithOutboundClient(oc)}
	if !setup.bound {
		first = append(first, httpsec.WithUnboundTokens())
	}

	if setup.opts != nil {
		first = append(first, setup.opts(w)...)
	}

	rsOpts := []httpsec.ResourceServerOption{httpsec.WithPathPrefix("/api/"), httpsec.FromIssuer(w.issuers[0].iss, first...)}
	if setup.second {
		rsOpts = append(rsOpts, httpsec.FromIssuer(w.issuers[1].iss, httpsec.WithOutboundClient(oc), httpsec.WithUnboundTokens()))
	}

	opts := []httpsec.Option{
		httpsec.WithClock(w.clk),
		httpsec.WithLogger(slog.New(w.logs)),
		httpsec.WithErrorHandler(func(rw http.ResponseWriter, _ *http.Request, err error) {
			w.failure.Store(&err)
			rw.WriteHeader(httpsec.StatusForError(err))
		}),
		httpsec.EnableResourceServer(riAPI, rsOpts...),
	}
	if setup.bound {
		opts = append(opts, httpsec.EnableDPoP(httpsec.DPoP{PublicURL: "https://api.example.com"}))
	}

	w.chain, err = httpsec.New(opts...)
	require.NoError(t, err)

	return w
}

// riToken is a token being built: its header and claims.
type riToken struct {
	headers map[string]any
	claims  map[string]any
}

// token is a valid at+jwt access token of issuer i signed with k, with change applied.
func (w *riWorld) token(t *testing.T, i *riIssuer, k riKey, change func(tok *riToken)) string {
	t.Helper()

	now := w.clk.Now()
	tok := &riToken{
		headers: map[string]any{jws.TypeKey: "at+jwt", jws.KeyIDKey: k.kid},
		claims: map[string]any{
			"iss": i.iss, "sub": "42", "aud": riAPI, "client_id": "web-app", "jti": "t-1",
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": "orders:read orders:write",
		},
	}

	if change != nil {
		change(tok)
	}

	return proofParts{alg: k.alg, signKey: k.priv, headers: tok.headers, claims: tok.claims}.sign(t)
}

// riCall is one call of the API, and what the handler saw.
type riCall struct {
	status  int
	header  http.Header
	body    string
	ran     bool
	caller  *identity.Principal
	token   *httpsec.AccessToken
	failure error
}

// call calls the API with tok under Bearer, or under DPoP with a proof from k when k is not nil.
func (w *riWorld) call(t *testing.T, tok string, k *dpopKey) riCall {
	t.Helper()

	ctx, leave := context.WithCancel(t.Context())
	defer leave()

	for _, i := range w.issuers {
		i.leave.Store(&leave)
	}

	r := httptest.NewRequestWithContext(ctx, http.MethodGet, riAPIURL, nil)

	if k == nil {
		r.Header.Set("Authorization", "Bearer "+tok)
	} else {
		r.Header.Set("Authorization", "DPoP "+tok)
		r.Header.Set("DPoP", k.validProof("p-1").with(map[string]any{
			"htu": riAPIURL, "iat": w.clk.Now().Unix(), "ath": tokenHash(tok),
		}).sign(t))
	}

	var out riCall

	h := w.chain.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		out.ran = true
		out.caller, _ = identity.PrincipalFromContext(r.Context())
		out.token, _ = httpsec.AccessTokenFromContext(r.Context())
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	out.status, out.header, out.body = rec.Code, rec.Header(), rec.Body.String()
	if f := w.failure.Swap(nil); f != nil {
		out.failure = *f
	}

	return out
}

// TestResourceServer_FromIssuer pins the remote-issuer source against a local TLS issuer: its key set,
// the profile's type and claims, the binding default, the dependency failures and JWT introspection.
func TestResourceServer_FromIssuer(t *testing.T) {
	t.Parallel()

	k1 := newRIKey(t, "k1", jwa.ES256())
	dk := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name   string
		setup  riSetup
		act    func(t *testing.T, w *riWorld) riCall
		assert func(t *testing.T, w *riWorld, out riCall)
	}

	accepted := func(t *testing.T, w *riWorld, out riCall) {
		t.Helper()
		require.Equal(t, http.StatusOK, out.status, out.body)
		require.True(t, out.ran)
		require.NotNil(t, out.caller)
		assert.Equal(t, identity.UserID(w.issuers[0].iss+"#42"), out.caller.ID)
	}

	invalidToken := func(t *testing.T, _ *riWorld, out riCall) {
		t.Helper()
		assert.Equal(t, http.StatusUnauthorized, out.status)
		assert.False(t, out.ran)
		require.ErrorIs(t, out.failure, httpsec.ErrInvalidToken)
	}

	dependency := func(t *testing.T, _ *riWorld, out riCall) {
		t.Helper()
		assert.Equal(t, http.StatusInternalServerError, out.status)
		assert.False(t, out.ran)
		require.Error(t, out.failure)
		assert.NotErrorIs(t, out.failure, httpsec.ErrInvalidToken)
		assert.Empty(t, out.header.Values("WWW-Authenticate"))
	}

	simple := func(change func(tok *riToken)) func(t *testing.T, w *riWorld) riCall {
		return func(t *testing.T, w *riWorld) riCall {
			return w.call(t, w.token(t, w.issuers[0], k1, change), nil)
		}
	}

	untyped := func(*riWorld) []httpsec.SourceOption {
		return []httpsec.SourceOption{httpsec.WithUntypedTokens("typ", "Bearer")}
	}

	typedJWT := func(claim string) func(tok *riToken) {
		return func(tok *riToken) {
			tok.headers[jws.TypeKey] = "JWT"
			tok.claims["typ"] = claim
			delete(tok.claims, "jti")
		}
	}

	cases := []testCase{
		{
			name: "a valid token is accepted as a claims-only caller with its scopes and claims",
			act:  simple(nil),
			assert: func(t *testing.T, w *riWorld, out riCall) {
				accepted(t, w, out)
				assert.Equal(t, identity.KindUser, out.caller.Kind)
				assert.Empty(t, out.caller.Roles)
				assert.Equal(t, []string{"orders:read", "orders:write"}, out.caller.Scopes)
				require.NotNil(t, out.token)
				assert.Equal(t, w.issuers[0].iss, out.token.Issuer)
				assert.Equal(t, "42", out.token.Subject)
				assert.Equal(t, "web-app", out.token.ClientID)
				assert.Equal(t, riAPI, out.token.Resource)
				assert.Equal(t, "t-1", out.token.Claims["jti"])
			},
		},
		{
			name: "scopes are read from scp as an array",
			act: simple(func(tok *riToken) {
				delete(tok.claims, "scope")
				tok.claims["scp"] = []any{"orders:read", "orders:write"}
			}),
			assert: func(t *testing.T, w *riWorld, out riCall) {
				accepted(t, w, out)
				assert.Equal(t, []string{"orders:read", "orders:write"}, out.caller.Scopes)
			},
		},
		{
			name: "scopes are read from scp as a string",
			act: simple(func(tok *riToken) {
				delete(tok.claims, "scope")
				tok.claims["scp"] = "orders:read"
			}),
			assert: func(t *testing.T, w *riWorld, out riCall) {
				accepted(t, w, out)
				assert.Equal(t, []string{"orders:read"}, out.caller.Scopes)
			},
		},
		{
			name: "scope is read before scp",
			act: simple(func(tok *riToken) {
				tok.claims["scope"] = "orders:read"
				tok.claims["scp"] = []any{"admin:all"}
			}),
			assert: func(t *testing.T, w *riWorld, out riCall) {
				accepted(t, w, out)
				assert.Equal(t, []string{"orders:read"}, out.caller.Scopes)
			},
		},
		{name: "a token typed JWT is refused by default", act: simple(typedJWT("Bearer")), assert: invalidToken},
		{
			name:   "a token typed JWT with the telling claim is accepted when opted in",
			setup:  riSetup{opts: untyped},
			act:    simple(typedJWT("Bearer")),
			assert: accepted,
		},
		{
			name:   "an ID token of the same issuer is refused when opted in",
			setup:  riSetup{opts: untyped},
			act:    simple(typedJWT("ID")),
			assert: invalidToken,
		},
		{
			name:  "an untyped token naming its client in azp only is accepted when opted in",
			setup: riSetup{opts: untyped},
			act: simple(func(tok *riToken) {
				typedJWT("Bearer")(tok)
				delete(tok.headers, jws.TypeKey)
				delete(tok.claims, "client_id")
				tok.claims["azp"] = "spa"
			}),
			assert: func(t *testing.T, w *riWorld, out riCall) {
				accepted(t, w, out)
				assert.Equal(t, "spa", out.token.ClientID)
			},
		},
		{
			name: "an at+jwt naming its client in azp only is refused",
			act: simple(func(tok *riToken) {
				delete(tok.claims, "client_id")
				tok.claims["azp"] = "spa"
			}),
			assert: invalidToken,
		},
		{name: "a token with no sub is refused", act: simple(func(tok *riToken) { delete(tok.claims, "sub") }), assert: invalidToken},
		{name: "a token with an empty sub is refused", act: simple(func(tok *riToken) { tok.claims["sub"] = "" }), assert: invalidToken},
		{name: "a token with no iat is refused", act: simple(func(tok *riToken) { delete(tok.claims, "iat") }), assert: invalidToken},
		{name: "a token with no exp is refused", act: simple(func(tok *riToken) { delete(tok.claims, "exp") }), assert: invalidToken},
		{name: "a token with no aud is refused", act: simple(func(tok *riToken) { delete(tok.claims, "aud") }), assert: invalidToken},
		{name: "a token with no client_id is refused", act: simple(func(tok *riToken) { delete(tok.claims, "client_id") }), assert: invalidToken},
		{name: "an at+jwt with no jti is refused", act: simple(func(tok *riToken) { delete(tok.claims, "jti") }), assert: invalidToken},
		{
			name:   "a token whose audience is another API's is refused",
			act:    simple(func(tok *riToken) { tok.claims["aud"] = "urn:billing" }),
			assert: invalidToken,
		},
		{
			name: "a token whose audience is only its issuer is refused",
			act: func(t *testing.T, w *riWorld) riCall {
				return w.call(t, w.token(t, w.issuers[0], k1, func(tok *riToken) { tok.claims["aud"] = w.issuers[0].iss }), nil)
			},
			assert: invalidToken,
		},
		{
			name: "a token that expires now is refused",
			act: func(t *testing.T, w *riWorld) riCall {
				return w.call(t, w.token(t, w.issuers[0], k1, func(tok *riToken) { tok.claims["exp"] = w.clk.Now().Unix() }), nil)
			},
			assert: invalidToken,
		},
		{
			name: "a token issued 30 seconds ahead is accepted with no skew",
			act: func(t *testing.T, w *riWorld) riCall {
				return w.call(t, w.token(t, w.issuers[0], k1, func(tok *riToken) {
					tok.claims["iat"] = w.clk.Now().Add(30 * time.Second).Unix()
				}), nil)
			},
			assert: accepted,
		},
		{
			name: "a token issued two minutes ahead is refused with no skew",
			act: func(t *testing.T, w *riWorld) riCall {
				return w.call(t, w.token(t, w.issuers[0], k1, func(tok *riToken) {
					tok.claims["iat"] = w.clk.Now().Add(2 * time.Minute).Unix()
				}), nil)
			},
			assert: invalidToken,
		},
		{
			name: "a token not valid for two minutes is refused with no skew",
			act: func(t *testing.T, w *riWorld) riCall {
				return w.call(t, w.token(t, w.issuers[0], k1, func(tok *riToken) {
					tok.claims["nbf"] = w.clk.Now().Add(2 * time.Minute).Unix()
				}), nil)
			},
			assert: invalidToken,
		},
		{
			name: "a token issued two minutes ahead is accepted with a three-minute skew",
			setup: riSetup{opts: func(*riWorld) []httpsec.SourceOption {
				return []httpsec.SourceOption{httpsec.WithClockSkew(3 * time.Minute)}
			}},
			act: func(t *testing.T, w *riWorld) riCall {
				return w.call(t, w.token(t, w.issuers[0], k1, func(tok *riToken) {
					tok.claims["iat"] = w.clk.Now().Add(2 * time.Minute).Unix()
				}), nil)
			},
			assert: accepted,
		},
		{
			name: "the first token under a rotated key refetches the key set once and is accepted",
			act: func(t *testing.T, w *riWorld) riCall {
				require.Equal(t, http.StatusOK, w.call(t, w.token(t, w.issuers[0], k1, nil), nil).status)
				require.Equal(t, int32(1), w.issuers[0].jwksHits.Load())

				k2 := newRIKey(t, "k2", jwa.ES256())
				w.issuers[0].publish(k2)

				return w.call(t, w.token(t, w.issuers[0], k2, nil), nil)
			},
			assert: func(t *testing.T, w *riWorld, out riCall) {
				accepted(t, w, out)
				assert.Equal(t, int32(2), w.issuers[0].jwksHits.Load())
			},
		},
		{
			name: "a flood of unknown key ids refetches at most once",
			act: func(t *testing.T, w *riWorld) riCall {
				var last riCall

				for n := range 20 {
					stranger := newRIKey(t, "unknown-"+strconv.Itoa(n), jwa.ES256())
					last = w.call(t, w.token(t, w.issuers[0], stranger, nil), nil)
					require.Equal(t, http.StatusUnauthorized, last.status)
				}

				return last
			},
			assert: func(t *testing.T, w *riWorld, out riCall) {
				invalidToken(t, w, out)
				assert.LessOrEqual(t, w.issuers[0].jwksHits.Load(), int32(2))
			},
		},
		{
			name: "an unsigned token is refused",
			act: func(t *testing.T, w *riWorld) riCall {
				tok := proofParts{none: true, headers: map[string]any{"typ": "at+jwt", "kid": "k1"}, claims: map[string]any{
					"iss": w.issuers[0].iss, "sub": "42", "aud": riAPI, "client_id": "web-app", "jti": "t-1",
					"iat": w.clk.Now().Unix(), "exp": w.clk.Now().Add(time.Minute).Unix(),
				}}.sign(t)

				return w.call(t, tok, nil)
			},
			assert: invalidToken,
		},
		{
			name: "a token signed with HS256 is refused",
			act: func(t *testing.T, w *riWorld) riCall {
				tok := proofParts{alg: jwa.HS256(), signKey: []byte("0123456789abcdef0123456789abcdef"),
					headers: map[string]any{"typ": "at+jwt", "kid": "k1"}, claims: map[string]any{
						"iss": w.issuers[0].iss, "sub": "42", "aud": riAPI, "client_id": "web-app", "jti": "t-1",
						"iat": w.clk.Now().Unix(), "exp": w.clk.Now().Add(time.Minute).Unix(),
					}}.sign(t)

				return w.call(t, tok, nil)
			},
			assert: invalidToken,
		},
		{
			name:   "a token with no kid is verified against the set's one signing key",
			act:    simple(func(tok *riToken) { delete(tok.headers, jws.KeyIDKey) }),
			assert: accepted,
		},
		{
			name:   "a token with no kid is refused when the set holds two signing keys",
			setup:  riSetup{keys: []riKey{k1, newRIKey(t, "k2", jwa.ES256())}},
			act:    simple(func(tok *riToken) { delete(tok.headers, jws.KeyIDKey) }),
			assert: invalidToken,
		},
		{
			name: "a token signed with an algorithm outside the narrowed list is refused",
			setup: riSetup{
				keys: []riKey{newRIKey(t, "rsa", jwa.RS256())},
				opts: func(*riWorld) []httpsec.SourceOption { return []httpsec.SourceOption{httpsec.WithAlgorithms("ES256")} },
			},
			act: func(t *testing.T, w *riWorld) riCall {
				return w.call(t, w.token(t, w.issuers[0], w.issuers[0].keys[0], nil), nil)
			},
			assert: invalidToken,
		},
		{
			name: "a token carrying the key that signed it in a jwk header is refused",
			act: func(t *testing.T, w *riWorld) riCall {
				stranger := newRIKey(t, "stranger", jwa.ES256())

				return w.call(t, w.token(t, w.issuers[0], stranger, func(tok *riToken) {
					tok.headers[jws.JWKKey] = stranger.pub
				}), nil)
			},
			assert: invalidToken,
		},
		{
			name: "a source's own audience is accepted for its tokens",
			setup: riSetup{second: true, opts: func(*riWorld) []httpsec.SourceOption {
				return []httpsec.SourceOption{httpsec.WithSourceAudience("orders-api")}
			}},
			act:    simple(func(tok *riToken) { tok.claims["aud"] = "orders-api" }),
			assert: accepted,
		},
		{
			name: "a source's own audience is refused for another source's tokens",
			setup: riSetup{second: true, opts: func(*riWorld) []httpsec.SourceOption {
				return []httpsec.SourceOption{httpsec.WithSourceAudience("orders-api")}
			}},
			act: func(t *testing.T, w *riWorld) riCall {
				k2 := w.issuers[1].keys[0]

				return w.call(t, w.token(t, w.issuers[1], k2, func(tok *riToken) { tok.claims["aud"] = "orders-api" }), nil)
			},
			assert: invalidToken,
		},
		{
			name:   "an unbound token is refused by default",
			setup:  riSetup{bound: true},
			act:    simple(nil),
			assert: invalidToken,
		},
		{
			name:  "a token bound to the caller's DPoP key is accepted by default",
			setup: riSetup{bound: true},
			act: func(t *testing.T, w *riWorld) riCall {
				return w.call(t, w.token(t, w.issuers[0], k1, func(tok *riToken) {
					tok.claims["cnf"] = map[string]any{"jkt": dk.jkt}
				}), &dk)
			},
			assert: func(t *testing.T, w *riWorld, out riCall) {
				accepted(t, w, out)
				assert.Equal(t, dk.jkt, out.token.Confirmation["jkt"])
			},
		},
		{
			name: "a confirmation naming only a method the chain cannot check is refused",
			act: simple(func(tok *riToken) {
				tok.claims["cnf"] = map[string]any{"jwk": map[string]any{"kty": "EC"}}
			}),
			assert: invalidToken,
		},
		{
			name: "a key set that cannot be fetched is a dependency failure",
			act: func(t *testing.T, w *riWorld) riCall {
				w.issuers[0].down.Store(true)

				return w.call(t, w.token(t, w.issuers[0], k1, nil), nil)
			},
			assert: dependency,
		},
		{
			name: "metadata naming another issuer is a dependency failure, and no key set is fetched",
			act: func(t *testing.T, w *riWorld) riCall {
				evil := "https://evil.example"
				w.issuers[0].metadataIssuer.Store(&evil)

				return w.call(t, w.token(t, w.issuers[0], k1, nil), nil)
			},
			assert: func(t *testing.T, w *riWorld, out riCall) {
				dependency(t, w, out)
				assert.Zero(t, w.issuers[0].jwksHits.Load())
			},
		},
		{
			name:  "a discovered key set on another origin is a dependency failure, and is not fetched",
			setup: riSetup{second: true},
			act: func(t *testing.T, w *riWorld) riCall {
				elsewhere := w.issuers[1].iss + "/jwks"
				w.issuers[0].jwksURI.Store(&elsewhere)

				return w.call(t, w.token(t, w.issuers[0], k1, nil), nil)
			},
			assert: func(t *testing.T, w *riWorld, out riCall) {
				dependency(t, w, out)
				assert.Zero(t, w.issuers[1].jwksHits.Load())
			},
		},
		{
			name: "a pinned key set is fetched where the consumer says, and no metadata is read",
			setup: riSetup{second: true, opts: func(w *riWorld) []httpsec.SourceOption {
				return []httpsec.SourceOption{httpsec.WithJWKSURL(w.issuers[1].iss + "/jwks")}
			}},
			act: func(t *testing.T, w *riWorld) riCall {
				w.issuers[1].publish(k1)

				return w.call(t, w.token(t, w.issuers[0], k1, nil), nil)
			},
			assert: func(t *testing.T, w *riWorld, out riCall) {
				accepted(t, w, out)
				assert.Zero(t, w.issuers[0].metadataHits.Load())
				assert.Positive(t, w.issuers[1].jwksHits.Load())
			},
		},
		{
			name: "every fetch goes through the consumer's outbound client",
			act:  simple(nil),
			assert: func(t *testing.T, w *riWorld, out riCall) {
				accepted(t, w, out)
				assert.Equal(t, w.issuers[0].metadataHits.Load()+w.issuers[0].jwksHits.Load(), w.sent.sent.Load())
			},
		},
		{
			name: "a caller who leaves while the key set is fetched gets the context's error and no error record",
			act: func(t *testing.T, w *riWorld) riCall {
				w.issuers[0].hangup.Store(true)

				return w.call(t, w.token(t, w.issuers[0], k1, nil), nil)
			},
			assert: func(t *testing.T, w *riWorld, out riCall) {
				assert.False(t, out.ran)
				require.ErrorIs(t, out.failure, context.Canceled)
				assert.NotErrorIs(t, out.failure, httpsec.ErrInvalidToken)

				for _, r := range w.logs.records() {
					assert.Less(t, r.Level, slog.LevelError, "an error record was written: %s", r.Message)
				}
			},
		},
		{
			name: "a token its issuer revoked is accepted by default until it expires",
			act: func(t *testing.T, w *riWorld) riCall {
				w.issuers[0].active.Store(false)

				return w.call(t, w.token(t, w.issuers[0], k1, nil), nil)
			},
			assert: func(t *testing.T, w *riWorld, out riCall) {
				accepted(t, w, out)
				assert.Zero(t, w.issuers[0].introspectionHits.Load())
			},
		},
		{
			name: "a token the introspection endpoint reports inactive is refused when the source introspects",
			setup: riSetup{opts: func(w *riWorld) []httpsec.SourceOption {
				return []httpsec.SourceOption{httpsec.WithJWTIntrospection(httpsec.IntrospectionConfig{
					Endpoint: w.issuers[0].iss + "/introspect", ClientID: "orders-api", Secret: "s3cret",
				})}
			}},
			act: func(t *testing.T, w *riWorld) riCall {
				w.issuers[0].active.Store(false)

				return w.call(t, w.token(t, w.issuers[0], k1, nil), nil)
			},
			assert: func(t *testing.T, w *riWorld, out riCall) {
				invalidToken(t, w, out)
				assert.Equal(t, int32(1), w.issuers[0].introspectionHits.Load())
			},
		},
		{
			name: "a token the introspection endpoint reports active is accepted when the source introspects",
			setup: riSetup{opts: func(w *riWorld) []httpsec.SourceOption {
				return []httpsec.SourceOption{httpsec.WithJWTIntrospection(httpsec.IntrospectionConfig{
					Endpoint: w.issuers[0].iss + "/introspect", ClientID: "orders-api", Secret: "s3cret",
				})}
			}},
			act:    simple(nil),
			assert: accepted,
		},
		{
			name: "an introspection endpoint that answers 503 is a dependency failure",
			setup: riSetup{opts: func(w *riWorld) []httpsec.SourceOption {
				return []httpsec.SourceOption{httpsec.WithJWTIntrospection(httpsec.IntrospectionConfig{
					Endpoint: w.issuers[0].iss + "/introspect", ClientID: "orders-api", Secret: "s3cret",
				})}
			}},
			act: func(t *testing.T, w *riWorld) riCall {
				w.issuers[0].introspectionDown.Store(true)

				return w.call(t, w.token(t, w.issuers[0], k1, nil), nil)
			},
			assert: dependency,
		},
		{
			name: "no record names the token",
			act: func(t *testing.T, w *riWorld) riCall {
				return w.call(t, w.token(t, w.issuers[0], k1, func(tok *riToken) { delete(tok.claims, "sub") }), nil)
			},
			assert: func(t *testing.T, w *riWorld, out riCall) {
				invalidToken(t, w, out)
				assert.NotContains(t, out.failure.Error(), "eyJ")
				assert.NotContains(t, out.body, "eyJ")

				for _, r := range w.logs.records() {
					assert.NotContains(t, r.Message, "eyJ")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			setup := tc.setup
			if len(setup.keys) == 0 {
				setup.keys = []riKey{k1}
			}

			w := newRIWorld(t, setup)
			tc.assert(t, w, tc.act(t, w))
		})
	}
}

// TestResourceServer_FromIssuerKind pins that a remote issuer's caller is published with the
// external-access-token kind.
func TestResourceServer_FromIssuerKind(t *testing.T) {
	t.Parallel()

	k1 := newRIKey(t, "k1", jwa.ES256())
	w := newRIWorld(t, riSetup{keys: []riKey{k1}})
	tok := w.token(t, w.issuers[0], k1, nil)

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, riAPIURL, nil)
	r.Header.Set("Authorization", "Bearer "+tok)

	out := readPublished(t, w.chain, r)

	require.NoError(t, out.err)
	assert.Equal(t, identity.CredentialsType(factor.ExternalAccessToken), out.kind)
}

// typedGenerator is a session token generator declaring typ, as a consumer's own may.
type typedGenerator struct {
	*token.JWTGenerator

	typ string
}

func (g typedGenerator) TokenType() string { return g.typ }

// TestResourceServer_FromIssuerConstruction pins the remote-issuer source's wiring mistakes, a
// source option a source does not take, and a session generator typed like an access token.
func TestResourceServer_FromIssuerConstruction(t *testing.T) {
	t.Parallel()

	const iss = "https://sso.example"

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

	built := func(t *testing.T, err error) { t.Helper(); require.NoError(t, err) }

	issuer := func(issuer string, opts ...httpsec.SourceOption) func(t *testing.T) []httpsec.Option {
		return func(*testing.T) []httpsec.Option {
			return []httpsec.Option{httpsec.EnableResourceServer("urn:orders",
				httpsec.FromIssuer(issuer, append([]httpsec.SourceOption{httpsec.WithUnboundTokens()}, opts...)...))}
		}
	}

	sessionTyped := func(typ string, opts ...httpsec.SourceOption) func(t *testing.T) []httpsec.Option {
		return func(t *testing.T) []httpsec.Option {
			gen, err := token.NewGenerator(f.keys, token.WithoutIssuer(), token.WithoutAudience())
			require.NoError(t, err)

			return append(issuer(iss, opts...)(t), httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
				Verifier: typedGenerator{JWTGenerator: gen, typ: typ},
				Sessions: must.Must(session.New()),
				Users:    NewMockUserLoader(gomock.NewController(t)),
			}))
		}
	}

	cases := []testCase{
		{name: "a valid issuer", build: issuer(iss), assert: built},
		{name: "a plain-http issuer", build: issuer("http://sso.example"), assert: refused("http://sso.example", "https")},
		{name: "an issuer with a fragment", build: issuer("https://sso.example#x"), assert: refused("https://sso.example#x")},
		{name: "an issuer with a query", build: issuer("https://sso.example?a=b"), assert: refused("https://sso.example?a=b")},
		{name: "an issuer with userinfo", build: issuer("https://u@sso.example"), assert: refused("userinfo")},
		{name: "an issuer that is not absolute", build: issuer("sso.example"), assert: refused("sso.example")},
		{
			name: "an issuer equal to the identifier",
			build: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableResourceServer(iss, httpsec.FromIssuer(iss, httpsec.WithUnboundTokens()))}
			},
			assert: refused(iss),
		},
		{
			name:   "a source audience equal to its issuer",
			build:  issuer(iss, httpsec.WithSourceAudience(iss)),
			assert: refused("WithSourceAudience"),
		},
		{name: "an empty source audience", build: issuer(iss, httpsec.WithSourceAudience("")), assert: refused("WithSourceAudience")},
		{name: "a five-minute clock skew", build: issuer(iss, httpsec.WithClockSkew(5*time.Minute)), assert: built},
		{name: "a clock skew above five minutes", build: issuer(iss, httpsec.WithClockSkew(6*time.Minute)), assert: refused("WithClockSkew")},
		{name: "a negative clock skew", build: issuer(iss, httpsec.WithClockSkew(-time.Second)), assert: refused("WithClockSkew")},
		{name: "no algorithm", build: issuer(iss, httpsec.WithAlgorithms()), assert: refused("WithAlgorithms")},
		{name: "the none algorithm", build: issuer(iss, httpsec.WithAlgorithms("none")), assert: refused("none")},
		{name: "a symmetric algorithm", build: issuer(iss, httpsec.WithAlgorithms("ES256", "HS256")), assert: refused("HS256")},
		{name: "untyped tokens without a claim", build: issuer(iss, httpsec.WithUntypedTokens("", "Bearer")), assert: refused("WithUntypedTokens")},
		{name: "untyped tokens without a value", build: issuer(iss, httpsec.WithUntypedTokens("typ", "")), assert: refused("WithUntypedTokens")},
		{name: "a plain-http key-set URL", build: issuer(iss, httpsec.WithJWKSURL("http://keys.example/certs")), assert: refused("FromIssuer")},
		{
			name: "a plain-http introspection endpoint",
			build: issuer(iss, httpsec.WithJWTIntrospection(httpsec.IntrospectionConfig{
				Endpoint: "http://sso.example/introspect", ClientID: "api", Secret: "s",
			})),
			assert: refused("WithJWTIntrospection"),
		},
		{
			name: "unbound tokens on a chain that requires DPoP",
			build: func(t *testing.T) []httpsec.Option {
				return append(issuer(iss)(t), httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL, Require: true}))
			},
			assert: refused("DPoP"),
		},
		{
			name: "a source option the provider source does not take",
			build: func(t *testing.T) []httpsec.Option {
				p := f.provider(t)

				return append(f.wired(t, p), httpsec.EnableCertificateBinding(), httpsec.EnableOIDCProvider(p),
					httpsec.EnableResourceServer("urn:orders", httpsec.FromProvider(p, httpsec.WithJWKSURL("https://keys.example"))))
			},
			assert: refused("FromProvider", "WithJWKSURL"),
		},
		{name: "a session generator typed AT+JWT", build: sessionTyped("AT+JWT"), assert: refused("AT+JWT")},
		{
			name:   "a session generator typed JWT beside a source accepting untyped tokens",
			build:  sessionTyped("JWT", httpsec.WithUntypedTokens("typ", "Bearer")),
			assert: refused("JWT", "WithUntypedTokens"),
		},
		{name: "a session generator typed JWT with no untyped source", build: sessionTyped("JWT"), assert: built},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(tc.build(t)...)
			tc.assert(t, err)
		})
	}
}
