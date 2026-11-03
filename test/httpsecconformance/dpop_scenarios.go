package httpsecconformance

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/store/seal"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// dpopOrigin is the scheme and host every adapter resolves for the
// scenarios' requests, which a proof's htu names.
const dpopOrigin = "http://example.com"

// The challenges a DPoP refusal carries.
const (
	dpopInvalidProofChallenge = `DPoP error="invalid_dpop_proof", algs="ES256"`
	dpopUseNonceChallenge     = `DPoP error="use_dpop_nonce", algs="ES256"`
)

// dpopScenarios is DPoP end to end on every adapter: a bound sign-in, a bound
// resource request, the refusals of a bound token as Bearer, of another
// key's proof and of a replayed proof, the path as the client sent it, and
// the server nonce round trip.
func dpopScenarios() []Scenario {
	return []Scenario{
		dpopSignInIsBound(),
		dpopBoundTokenReachesTheRoute(),
		dpopBoundTokenAsBearerIsRefused(),
		dpopAnotherKeysProofIsRefused(),
		dpopReplayedProofIsRefused(),
		dpopPathIsComparedAsSent(),
		dpopNonceRoundTrip(),
		dpopNoTokenGetsBothChallenges(),
		dpopNonceIsRefreshedOnASuccess(),
	}
}

// dpopClientKey is a client's DPoP key pair and its RFC 7638 thumbprint.
type dpopClientKey struct {
	priv *ecdsa.PrivateKey
	pub  jwk.Key
	jkt  string
}

func newDPoPClientKey(t *testing.T) dpopClientKey {
	t.Helper()

	priv := must.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	pub := must.Must(jwk.PublicKeyOf(priv))
	sum := must.Must(pub.Thumbprint(crypto.SHA256))

	return dpopClientKey{priv: priv, pub: pub, jkt: base64.RawURLEncoding.EncodeToString(sum)}
}

// proof is k's proof for method on path, its ath over credential unless that
// is empty, carrying nonce unless that is empty.
func (k dpopClientKey) proof(t *testing.T, method, path, credential, nonce string) string {
	t.Helper()

	claims := map[string]any{
		"jti": rand.Text(),
		"htm": method,
		"htu": dpopOrigin + path,
		"iat": time.Now().Unix(),
	}
	if credential != "" {
		sum := sha256.Sum256([]byte(credential))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	payload := must.Must(json.Marshal(claims))

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, "dpop+jwt"))
	require.NoError(t, headers.Set(jws.JWKKey, k.pub))

	return string(must.Must(jws.Sign(payload, jws.WithKey(jwa.ES256(), k.priv, jws.WithProtectedHeaders(headers)))))
}

// dpopFixture is one run's DPoP wiring: a token generator that binds, a
// replay store and a nonce cipher every request of the run shares, since each
// request builds its chain afresh, and the client's key.
type dpopFixture struct {
	gen    *token.JWTGenerator
	replay *fixtureReplayStore
	nonces httpsec.NonceCipher
	key    dpopClientKey

	// clock is the chain's clock where a scenario installs it, which the
	// scenario advances to age a nonce.
	clock *clockwork.FakeClock
}

func newDPoPFixture(t *testing.T) *dpopFixture {
	t.Helper()

	keys := must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
	secret := make([]byte, 32)
	_ = must.Must(rand.Read(secret))
	kr := must.Must(seal.NewKeyring(seal.WithKeyringEncryptionKey("k1", secret)))

	return &dpopFixture{
		gen:    must.Must(token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience())),
		replay: &fixtureReplayStore{seen: map[string]time.Time{}},
		nonces: seal.SessionCipher(must.Must(seal.NewAEADCipher(kr))),
		key:    newDPoPClientKey(t),
	}
}

// spec is the chain: form login and the signed bearer issuing and verifying
// through the fixture's generator, with DPoP on, and server nonces when
// nonces is true.
func (fx *dpopFixture) spec(t *testing.T, nonces bool) ChainSpec {
	t.Helper()

	effects := newEffects(t)

	d := httpsec.DPoP{PublicURL: dpopOrigin, Replay: fx.replay}
	if nonces {
		d.Nonce, d.NonceCipher, d.NonceLifetime = true, fx.nonces, httpsec.MinDPoPNonceLifetime
	}

	return ChainSpec{
		Options: []httpsec.Option{
			httpsec.EnableFormLogin(httpsec.FormLoginDeps{
				Authenticator: &fixtureAuthenticator{calls: &effects.authCalls},
				Sessions:      effects.Sessions,
				Tokens:        fx.gen,
				Attempts:      effects.Attempts,
			}),
			httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
				Verifier: fx.gen, Sessions: effects.Sessions, Users: fixtureUsers{},
			}),
			httpsec.EnableDPoP(d),
		},
		Effects: effects,
		Routes:  plainRoute(),
	}
}

// login is a sign-in carrying proof as its DPoP header, unless it is empty.
func dpopLogin(proof string) RequestSpec {
	req := formBody("username=" + Username + "&password=" + Password)
	if proof != "" {
		req.Header = map[string]string{"Content-Type": req.Header["Content-Type"], "DPoP": proof}
	}

	return req
}

// dpopResource is a GET of path presenting credential under scheme, with
// proof as its DPoP header unless it is empty.
func dpopResource(path, scheme, credential, proof string) RequestSpec {
	header := map[string]string{"Authorization": scheme + " " + credential}
	if proof != "" {
		header["DPoP"] = proof
	}

	return RequestSpec{Method: http.MethodGet, Path: path, Header: header, ClientAddress: ClientAddress}
}

// issuedDocument is a sign-in's token response.
type issuedDocument struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

// signedInBound signs in through send with a proof by fx's key and returns
// the token, asserting it is issued bound.
func (fx *dpopFixture) signedInBound(t *testing.T, send func(RequestSpec) Result) string {
	t.Helper()

	res := send(dpopLogin(fx.key.proof(t, http.MethodPost, LoginPath, "", "")))
	require.Equal(t, http.StatusOK, res.Status)

	return fx.boundDocument(t, res)
}

// boundDocument reads res's token response and asserts the token, and the
// sign-in it was issued for, are bound to fx's key.
func (fx *dpopFixture) boundDocument(t *testing.T, res Result) string {
	t.Helper()

	var doc issuedDocument
	require.NoError(t, json.Unmarshal([]byte(res.Body), &doc))
	assert.Equal(t, string(httpsec.TokenTypeDPoP), doc.TokenType)

	claims, err := fx.gen.Verify(t.Context(), doc.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, fx.key.jkt, claims.Confirmation().JKT, "the token carries cnf.jkt")
	assert.Equal(t, fx.key.jkt, res.Effects.LoadSession(t, claims.ID()).KeyBinding.JKT, "the sign-in is bound")

	return doc.AccessToken
}

// refusedProof asserts res was refused for its proof, with the DPoP
// challenge, before the route.
func refusedProof(t *testing.T, res Result) {
	t.Helper()

	assert.Equal(t, http.StatusUnauthorized, res.Status)
	require.ErrorIs(t, res.Refusal, httpsec.ErrInvalidDPoPProof)
	assert.Equal(t, []string{dpopInvalidProofChallenge}, res.Header.Values("WWW-Authenticate"))
	assert.False(t, res.RouteRan)
}

// dpopScenario is a DPoP scenario's Build and Steps over one fixture, made per
// run of the scenario so no two adapters share one.
func dpopScenario(name string, nonces bool, steps func(t *testing.T, fx *dpopFixture, send func(RequestSpec) Result)) Scenario {
	return dpopScenarioWith(name, nonces, nil, steps)
}

// dpopScenarioWith is dpopScenario with tweak applied to the built chain spec
// when it is not nil.
func dpopScenarioWith(name string, nonces bool, tweak func(fx *dpopFixture, spec *ChainSpec),
	steps func(t *testing.T, fx *dpopFixture, send func(RequestSpec) Result)) Scenario {
	var (
		mu       sync.Mutex
		fixtures = map[*Effects]*dpopFixture{}
	)

	return Scenario{
		Name: name,
		Build: func(t *testing.T) ChainSpec {
			fx := newDPoPFixture(t)
			spec := fx.spec(t, nonces)
			if tweak != nil {
				tweak(fx, &spec)
			}

			mu.Lock()
			fixtures[spec.Effects] = fx
			mu.Unlock()

			return spec
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			mu.Lock()
			fx := fixtures[spec.Effects]
			mu.Unlock()

			steps(t, fx, send)
		},
	}
}

func dpopSignInIsBound() Scenario {
	return dpopScenario("DPoP: a sign-in with a proof issues a token and a sign-in bound to its key", false,
		func(t *testing.T, fx *dpopFixture, send func(RequestSpec) Result) {
			res := send(dpopLogin(fx.key.proof(t, http.MethodPost, LoginPath, "", "")))

			require.Equal(t, http.StatusOK, res.Status)
			assert.NoError(t, res.Refusal)
			fx.boundDocument(t, res)
		})
}

func dpopBoundTokenReachesTheRoute() Scenario {
	return dpopScenario("DPoP: a bound token with a proof from its key reaches the route", false,
		func(t *testing.T, fx *dpopFixture, send func(RequestSpec) Result) {
			tok := fx.signedInBound(t, send)

			res := send(dpopResource(RoutePath, "DPoP", tok, fx.key.proof(t, http.MethodGet, RoutePath, tok, "")))

			assert.NoError(t, res.Refusal)
			assert.True(t, res.RouteRan)
			require.True(t, res.PrincipalKnown)
			assert.Equal(t, UserID, res.Principal.ID)
		})
}

func dpopBoundTokenAsBearerIsRefused() Scenario {
	return dpopScenario("DPoP: a bound token presented as Bearer is refused with the DPoP challenge", false,
		func(t *testing.T, fx *dpopFixture, send func(RequestSpec) Result) {
			tok := fx.signedInBound(t, send)

			refusedProof(t, send(dpopResource(RoutePath, "Bearer", tok, "")))
		})
}

func dpopAnotherKeysProofIsRefused() Scenario {
	return dpopScenario("DPoP: a bound token with another key's proof is refused", false,
		func(t *testing.T, fx *dpopFixture, send func(RequestSpec) Result) {
			tok := fx.signedInBound(t, send)
			thief := newDPoPClientKey(t)

			refusedProof(t, send(dpopResource(RoutePath, "DPoP", tok, thief.proof(t, http.MethodGet, RoutePath, tok, ""))))
		})
}

func dpopReplayedProofIsRefused() Scenario {
	return dpopScenario("DPoP: a replayed proof is refused", false,
		func(t *testing.T, fx *dpopFixture, send func(RequestSpec) Result) {
			tok := fx.signedInBound(t, send)
			proof := fx.key.proof(t, http.MethodGet, RoutePath, tok, "")

			first := send(dpopResource(RoutePath, "DPoP", tok, proof))
			require.NoError(t, first.Refusal)
			require.True(t, first.RouteRan)

			refusedProof(t, send(dpopResource(RoutePath, "DPoP", tok, proof)))
		})
}

func dpopPathIsComparedAsSent() Scenario {
	// The client sends /records/r%2D1; a proof naming the decoded path names
	// another URL than the one sent.
	const sent = "/records/r%2D1"

	return dpopScenario("DPoP: htu is compared with the path as the client sent it", false,
		func(t *testing.T, fx *dpopFixture, send func(RequestSpec) Result) {
			tok := fx.signedInBound(t, send)

			refusedProof(t, send(dpopResource(sent, "DPoP", tok, fx.key.proof(t, http.MethodGet, RoutePath, tok, ""))))

			res := send(dpopResource(sent, "DPoP", tok, fx.key.proof(t, http.MethodGet, sent, tok, "")))
			// The chain accepts it. Whether a route then matches the encoded
			// path is the framework's routing, which differs: fiber matches the
			// path as sent, net/http and gin the decoded one.
			assert.NotErrorIs(t, res.Refusal, httpsec.ErrInvalidDPoPProof, "a proof for the path as sent passes")
			assert.NotEqual(t, http.StatusUnauthorized, res.Status)
			assert.Empty(t, res.Header.Values("WWW-Authenticate"))
		})
}

func dpopNonceRoundTrip() Scenario {
	return dpopScenario("DPoP: a proof without a server nonce is asked for one, and the retry with it passes", true,
		func(t *testing.T, fx *dpopFixture, send func(RequestSpec) Result) {
			asked := send(dpopLogin(fx.key.proof(t, http.MethodPost, LoginPath, "", "")))

			assert.Equal(t, http.StatusUnauthorized, asked.Status)
			require.ErrorIs(t, asked.Refusal, httpsec.ErrDPoPNonceRequired)
			assert.Equal(t, []string{dpopUseNonceChallenge}, asked.Header.Values("WWW-Authenticate"))
			assert.Equal(t, 0, asked.Effects.ActiveSessions(t), "nothing was issued")

			nonce := asked.Header.Get("DPoP-Nonce")
			require.NotEmpty(t, nonce)

			// Each request builds its chain afresh: the nonce is accepted by a
			// chain that did not issue it, over the same key material.
			res := send(dpopLogin(fx.key.proof(t, http.MethodPost, LoginPath, "", nonce)))
			require.Equal(t, http.StatusOK, res.Status)
			tok := fx.boundDocument(t, res)

			resource := send(dpopResource(RoutePath, "DPoP", tok, fx.key.proof(t, http.MethodGet, RoutePath, tok, nonce)))
			assert.NoError(t, resource.Refusal)
			assert.True(t, resource.RouteRan)
		})
}

func dpopNoTokenGetsBothChallenges() Scenario {
	return dpopScenarioWith("DPoP: a request with no token to a protected route gets the DPoP and the Bearer challenge", false,
		func(_ *dpopFixture, spec *ChainSpec) {
			spec.Options = append(spec.Options, httpsec.EnableAuthorization(
				fixtureAuthorizer{},
				authorize.Rule[httpsec.Request]{
					Match:   func(r httpsec.Request) bool { return r.Path() == RoutePath },
					Require: authorize.Authenticated(),
				},
			))
		},
		func(t *testing.T, _ *dpopFixture, send func(RequestSpec) Result) {
			res := send(RequestSpec{Method: http.MethodGet, Path: RoutePath, ClientAddress: ClientAddress})

			assert.Equal(t, http.StatusUnauthorized, res.Status)
			assert.False(t, res.RouteRan)
			assert.Equal(t, []string{`DPoP algs="ES256"`, "Bearer"}, res.Header.Values("WWW-Authenticate"))
		})
}

func dpopNonceIsRefreshedOnASuccess() Scenario {
	return dpopScenarioWith("DPoP: a success to a proof whose nonce is past half its lifetime carries the next nonce", true,
		func(fx *dpopFixture, spec *ChainSpec) {
			fx.clock = clockwork.NewFakeClockAt(time.Now())
			spec.Options = append(spec.Options, httpsec.WithClock(fx.clock))
		},
		func(t *testing.T, fx *dpopFixture, send func(RequestSpec) Result) {
			asked := send(dpopLogin(fx.key.proof(t, http.MethodPost, LoginPath, "", "")))
			nonce := asked.Header.Get("DPoP-Nonce")
			require.NotEmpty(t, nonce)

			res := send(dpopLogin(fx.key.proof(t, http.MethodPost, LoginPath, "", nonce)))
			require.Equal(t, http.StatusOK, res.Status)
			tok := fx.boundDocument(t, res)

			// Past half the lifetime, and inside it.
			fx.clock.Advance(httpsec.MinDPoPNonceLifetime/2 + time.Second)

			res = send(dpopResource(RoutePath, "DPoP", tok, fx.key.proof(t, http.MethodGet, RoutePath, tok, nonce)))

			assert.NoError(t, res.Refusal)
			assert.True(t, res.RouteRan)
			next := res.Header.Get("DPoP-Nonce")
			assert.NotEmpty(t, next, "the response carries the next nonce")
			assert.NotEqual(t, nonce, next)
			assert.Contains(t, res.Header.Values("Cache-Control"), "no-store")
		})
}

// fixtureReplayStore is a replay store the requests of one run share, since
// each builds its chain, and the chain's in-memory default, afresh.
type fixtureReplayStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (s *fixtureReplayStore) Record(_ context.Context, key string, until time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if exp, ok := s.seen[key]; ok && time.Now().Before(exp) {
		return false, nil
	}

	s.seen[key] = until

	return true, nil
}
