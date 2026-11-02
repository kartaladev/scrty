package httpsec_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// dpopNow is the instant every DPoP case judges proofs at.
var dpopNow = time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)

// dpopKey is a client's DPoP key pair: the private key it signs proofs with,
// the public JWK it puts in each proof's header, and that key's RFC 7638
// thumbprint, which a bound token carries as cnf.jkt.
type dpopKey struct {
	priv *ecdsa.PrivateKey
	pub  jwk.Key
	jkt  string
}

// newDPoPKey generates a key pair on curve.
func newDPoPKey(t *testing.T, curve elliptic.Curve) dpopKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	pub, err := jwk.PublicKeyOf(priv)
	require.NoError(t, err)

	sum, err := pub.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	return dpopKey{priv: priv, pub: pub, jkt: base64.RawURLEncoding.EncodeToString(sum)}
}

// proofParts is everything a proof is built from. A case changes one part of
// a valid proof to break exactly one check.
type proofParts struct {
	alg     jwa.SignatureAlgorithm
	signKey any            // what the proof is signed with
	headers map[string]any // protected headers besides alg; a nil value removes one
	claims  map[string]any // a nil value removes a claim
	none    bool           // build an unsigned proof by hand: jwx refuses to sign one
}

// validProof is a proof by k for GET http://example.com/api/orders, issued at
// dpopNow, carrying jti and no ath.
func (k dpopKey) validProof(jti string) proofParts {
	return proofParts{
		alg:     jwa.ES256(),
		signKey: k.priv,
		headers: map[string]any{jws.TypeKey: "dpop+jwt", jws.JWKKey: k.pub},
		claims: map[string]any{
			"jti": jti,
			"htm": http.MethodGet,
			"htu": "http://example.com/api/orders",
			"iat": dpopNow.Unix(),
		},
	}
}

// with returns p with the claims in c set over its own, a nil value removing
// one.
func (p proofParts) with(c map[string]any) proofParts {
	claims := make(map[string]any, len(p.claims)+len(c))
	for k, v := range p.claims {
		claims[k] = v
	}
	for k, v := range c {
		if v == nil {
			delete(claims, k)

			continue
		}
		claims[k] = v
	}
	p.claims = claims

	return p
}

// withHeader returns p with header name set to v, or removed for nil.
func (p proofParts) withHeader(name string, v any) proofParts {
	headers := make(map[string]any, len(p.headers)+1)
	for k, hv := range p.headers {
		headers[k] = hv
	}
	if v == nil {
		delete(headers, name)
	} else {
		headers[name] = v
	}
	p.headers = headers

	return p
}

// sign renders p as a compact JWS, signed with jwx v4.
func (p proofParts) sign(t *testing.T) string {
	t.Helper()

	payload, err := json.Marshal(p.claims)
	require.NoError(t, err)

	if p.none {
		header := map[string]any{"alg": "none"}
		for k, v := range p.headers {
			header[k] = v
		}
		raw, herr := json.Marshal(header)
		require.NoError(t, herr)

		return base64.RawURLEncoding.EncodeToString(raw) + "." +
			base64.RawURLEncoding.EncodeToString(payload) + "."
	}

	headers := jws.NewHeaders()
	for k, v := range p.headers {
		require.NoError(t, headers.Set(k, v))
	}

	signed, err := jws.Sign(payload, jws.WithKey(p.alg, p.signKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)

	return string(signed)
}

// tokenHash is the ath of tok: its base64url SHA-256.
func tokenHash(tok string) string {
	sum := sha256.Sum256([]byte(tok))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// dpopRequest is a request for method target carrying each of proofs as one
// DPoP header line.
func dpopRequest(t *testing.T, method, target string, proofs ...string) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	for _, p := range proofs {
		req.Header.Add("DPoP", p)
	}

	return req
}

// dpopSessions is a session manager over a memory store, on clk.
func dpopSessions(t *testing.T, clk clockwork.Clock) *session.Sessions {
	t.Helper()

	sessions, err := session.New(session.WithClock(clk),
		session.WithStore(must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))))
	require.NoError(t, err)

	return sessions
}

func TestDPoP_Construction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// opts are the chain's options besides a signed bearer, which every
		// row has unless noBearer is set.
		opts     func(t *testing.T) []httpsec.Option
		noBearer bool
		assert   func(t *testing.T, chain *httpsec.Chain, err error)
	}

	built := func(t *testing.T, chain *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, chain)
	}
	refused := func(contains string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), contains)
			assert.Nil(t, chain)
		}
	}
	dpop := func(d httpsec.DPoP) func(*testing.T) []httpsec.Option {
		return func(*testing.T) []httpsec.Option { return []httpsec.Option{httpsec.EnableDPoP(d)} }
	}

	var nilStore *typedNilReplayStore

	// issuing is a form login issuing through tokens, beside DPoP.
	issuing := func(tokens func(t *testing.T) token.Generator) func(*testing.T) []httpsec.Option {
		return func(t *testing.T) []httpsec.Option {
			return []httpsec.Option{
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: NewMockAuthenticator(gomock.NewController(t)),
					Sessions:      dpopSessions(t, clockwork.NewFakeClockAt(dpopNow)),
					Tokens:        tokens(t),
					Attempts:      must.Must(lockout.NewMemoryAttemptStore()),
				}),
				httpsec.EnableDPoP(httpsec.DPoP{}),
			}
		}
	}

	// refusing is a row whose chain enables an endpoint with a generator that
	// cannot bind, beside DPoP: it is refused, naming the endpoint's option
	// and the field the generator was given in.
	refusing := func(name, field string, opts func(t *testing.T, nonBinding token.Generator) []httpsec.Option) testCase {
		return testCase{
			name: name,
			opts: func(t *testing.T) []httpsec.Option {
				return append(opts(t, NewMockGenerator(gomock.NewController(t))), httpsec.EnableDPoP(httpsec.DPoP{}))
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				refused("EnableDPoP")(t, chain, err)
				assert.Contains(t, err.Error(), field)
				assert.Contains(t, err.Error(), "token.ConfirmingGenerator")
			},
		}
	}
	binding := func(t *testing.T) token.Generator {
		t.Helper()

		keys, err := signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
		require.NoError(t, err)

		return must.Must(token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience()))
	}
	totpLike := func(t *testing.T) mfa.Method {
		t.Helper()

		method := NewMockMethod(gomock.NewController(t))
		method.EXPECT().Name().Return("totp").AnyTimes()
		method.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
		method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
		method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

		return method
	}
	oidcOver := func(t *testing.T, opts ...httpsec.OIDCOption) httpsec.Option {
		t.Helper()

		flows, err := oidc.NewMemoryFlowStore()
		require.NoError(t, err)

		sessions, err := session.New()
		require.NoError(t, err)

		deps := httpsec.OIDCDeps{RelyingParty: oidcManagerOver(t, flows), Handoff: newTestHandoffManager(t)}

		return httpsec.EnableOIDCLogin(deps, append(opts, httpsec.WithOIDCSessions(sessions))...)
	}

	cases := []testCase{
		{
			name: "with a token generator that can bind",
			opts: issuing(func(t *testing.T) token.Generator {
				keys, err := signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
				require.NoError(t, err)

				return must.Must(token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience()))
			}),
			assert: built,
		},
		{
			// It would issue every token unbound while DPoP was asked for.
			name: "with a consumer token generator that cannot bind",
			opts: issuing(func(t *testing.T) token.Generator {
				return NewMockGenerator(gomock.NewController(t))
			}),
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				refused("EnableDPoP")(t, chain, err)
				assert.Contains(t, err.Error(), "FormLoginDeps.Tokens")
				assert.Contains(t, err.Error(), "token.ConfirmingGenerator")
			},
		},
		refusing("with an OIDC handoff login and a generator that cannot bind", "WithOIDCTokens",
			func(t *testing.T, g token.Generator) []httpsec.Option {
				return []httpsec.Option{oidcOver(t, httpsec.WithOIDCTokens(g))}
			}),
		refusing("with an OIDC login conveyed by the consumer and a generator that cannot bind", "WithOIDCTokens",
			func(t *testing.T, g token.Generator) []httpsec.Option {
				convey := httpsec.WithOIDCCallbackSuccess(func(*httpsec.Exchange, oidc.CallbackResult, string) error { return nil })
				flows, err := oidc.NewMemoryFlowStore()
				require.NoError(t, err)
				sessions, err := session.New()
				require.NoError(t, err)

				return []httpsec.Option{httpsec.EnableOIDCLogin(
					httpsec.OIDCDeps{RelyingParty: oidcManagerOver(t, flows)},
					httpsec.WithOIDCSessions(sessions), convey, httpsec.WithOIDCTokens(g))}
			}),
		refusing("with MFA and a generator that cannot bind", "WithMFATokens",
			func(t *testing.T, g token.Generator) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableMFA([]mfa.Method{totpLike(t)}, httpsec.WithMFATokens(g))}
			}),
		refusing("with a magic link and a generator that cannot bind", "WithMagicLinkTokens",
			func(t *testing.T, g token.Generator) []httpsec.Option {
				h := newMagicLinkHarness(t)

				return []httpsec.Option{httpsec.EnableMagicLink(h.manager,
					httpsec.WithMagicLinkSessions(h.sessions), httpsec.WithMagicLinkTokens(g))}
			}),
		refusing("with passkey passwordless login and a generator that cannot bind", "PasswordlessTokens",
			func(t *testing.T, g token.Generator) []httpsec.Option {
				h := newPasskeyHarness(t)
				h.pkOpts = append(h.pkOpts, passkey.WithOptionalRecoveryCodes())
				h.mfaOpts = append(h.mfaOpts, httpsec.WithMFATokens(binding(t)))
				h.withoutReauth = true
				h.extra = append(h.extra, httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(binding(t))))
				h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyPasswordlessLogin(httpsec.PasswordlessTokens(g)))

				return h.chainOptions(t, nil)
			}),
		refusing("with re-authentication and a generator that cannot bind", "WithReauthenticationTokens",
			func(t *testing.T, g token.Generator) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableMFA([]mfa.Method{totpLike(t)}, httpsec.WithMFATokens(binding(t))),
					httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(g)),
				}
			}),
		refusing("with account recovery and a generator that cannot bind", "WithRecoveryTokens",
			func(t *testing.T, g token.Generator) []httpsec.Option {
				h := newRecoveryHarness(t)
				h.noFormLogin = true
				h.proofs = []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued}
				h.recOpts = append(h.recOpts, httpsec.WithRecoveryTokens(g))

				return h.options(t)
			}),
		{name: "with the signed bearer", opts: dpop(httpsec.DPoP{}), assert: built},
		{
			name:     "with the session-reference bearer",
			noBearer: true,
			opts: func(t *testing.T) []httpsec.Option {
				sessions := dpopSessions(t, clockwork.NewFakeClockAt(dpopNow))

				return []httpsec.Option{
					httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{
						Sessions: sessions, Users: NewMockUserLoader(gomock.NewController(t)),
					}),
					httpsec.EnableDPoP(httpsec.DPoP{}),
				}
			},
			assert: built,
		},
		{name: "without either bearer mode", noBearer: true, opts: dpop(httpsec.DPoP{}), assert: refused("EnableDPoP")},
		{
			name: "enabled twice",
			opts: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableDPoP(httpsec.DPoP{}), httpsec.EnableDPoP(httpsec.DPoP{})}
			},
			assert: refused("EnableDPoP"),
		},
		{
			name:   "a symmetric algorithm",
			opts:   dpop(httpsec.DPoP{Algorithms: []jwa.SignatureAlgorithm{jwa.ES256(), jwa.HS256()}}),
			assert: refused("HS256"),
		},
		{
			name:   "no signature",
			opts:   dpop(httpsec.DPoP{Algorithms: []jwa.SignatureAlgorithm{jwa.NoSignature()}}),
			assert: refused("none"),
		},
		{name: "a negative proof lifetime", opts: dpop(httpsec.DPoP{ProofMaxAge: -time.Second}), assert: refused("ProofMaxAge")},
		{name: "a negative proof size", opts: dpop(httpsec.DPoP{MaxProofSize: -1}), assert: refused("MaxProofSize")},
		{name: "a typed-nil replay store", opts: dpop(httpsec.DPoP{Replay: nilStore}), assert: refused("Replay")},
		{
			name:   "a public URL with a query",
			opts:   dpop(httpsec.DPoP{PublicURL: "https://app.example.com/?a=b"}),
			assert: refused("PublicURL"),
		},
		{name: "a relative public URL", opts: dpop(httpsec.DPoP{PublicURL: "app.example.com"}), assert: refused("PublicURL")},
		{
			// Not offered until it can be honoured: accepting it would read as
			// nonces enforced while none were.
			name:   "server nonces, which this version cannot honour",
			opts:   dpop(httpsec.DPoP{Nonce: true}),
			assert: refused("Nonce"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opts []httpsec.Option
			if !tc.noBearer {
				sessions := dpopSessions(t, clockwork.NewFakeClockAt(dpopNow))
				opts = append(opts, httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
					Verifier: NewMockVerifier(gomock.NewController(t)),
					Sessions: sessions,
					Users:    NewMockUserLoader(gomock.NewController(t)),
				}))
			}
			opts = append(opts, tc.opts(t)...)

			chain, err := httpsec.New(opts...)
			tc.assert(t, chain, err)
		})
	}
}

// typedNilReplayStore is a replay store whose nil pointer an unchecked
// constructor error would hand over.
type typedNilReplayStore struct{}

func (*typedNilReplayStore) Record(context.Context, string, time.Time) (bool, error) {
	return true, nil
}

func TestDPoP_Defaults(t *testing.T) {
	t.Parallel()

	store := httpsec.NewMemoryReplayStoreForTest(time.Now)

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, d httpsec.DPoP, enabled bool, err error)
	}

	cases := []testCase{
		{
			name: "every default filled",
			opts: []httpsec.Option{httpsec.EnableDPoP(httpsec.DPoP{})},
			assert: func(t *testing.T, d httpsec.DPoP, enabled bool, err error) {
				require.NoError(t, err)
				require.True(t, enabled)
				assert.False(t, d.Require, "accepted, not required")
				assert.Equal(t, 60*time.Second, d.ProofMaxAge)
				assert.Equal(t, []jwa.SignatureAlgorithm{jwa.ES256()}, d.Algorithms)
				assert.Equal(t, 8<<10, d.MaxProofSize)
				assert.NotNil(t, d.Replay, "an in-memory store")
				assert.False(t, d.Nonce)
				assert.Empty(t, d.PublicURL, "built from the resolved scheme and host")
			},
		},
		{
			name: "a consumer's own values are kept",
			opts: []httpsec.Option{httpsec.EnableDPoP(httpsec.DPoP{
				Require:      true,
				ProofMaxAge:  30 * time.Second,
				Replay:       store,
				Algorithms:   []jwa.SignatureAlgorithm{jwa.ES384(), jwa.EdDSA()},
				PublicURL:    "https://app.example.com",
				MaxProofSize: 4 << 10,
			})},
			assert: func(t *testing.T, d httpsec.DPoP, enabled bool, err error) {
				require.NoError(t, err)
				require.True(t, enabled)
				assert.True(t, d.Require)
				assert.Equal(t, 30*time.Second, d.ProofMaxAge)
				assert.Same(t, store, d.Replay)
				assert.Equal(t, []jwa.SignatureAlgorithm{jwa.ES384(), jwa.EdDSA()}, d.Algorithms)
				assert.Equal(t, "https://app.example.com", d.PublicURL)
				assert.Equal(t, 4<<10, d.MaxProofSize)
			},
		},
		{
			name: "not enabled",
			assert: func(t *testing.T, _ httpsec.DPoP, enabled bool, err error) {
				require.NoError(t, err)
				assert.False(t, enabled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d, enabled, err := httpsec.DPoPSettings(tc.opts...)
			tc.assert(t, d, enabled, err)
		})
	}
}

// TestDPoP_NotEnabled pins that without EnableDPoP the DPoP scheme is any
// unknown scheme: no bearer claims it, the verifier is never asked, and a
// route requiring authentication refuses the request.
//
// Standalone: one request through one chain; its rows are DPoP_Bearer's once
// the feature is on.
func TestDPoP_NotEnabled(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	sessions := dpopSessions(t, clockwork.NewFakeClockAt(dpopNow))

	authenticated := authorize.Rule[httpsec.Request]{
		Match:   func(httpsec.Request) bool { return true },
		Require: authorize.Authenticated(),
	}

	chain, err := httpsec.New(
		httpsec.WithLogger(slog.New(slog.DiscardHandler)),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: NewMockVerifier(gomock.NewController(t)), // no call expected
			Sessions: sessions,
			Users:    NewMockUserLoader(gomock.NewController(t)),
		}),
		httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t)), authenticated),
	)
	require.NoError(t, err)

	req := dpopRequest(t, http.MethodGet, "/api/orders", key.validProof("j-1").sign(t))
	req.Header.Set("Authorization", "DPoP some-token")

	out := serve(t, chain, req)

	assert.False(t, out.handlerRan)
	require.Error(t, out.err)
	assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
	assert.False(t, strings.Contains(out.err.Error(), "some-token"))
}
