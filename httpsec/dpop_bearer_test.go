package httpsec_test

import (
	"crypto/elliptic"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// dpopBearerWorld is a chain in one bearer mode over real components: a
// memory-store session manager, a JWT generator that also verifies, and a
// user loader answering with the session's active user.
type dpopBearerWorld struct {
	t        *testing.T
	clk      *clockwork.FakeClock
	sessions *session.Sessions
	keys     *signingkey.Keys
	gen      *token.JWTGenerator
	users    *MockUserLoader
}

func newDPoPBearerWorld(t *testing.T) *dpopBearerWorld {
	t.Helper()

	clk := clockwork.NewFakeClockAt(dpopNow)

	keys, err := signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
	require.NoError(t, err)

	gen, err := token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience(), token.WithClock(clk))
	require.NoError(t, err)

	u := &switchableUser{}
	u.set(userActive(true))

	return &dpopBearerWorld{
		t: t, clk: clk, sessions: dpopSessions(t, clk), keys: keys, gen: gen, users: u.loader(t),
	}
}

// session creates a session for u-1, bound to jkt unless it is empty.
func (w *dpopBearerWorld) session(jkt string) string {
	w.t.Helper()

	opts := []session.CreateOption{session.WithFirstFactor(factor.Password)}
	if jkt != "" {
		opts = append(opts, session.WithKeyBinding(session.KeyBinding{JKT: jkt}))
	}

	s, err := w.sessions.Create(w.t.Context(), "u-1", opts...)
	require.NoError(w.t, err)

	return s.ID
}

// token issues a token for a new session of u-1's, carrying cnf.
func (w *dpopBearerWorld) token(cnf token.Confirmation) string {
	w.t.Helper()

	sid := w.session(cnf.JKT)

	tok, err := w.gen.GenerateWith(w.t.Context(), sid, &identity.Principal{ID: "u-1", Username: testUsername},
		token.WithConfirmation(cnf))
	require.NoError(w.t, err)

	return tok
}

// rawToken signs a token for a new unbound session of u-1's with the
// generator's own key, carrying the cnf claim as given: a confirmation no
// generator of this library would issue.
func (w *dpopBearerWorld) rawToken(cnf any) string {
	w.t.Helper()

	sid := w.session("")

	payload, err := json.Marshal(map[string]any{
		"sub": testSubject, "jti": sid, "iat": dpopNow.Unix(),
		"exp": dpopNow.Add(time.Hour).Unix(), "cnf": cnf,
	})
	require.NoError(w.t, err)

	kid, signer, err := w.keys.Signer(w.t.Context(), signingkey.RS256)
	require.NoError(w.t, err)

	headers := jws.NewHeaders()
	require.NoError(w.t, headers.Set(jws.KeyIDKey, kid))

	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), signer, jws.WithProtectedHeaders(headers)))
	require.NoError(w.t, err)

	return string(signed)
}

// chain builds the chain in mode, with DPoP configured by d, or off for nil.
func (w *dpopBearerWorld) chain(mode bearerMode, d *httpsec.DPoP) *httpsec.Chain {
	w.t.Helper()

	opts := []httpsec.Option{httpsec.WithClock(w.clk), httpsec.WithLogger(slog.New(slog.DiscardHandler))}

	switch mode {
	case signedBearer:
		opts = append(opts, httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: w.gen, Sessions: w.sessions, Users: w.users,
		}))
	case referenceBearer:
		opts = append(opts, httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{
			Sessions: w.sessions, Users: w.users,
		}))
	}

	if d != nil {
		opts = append(opts, httpsec.EnableDPoP(*d))
	}

	chain, err := httpsec.New(opts...)
	require.NoError(w.t, err)

	return chain
}

// present runs a GET of /api/orders through chain, presenting credential
// under scheme, with proof as its DPoP header unless proof is empty.
func (w *dpopBearerWorld) present(chain *httpsec.Chain, scheme, credential, proof string) served {
	w.t.Helper()

	var proofs []string
	if proof != "" {
		proofs = append(proofs, proof)
	}

	req := dpopRequest(w.t, http.MethodGet, "http://example.com/api/orders", proofs...)
	req.Header.Set("Authorization", scheme+" "+credential)

	return serve(w.t, chain, req)
}

func TestDPoP_Bearer(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	thief := newDPoPKey(t, elliptic.P256())
	certThumb := tokenHash("client certificate")

	// proofFor is k's valid proof for a request presenting credential.
	proofFor := func(t *testing.T, k dpopKey, jti, credential string) string {
		t.Helper()

		return k.validProof(jti).with(map[string]any{"ath": tokenHash(credential)}).sign(t)
	}

	authenticated := func(t *testing.T, out served) {
		t.Helper()

		require.NoError(t, out.err)
		authenticatedAsOwner(t, out)
	}
	refusedProof := func(t *testing.T, out served) {
		t.Helper()

		assert.False(t, out.handlerRan, "never reaches the handler")
		require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
	}
	// refusedToken is refused as a token this chain cannot honour, and never
	// accepted as a plain bearer token.
	refusedToken := func(t *testing.T, out served) {
		t.Helper()

		assert.False(t, out.handlerRan, "not accepted as a bearer token")
		require.Error(t, out.err)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
	}

	enabled := &httpsec.DPoP{PublicURL: dpopPublicURL}
	required := &httpsec.DPoP{PublicURL: dpopPublicURL, Require: true}

	type testCase struct {
		name string
		mode bearerMode
		d    *httpsec.DPoP // nil: DPoP off
		// run presents the case's credential through chain and returns what
		// the last request produced.
		run    func(t *testing.T, w *dpopBearerWorld, chain *httpsec.Chain) served
		assert func(t *testing.T, out served)
	}

	cases := []testCase{
		{
			name: "a bound token under DPoP with a proof from its key",
			mode: signedBearer, d: enabled,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				tok := w.token(token.Confirmation{JKT: key.jkt})

				return w.present(c, "DPoP", tok, proofFor(t, key, "j-1", tok))
			},
			assert: authenticated,
		},
		{
			name: "the DPoP scheme in another case",
			mode: signedBearer, d: enabled,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				tok := w.token(token.Confirmation{JKT: key.jkt})

				return w.present(c, "dpop", tok, proofFor(t, key, "j-1", tok))
			},
			assert: authenticated,
		},
		{
			name: "an unbound token as Bearer keeps working",
			mode: signedBearer, d: enabled,
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "Bearer", w.token(token.Confirmation{}), "")
			},
			assert: authenticated,
		},
		{
			name: "a bound token as Bearer",
			mode: signedBearer, d: enabled,
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "Bearer", w.token(token.Confirmation{JKT: key.jkt}), "")
			},
			assert: refusedProof,
		},
		{
			name: "a bound token as Bearer, with a proof from its key",
			mode: signedBearer, d: enabled,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				tok := w.token(token.Confirmation{JKT: key.jkt})

				return w.present(c, "Bearer", tok, proofFor(t, key, "j-1", tok))
			},
			assert: refusedProof,
		},
		{
			name: "a bound token under DPoP with no proof",
			mode: signedBearer, d: enabled,
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "DPoP", w.token(token.Confirmation{JKT: key.jkt}), "")
			},
			assert: refusedProof,
		},
		{
			name: "a bound token with a proof from another key",
			mode: signedBearer, d: enabled,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				tok := w.token(token.Confirmation{JKT: key.jkt})

				return w.present(c, "DPoP", tok, proofFor(t, thief, "j-1", tok))
			},
			assert: refusedProof,
		},
		{
			name: "an unbound token under DPoP",
			mode: signedBearer, d: enabled,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				tok := w.token(token.Confirmation{})

				return w.present(c, "DPoP", tok, proofFor(t, key, "j-1", tok))
			},
			assert: refusedProof,
		},
		{
			name: "a proof presented twice",
			mode: signedBearer, d: enabled,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				tok := w.token(token.Confirmation{JKT: key.jkt})
				proof := proofFor(t, key, "j-1", tok)

				authenticated(t, w.present(c, "DPoP", tok, proof))

				return w.present(c, "DPoP", tok, proof)
			},
			assert: refusedProof,
		},
		{
			name: "required refuses an old unbound token",
			mode: signedBearer, d: required,
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "Bearer", w.token(token.Confirmation{}), "")
			},
			assert: refusedProof,
		},
		{
			name: "required accepts a bound token with its proof",
			mode: signedBearer, d: required,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				tok := w.token(token.Confirmation{JKT: key.jkt})

				return w.present(c, "DPoP", tok, proofFor(t, key, "j-1", tok))
			},
			assert: authenticated,
		},
		{
			name: "a cnf naming another member",
			mode: signedBearer, d: enabled,
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "Bearer", w.rawToken(map[string]any{"jwk": map[string]any{"kty": "EC"}}), "")
			},
			assert: refusedToken,
		},
		{
			name: "a cnf naming another member, with DPoP off",
			mode: signedBearer,
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "Bearer", w.rawToken(map[string]any{"jwk": map[string]any{"kty": "EC"}}), "")
			},
			assert: refusedToken,
		},
		{
			name: "a cnf naming both bindings, with a proof from the key",
			mode: signedBearer, d: enabled,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				tok := w.rawToken(map[string]any{"jkt": key.jkt, "x5t#S256": certThumb})

				return w.present(c, "DPoP", tok, proofFor(t, key, "j-1", tok))
			},
			assert: refusedToken,
		},
		{
			name: "a certificate binding while certificate binding is off",
			mode: signedBearer, d: enabled,
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "Bearer", w.token(token.Confirmation{X5TS256: certThumb}), "")
			},
			assert: refusedToken,
		},
		{
			name: "a DPoP binding while DPoP is off",
			mode: signedBearer,
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "Bearer", w.token(token.Confirmation{JKT: key.jkt}), "")
			},
			assert: refusedProof,
		},
		{
			// A consumer's own Verifier may report a bound token's claims
			// without its cnf; the session's own binding still holds.
			name: "an unbound token for a bound session, as Bearer",
			mode: signedBearer, d: enabled,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				sid := w.session(key.jkt)
				tok, err := w.gen.Generate(t.Context(), sid, &identity.Principal{ID: "u-1", Username: testUsername})
				require.NoError(t, err)

				return w.present(c, "Bearer", tok, "")
			},
			assert: refusedProof,
		},
		{
			name: "a token bound to one key for a session bound to another",
			mode: signedBearer, d: enabled,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				sid := w.session(thief.jkt)
				tok, err := w.gen.GenerateWith(t.Context(), sid,
					&identity.Principal{ID: "u-1", Username: testUsername},
					token.WithConfirmation(token.Confirmation{JKT: key.jkt}))
				require.NoError(t, err)

				return w.present(c, "DPoP", tok, proofFor(t, key, "j-1", tok))
			},
			assert: refusedProof,
		},
		{
			name: "a bound reference under DPoP, its proof hashing the reference",
			mode: referenceBearer, d: enabled,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				sid := w.session(key.jkt)

				return w.present(c, "DPoP", sid, proofFor(t, key, "j-1", sid))
			},
			assert: authenticated,
		},
		{
			name: "a bound reference under DPoP, its proof hashing something else",
			mode: referenceBearer, d: enabled,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				sid := w.session(key.jkt)

				return w.present(c, "DPoP", sid, proofFor(t, key, "j-1", "another-reference"))
			},
			assert: refusedProof,
		},
		{
			name: "an unbound reference as Bearer keeps working",
			mode: referenceBearer, d: enabled,
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "Bearer", w.session(""), "")
			},
			assert: authenticated,
		},
		{
			name: "a bound reference as Bearer",
			mode: referenceBearer, d: enabled,
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "Bearer", w.session(key.jkt), "")
			},
			assert: refusedProof,
		},
		{
			name: "a bound reference with a proof from another key",
			mode: referenceBearer, d: enabled,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				sid := w.session(key.jkt)

				return w.present(c, "DPoP", sid, proofFor(t, thief, "j-1", sid))
			},
			assert: refusedProof,
		},
		{
			name: "an unbound reference under DPoP",
			mode: referenceBearer, d: enabled,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				sid := w.session("")

				return w.present(c, "DPoP", sid, proofFor(t, key, "j-1", sid))
			},
			assert: refusedProof,
		},
		{
			name: "required refuses an unbound reference",
			mode: referenceBearer, d: required,
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "Bearer", w.session(""), "")
			},
			assert: refusedProof,
		},
		{
			name: "a bound reference while DPoP is off",
			mode: referenceBearer,
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "Bearer", w.session(key.jkt), "")
			},
			assert: refusedProof,
		},
		{
			name: "a reference proof presented twice",
			mode: referenceBearer, d: enabled,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				sid := w.session(key.jkt)
				proof := proofFor(t, key, "j-1", sid)

				authenticated(t, w.present(c, "DPoP", sid, proof))

				return w.present(c, "DPoP", sid, proof)
			},
			assert: refusedProof,
		},
	}

	for _, tc := range cases {
		t.Run(tc.mode.String()+"/"+tc.name, func(t *testing.T) {
			t.Parallel()

			w := newDPoPBearerWorld(t)
			tc.assert(t, tc.run(t, w, w.chain(tc.mode, tc.d)))
		})
	}
}

// TestDPoP_ReferenceBindingCharged pins that a session reference refused for
// its binding, a valid credential presented by the wrong sender, is charged
// to its source like any refused reference and reads as a missing session,
// while a proof the interceptor refuses on its own is not charged.
func TestDPoP_ReferenceBindingCharged(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	thief := newDPoPKey(t, elliptic.P256())

	proofFor := func(t *testing.T, k dpopKey, credential string) string {
		t.Helper()

		return k.validProof("j-1").with(map[string]any{"ath": tokenHash(credential)}).sign(t)
	}

	type testCase struct {
		name string
		// charged is how many failures the source limiter records.
		charged int
		run     func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served
		assert  func(t *testing.T, out served)
	}

	wrongSender := func(t *testing.T, out served) {
		t.Helper()

		assert.False(t, out.handlerRan)
		require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
		require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired, "it reads as a missing session")
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
	}

	cases := []testCase{
		{
			name: "a bound reference as Bearer", charged: 1,
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "Bearer", w.session(key.jkt), "")
			},
			assert: wrongSender,
		},
		{
			name: "a bound reference with another key's proof", charged: 1,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				sid := w.session(key.jkt)

				return w.present(c, "DPoP", sid, proofFor(t, thief, sid))
			},
			assert: wrongSender,
		},
		{
			name: "a proof whose signature does not verify", charged: 0,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				sid := w.session(key.jkt)
				parts := key.validProof("j-1").with(map[string]any{"ath": tokenHash(sid)})
				parts.signKey = thief.priv

				return w.present(c, "DPoP", sid, parts.sign(t))
			},
			assert: func(t *testing.T, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
				assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			limiter := NewMockLimiter(gomock.NewController(t))
			limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
			limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).Times(tc.charged)

			w := newDPoPBearerWorld(t)
			chain, err := httpsec.New(httpsec.WithClock(w.clk), httpsec.WithLogger(slog.New(slog.DiscardHandler)),
				httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users},
					httpsec.WithSessionBearerLimiter(limiter)),
				httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}))
			require.NoError(t, err)

			tc.assert(t, tc.run(t, w, chain))
		})
	}
}

func TestDPoP_PublicURL(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	proxies := httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Headers: httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto,
			httpsec.ForwardedHost("app.example.com")),
	})

	// forwarded is a GET of /api/orders the app receives from trusted proxy
	// 10.20.0.2 at http://10.20.1.5:8080, forwarded for https and
	// app.example.com.
	// untrusting trusts another network, so 10.20.0.2's forwarded headers
	// are not read; it allows the host the app received, and the forwarded
	// one too, so only the unread headers can explain a refusal.
	untrusting := httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		Headers: httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto,
			httpsec.ForwardedHost("10.20.1.5", "app.example.com")),
	})

	forwarded := func(t *testing.T) *http.Request {
		t.Helper()

		req := dpopRequest(t, http.MethodGet, "http://10.20.1.5:8080/api/orders")
		req.RemoteAddr = "10.20.0.2:41000"
		req.Header.Set("X-Forwarded-For", "198.51.100.7")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "app.example.com")

		return req
	}
	direct := func(t *testing.T) *http.Request {
		t.Helper()

		return dpopRequest(t, http.MethodGet, "http://example.com/api/orders")
	}

	type testCase struct {
		name    string
		opts    []httpsec.Option
		d       httpsec.DPoP
		request func(t *testing.T) *http.Request
		// htu is what the client signs its proof for.
		htu    string
		assert func(t *testing.T, out served)
	}

	accepted := func(t *testing.T, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.True(t, out.handlerRan)
	}
	refused := func(t *testing.T, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
		assert.False(t, out.handlerRan)
	}

	cases := []testCase{
		{
			name: "behind a trusted proxy, the public URL it forwarded",
			opts: []httpsec.Option{proxies}, request: forwarded,
			htu: "https://app.example.com/api/orders", assert: accepted,
		},
		{
			name: "behind a trusted proxy, the URL the app received",
			opts: []httpsec.Option{proxies}, request: forwarded,
			htu: "http://10.20.1.5:8080/api/orders", assert: refused,
		},
		{
			name: "without trusting the proxy, the forwarded URL",
			opts: []httpsec.Option{untrusting}, request: forwarded,
			htu: "https://app.example.com/api/orders", assert: refused,
		},
		{
			name: "without trusting the proxy, the URL the app received",
			opts: []httpsec.Option{untrusting}, request: forwarded,
			htu: "http://10.20.1.5:8080/api/orders", assert: accepted,
		},
		{
			name: "a configured public URL",
			d:    httpsec.DPoP{PublicURL: "https://api.example.com"}, request: direct,
			htu: "https://api.example.com/api/orders", assert: accepted,
		},
		{
			name: "a configured public URL with a path prefix",
			d:    httpsec.DPoP{PublicURL: "https://api.example.com/v1/"}, request: direct,
			htu: "https://api.example.com/v1/api/orders", assert: accepted,
		},
		{
			name: "a configured public URL overrides the resolved one",
			opts: []httpsec.Option{proxies}, d: httpsec.DPoP{PublicURL: "https://api.example.com"}, request: forwarded,
			htu: "https://app.example.com/api/orders", assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newDPoPBearerWorld(t)

			opts := append([]httpsec.Option{
				httpsec.WithClock(w.clk), httpsec.WithLogger(slog.New(slog.DiscardHandler)),
				httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: w.gen, Sessions: w.sessions, Users: w.users}),
				httpsec.EnableDPoP(tc.d),
			}, tc.opts...)
			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tok := w.token(token.Confirmation{JKT: key.jkt})
			req := tc.request(t)
			req.Header.Set("Authorization", "DPoP "+tok)
			req.Header.Set("DPoP", key.validProof("j-1").with(map[string]any{
				"htu": tc.htu, "ath": tokenHash(tok),
			}).sign(t))

			tc.assert(t, serve(t, chain, req))
		})
	}
}

func TestDPoP_HTURefusesHostOffTheForwardedHostAllowlist(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	// The host is declared only by the allowlist: no PublicURL.
	proxies := httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Headers: httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto,
			httpsec.ForwardedHost("app.example.com")),
	})

	// request is a GET of /api/orders with Host host, from peer.
	request := func(host, peer string, forwarded map[string]string) func(t *testing.T) *http.Request {
		return func(t *testing.T) *http.Request {
			t.Helper()

			req := dpopRequest(t, http.MethodGet, "http://"+host+"/api/orders")
			req.RemoteAddr = peer
			for k, v := range forwarded {
				req.Header.Set(k, v)
			}

			return req
		}
	}

	type testCase struct {
		name    string
		request func(t *testing.T) *http.Request
		// htu is what the client signs its proof for.
		htu    string
		assert func(t *testing.T, out served)
	}

	accepted := func(t *testing.T, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.True(t, out.handlerRan)
	}
	refused := func(t *testing.T, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
		assert.False(t, out.handlerRan)
	}

	cases := []testCase{
		{
			name:    "an untrusted peer's own Host, off the allowlist",
			request: request("evil.example", "198.51.100.7:41000", nil),
			htu:     "http://evil.example/api/orders", assert: refused,
		},
		{
			name: "a trusted peer forwarding no host, with a Host off the allowlist",
			request: request("evil.example", "10.20.0.2:41000", map[string]string{
				"X-Forwarded-For": "198.51.100.7", "X-Forwarded-Proto": "https",
			}),
			htu: "https://evil.example/api/orders", assert: refused,
		},
		{
			name: "a trusted peer forwarding an allowed host",
			request: request("10.20.1.5:8080", "10.20.0.2:41000", map[string]string{
				"X-Forwarded-For": "198.51.100.7", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com",
			}),
			htu: "https://app.example.com/api/orders", assert: accepted,
		},
		{
			name:    "an untrusted peer's own Host, on the allowlist",
			request: request("App.Example.com", "198.51.100.7:41000", nil),
			htu:     "http://app.example.com/api/orders", assert: accepted,
		},
		{
			name:    "an untrusted peer's own Host, on the allowlist with a port",
			request: request("app.example.com:8080", "198.51.100.7:41000", nil),
			htu:     "http://app.example.com:8080/api/orders", assert: accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newDPoPBearerWorld(t)

			chain, err := httpsec.New(
				httpsec.WithClock(w.clk), httpsec.WithLogger(slog.New(slog.DiscardHandler)),
				httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: w.gen, Sessions: w.sessions, Users: w.users}),
				httpsec.EnableDPoP(httpsec.DPoP{}), proxies,
			)
			require.NoError(t, err)

			tok := w.token(token.Confirmation{JKT: key.jkt})
			req := tc.request(t)
			req.Header.Set("Authorization", "DPoP "+tok)
			req.Header.Set("DPoP", key.validProof("j-1").with(map[string]any{
				"htu": tc.htu, "ath": tokenHash(tok),
			}).sign(t))

			tc.assert(t, serve(t, chain, req))
		})
	}
}
