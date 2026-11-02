package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/seal"
	"github.com/kartaladev/scrty/token"
)

// The key material two replicas of one deployment share (A), and another
// deployment's (B).
var (
	nonceKeyA = []byte("0123456789abcdef0123456789abcdef")
	nonceKeyB = []byte("fedcba9876543210fedcba9876543210")
)

// newNonceCipher is the cipher a deployment seals with, over key: the
// store/seal keyring and AEAD cipher, adapted as sessions use them. Each call
// is a cipher of its own, as each replica holds its own.
func newNonceCipher(t *testing.T, key []byte) httpsec.NonceCipher {
	t.Helper()

	kr := must.Must(seal.NewKeyring(seal.WithKeyringEncryptionKey("k1", key)))

	return seal.SessionCipher(must.Must(seal.NewAEADCipher(kr)))
}

// nonceDPoP is DPoP with server nonces sealed under key.
func nonceDPoP(t *testing.T, key []byte) *httpsec.DPoP {
	t.Helper()

	return &httpsec.DPoP{Nonce: true, NonceCipher: newNonceCipher(t, key)}
}

// headerDPoPNonce is the response header a server nonce travels in.
const headerDPoPNonce = "DPoP-Nonce"

// useNonceChallenge is the challenge a proof without a current nonce gets.
const useNonceChallenge = `DPoP error="use_dpop_nonce", algs="ES256"`

// errCipherFixture is a cipher failure whose text names what must never
// reach an error the chain returns.
var errCipherFixture = errors.New("kms: key arn:aws:kms:eu-west-1:1:key/k-secret unreachable")

// askedForNonce asserts out was refused for want of a current nonce, with
// the challenge and a fresh nonce, and returns that nonce.
func askedForNonce(t *testing.T, out served) string {
	t.Helper()

	assert.False(t, out.handlerRan, "never reaches the handler")
	require.ErrorIs(t, out.err, httpsec.ErrDPoPNonceRequired)
	require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof, "also an invalid proof")
	assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
	assert.Equal(t, []string{useNonceChallenge}, out.rec.Header().Values("WWW-Authenticate"))

	nonce := out.rec.Header().Get(headerDPoPNonce)
	require.NotEmpty(t, nonce, "a fresh nonce to retry with")
	assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"), "a nonce is never cached (RFC 9449 section 8.2)")

	return nonce
}

// serveWithin is serve on an exchange whose context is ctx.
func serveWithin(ctx context.Context, t *testing.T, chain *httpsec.Chain, req *http.Request) served {
	t.Helper()

	out := served{rec: httptest.NewRecorder()}
	//nolint:contextcheck // the exchange below carries ctx to every interceptor
	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true
		out.handled = ex

		return nil
	})

	ex := httpsec.NewExchange(ctx, httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec))
	out.err = run(ex)

	return out
}

func TestDPoP_Nonce(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	// resourceProof is key's proof for the world's resource request,
	// presenting tok, carrying nonce unless it is empty, issued at the
	// world's now.
	resourceProof := func(t *testing.T, w *dpopBearerWorld, jti, tok, nonce string) string {
		t.Helper()

		parts := key.validProof(jti).with(map[string]any{"ath": tokenHash(tok), "iat": w.clk.Now().Unix()})
		if nonce != "" {
			parts = parts.with(map[string]any{"nonce": nonce})
		}

		return parts.sign(t)
	}

	// askNonce presents a bound token without a nonce to chain and returns
	// the nonce the refusal hands out.
	askNonce := func(t *testing.T, w *dpopBearerWorld, chain *httpsec.Chain) string {
		t.Helper()

		tok := w.token(token.Confirmation{JKT: key.jkt})

		return askedForNonce(t, w.present(chain, "DPoP", tok, resourceProof(t, w, "j-ask", tok, "")))
	}

	// presentWith presents a fresh bound token with a proof carrying nonce.
	presentWith := func(t *testing.T, w *dpopBearerWorld, chain *httpsec.Chain, jti, nonce string) served {
		t.Helper()

		tok := w.token(token.Confirmation{JKT: key.jkt})

		return w.present(chain, "DPoP", tok, resourceProof(t, w, jti, tok, nonce))
	}

	type testCase struct {
		name   string
		run    func(t *testing.T, w *dpopBearerWorld) served
		assert func(t *testing.T, out served)
	}

	cases := []testCase{
		{
			name: "a proof without a nonce is asked for one",
			run: func(t *testing.T, w *dpopBearerWorld) served {
				tok := w.token(token.Confirmation{JKT: key.jkt})

				return w.present(w.chain(signedBearer, nonceDPoP(t, nonceKeyA)), "DPoP", tok,
					resourceProof(t, w, "j-1", tok, ""))
			},
			assert: func(t *testing.T, out served) { askedForNonce(t, out) },
		},
		{
			// The jti of the refused proof is presented again: a proof
			// refused for its nonce records nothing.
			name: "the nonce round trip, the refused proof's jti unspent",
			run: func(t *testing.T, w *dpopBearerWorld) served {
				chain := w.chain(signedBearer, nonceDPoP(t, nonceKeyA))
				tok := w.token(token.Confirmation{JKT: key.jkt})

				nonce := askedForNonce(t, w.present(chain, "DPoP", tok, resourceProof(t, w, "j-1", tok, "")))

				return w.present(chain, "DPoP", tok, resourceProof(t, w, "j-1", tok, nonce))
			},
			assert: func(t *testing.T, out served) {
				authenticatedAsOwner(t, out)
				assert.Empty(t, out.rec.Header().Get(headerDPoPNonce), "a fresh nonce is not replaced")
			},
		},
		{
			name: "session-reference mode asks for a nonce too",
			run: func(t *testing.T, w *dpopBearerWorld) served {
				chain := w.chain(referenceBearer, nonceDPoP(t, nonceKeyA))
				ref := w.session(key.jkt)

				nonce := askedForNonce(t, w.present(chain, "DPoP", ref, resourceProof(t, w, "j-1", ref, "")))

				return w.present(chain, "DPoP", ref, resourceProof(t, w, "j-1", ref, nonce))
			},
			assert: authenticatedAsOwner,
		},
		{
			name: "an expired nonce is replaced by a fresh one",
			run: func(t *testing.T, w *dpopBearerWorld) served {
				chain := w.chain(signedBearer, nonceDPoP(t, nonceKeyA))
				old := askNonce(t, w, chain)

				w.clk.Advance(httpsec.DefaultDPoPNonceLifetime)

				out := presentWith(t, w, chain, "j-2", old)
				fresh := askedForNonce(t, out)
				assert.NotEqual(t, old, fresh)

				return presentWith(t, w, chain, "j-3", fresh)
			},
			assert: authenticatedAsOwner,
		},
		{
			name: "a nonce about to expire is accepted and replaced",
			run: func(t *testing.T, w *dpopBearerWorld) served {
				chain := w.chain(signedBearer, nonceDPoP(t, nonceKeyA))
				nonce := askNonce(t, w, chain)

				w.clk.Advance(httpsec.DefaultDPoPNonceLifetime - time.Second)

				out := presentWith(t, w, chain, "j-2", nonce)
				assert.NotEqual(t, nonce, out.rec.Header().Get(headerDPoPNonce))

				return out
			},
			assert: func(t *testing.T, out served) {
				authenticatedAsOwner(t, out)
				assert.NotEmpty(t, out.rec.Header().Get(headerDPoPNonce), "the next nonce, before this one expires")
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"), "a nonce is never cached")
			},
		},
		{
			name: "a nonce issued by another replica with the same key material",
			run: func(t *testing.T, w *dpopBearerWorld) served {
				replica := w.chain(signedBearer, nonceDPoP(t, nonceKeyA))
				nonce := askNonce(t, w, replica)

				return presentWith(t, w, w.chain(signedBearer, nonceDPoP(t, nonceKeyA)), "j-2", nonce)
			},
			assert: authenticatedAsOwner,
		},
		{
			name: "a nonce issued under other key material",
			run: func(t *testing.T, w *dpopBearerWorld) served {
				other := w.chain(signedBearer, nonceDPoP(t, nonceKeyB))
				nonce := askNonce(t, w, other)

				return presentWith(t, w, w.chain(signedBearer, nonceDPoP(t, nonceKeyA)), "j-2", nonce)
			},
			assert: func(t *testing.T, out served) { askedForNonce(t, out) },
		},
		{
			name: "a nonce the server never issued",
			run: func(t *testing.T, w *dpopBearerWorld) served {
				return presentWith(t, w, w.chain(signedBearer, nonceDPoP(t, nonceKeyA)), "j-1", "made-up")
			},
			assert: func(t *testing.T, out served) { askedForNonce(t, out) },
		},
		{
			name: "nonces off: a nonce claim is ignored",
			run: func(t *testing.T, w *dpopBearerWorld) served {
				return presentWith(t, w, w.chain(signedBearer, &httpsec.DPoP{}), "j-1", "anything")
			},
			assert: func(t *testing.T, out served) {
				authenticatedAsOwner(t, out)
				assert.Empty(t, out.rec.Header().Get(headerDPoPNonce))
			},
		},
		{
			name: "a nonce cipher that cannot seal is a dependency failure",
			run: func(t *testing.T, w *dpopBearerWorld) served {
				c := NewMockNonceCipher(gomock.NewController(t))
				c.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errCipherFixture)

				tok := w.token(token.Confirmation{JKT: key.jkt})

				return w.present(w.chain(signedBearer, &httpsec.DPoP{Nonce: true, NonceCipher: c}), "DPoP", tok,
					resourceProof(t, w, "j-1", tok, ""))
			},
			assert: func(t *testing.T, out served) {
				assert.False(t, out.handlerRan)
				require.ErrorIs(t, out.err, errCipherFixture, "the cipher's error stays reachable")
				assert.NotErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof, "an outage, not the client's proof")
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				assert.NotContains(t, out.err.Error(), "k-secret", "fixed text")
				assert.Empty(t, out.rec.Header().Get(headerDPoPNonce))
			},
		},
		{
			name: "a nonce cipher that cannot reach its keys to open is a dependency failure",
			run: func(t *testing.T, w *dpopBearerWorld) served {
				c := NewMockNonceCipher(gomock.NewController(t))
				c.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.Join(session.ErrCipherUnavailable, errCipherFixture))

				return presentWith(t, w, w.chain(signedBearer, &httpsec.DPoP{Nonce: true, NonceCipher: c}),
					"j-1", "c2VhbGVk")
			},
			assert: func(t *testing.T, out served) {
				assert.False(t, out.handlerRan)
				require.ErrorIs(t, out.err, errCipherFixture)
				assert.NotErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				assert.NotContains(t, out.err.Error(), "k-secret")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.run(t, newDPoPBearerWorld(t)))
		})
	}
}

// countingNonceCipher is the deployment's cipher over key, counting the
// nonces it seals. Each seal takes a moment, so concurrent requests that each
// sealed would overlap.
func countingNonceCipher(t *testing.T, key []byte) (httpsec.NonceCipher, *atomic.Int32) {
	t.Helper()

	sealer := newNonceCipher(t, key)

	var seals atomic.Int32

	c := NewMockNonceCipher(gomock.NewController(t))
	c.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, plaintext, additionalData []byte) ([]byte, error) {
			seals.Add(1)
			time.Sleep(time.Millisecond)

			return sealer.Seal(ctx, plaintext, additionalData)
		})
	c.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(sealer.Open)

	return c, &seals
}

// TestDPoP_NonceSealedOncePerHalfLifetime pins that a replica seals one
// current nonce and hands it to every client until half the nonce lifetime
// has passed, so sealing is bounded by time and not by traffic, while every
// nonce it sealed is still accepted for its whole lifetime.
func TestDPoP_NonceSealedOncePerHalfLifetime(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	const clients = 32

	// request is a bound token presented with a proof carrying nonce unless
	// it is empty, issued at the world's now.
	request := func(t *testing.T, w *dpopBearerWorld, jti, nonce string) *http.Request {
		t.Helper()

		tok := w.token(token.Confirmation{JKT: key.jkt})
		parts := key.validProof(jti).with(map[string]any{"ath": tokenHash(tok), "iat": w.clk.Now().Unix()})
		if nonce != "" {
			parts = parts.with(map[string]any{"nonce": nonce})
		}

		req := dpopRequest(t, http.MethodGet, "http://example.com/api/orders", parts.sign(t))
		req.Header.Set("Authorization", "DPoP "+tok)

		return req
	}

	// askAll sends clients requests without a nonce to chain at once, and
	// returns the nonces they were handed.
	askAll := func(t *testing.T, w *dpopBearerWorld, chain *httpsec.Chain) []string {
		t.Helper()

		reqs := make([]*http.Request, clients)
		for i := range reqs {
			reqs[i] = request(t, w, "j-ask-"+strconv.Itoa(i), "")
		}

		nonces := make([]string, clients)

		var wg sync.WaitGroup
		for i, req := range reqs {
			wg.Go(func() { nonces[i] = serve(t, chain, req).rec.Header().Get(headerDPoPNonce) })
		}
		wg.Wait()

		return nonces
	}

	// shared asserts every client was handed the same nonce, and returns it.
	shared := func(t *testing.T, nonces []string) string {
		t.Helper()

		require.NotEmpty(t, nonces[0])
		for _, n := range nonces {
			assert.Equal(t, nonces[0], n, "every client is handed the replica's current nonce")
		}

		return nonces[0]
	}

	half := httpsec.DefaultDPoPNonceLifetime / 2

	type testCase struct {
		name string
		run  func(t *testing.T, w *dpopBearerWorld, chain *httpsec.Chain, seals *atomic.Int32)
	}

	cases := []testCase{
		{
			name: "concurrent clients within half a lifetime share one seal",
			run: func(t *testing.T, w *dpopBearerWorld, chain *httpsec.Chain, seals *atomic.Int32) {
				shared(t, askAll(t, w, chain))
				assert.Equal(t, int32(1), seals.Load())

				w.clk.Advance(half - time.Second)
				shared(t, askAll(t, w, chain))
				assert.Equal(t, int32(1), seals.Load(), "still the current nonce")
			},
		},
		{
			name: "concurrent clients at the refresh boundary seal once more",
			run: func(t *testing.T, w *dpopBearerWorld, chain *httpsec.Chain, seals *atomic.Int32) {
				first := shared(t, askAll(t, w, chain))

				w.clk.Advance(half)
				next := shared(t, askAll(t, w, chain))
				assert.NotEqual(t, first, next)
				assert.Equal(t, int32(2), seals.Load(), "one seal per half lifetime, whatever the traffic")
			},
		},
		{
			name: "a nonce sealed before the refresh is accepted until its lifetime ends",
			run: func(t *testing.T, w *dpopBearerWorld, chain *httpsec.Chain, seals *atomic.Int32) {
				first := askedForNonce(t, serve(t, chain, request(t, w, "j-1", "")))

				w.clk.Advance(half)
				next := askedForNonce(t, serve(t, chain, request(t, w, "j-2", "")))
				require.NotEqual(t, first, next)

				out := serve(t, chain, request(t, w, "j-3", first))
				authenticatedAsOwner(t, out)
				assert.Equal(t, next, out.rec.Header().Get(headerDPoPNonce), "refreshed with the current nonce")
				assert.Equal(t, int32(2), seals.Load(), "the refresh seals nothing new")

				w.clk.Advance(httpsec.DefaultDPoPNonceLifetime - half)
				askedForNonce(t, serve(t, chain, request(t, w, "j-4", first)))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newDPoPBearerWorld(t)
			c, seals := countingNonceCipher(t, nonceKeyA)
			tc.run(t, w, w.chain(signedBearer, &httpsec.DPoP{Nonce: true, NonceCipher: c}), seals)
		})
	}
}

// TestDPoP_NonceHangUp pins that a client leaving while its nonce is opened
// fails with its own cancellation, not as an outage or a refused proof.
//
// Standalone: the exchange runs under a context the cipher cancels, which no
// other case's runner takes.
func TestDPoP_NonceHangUp(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	w := newDPoPBearerWorld(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	c := NewMockNonceCipher(gomock.NewController(t))
	c.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, []byte, []byte) ([]byte, error) {
			cancel()

			return nil, context.Canceled
		})

	tok := w.token(token.Confirmation{JKT: key.jkt})
	req := dpopRequest(t, http.MethodGet, "http://example.com/api/orders",
		key.validProof("j-1").with(map[string]any{"ath": tokenHash(tok), "nonce": "c2VhbGVk"}).sign(t))
	req.Header.Set("Authorization", "DPoP "+tok)

	out := serveWithin(ctx, t, w.chain(signedBearer, &httpsec.DPoP{Nonce: true, NonceCipher: c}), req)

	assert.False(t, out.handlerRan)
	require.ErrorIs(t, out.err, context.Canceled)
	assert.NotErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
}

// TestDPoP_NonceAtIssuing runs the nonce round trip at an issuing endpoint:
// a sign-in without a nonce is asked for one before any account is looked
// up, and the retry with it signs in bound.
//
// Standalone: an issuing endpoint's fixture, unlike TestDPoP_Nonce's
// resource requests.
func TestDPoP_NonceAtIssuing(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	f := loginEndpoint(t, *nonceDPoP(t, nonceKeyA))
	login := f.prepare(t, "")

	nonce := askedForNonce(t, login(t, key.validProver("j-1")))
	assert.Zero(t, f.lookups(), "refused before any account is looked up")
	assert.Zero(t, f.activeSessions(t), "nothing stored")

	withNonce := func(t *testing.T, path, credential string) string {
		t.Helper()

		return key.issuingProofParts(path, "j-1", credential).with(map[string]any{"nonce": nonce}).sign(t)
	}

	jkt, s := f.issued(t, login(t, withNonce))
	assert.Equal(t, key.jkt, jkt)
	assert.Equal(t, key.jkt, s.KeyBinding.JKT)
}

func TestDPoP_Challenge(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	// protected is a chain in mode with DPoP configured by d, whose every
	// route requires an authenticated caller.
	protected := func(t *testing.T, w *dpopBearerWorld, mode bearerMode, d httpsec.DPoP) *httpsec.Chain {
		t.Helper()

		opts := []httpsec.Option{
			httpsec.WithClock(w.clk), httpsec.WithLogger(slog.New(slog.DiscardHandler)),
			httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t)), authorize.Rule[httpsec.Request]{
				Match:   func(httpsec.Request) bool { return true },
				Require: authorize.Authenticated(),
			}),
			httpsec.EnableDPoP(d),
		}

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

		return must.Must(httpsec.New(opts...))
	}

	// challenged asserts out was refused 401 with exactly challenges.
	challenged := func(challenges ...string) func(*testing.T, served) {
		return func(t *testing.T, out served) {
			t.Helper()

			assert.False(t, out.handlerRan)
			require.Error(t, out.err)
			assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
			assert.Equal(t, challenges, out.rec.Header().Values("WWW-Authenticate"))
			assert.Empty(t, out.rec.Header().Get(headerDPoPNonce), "no nonces asked for")
		}
	}
	invalidProof := challenged(`DPoP error="invalid_dpop_proof", algs="ES256"`)

	noToken := func(t *testing.T, _ *dpopBearerWorld, c *httpsec.Chain) served {
		return serve(t, c, dpopRequest(t, http.MethodGet, "http://example.com/api/orders"))
	}

	type testCase struct {
		name   string
		mode   bearerMode
		d      httpsec.DPoP
		run    func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served
		assert func(t *testing.T, out served)
	}

	cases := []testCase{
		{
			name: "a proof whose signature does not verify",
			mode: signedBearer,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				tok := w.token(token.Confirmation{JKT: key.jkt})
				parts := key.validProof("j-1").with(map[string]any{"ath": tokenHash(tok)})
				parts.signKey = newDPoPKey(t, elliptic.P256()).priv

				return w.present(c, "DPoP", tok, parts.sign(t))
			},
			assert: func(t *testing.T, out served) {
				invalidProof(t, out)
				require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
			},
		},
		{
			name: "the accepted algorithms are listed",
			mode: signedBearer,
			d:    httpsec.DPoP{Algorithms: []jwa.SignatureAlgorithm{jwa.ES256(), jwa.EdDSA()}},
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "DPoP", w.token(token.Confirmation{JKT: key.jkt}), "")
			},
			assert: challenged(`DPoP error="invalid_dpop_proof", algs="ES256 EdDSA"`),
		},
		{
			name: "a bound token as Bearer",
			mode: signedBearer,
			run: func(_ *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				return w.present(c, "Bearer", w.token(token.Confirmation{JKT: key.jkt}), "")
			},
			assert: invalidProof,
		},
		{
			name: "a bound session reference with another key's proof",
			mode: referenceBearer,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				ref := w.session(key.jkt)
				thief := newDPoPKey(t, elliptic.P256())

				return w.present(c, "DPoP", ref,
					thief.validProof("j-1").with(map[string]any{"ath": tokenHash(ref)}).sign(t))
			},
			assert: invalidProof,
		},
		{
			name:   "no token with DPoP optional gets both challenges",
			mode:   signedBearer,
			run:    noToken,
			assert: challenged(`DPoP algs="ES256"`, "Bearer"),
		},
		{
			name:   "no token in session-reference mode gets both challenges",
			mode:   referenceBearer,
			run:    noToken,
			assert: challenged(`DPoP algs="ES256"`, "Bearer"),
		},
		{
			name:   "no token with DPoP required gets the DPoP challenge alone",
			mode:   signedBearer,
			d:      httpsec.DPoP{Require: true},
			run:    noToken,
			assert: challenged(`DPoP algs="ES256"`),
		},
		{
			name: "an authenticated request is challenged with nothing",
			mode: signedBearer,
			run: func(t *testing.T, w *dpopBearerWorld, c *httpsec.Chain) served {
				// The authorizer is never asked: the rule needs only a caller.
				tok := w.token(token.Confirmation{JKT: key.jkt})

				return w.present(c, "DPoP", tok, key.validProof("j-1").with(map[string]any{"ath": tokenHash(tok)}).sign(t))
			},
			assert: func(t *testing.T, out served) {
				authenticatedAsOwner(t, out)
				assert.Empty(t, out.rec.Header().Values("WWW-Authenticate"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newDPoPBearerWorld(t)
			tc.assert(t, tc.run(t, w, protected(t, w, tc.mode, tc.d)))
		})
	}
}

// TestDPoP_ChallengeAtIssuing pins that an issuing endpoint's proof refusal
// carries the DPoP challenge, and names no check in it.
//
// Standalone: an issuing endpoint's fixture, unlike TestDPoP_Challenge's
// resource requests.
func TestDPoP_ChallengeAtIssuing(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	f := loginEndpoint(t, httpsec.DPoP{})

	out := f.prepare(t, "")(t, key.brokenProver("j-1"))

	require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
	assert.Equal(t, []string{`DPoP error="invalid_dpop_proof", algs="ES256"`},
		out.rec.Header().Values("WWW-Authenticate"))
	assert.False(t, strings.Contains(out.rec.Header().Get("WWW-Authenticate"), "signature"))
}
