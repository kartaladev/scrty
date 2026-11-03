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
	"testing/synctest"
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

	return &httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: newNonceCipher(t, key)}
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
			// The nonce carries its issuing instant in whole seconds; one
			// sealed mid-second is past half its lifetime by its own instant
			// before it is by the exact one, and must not be handed back as
			// its own replacement then.
			name: "a nonce sealed mid-second is replaced at half its lifetime, not handed back",
			run: func(t *testing.T, w *dpopBearerWorld) served {
				chain := w.chain(signedBearer, nonceDPoP(t, nonceKeyA))
				w.clk.Advance(500 * time.Millisecond)
				nonce := askNonce(t, w, chain)

				w.clk.Advance(httpsec.DefaultDPoPNonceLifetime/2 - 400*time.Millisecond)

				out := presentWith(t, w, chain, "j-2", nonce)
				assert.NotEqual(t, nonce, out.rec.Header().Get(headerDPoPNonce), "the presented nonce is not its own replacement")

				return out
			},
			assert: func(t *testing.T, out served) {
				authenticatedAsOwner(t, out)
				assert.NotEmpty(t, out.rec.Header().Get(headerDPoPNonce), "the next nonce")
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
				return presentWith(t, w, w.chain(signedBearer, &httpsec.DPoP{PublicURL: dpopPublicURL}), "j-1", "anything")
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

				return w.present(w.chain(signedBearer, &httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: c}), "DPoP", tok,
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
			name: "a seal that failed is not kept: the next request seals again",
			run: func(t *testing.T, w *dpopBearerWorld) served {
				c := NewMockNonceCipher(gomock.NewController(t))
				sealer := newNonceCipher(t, nonceKeyA)
				gomock.InOrder(
					c.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errCipherFixture),
					c.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(sealer.Seal),
				)

				chain := w.chain(signedBearer, &httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: c})
				tok := w.token(token.Confirmation{JKT: key.jkt})

				failed := w.present(chain, "DPoP", tok, resourceProof(t, w, "j-1", tok, ""))
				require.ErrorIs(t, failed.err, errCipherFixture)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(failed.err))

				return w.present(chain, "DPoP", tok, resourceProof(t, w, "j-1", tok, ""))
			},
			assert: func(t *testing.T, out served) { askedForNonce(t, out) },
		},
		{
			name: "a nonce cipher that cannot reach its keys to open is a dependency failure",
			run: func(t *testing.T, w *dpopBearerWorld) served {
				c := NewMockNonceCipher(gomock.NewController(t))
				c.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.Join(session.ErrCipherUnavailable, errCipherFixture))

				return presentWith(t, w, w.chain(signedBearer, &httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: c}),
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
			tc.run(t, w, w.chain(signedBearer, &httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: c}), seals)
		})
	}
}

// TestDPoP_NonceSealDoesNotBlock pins that a seal in progress holds up only
// the requests that have no nonce to be handed without it, and each of those
// only as long as its own context lasts: a request presenting a nonce still
// valid is served while the next is sealed, and a waiter outlives a sealer
// that hung up by sealing itself.
func TestDPoP_NonceSealDoesNotBlock(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type world struct {
		w       *dpopBearerWorld
		chain   *httpsec.Chain
		entered chan struct{}
		release chan struct{}
	}

	// build is a chain whose cipher seals the nth call at once unless hang
	// reports true for it; a hanging seal reports entering, then waits for
	// the test's end or its context's.
	build := func(t *testing.T, hang func(call int32) bool) *world {
		t.Helper()

		w := newDPoPBearerWorld(t)
		sealer := newNonceCipher(t, nonceKeyA)
		x := &world{w: w, entered: make(chan struct{}, 8), release: make(chan struct{})}

		var calls atomic.Int32

		c := NewMockNonceCipher(gomock.NewController(t))
		c.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
			DoAndReturn(func(ctx context.Context, p, ad []byte) ([]byte, error) {
				if hang(calls.Add(1)) {
					x.entered <- struct{}{}
					select {
					case <-x.release:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}

				return sealer.Seal(ctx, p, ad)
			})
		c.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(sealer.Open)
		x.chain = w.chain(signedBearer, &httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: c})
		t.Cleanup(func() { close(x.release) })

		return x
	}

	request := func(t *testing.T, x *world, jti, nonce string) *http.Request {
		t.Helper()

		tok := x.w.token(token.Confirmation{JKT: key.jkt})
		parts := key.validProof(jti).with(map[string]any{"ath": tokenHash(tok), "iat": x.w.clk.Now().Unix()})
		if nonce != "" {
			parts = parts.with(map[string]any{"nonce": nonce})
		}

		req := dpopRequest(t, http.MethodGet, "http://example.com/api/orders", parts.sign(t))
		req.Header.Set("Authorization", "DPoP "+tok)

		return req
	}

	// serveAsync serves req under ctx on a goroutine of its own.
	serveAsync := func(ctx context.Context, t *testing.T, chain *httpsec.Chain, req *http.Request) chan served {
		t.Helper()

		done := make(chan served, 1)
		go func() {
			out := served{rec: httptest.NewRecorder()}
			run := chain.Assemble(func(ex *httpsec.Exchange) error { //nolint:contextcheck // the exchange carries the request context, and begin reads it through ex.Context()
				out.handlerRan = true
				out.handled = ex

				return nil
			})
			out.err = run(httpsec.NewExchange(ctx, httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec)))
			done <- out
		}()

		return done
	}

	// within is what done serves, failing the test with stuck when nothing
	// is served within a second.
	within := func(t *testing.T, done chan served, stuck string) served {
		t.Helper()

		select {
		case out := <-done:
			return out
		case <-time.After(time.Second):
			t.Fatal(stuck)

			return served{}
		}
	}

	type testCase struct {
		name string
		// bubble runs the case in a synctest bubble, so synctest.Wait can
		// stand in for a pause.
		bubble bool
		run    func(t *testing.T) chan served
		assert func(t *testing.T, done chan served)
	}

	cases := []testCase{
		{
			name: "a waiter whose context ended returns",
			run: func(t *testing.T) chan served {
				x := build(t, func(int32) bool { return true })
				serveAsync(t.Context(), t, x.chain, request(t, x, "j-a", ""))
				<-x.entered

				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				t.Cleanup(cancel)

				return serveAsync(ctx, t, x.chain, request(t, x, "j-b", ""))
			},
			assert: func(t *testing.T, done chan served) {
				out := within(t, done, "a request whose context had ended was still waiting on another request's seal")
				require.ErrorIs(t, out.err, context.DeadlineExceeded)
				assert.NotErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
			},
		},
		{
			name: "a still-valid nonce is served while the next is sealed",
			run: func(t *testing.T) chan served {
				x := build(t, func(call int32) bool { return call > 1 })
				first := askedForNonce(t, serve(t, x.chain, request(t, x, "j-1", "")))

				x.w.clk.Advance(httpsec.DefaultDPoPNonceLifetime / 2)
				serveAsync(t.Context(), t, x.chain, request(t, x, "j-a", ""))
				<-x.entered

				return serveAsync(t.Context(), t, x.chain, request(t, x, "j-b", first))
			},
			assert: func(t *testing.T, done chan served) {
				out := within(t, done, "a request with a valid nonce was blocked by another request's seal of the next one")
				authenticatedAsOwner(t, out)
			},
		},
		{
			name: "a nonce from another replica is served while this replica seals its first",
			run: func(t *testing.T) chan served {
				x := build(t, func(call int32) bool { return call == 1 })
				replicaB := x.w.chain(signedBearer, nonceDPoP(t, nonceKeyA))
				other := askedForNonce(t, serve(t, replicaB, request(t, x, "j-0", "")))

				x.w.clk.Advance(httpsec.DefaultDPoPNonceLifetime / 2)
				serveAsync(t.Context(), t, x.chain, request(t, x, "j-a", ""))
				<-x.entered

				return serveAsync(t.Context(), t, x.chain, request(t, x, "j-b", other))
			},
			assert: func(t *testing.T, done chan served) {
				out := within(t, done, "a request presenting a still-valid nonce waited on this replica's seal")
				authenticatedAsOwner(t, out)
			},
		},
		{
			name:   "a waiter seals itself when the sealer hung up",
			bubble: true,
			run: func(t *testing.T) chan served {
				x := build(t, func(call int32) bool { return call == 1 })

				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)

				sealer := serveAsync(ctx, t, x.chain, request(t, x, "j-a", ""))
				<-x.entered

				waiter := serveAsync(t.Context(), t, x.chain, request(t, x, "j-b", ""))
				// Wait returns once the waiter is blocked behind the seal; one
				// that had not queued yet would seal itself, and the case
				// would show nothing.
				synctest.Wait()
				cancel()

				out := within(t, sealer, "the sealer that hung up did not return")
				require.ErrorIs(t, out.err, context.Canceled, "the sealer fails with its own hang-up")

				return waiter
			},
			assert: func(t *testing.T, done chan served) {
				askedForNonce(t, within(t, done, "the waiter did not outlive the sealer's hang-up"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.bubble {
				synctest.Test(t, func(t *testing.T) { tc.assert(t, tc.run(t)) })

				return
			}

			tc.assert(t, tc.run(t))
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

	out := serveWithin(ctx, t, w.chain(signedBearer, &httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: c}), req)

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

		if d.PublicURL == "" {
			d.PublicURL = dpopPublicURL
		}

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
			d:    httpsec.DPoP{PublicURL: dpopPublicURL, Algorithms: []jwa.SignatureAlgorithm{jwa.ES256(), jwa.EdDSA()}},
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
			d:      httpsec.DPoP{PublicURL: dpopPublicURL, Require: true},
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
	f := loginEndpoint(t, httpsec.DPoP{PublicURL: dpopPublicURL})

	out := f.prepare(t, "")(t, key.brokenProver("j-1"))

	require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
	assert.Equal(t, []string{`DPoP error="invalid_dpop_proof", algs="ES256"`},
		out.rec.Header().Values("WWW-Authenticate"))
	assert.False(t, strings.Contains(out.rec.Header().Get("WWW-Authenticate"), "signature"))
}

// sharedReplay is a replay store two replicas share.
type sharedReplay struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (s *sharedReplay) Record(_ context.Context, key string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.seen[key] {
		return false, nil
	}
	s.seen[key] = true

	return true, nil
}

// A proof refused as a replay, which carried a nonce past half its lifetime,
// must not cost a seal nor be answered with a fresh nonce: the replay check
// refuses it, so the refresh is owed to the accepted proof alone.
func TestDPoP_ReplayedProofGetsNoNonceRefreshAndSealsNothing(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	w := newDPoPBearerWorld(t)
	replay := &sharedReplay{seen: map[string]bool{}}

	cipherA, _ := countingNonceCipher(t, nonceKeyA)
	cipherB, sealsB := countingNonceCipher(t, nonceKeyA)
	chainA := w.chain(signedBearer, &httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: cipherA, Replay: replay})
	chainB := w.chain(signedBearer, &httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: cipherB, Replay: replay})

	request := func(jti, nonce string) *http.Request {
		tok := w.token(token.Confirmation{JKT: key.jkt})
		parts := key.validProof(jti).with(map[string]any{"ath": tokenHash(tok), "iat": w.clk.Now().Unix()})
		if nonce != "" {
			parts = parts.with(map[string]any{"nonce": nonce})
		}
		req := dpopRequest(t, http.MethodGet, "http://example.com/api/orders", parts.sign(t))
		req.Header.Set("Authorization", "DPoP "+tok)

		return req
	}

	first := askedForNonce(t, serve(t, chainA, request("j-ask", "")))

	w.clk.Advance(httpsec.DefaultDPoPNonceLifetime / 2)

	// One signed proof, presented twice: past half its nonce's lifetime.
	proofReq := request("j-replayed", first)
	again := request("j-replayed", first)
	again.Header.Set("DPoP", proofReq.Header.Get("DPoP"))
	again.Header.Set("Authorization", proofReq.Header.Get("Authorization"))

	ok := serve(t, chainA, proofReq)
	authenticatedAsOwner(t, ok)
	require.NotEmpty(t, ok.rec.Header().Get(headerDPoPNonce), "the accepted proof is handed the refreshed nonce")
	sealedBefore := sealsB.Load()
	require.Zero(t, sealedBefore)

	// Same replica: the replay is refused.
	sameReplica := serve(t, chainA, again)
	require.ErrorIs(t, sameReplica.err, httpsec.ErrInvalidDPoPProof)
	assert.Empty(t, sameReplica.rec.Header().Get(headerDPoPNonce), "a refused replay is handed no nonce (same replica)")

	// Another replica, whose current nonce is not yet sealed: the replay is
	// refused and costs it no seal.
	again2 := request("j-replayed", first)
	again2.Header.Set("DPoP", proofReq.Header.Get("DPoP"))
	again2.Header.Set("Authorization", proofReq.Header.Get("Authorization"))
	other := serve(t, chainB, again2)
	require.ErrorIs(t, other.err, httpsec.ErrInvalidDPoPProof)
	assert.Empty(t, other.rec.Header().Get(headerDPoPNonce), "a refused replay is handed no nonce (other replica)")
	assert.Equal(t, sealedBefore, sealsB.Load(), "a refused replay costs a replica no NonceCipher.Seal")
}
