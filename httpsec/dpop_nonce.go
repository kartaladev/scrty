package httpsec

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/guardauth"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/session"
)

//go:generate mockgen -destination=noncecipher_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/httpsec NonceCipher

// ErrDPoPNonceRequired refuses a DPoP proof that carries no server nonce, or
// one the chain no longer accepts, while server nonces are on (DPoP.Nonce).
// It matches ErrInvalidDPoPProof, and maps to 401 as that refusal does. The
// chain answers it with WWW-Authenticate: DPoP error="use_dpop_nonce" and a
// fresh nonce in the DPoP-Nonce header (RFC 9449 section 8), which the
// client puts in the proof it retries with.
var ErrDPoPNonceRequired = fmt.Errorf("%w: a server nonce is required", ErrInvalidDPoPProof)

// NonceCipher seals and opens the server nonces DPoP issues when DPoP.Nonce
// is on. A nonce is the issuing instant sealed under it, so every replica
// given a cipher over the same keys accepts the nonces any of them issued,
// without a shared store.
//
// It has the method set of session.Cipher, so seal.SessionCipher(c) over a
// store/seal keyring serves. Give it a keyring kept for nonces alone. A nonce
// is sealed with its own additional data, so it never opens as anything else
// sealed under the same keys, and nothing else opens as a nonce, but nonces
// are sealed for requests that carry no credential: on a keyring shared with
// sessions, that traffic would spend the session keys' bounded number of
// safe seals. Keys rotate as that keyring rotates them: a nonce sealed under
// a key that is now retired still opens.
//
// The chain bounds the seals it asks for: each replica seals one current
// nonce and hands it to every client until half DPoP.NonceLifetime has
// passed, so at most one seal per half lifetime per replica, whatever the
// traffic. Open is called for every proof that carries a nonce.
//
// An implementation must be safe for concurrent use and must make Open fail
// when additionalData differs from what Seal was given. An Open failure
// marked with session.ErrCipherUnavailable, and any failure of Seal, is a
// dependency failure: the request fails with fixed text and maps to 500. Any
// other Open failure means the nonce is not one the chain issued, and the
// proof is refused with ErrDPoPNonceRequired.
type NonceCipher interface {
	// Seal encrypts plaintext, authenticating additionalData alongside it
	// without storing it.
	Seal(ctx context.Context, plaintext, additionalData []byte) ([]byte, error)

	// Open decrypts ciphertext, and fails unless additionalData is exactly
	// what Seal was given.
	Open(ctx context.Context, ciphertext, additionalData []byte) ([]byte, error)
}

// nonceAdditionalData is what every nonce is sealed with beside it, so a
// nonce opens as nothing else sealed under the same keys, and nothing else
// opens as a nonce.
const nonceAdditionalData = "scrty/httpsec:dpop-nonce:v1"

// nonceVersion is the first byte of a nonce's plaintext; the next eight are
// the issuing instant in Unix seconds, big-endian.
const (
	nonceVersion        byte = 1
	noncePlaintextBytes int  = 9
)

// maxNonceLength is the longest nonce claim, in bytes, the chain opens. A
// nonce the chain issued is far shorter; a longer one is refused unopened.
const maxNonceLength = 512

// What a nonce cipher that failed is recorded and returned with. The text is
// fixed: a consumer's cipher may word its failure with a key's name.
const (
	reasonNonceCipher    = "dpop-nonce-cipher"
	reasonProofNonce     = "nonce"
	msgDPoPNonceFailed   = "httpsec: a DPoP nonce could not be sealed or opened; the nonce cipher failed"
	textDPoPNonceFailed  = "httpsec: DPoP nonce cipher unavailable"
	msgDPoPNonceEnded    = "httpsec: the request ended while a DPoP nonce was sealed or opened"
	textDPoPNonceEnded   = "httpsec: the request ended while a DPoP nonce was sealed or opened"
	nonceSampleKeySuffix = sampleKeySeparator + reasonNonceCipher
)

// nonceFailure is the error a nonce cipher's failure err becomes: the
// context's error when the request's own context ended, recorded at debug,
// and otherwise a dependency failure with fixed text, recorded at ERROR by
// type and sampled. err stays reachable either way.
func (v *dpopVerifier) nonceFailure(ctx context.Context, err error) error {
	if hangup.ByCaller(ctx, err) {
		v.log.LogAttrs(ctx, slog.LevelDebug, msgDPoPNonceEnded)

		return diag.Wrap(err, textDPoPNonceEnded, ctx.Err())
	}

	logSampled(ctx, v.sampler, v.log, slog.LevelError, v.now(),
		dpopFlow+nonceSampleKeySuffix, msgDPoPNonceFailed,
		diag.Failure(reasonNonceCipher, err)...)

	return diag.Wrap(err, textDPoPNonceFailed)
}

// currentNonce is the nonce a replica hands every client: sealed once, and
// sealed again only once half the nonce lifetime has passed. Sealing is then
// bounded by time, at most once per half lifetime, and never by traffic: a
// client that sends a proof with a key it made itself costs no seal.
//
// The request that finds the current nonce due seals the next one under its
// own context, and no other request seals meanwhile. A request whose proof
// carries a nonce still valid never waits for that seal: it is served, and
// its response carries the next nonce only once that exists. A request being
// handed a nonce to retry with waits for the seal, so every client asking at
// once is handed the same next nonce, but each only for as long as its own
// context lasts.
type currentNonce struct {
	// current is the nonce last sealed, nil until the first seal; it is read
	// without a lock.
	current atomic.Pointer[sealedNonce]

	// mu guards inflight alone, and is never held across a seal.
	mu       sync.Mutex
	inflight *nonceSeal
}

// sealedNonce is one sealed nonce and the issuing instant sealed in it.
type sealedNonce struct {
	value  string
	issued time.Time
}

// nonceSeal is a seal in progress. done closes when it ends; err is then
// what it failed with, and hungUp whether that was its sealer's own context
// ending, which leaves a waiter free to seal in its place.
type nonceSeal struct {
	done   chan struct{}
	err    error
	hungUp bool
}

// issueNonce returns the replica's current nonce, sealing the next one first
// when half the nonce lifetime has passed since the current one was issued,
// or none has been. While another request seals that next nonce, a caller
// that is refreshing (refresh true) holds a nonce already judged valid, and
// is handed none at once, with fresh false; any other caller waits for the
// seal.
//
// A cipher that fails is a dependency failure (nonceFailure), and is not
// kept: the next request tries the seal again. A request waiting for a seal
// fails with its own context's error when that ends first.
func (v *dpopVerifier) issueNonce(ctx context.Context, refresh bool) (nonce string, fresh bool, err error) {
	n := &v.nonce
	half := v.cfg.NonceLifetime / 2

	for {
		now := v.now()
		cur := n.current.Load()
		if cur != nil && now.Sub(cur.issued) < half {
			return cur.value, true, nil
		}

		n.mu.Lock()
		if n.current.Load() != cur {
			// Another request stored a seal since cur was read.
			n.mu.Unlock()

			continue
		}

		s := n.inflight
		if s == nil {
			s = &nonceSeal{done: make(chan struct{})}
			n.inflight = s
			n.mu.Unlock()

			return v.sealNonce(ctx, s, now)
		}
		n.mu.Unlock()

		if refresh {
			// The caller holds a nonce the replica has judged valid, and
			// discards the value when fresh is false.
			return "", false, nil
		}

		select {
		case <-s.done:
			if s.err != nil && !s.hungUp {
				return "", false, v.nonceFailure(ctx, s.err)
			}
		case <-ctx.Done():
			return "", false, v.nonceFailure(ctx, ctx.Err())
		}
	}
}

// sealNonce seals the nonce issued at now under ctx, as the one seal s in
// progress, stores it as current when it succeeds, and ends s either way.
func (v *dpopVerifier) sealNonce(ctx context.Context, s *nonceSeal, now time.Time) (string, bool, error) {
	n := &v.nonce

	defer func() {
		n.mu.Lock()
		n.inflight = nil
		n.mu.Unlock()
		close(s.done)
	}()

	// The nonce carries its instant in whole seconds; the replica judges it
	// by the same instant, so it is due exactly when a proof presenting it is.
	issued := time.Unix(now.Unix(), 0)

	var plain [noncePlaintextBytes]byte
	plain[0] = nonceVersion
	binary.BigEndian.PutUint64(plain[1:], uint64(issued.Unix())) //nolint:gosec // G115: a clock after 1970

	sealed, err := v.cfg.NonceCipher.Seal(ctx, plain[:], []byte(nonceAdditionalData))
	if err != nil {
		s.err, s.hungUp = err, hangup.ByCaller(ctx, err)

		return "", false, v.nonceFailure(ctx, err)
	}

	value := base64.RawURLEncoding.EncodeToString(sealed)
	n.current.Store(&sealedNonce{value: value, issued: issued})

	return value, true, nil
}

// checkNonce judges a proof's nonce claim, and reports whether it is past
// half its lifetime, so the response carries the next one before it expires.
//
// A nonce is accepted when it opens under the nonce cipher and was issued no
// longer than the nonce lifetime ago, by the chain's clock; one issued ahead
// of that clock by up to the proof lifetime is accepted, as a replica's
// clock may lead. Anything else, an absent nonce included, is
// ErrDPoPNonceRequired. A cipher that cannot reach its keys, an Open failure
// marked session.ErrCipherUnavailable, is a dependency failure, and one cut
// short by the request's own end fails with the context's error.
func (v *dpopVerifier) checkNonce(ctx context.Context, claim *string) (stale bool, err error) {
	if claim == nil || *claim == "" || len(*claim) > maxNonceLength {
		return false, v.refuseNonce(ctx)
	}

	sealed, err := base64.RawURLEncoding.DecodeString(*claim)
	if err != nil {
		return false, v.refuseNonce(ctx)
	}

	plain, err := v.cfg.NonceCipher.Open(ctx, sealed, []byte(nonceAdditionalData))
	if err != nil {
		if hangup.ByCaller(ctx, err) || errors.Is(err, session.ErrCipherUnavailable) {
			return false, v.nonceFailure(ctx, err)
		}

		return false, v.refuseNonce(ctx)
	}

	if len(plain) != noncePlaintextBytes || plain[0] != nonceVersion {
		return false, v.refuseNonce(ctx)
	}

	issued := time.Unix(int64(binary.BigEndian.Uint64(plain[1:])), 0) //nolint:gosec // G115: sealed by this chain
	now := v.now()
	if issued.After(now.Add(v.cfg.ProofMaxAge)) || !now.Before(issued.Add(v.cfg.NonceLifetime)) {
		return false, v.refuseNonce(ctx)
	}

	return now.Sub(issued) >= v.cfg.NonceLifetime/2, nil
}

// refuseNonce records a proof refused for its nonce and returns the refusal.
func (v *dpopVerifier) refuseNonce(ctx context.Context) error {
	v.log.LogAttrs(ctx, slog.LevelDebug, msgDPoPRefused, slog.String("check", reasonProofNonce))

	return ErrDPoPNonceRequired
}

// chargesProofRefusal reports whether an issuing endpoint that charges its
// source charges err, the failure of an issuing proof check. Only an invalid
// proof is charged. A refusal asking for a nonce is the protocol's normal
// first step, and a replay store or nonce cipher that failed is a dependency
// failure, neither of which the client's request caused.
func chargesProofRefusal(err error) bool {
	return errors.Is(err, ErrInvalidDPoPProof) && !errors.Is(err, ErrDPoPNonceRequired)
}

// dpopResponseKey is the context key under which the challenge interceptor
// leaves the exchange's writer, so the verifier can hand out the next nonce
// on a response whose proof carried an ageing one.
type dpopResponseKey struct{}

// refreshNonce sets a fresh nonce on the response of the exchange ctx
// belongs to. It is best effort: the presented nonce is still current, so a
// cipher that fails is recorded and the request goes on, and while another
// request seals the next nonce the response carries none, rather than one as
// close to expiring as the nonce presented.
func (v *dpopVerifier) refreshNonce(ctx context.Context) {
	w, ok := ctx.Value(dpopResponseKey{}).(ResponseWriter)
	if !ok {
		return
	}

	nonce, fresh, err := v.issueNonce(ctx, true)
	if err != nil || !fresh {
		return
	}

	setNonce(w, nonce)
}

// setNonce hands nonce out on w, on a response no cache may keep: a stored
// one would hand a later client a nonce that may have expired (RFC 9449
// section 8.2).
func setNonce(w guardauth.HeaderWriter, nonce string) {
	w.SetHeader(headerDPoPNonce, nonce)
	w.SetHeader("Cache-Control", "no-store")
}

// dpopChallenge is the interceptor that answers DPoP's refusals with the
// challenge RFC 9449 section 7.1 gives, and a refusal for want of a nonce
// with a fresh one (section 8). It runs just inside the security-headers
// slot, so every refusal behind it, at an issuing endpoint or a bearer, is
// answered. It is always on with EnableDPoP, because the RFC asks for it; a
// consumer's WithErrorHandler or WithGuardErrorHandler may replace or remove
// the header it set.
type dpopChallenge struct{ v *dpopVerifier }

// orderDPoPChallenge is the challenge interceptor's slot.
const orderDPoPChallenge = OrderSecurityHeaders + 1

// Intercept runs the rest of the chain, and sets the challenge a refusal
// coming back from it calls for. It publishes the challenge on the request,
// so a guard behind the chain answers its own refusal alike.
func (c *dpopChallenge) Intercept(ex *Exchange, next Next) error {
	ctx := guardauth.WithChallenger(ex.Context(), c.v.challenge)
	if c.v.cfg.Nonce {
		ctx = context.WithValue(ctx, dpopResponseKey{}, ex.Writer)
	}

	ex.SetContext(ctx)

	err := next(ex)
	if err == nil {
		return nil
	}

	return c.v.challenge(ex.Context(), ex.Writer, err)
}

// challenge sets on w the WWW-Authenticate challenge err calls for, and
// returns the error the request fails with:
//
//   - ErrDPoPNonceRequired: DPoP error="use_dpop_nonce", and a fresh nonce
//     in DPoP-Nonce; a cipher that cannot seal one fails the request as a
//     dependency failure instead;
//   - any other ErrInvalidDPoPProof: DPoP error="invalid_dpop_proof";
//   - a request refused for want of a caller (ErrAuthenticationRequired):
//     DPoP with no error, and a Bearer challenge beside it unless DPoP is
//     required.
//
// Each DPoP challenge names the accepted algorithms, and none names the
// check that failed. Every other error is returned as it came, with no
// challenge.
func (v *dpopVerifier) challenge(ctx context.Context, w guardauth.HeaderWriter, err error) error {
	algs := "algs=" + strconv.Quote(v.algorithmNames())

	switch {
	case errors.Is(err, ErrDPoPNonceRequired):
		nonce, _, serr := v.issueNonce(ctx, false)
		if serr != nil {
			return serr
		}

		w.AddHeader(headerWWWAuthenticate, `DPoP error="use_dpop_nonce", `+algs)
		setNonce(w, nonce)
	case errors.Is(err, ErrInvalidDPoPProof):
		w.AddHeader(headerWWWAuthenticate, `DPoP error="invalid_dpop_proof", `+algs)
	case errors.Is(err, ErrAuthenticationRequired), errors.Is(err, authorize.ErrAuthenticationRequired):
		w.AddHeader(headerWWWAuthenticate, "DPoP "+algs)
		if !v.cfg.Require {
			w.AddHeader(headerWWWAuthenticate, "Bearer")
		}
	}

	return err
}

// algorithmNames is the accepted proof algorithms, space-separated, as a
// challenge's algs parameter lists them.
func (v *dpopVerifier) algorithmNames() string {
	names := make([]string, len(v.cfg.Algorithms))
	for i, alg := range v.cfg.Algorithms {
		names[i] = alg.String()
	}

	return strings.Join(names, " ")
}

// checkNonceConfig refuses a nonce configuration that cannot be honoured, or
// that names nonce settings while nonces are off, and fills the default
// lifetime when they are on.
func checkNonceConfig(d *DPoP) error {
	if d.NonceLifetime < 0 {
		return newConfigError("%s was given a negative NonceLifetime (%s)", optionDPoP, d.NonceLifetime)
	}

	if d.NonceLifetime > 0 && d.NonceLifetime < MinDPoPNonceLifetime {
		return newConfigError("%s was given a NonceLifetime of %s, under the floor of %s (MinDPoPNonceLifetime); "+
			"a nonce is dated in whole seconds, so a shorter lifetime would be due again the moment it is sealed",
			optionDPoP, d.NonceLifetime, MinDPoPNonceLifetime)
	}

	if !d.Nonce {
		switch {
		case d.NonceCipher != nil:
			return newConfigError("%s was given a NonceCipher with Nonce off; turn Nonce on, or "+
				"leave NonceCipher out", optionDPoP)
		case d.NonceLifetime != 0:
			return newConfigError("%s was given a NonceLifetime with Nonce off; turn Nonce on, or "+
				"leave NonceLifetime out", optionDPoP)
		}

		return nil
	}

	if nilcheck.IsNil(d.NonceCipher) {
		return newConfigError("%s was given Nonce without a NonceCipher; server nonces are sealed "+
			"with the deployment's key material, such as seal.SessionCipher over its keyring", optionDPoP)
	}

	if d.NonceLifetime == 0 {
		d.NonceLifetime = DefaultDPoPNonceLifetime
	}

	return nil
}
