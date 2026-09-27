package seal

import (
	"context"
	"fmt"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/signingkey"
)

// SigningKeyResealer replaces the stored private material of one signing key
// with the same key re-sealed under the cipher's active key. It is the port
// NewSigningKeyStore re-seals on read through; a durable signing-key store
// implements it, and the library supplies no default, because only the store
// can make the replacement conditional.
//
// An implementation must be one conditional write: replace the value for kid
// with resealed only where the stored value still equals old, so a key
// rewritten between the read and the re-seal is never overwritten with what
// was read. It must write nothing when the read ran inside a transaction the
// caller attached, because a failed statement there would abort the caller's
// transaction and the store discards the re-seal's error. A replacement that
// changes nothing is not an error.
//
//go:generate mockgen -source=signingkey.go -package=seal_test -destination=signingkey_mock_test.go -typed
//go:generate mockgen -source=../signingkey/record.go -package=seal_test -destination=keystore_mock_test.go -typed
type SigningKeyResealer interface {
	// ResealSigningKey replaces the private material stored for kid with
	// resealed, only if the stored value still equals old.
	ResealSigningKey(ctx context.Context, kid string, old, resealed []byte) error
}

// signingKeyStore seals Record.Private on the way into inner and opens it on
// the way out.
type signingKeyStore struct {
	inner    signingkey.KeyStore
	resealer SigningKeyResealer
	cipher   Cipher
	opts     options
}

// NewSigningKeyStore wraps inner so a signing key's private material is
// sealed by c before it is stored and opened when it is loaded. Every other
// field of the record, the public JWK included, is stored as given: it is
// published anyway.
//
// The private material is bound to the key's id (SigningKeyAAD), so a value
// copied to another key's record will not open there.
//
// LoadAll fails as a whole, returning no keys, when any stored key will not
// open. Skipping the key instead would let the key manager mint a fresh one
// and orphan every token the skipped key signed. The error matches the
// cipher's own (ErrDecryptionFailed or ErrUnknownKeyID from the default
// cipher) through errors.Is and errors.As, and its text is fixed: it names no
// key id and carries no text of the cipher's or of inner's errors. A failure
// of inner, or of c while sealing, is returned the same way; nothing is
// stored when sealing fails.
//
// By default a load re-seals, under the active key, every key that opened
// under another one, and hands the old and new values to r. A failed
// re-seal, or a cipher that cannot say which key is active, never fails the
// load. Keys are re-sealed only once every key has opened, so a load that
// fails rewrites nothing. WithResealOnRead(false) turns re-sealing off.
//
// A nil inner store or a nil cipher, typed nil included, or a nil option is a
// configuration error matching ErrInvalidConfiguration, and so is a nil r
// unless re-sealing on read is turned off: re-sealing is the default, and a
// store with nowhere to re-seal to would quietly keep retired keys in use. With
// re-sealing off, r is not used and may be nil. WithClock is refused: the
// store judges no time, so a clock would be silently ignored.
func NewSigningKeyStore(
	inner signingkey.KeyStore, r SigningKeyResealer, c Cipher, opts ...Option,
) (signingkey.KeyStore, error) {
	if nilcheck.IsNil(inner) {
		return nil, fmt.Errorf("%w: the sealing signing-key store has no inner store", ErrInvalidConfiguration)
	}
	if nilcheck.IsNil(c) {
		return nil, fmt.Errorf("%w: the sealing signing-key store has no cipher", ErrInvalidConfiguration)
	}

	o, err := newOptions("signing-key", !nilcheck.IsNil(r), false, opts)
	if err != nil {
		return nil, err
	}

	return &signingKeyStore{inner: inner, resealer: r, cipher: c, opts: o}, nil
}

// Store seals the private material of a copy of rec and stores the copy.
func (s *signingKeyStore) Store(ctx context.Context, rec signingkey.Record) error {
	sealed, err := s.cipher.Seal(rec.Private, SigningKeyAAD(rec.Kid))
	if err != nil {
		return diag.Wrap(err, "seal: the signing key's private material could not be sealed")
	}

	rec.Private = sealed

	return diag.Wrap(s.inner.Store(ctx, rec), "seal: the inner store could not store the signing key")
}

// LoadAll loads every record and opens its private material, failing the whole
// load when any record will not open.
func (s *signingKeyStore) LoadAll(ctx context.Context) ([]signingkey.Record, error) {
	loaded, err := s.inner.LoadAll(ctx)
	if err != nil {
		return nil, diag.Wrap(err, "seal: the inner store could not load the signing keys")
	}

	// recs is a copy of loaded's spine: inner may hand back its own backing
	// slice, and opening private material in place would rewrite it there.
	recs := make([]signingkey.Record, len(loaded))
	copy(recs, loaded)

	active, reseal := s.activeKeyForReseal()

	// stale holds the records that opened under a key other than the active
	// one, re-sealed only once every record has opened.
	var stale []staleKey
	for i := range recs {
		aad := SigningKeyAAD(recs[i].Kid)
		plaintext, keyID, err := s.cipher.Open(recs[i].Private, aad)
		if err != nil {
			return nil, diag.Wrap(err, "seal: a stored signing key could not be opened")
		}

		if reseal && keyID != active {
			stale = append(stale, staleKey{index: i, aad: aad, old: recs[i].Private})
		}
		recs[i].Private = plaintext
	}

	for _, k := range stale {
		s.reseal(ctx, recs[k.index], k.aad, k.old)
	}

	return recs, nil
}

// staleKey is a loaded record, by index, that opened under a retired key: the
// additional data it is bound to and its private material as stored.
type staleKey struct {
	index int
	aad   []byte
	old   []byte
}

// activeKeyForReseal returns the active key id and whether a load re-seals.
// A cipher that cannot name its active key turns re-sealing off for the load:
// a re-seal is best effort and never fails the read.
func (s *signingKeyStore) activeKeyForReseal() (string, bool) {
	if !s.opts.resealOnRead {
		return "", false
	}

	active, err := s.cipher.ActiveKeyID()

	return active, err == nil
}

// reseal seals rec's plaintext private material under the active key and
// hands it to the resealer in place of old. Every failure is dropped: the
// value still opens under the key it was sealed with.
func (s *signingKeyStore) reseal(ctx context.Context, rec signingkey.Record, aad, old []byte) {
	resealed, err := s.cipher.Seal(rec.Private, aad)
	if err != nil {
		return
	}

	_ = s.resealer.ResealSigningKey(ctx, rec.Kid, old, resealed)
}
