package seal

import (
	"context"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/pkg/id"
)

// EnrolmentResealer replaces a user's stored MFA secret with the same secret
// re-sealed under the cipher's active key. It is the port NewEnrolmentStore
// re-seals on read through; a durable enrolment store implements it, and the
// library supplies no default, because only the store can make the
// replacement conditional.
//
// An implementation must be one conditional write: replace the secret stored
// for user with resealed only where the stored value still equals old, so a
// new pending enrolment written between the read and the re-seal keeps its
// new secret. It must write nothing when the read ran inside a transaction
// the caller attached, because a failed statement there would abort the
// caller's transaction and the store discards the re-seal's error. A
// replacement that changes nothing is not an error.
//
//go:generate mockgen -source=mfa.go -package=seal_test -destination=mfa_mock_test.go -typed
//go:generate mockgen -source=../mfa/store.go -package=seal_test -destination=enrolmentstore_mock_test.go -typed -exclude_interfaces=DeviceProofStore
type EnrolmentResealer interface {
	// ResealEnrolmentSecret replaces the secret stored for user with resealed,
	// only if the stored value still equals old.
	ResealEnrolmentSecret(ctx context.Context, user identity.UserID, old, resealed []byte) error
}

// enrolmentStore seals Enrolment.Secret on the way into inner and opens it on
// the way out.
type enrolmentStore struct {
	inner    mfa.EnrolmentStore
	resealer EnrolmentResealer
	cipher   Cipher
	opts     options
}

// provingEnrolmentStore is an enrolmentStore over an inner store that also
// implements mfa.DeviceProofStore, which it passes through.
type provingEnrolmentStore struct {
	*enrolmentStore

	proofs mfa.DeviceProofStore
}

// NewEnrolmentStore wraps inner so an MFA secret is sealed by c before it is
// stored and opened when it is read. The secret is the only field sealed:
// every other field and every other operation passes straight through, and
// the secret inner receives is the raw sealed value, which a store with a
// text column encodes itself.
//
// The secret is bound to the user reference (MFASecretAAD), byte for byte, so
// a secret copied to another user's enrolment will not open there.
//
// Get fails closed: a secret that will not open is returned as an error with
// the found flag false, never as an absent enrolment, which a caller would
// read as "no second factor" and let the login through on its first. The
// error matches the cipher's own (ErrDecryptionFailed or ErrUnknownKeyID
// from the default cipher) through errors.Is and errors.As. An absent
// enrolment is absent without consulting the cipher.
//
// A failure of c or of inner is returned behind fixed text that names no user
// and carries none of the failing error's text, and still matches that error
// through errors.Is and errors.As; mfa.ErrAlreadyEnrolled returned bare by
// inner comes back as itself. Nothing is stored when sealing fails.
//
// By default a read that opens a secret under a key other than the active
// one re-seals it under the active key and hands the old and new values to r.
// A failed re-seal, or a cipher that cannot say which key is active, never
// fails the read. WithResealOnRead(false) turns re-sealing off.
//
// When inner also implements mfa.DeviceProofStore, so does the returned store,
// passing those operations through, so the enrolment path stays available.
// When inner does not, neither does the returned store.
//
// A nil inner store or a nil cipher, typed nil included, or a nil option is a
// configuration error matching ErrInvalidConfiguration, and so is a nil r
// unless re-sealing on read is turned off. With re-sealing off, r is not used
// and may be nil.
func NewEnrolmentStore(
	inner mfa.EnrolmentStore, r EnrolmentResealer, c Cipher, opts ...Option,
) (mfa.EnrolmentStore, error) {
	if nilcheck.IsNil(inner) {
		return nil, fmt.Errorf("%w: the sealing MFA enrolment store has no inner store", ErrInvalidConfiguration)
	}
	if nilcheck.IsNil(c) {
		return nil, fmt.Errorf("%w: the sealing MFA enrolment store has no cipher", ErrInvalidConfiguration)
	}

	o, err := newOptions("MFA enrolment", !nilcheck.IsNil(r), opts)
	if err != nil {
		return nil, err
	}

	s := &enrolmentStore{inner: inner, resealer: r, cipher: c, opts: o}
	if proofs, ok := inner.(mfa.DeviceProofStore); ok {
		return provingEnrolmentStore{enrolmentStore: s, proofs: proofs}, nil
	}

	return s, nil
}

// Get reads the user's enrolment and opens its secret.
func (s *enrolmentStore) Get(ctx context.Context, user identity.UserID) (mfa.Enrolment, bool, error) {
	e, found, err := s.inner.Get(ctx, user)
	if err != nil {
		return mfa.Enrolment{}, false, diag.Wrap(err, "seal: the inner store could not read the MFA enrolment")
	}
	if !found {
		return mfa.Enrolment{}, false, nil
	}

	aad := MFASecretAAD(user)
	plaintext, keyID, err := s.cipher.Open(e.Secret, aad)
	if err != nil {
		return mfa.Enrolment{}, false, diag.Wrap(err, "seal: the stored MFA secret could not be opened")
	}

	if s.opts.resealOnRead {
		if active, err := s.cipher.ActiveKeyID(); err == nil && keyID != active {
			s.reseal(ctx, user, plaintext, aad, e.Secret)
		}
	}

	e.Secret = plaintext

	return e, true, nil
}

// reseal seals the user's plaintext secret under the active key and hands it
// to the resealer in place of old. Every failure is dropped, as is a cipher
// that cannot name its active key: the secret still opens under the key it
// was sealed with.
func (s *enrolmentStore) reseal(ctx context.Context, user identity.UserID, plaintext, aad, old []byte) {
	resealed, err := s.cipher.Seal(plaintext, aad)
	if err != nil {
		return
	}

	_ = s.resealer.ResealEnrolmentSecret(ctx, user, old, resealed)
}

// PutPending seals the secret of a copy of e and stores the copy as pending.
func (s *enrolmentStore) PutPending(ctx context.Context, e mfa.Enrolment) error {
	sealed, err := s.cipher.Seal(e.Secret, MFASecretAAD(e.User))
	if err != nil {
		return diag.Wrap(err, "seal: the MFA secret could not be sealed")
	}

	e.Secret = sealed

	return enrolmentFailed(s.inner.PutPending(ctx, e), "seal: the inner store could not store the pending MFA enrolment")
}

// Confirm passes through to inner.
func (s *enrolmentStore) Confirm(ctx context.Context, user identity.UserID, step int64, at time.Time) (bool, error) {
	ok, err := s.inner.Confirm(ctx, user, step, at)

	return ok, enrolmentFailed(err, "seal: the inner store could not confirm the MFA enrolment")
}

// AcceptStep passes through to inner.
func (s *enrolmentStore) AcceptStep(ctx context.Context, user identity.UserID, step int64) (bool, error) {
	ok, err := s.inner.AcceptStep(ctx, user, step)

	return ok, enrolmentFailed(err, "seal: the inner store could not accept the MFA time step")
}

// Delete passes through to inner.
func (s *enrolmentStore) Delete(ctx context.Context, user identity.UserID) error {
	return enrolmentFailed(s.inner.Delete(ctx, user), "seal: the inner store could not delete the MFA enrolment")
}

// ProveDevice passes through to the inner store's device proofs.
func (s provingEnrolmentStore) ProveDevice(
	ctx context.Context, user identity.UserID, gen id.ID,
	step int64, code []byte, codeUntil, at time.Time,
) (bool, error) {
	ok, err := s.proofs.ProveDevice(ctx, user, gen, step, code, codeUntil, at)

	return ok, enrolmentFailed(err, "seal: the inner store could not record the device proof")
}

// Complete passes through to the inner store's device proofs.
func (s provingEnrolmentStore) Complete(ctx context.Context, user identity.UserID, gen id.ID, at time.Time) (bool, error) {
	ok, err := s.proofs.Complete(ctx, user, gen, at)

	return ok, enrolmentFailed(err, "seal: the inner store could not complete the MFA enrolment")
}

// ChargeEmailCode passes through to the inner store's device proofs.
func (s provingEnrolmentStore) ChargeEmailCode(
	ctx context.Context, user identity.UserID, gen id.ID, at time.Time,
) (int, bool, error) {
	n, ok, err := s.proofs.ChargeEmailCode(ctx, user, gen, at)

	return n, ok, enrolmentFailed(err, "seal: the inner store could not charge the emailed code")
}

// enrolmentFailed returns an inner store's error behind text, except
// mfa.ErrAlreadyEnrolled returned bare, which carries no store text and which
// callers match on.
func enrolmentFailed(err error, text string) error {
	//nolint:errorlint // identity: only the bare sentinel is known to carry no store text
	if err == mfa.ErrAlreadyEnrolled {
		return err
	}

	return diag.Wrap(err, text)
}

var (
	_ mfa.EnrolmentStore   = (*enrolmentStore)(nil)
	_ mfa.DeviceProofStore = provingEnrolmentStore{}
)
