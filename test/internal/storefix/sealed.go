package storefix

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/test/storetest"
)

// storeOver builds a store with newWith over handle and the default cipher
// over kr: the NewWithKeyring of every sealed-column view here.
func storeOver[H, S any](handle H, newWith func(t *testing.T, handle H, c seal.Cipher) S) func(*testing.T, seal.Keyring) S {
	return func(t *testing.T, kr seal.Keyring) S {
		c, err := seal.NewAEADCipher(kr)
		require.NoError(t, err)
		return newWith(t, handle, c)
	}
}

// SealedSessions is the sealed-column suite's view of the session store,
// built by newWith over handle and a cipher. The owner is the session
// identifier, digested exactly as the store itself digests it.
func SealedSessions[H any](
	handle H, newWith func(t *testing.T, handle H, c seal.Cipher) session.Store,
) storetest.Sealed[session.Store] {
	return storetest.Sealed[session.Store]{
		Encoding:       storetest.SealedBase64URL,
		Rotation:       storetest.UnchangedOnRead,
		NewWithKeyring: storeOver(handle, newWith),
		Put: func(ctx context.Context, s session.Store, owner string, secret []byte) error {
			sess := DurableSession(owner, time.Now())
			sess.ExternalIDToken = string(secret)
			return s.Create(ctx, sess)
		},
		Get: func(ctx context.Context, s session.Store, owner string) ([]byte, bool, error) {
			sess, err := s.Load(ctx, owner)
			if errors.Is(err, session.ErrSessionNotFound) {
				return nil, false, nil
			}
			if err != nil {
				return nil, false, err
			}
			return []byte(sess.ExternalIDToken), true, nil
		},
		RawColumn: func(t *testing.T, raw *sql.DB, owner string) []byte {
			var col sql.NullString
			require.NoError(t, raw.QueryRowContext(t.Context(),
				`SELECT external_id_token FROM sessions WHERE id_digest = $1`, Digest(owner)).Scan(&col))
			return []byte(col.String)
		},
		CopySealed: func(t *testing.T, raw *sql.DB, from, to string) {
			_, err := raw.ExecContext(t.Context(), `UPDATE sessions
SET external_id_token = (SELECT external_id_token FROM sessions WHERE id_digest = $1) WHERE id_digest = $2`,
				Digest(from), Digest(to))
			require.NoError(t, err)
		},
	}
}

// SealedEnrolments is the sealed-column suite's view of the MFA store, built
// by newWith over handle and a cipher.
func SealedEnrolments[H any](
	handle H, newWith func(t *testing.T, handle H, c seal.Cipher) mfa.EnrolmentStore,
) storetest.Sealed[mfa.EnrolmentStore] {
	return storetest.Sealed[mfa.EnrolmentStore]{
		Encoding:       storetest.SealedBase64URL,
		Rotation:       storetest.ResealOnRead,
		NewWithKeyring: storeOver(handle, newWith),
		Put: func(ctx context.Context, s mfa.EnrolmentStore, owner string, secret []byte) error {
			return s.PutPending(ctx, mfa.Enrolment{User: identity.UserID(owner), Secret: secret, CreatedAt: EnrolmentBegun})
		},
		Get: func(ctx context.Context, s mfa.EnrolmentStore, owner string) ([]byte, bool, error) {
			e, ok, err := s.Get(ctx, identity.UserID(owner))
			return e.Secret, ok, err
		},
		RawColumn: func(t *testing.T, raw *sql.DB, owner string) []byte {
			return []byte(SecretColumn(t.Context(), t, raw, identity.UserID(owner)))
		},
		CopySealed: func(t *testing.T, raw *sql.DB, from, to string) {
			_, err := raw.ExecContext(t.Context(), `UPDATE mfa_enrolments
SET secret = (SELECT secret FROM mfa_enrolments WHERE user_id = $1) WHERE user_id = $2`, from, to)
			require.NoError(t, err)
		},
	}
}

// EmailCodeGeneration is the generation SealedEmailCodes begins every
// owner's enrolment on, so owners differ only by their user reference.
var EmailCodeGeneration = id.MustParse("01926a4e-0000-7000-8000-00000000c0de")

// SealedEmailCodes is the sealed-column suite's view of the emailed code the
// MFA store keeps for the enrolment path, built by newWith over handle and a
// cipher. Put begins owner's enrolment on EmailCodeGeneration, with a secret
// of its own, and proves its device issuing the suite's secret as the
// emailed code; the column is email_code. The code is never re-sealed on
// read, so a read under a retired key leaves it as stored.
func SealedEmailCodes[H any](
	handle H, newWith func(t *testing.T, handle H, c seal.Cipher) mfa.EnrolmentStore,
) storetest.Sealed[mfa.EnrolmentStore] {
	return storetest.Sealed[mfa.EnrolmentStore]{
		Encoding:       storetest.SealedBase64URL,
		Rotation:       storetest.UnchangedOnRead,
		NewWithKeyring: storeOver(handle, newWith),
		Put: func(ctx context.Context, s mfa.EnrolmentStore, owner string, code []byte) error {
			return beginAndProve(ctx, s, identity.UserID(owner), EmailCodeGeneration, code)
		},
		Get: func(ctx context.Context, s mfa.EnrolmentStore, owner string) ([]byte, bool, error) {
			e, ok, err := s.Get(ctx, identity.UserID(owner))
			return e.EmailCode, ok, err
		},
		RawColumn: func(t *testing.T, raw *sql.DB, owner string) []byte {
			return []byte(emailCodeColumn(t, raw, owner).String)
		},
		CopySealed: func(t *testing.T, raw *sql.DB, from, to string) {
			_, err := raw.ExecContext(t.Context(), `UPDATE mfa_enrolments
SET email_code = (SELECT email_code FROM mfa_enrolments WHERE user_id = $1) WHERE user_id = $2`, from, to)
			require.NoError(t, err)
		},
	}
}

// beginAndProve begins user's enrolment on gen, with a secret of its own, and
// proves its device issuing code.
func beginAndProve(ctx context.Context, s mfa.EnrolmentStore, user identity.UserID, gen id.ID, code []byte) error {
	p, ok := s.(mfa.DeviceProofStore)
	if !ok {
		return fmt.Errorf("storefix: store %T does not implement mfa.DeviceProofStore", s)
	}

	e := mfa.Enrolment{User: user, Secret: []byte("TOTP-" + string(user)), CreatedAt: EnrolmentBegun, Generation: gen}
	if err := s.PutPending(ctx, e); err != nil {
		return err
	}

	at := EnrolmentBegun.Add(time.Minute)
	proven, err := p.ProveDevice(ctx, user, gen, 1, code, at.Add(10*time.Minute), at)
	if err != nil {
		return err
	}
	if !proven {
		return errors.New("storefix: the device proof of a fresh pending enrolment was refused")
	}

	return nil
}

// emailCodeColumn is owner's email_code column as stored, read out of band.
func emailCodeColumn(t *testing.T, raw *sql.DB, owner string) sql.NullString {
	t.Helper()

	var col sql.NullString
	require.NoError(t, raw.QueryRowContext(t.Context(),
		`SELECT email_code FROM mfa_enrolments WHERE user_id = $1`, owner).Scan(&col))

	return col
}

// RunEmailCodeBindings holds the emailed code to the two bindings the
// sealed-column suite's copy to another record does not reach, by copying it
// out of band through raw:
//   - into its owner's secret column, where it must not open as the secret,
//     because the two are sealed against different additional data;
//   - back onto the same user after a new begin, where it must not open,
//     because it is bound to the generation it was issued on.
//
// Each read must fail with seal.ErrDecryptionFailed, never read as absent.
// codes is the view SealedEmailCodes returns; its stores seal under a key the
// run generates.
func RunEmailCodeBindings(t *testing.T, raw *sql.DB, codes storetest.Sealed[mfa.EnrolmentStore]) {
	t.Helper()

	key := make([]byte, seal.KeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)
	kr, err := seal.NewKeyring(seal.WithEncryptionKey("k1", key))
	require.NoError(t, err)

	// refused requires owner's enrolment to fail to open for its binding.
	refused := func(t *testing.T, s mfa.EnrolmentStore, owner string, msg string) {
		t.Helper()
		e, ok, err := s.Get(t.Context(), identity.UserID(owner))
		require.Error(t, err, "%s (present=%t)", msg, ok)
		assert.ErrorIs(t, err, seal.ErrDecryptionFailed, "the read failed, but not for the binding")
		assert.False(t, ok)
		assert.Zero(t, e)
	}

	t.Run("Emailed code copied into the secret column", func(t *testing.T) {
		s := codes.NewWithKeyring(t, kr)
		require.NoError(t, codes.Put(t.Context(), s, "code-into-secret", []byte("SENTINEL-CODE")))

		_, err := raw.ExecContext(t.Context(),
			`UPDATE mfa_enrolments SET secret = email_code WHERE user_id = $1`, "code-into-secret")
		require.NoError(t, err)

		refused(t, s, "code-into-secret", "the emailed code opened as the secret")
	})

	t.Run("Emailed code carried into a new generation", func(t *testing.T) {
		s := codes.NewWithKeyring(t, kr)
		require.NoError(t, codes.Put(t.Context(), s, "code-carried", []byte("SENTINEL-CODE")))
		issued := emailCodeColumn(t, raw, "code-carried")
		require.True(t, issued.Valid, "the device proof stored no emailed code")

		next := id.MustParse("01926a4e-0000-7000-8000-00000000c0df")
		require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{
			User: "code-carried", Secret: []byte("TOTP-code-carried"), CreatedAt: EnrolmentBegun, Generation: next,
		}))
		_, err := raw.ExecContext(t.Context(), `UPDATE mfa_enrolments
SET email_code = $2, device_proven_at = $3, email_code_until = $4 WHERE user_id = $1`,
			"code-carried", issued.String, EnrolmentBegun.Add(time.Minute), EnrolmentBegun.Add(11*time.Minute))
		require.NoError(t, err)

		refused(t, s, "code-carried", "the emailed code of an earlier generation opened on a new one")
	})
}

// SealedSigningKeys is the sealed-column suite's view of the signing-key
// store, built by newWith over handle and a cipher.
func SealedSigningKeys[H any](
	handle H, newWith func(t *testing.T, handle H, c seal.Cipher) signingkey.KeyStore,
) storetest.Sealed[signingkey.KeyStore] {
	return storetest.Sealed[signingkey.KeyStore]{
		Encoding:       storetest.SealedBytes,
		Rotation:       storetest.ResealOnRead,
		NewWithKeyring: storeOver(handle, newWith),
		Put: func(ctx context.Context, s signingkey.KeyStore, owner string, secret []byte) error {
			return s.Store(ctx, SigningKey(owner, secret))
		},
		Get: func(ctx context.Context, s signingkey.KeyStore, owner string) ([]byte, bool, error) {
			recs, err := s.LoadAll(ctx)
			if err != nil {
				return nil, false, err
			}
			i := slices.IndexFunc(recs, func(r signingkey.Record) bool { return r.Kid == owner })
			if i < 0 {
				return nil, false, nil
			}
			return recs[i].Private, true, nil
		},
		RawColumn: func(t *testing.T, raw *sql.DB, owner string) []byte {
			return PrivateColumn(t.Context(), t, raw, owner)
		},
		CopySealed: func(t *testing.T, raw *sql.DB, from, to string) {
			_, err := raw.ExecContext(t.Context(), `UPDATE signing_keys
SET private_key = (SELECT private_key FROM signing_keys WHERE kid = $1) WHERE kid = $2`, from, to)
			require.NoError(t, err)
		},
	}
}
