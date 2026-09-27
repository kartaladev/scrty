package storefix

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
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
