package storetest_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/test/storetest"
)

// The sealed-column fake is seal's real enrolment wrapper over an in-memory
// enrolment store, which stands in for the table: RawColumn reads the sealed
// secret the wrapper handed it, as a durable store's column would hold it.

type sealedDefect string

const (
	sealedConforming      sealedDefect = "conforming"
	sealedIdentityCipher  sealedDefect = "identity-cipher"
	sealedMissingAAD      sealedDefect = "missing-aad"
	sealedNoReseal        sealedDefect = "no-reseal"
	sealedAbsentOnFailure sealedDefect = "absent-on-failure"
	sealedOpaqueFailure   sealedDefect = "opaque-failure"
)

// errReadFailed is the only error a store carrying the opaque-failure defect
// returns: it drops the reason a value would not open.
var errReadFailed = errors.New("the secret could not be read")

// sealedCipher returns the cipher a fake store seals through over kr, as
// defect d has it.
func sealedCipher(t *testing.T, kr seal.Keyring, d sealedDefect) seal.Cipher {
	t.Helper()

	c, err := seal.NewAEADCipher(kr)
	require.NoError(t, err)
	switch d {
	case sealedIdentityCipher:
		return identityCipher{}
	case sealedMissingAAD:
		return missingAADCipher{c}
	}
	return c
}

// sealedRead is what a fake's Get returns for a read that came back with
// secret, ok and err, as defect d has it.
func sealedRead(d sealedDefect, secret []byte, ok bool, err error) ([]byte, bool, error) {
	switch {
	case err != nil && d == sealedAbsentOnFailure:
		return nil, false, nil
	case err != nil && d == sealedOpaqueFailure:
		return nil, false, errReadFailed
	}
	return secret, ok, err
}

// identityCipher returns its input unchanged: it seals nothing.
type identityCipher struct{}

func (identityCipher) Seal(p, _ []byte) ([]byte, error)         { return bytes.Clone(p), nil }
func (identityCipher) Open(s, _ []byte) ([]byte, string, error) { return bytes.Clone(s), "k1", nil }
func (identityCipher) ActiveKeyID() (string, error)             { return "k1", nil }

// missingAADCipher seals with the real cipher but binds nothing, so a sealed
// value opens in any record.
type missingAADCipher struct{ seal.Cipher }

func (c missingAADCipher) Seal(p, _ []byte) ([]byte, error)         { return c.Cipher.Seal(p, nil) }
func (c missingAADCipher) Open(s, _ []byte) ([]byte, string, error) { return c.Cipher.Open(s, nil) }

// tableResealer is the conditional re-seal write over the in-memory table.
type tableResealer struct{ table *mfa.MemoryEnrolmentStore }

func (r tableResealer) ResealEnrolmentSecret(ctx context.Context, user identity.UserID, old, resealed []byte) error {
	e, ok, err := r.table.Get(ctx, user)
	if err != nil || !ok || !bytes.Equal(e.Secret, old) {
		return err
	}
	e.Secret = resealed
	return r.table.PutPending(ctx, e)
}

func sealedFake(
	table *mfa.MemoryEnrolmentStore, d sealedDefect, enc storetest.SealedEncoding, rot storetest.SealedRotation,
) storetest.Sealed[mfa.EnrolmentStore] {
	return storetest.Sealed[mfa.EnrolmentStore]{
		Encoding: enc,
		Rotation: rot,
		NewWithKeyring: func(t *testing.T, kr seal.Keyring) mfa.EnrolmentStore {
			var opts []seal.Option
			if d == sealedNoReseal {
				opts = append(opts, seal.WithResealOnRead(false))
			}
			s, err := seal.NewEnrolmentStore(table, tableResealer{table}, sealedCipher(t, kr, d), opts...)
			require.NoError(t, err)
			return s
		},
		Put: func(ctx context.Context, s mfa.EnrolmentStore, owner string, secret []byte) error {
			return s.PutPending(ctx, mfa.Enrolment{User: identity.UserID(owner), Secret: secret})
		},
		Get: func(ctx context.Context, s mfa.EnrolmentStore, owner string) ([]byte, bool, error) {
			e, ok, err := s.Get(ctx, identity.UserID(owner))
			return sealedRead(d, e.Secret, ok, err)
		},
		RawColumn: func(t *testing.T, _ *sql.DB, owner string) []byte {
			e, ok, err := table.Get(t.Context(), identity.UserID(owner))
			require.NoError(t, err)
			require.True(t, ok, "no row for the owner")
			if enc == storetest.SealedBase64URL {
				return []byte(base64.RawURLEncoding.EncodeToString(e.Secret))
			}
			return e.Secret
		},
		CopySealed: func(t *testing.T, _ *sql.DB, from, to string) {
			src, ok, err := table.Get(t.Context(), identity.UserID(from))
			require.NoError(t, err)
			require.True(t, ok)
			dst, ok, err := table.Get(t.Context(), identity.UserID(to))
			require.NoError(t, err)
			require.True(t, ok)
			dst.Secret = src.Secret
			require.NoError(t, table.PutPending(t.Context(), dst))
		},
	}
}

// The whole-table fake is seal's real signing-key wrapper over the in-memory
// signing-key store. Its reads load every key at once, as the signing-key
// store does, so one record that will not open fails every read: Get picks the
// owner's key out of the whole load.

// keyTableResealer is the conditional re-seal write over the in-memory key
// table.
type keyTableResealer struct{ table signingkey.KeyStore }

func (r keyTableResealer) ResealSigningKey(ctx context.Context, kid string, old, resealed []byte) error {
	rec, ok, err := loadKey(ctx, r.table, kid)
	if err != nil || !ok || !bytes.Equal(rec.Private, old) {
		return err
	}
	rec.Private = resealed
	return r.table.Store(ctx, rec)
}

// loadKey picks kid's record out of everything s loads.
func loadKey(ctx context.Context, s signingkey.KeyStore, kid string) (signingkey.Record, bool, error) {
	recs, err := s.LoadAll(ctx)
	if err != nil {
		return signingkey.Record{}, false, err
	}
	for _, rec := range recs {
		if rec.Kid == kid {
			return rec, true, nil
		}
	}
	return signingkey.Record{}, false, nil
}

func sealedKeysFake(table signingkey.KeyStore, d sealedDefect) storetest.Sealed[signingkey.KeyStore] {
	// created dates each key after the last, so the table loads in the order
	// the suite stored them.
	created := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	return storetest.Sealed[signingkey.KeyStore]{
		Encoding: storetest.SealedBytes,
		Rotation: storetest.ResealOnRead,
		NewWithKeyring: func(t *testing.T, kr seal.Keyring) signingkey.KeyStore {
			s, err := seal.NewSigningKeyStore(table, keyTableResealer{table}, sealedCipher(t, kr, d))
			require.NoError(t, err)
			return s
		},
		Put: func(ctx context.Context, s signingkey.KeyStore, owner string, secret []byte) error {
			created = created.Add(time.Second)
			return s.Store(ctx, signingkey.Record{Kid: owner, Alg: "EdDSA", Private: secret, CreatedAt: created})
		},
		Get: func(ctx context.Context, s signingkey.KeyStore, owner string) ([]byte, bool, error) {
			rec, ok, err := loadKey(ctx, s, owner)
			return sealedRead(d, rec.Private, ok, err)
		},
		RawColumn: func(t *testing.T, _ *sql.DB, owner string) []byte {
			rec, ok, err := loadKey(t.Context(), table, owner)
			require.NoError(t, err)
			require.True(t, ok, "no row for the owner")
			return rec.Private
		},
		CopySealed: func(t *testing.T, _ *sql.DB, from, to string) {
			src, ok, err := loadKey(t.Context(), table, from)
			require.NoError(t, err)
			require.True(t, ok)
			dst, ok, err := loadKey(t.Context(), table, to)
			require.NoError(t, err)
			require.True(t, ok)
			dst.Private = src.Private
			require.NoError(t, table.Store(t.Context(), dst))
		},
	}
}

func sealedKeysVariant(d sealedDefect, failsCase string) brokenVariant {
	return brokenVariant{
		name: "sealed-keys-" + string(d),
		run: func(t *testing.T) {
			table := signingkey.NewInMemoryKeyStore()
			h := fakeHarness(func(*testing.T) signingkey.KeyStore { return table })
			storetest.RunSealedColumns(t, h, sealedKeysFake(table, d))
		},
		failsCase: failsCase,
	}
}

// encodingNames and rotationNames name a variant's encoding and rotation.
var (
	encodingNames = map[storetest.SealedEncoding]string{storetest.SealedBytes: "bytes", storetest.SealedBase64URL: "text"}
	rotationNames = map[storetest.SealedRotation]string{
		storetest.ResealOnRead: "reseal", storetest.UnchangedOnRead: "unchanged",
	}
)

func sealedVariant(
	d sealedDefect, enc storetest.SealedEncoding, rot storetest.SealedRotation, failsCase string,
) brokenVariant {
	return brokenVariant{
		name: "sealed-" + string(d) + "-" + encodingNames[enc] + "-" + rotationNames[rot],
		run: func(t *testing.T) {
			table := mfa.NewMemoryEnrolmentStore()
			h := fakeHarness(func(*testing.T) mfa.EnrolmentStore { return table })
			storetest.RunSealedColumns(t, h, sealedFake(table, d, enc, rot))
		},
		failsCase: failsCase,
	}
}

const (
	plaintextCase  = "the stored value, decoded, does not hold the plaintext"
	copyCase       = "a sealed value copied to another record does not open there"
	missingKeyCase = "a read without the sealing key is an error, never absence"
	resealCase     = "a read under a retired key re-seals the value under the active key"
	unchangedCase  = "a read under a retired key leaves the stored value unchanged"
)

var sealedVariants = []brokenVariant{
	sealedVariant(sealedConforming, storetest.SealedBase64URL, storetest.ResealOnRead, ""),
	sealedVariant(sealedConforming, storetest.SealedBytes, storetest.ResealOnRead, ""),
	sealedVariant(sealedNoReseal, storetest.SealedBase64URL, storetest.UnchangedOnRead, ""),
	sealedVariant(sealedIdentityCipher, storetest.SealedBase64URL, storetest.ResealOnRead, plaintextCase),
	sealedVariant(sealedIdentityCipher, storetest.SealedBytes, storetest.ResealOnRead, plaintextCase),
	sealedVariant(sealedMissingAAD, storetest.SealedBase64URL, storetest.ResealOnRead, copyCase),
	sealedVariant(sealedAbsentOnFailure, storetest.SealedBase64URL, storetest.ResealOnRead, missingKeyCase),
	sealedVariant(sealedNoReseal, storetest.SealedBase64URL, storetest.ResealOnRead, resealCase),
	sealedVariant(sealedConforming, storetest.SealedBase64URL, storetest.UnchangedOnRead, unchangedCase),
	sealedVariant(sealedOpaqueFailure, storetest.SealedBase64URL, storetest.ResealOnRead, missingKeyCase),
	sealedKeysVariant(sealedConforming, ""),
	sealedKeysVariant(sealedMissingAAD, copyCase),
	sealedKeysVariant(sealedIdentityCipher, plaintextCase),
	sealedKeysVariant(sealedOpaqueFailure, missingKeyCase),
	{
		name: "sealed-missing-raw",
		// Wrapped in a subtest, as the narrow-pool race variant is, for the
		// guard to find the input check's failure by name.
		run: func(t *testing.T) {
			t.Run("missing raw", func(t *testing.T) {
				table := mfa.NewMemoryEnrolmentStore()
				h := fakeHarness(func(*testing.T) mfa.EnrolmentStore { return table })
				h.Raw = nil
				storetest.RunSealedColumns(t, h,
					sealedFake(table, sealedConforming, storetest.SealedBase64URL, storetest.ResealOnRead))
			})
		},
		failsCase: "missing raw",
		failsWith: "storetest: DurableHarness.Raw is required",
	},
}
