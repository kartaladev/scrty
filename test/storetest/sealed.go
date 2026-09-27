package storetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/seal"
)

// SealedEncoding is how a sealed column holds the sealed value. It has no
// default: the suite decodes by it before looking for the plaintext, and a
// guess would let a text column pass on its encoding alone.
type SealedEncoding int

const (
	// SealedBytes is a binary column (bytea) holding the sealed value as it
	// is, as signing keys' private material is stored.
	SealedBytes SealedEncoding = iota + 1

	// SealedBase64URL is a text column holding the sealed value
	// base64url-encoded, padded or not, as MFA secrets and sessions' provider
	// ID tokens are stored.
	SealedBase64URL
)

// SealedRotation is what a store does when it reads a value sealed under a
// key that is no longer the active one. It has no default: which behaviour is
// right depends on the store's contract.
type SealedRotation int

const (
	// ResealOnRead re-seals the value under the active key, as the signing
	// key and MFA stores do by default.
	ResealOnRead SealedRotation = iota + 1

	// UnchangedOnRead leaves the stored value as it is, as the session store
	// does: a session load never rewrites the record, and a session re-seals
	// on its next write instead.
	UnchangedOnRead
)

// Sealed is what the sealed-column suite needs from one store with a sealed
// column. Each value is the secret of one owner: the record's key the
// value's additional data is bound to (a signing key's id, an MFA user
// reference, a session identifier). Every field is required, and probes
// missing one fail the suite at once, naming it.
type Sealed[S any] struct {
	// Encoding is how the column holds the sealed value.
	Encoding SealedEncoding

	// Rotation is what a read under a retired key does to the stored value.
	Rotation SealedRotation

	// NewWithKeyring returns the store sealing through the default cipher
	// over kr (seal.NewAEADCipher(kr)), on the database DurableHarness.Raw
	// reaches. Every store it returns in one run shares that database, so a
	// value one store writes is what the next reads.
	NewWithKeyring func(t *testing.T, kr seal.Keyring) S

	// Put stores secret as owner's sealed value, creating owner's record.
	Put func(ctx context.Context, s S, owner string, secret []byte) error

	// Get reads owner's secret through the store, opening it. present is
	// false only when the store holds no value for owner; a value that will
	// not open must be an error.
	Get func(ctx context.Context, s S, owner string) (secret []byte, present bool, err error)

	// RawColumn returns owner's sealed column as stored, read through raw
	// (DurableHarness.Raw), before any decoding: the bytes of a binary
	// column, the text of a text one.
	RawColumn func(t *testing.T, raw *sql.DB, owner string) []byte

	// CopySealed copies from's sealed column, as stored, over to's, through
	// raw: what an attacker with write access but no key would do.
	CopySealed func(t *testing.T, raw *sql.DB, from, to string)
}

// sealedPlaintext marks the suite's secrets, so a stored value holding one is
// found whatever surrounds it.
const sealedPlaintext = "SENTINEL-SECRET"

// RunSealedColumns holds a durable store with a sealed column to keeping its
// secret unusable at rest, reading the column through h.Raw rather than the
// store. Its stores seal under keys the suite generates: k1, then k2 with k1
// retired. It checks that:
//   - the stored value, and for a text column its decoded bytes, neither
//     equals nor contains the plaintext, while the store reads the plaintext
//     back;
//   - a read through a keyring without the sealing key is an error, never
//     absence, and the error matches seal.ErrUnknownKeyID;
//   - a read through a keyring whose active key is k2 and which still holds
//     k1 opens a value sealed under k1, and then, under ResealOnRead, the
//     value opens through a keyring holding only k2, which proves where the
//     re-seal landed; under UnchangedOnRead the stored value is exactly what
//     it was before the read;
//   - a sealed value copied into another record does not open there, read
//     through a keyring holding every key the suite sealed under, and the
//     error matches seal.ErrDecryptionFailed.
//
// Each failure case asserts its reason, not only an error, so a store that
// opens its whole table at once cannot pass a case by failing for another
// record's key.
//
// The cases run in that order on one database, the copy last: it leaves a
// record that will not open, which fails every later read of a store that
// opens its whole table at once, as the signing-key store does.
//
// h.New, h.Begin, h.BeginResolved and h.BeginForeign are not used, but are
// required as every durable suite requires them. It fails at once, naming
// every missing input, when h or s is missing one.
func RunSealedColumns[S any](t *testing.T, h DurableHarness[S], s Sealed[S]) {
	t.Helper()

	requireSealed(t, h, s)

	k1, k2 := sealKey(t), sealKey(t)
	underK1 := sealRing(t, seal.WithEncryptionKey("k1", k1))
	underK2 := sealRing(t, seal.WithEncryptionKey("k2", k2))
	rotated := sealRing(t, seal.WithEncryptionKey("k2", k2), seal.WithRetiredEncryptionKey("k1", k1))

	// put stores owner's secret sealed under k1, and returns it.
	put := func(t *testing.T, owner string) []byte {
		t.Helper()
		secret := []byte(sealedPlaintext + "-" + owner)
		require.NoError(t, s.Put(t.Context(), s.NewWithKeyring(t, underK1), owner, secret))
		return secret
	}
	// opens requires owner's secret to read back as want through a store over
	// kr.
	opens := func(t *testing.T, kr seal.Keyring, owner string, want []byte, msg string) {
		t.Helper()
		got, present, err := s.Get(t.Context(), s.NewWithKeyring(t, kr), owner)
		require.NoError(t, err, msg)
		require.True(t, present, msg)
		assert.Equal(t, want, got, msg)
	}

	// rotation is the case for a read under a retired key, by s.Rotation.
	rotation := durableCase{
		name: "a read under a retired key re-seals the value under the active key",
		assert: func(t *testing.T) {
			secret := put(t, "resealed")

			opens(t, rotated, "resealed", secret, "a value sealed under the retired key did not open")
			opens(t, underK2, "resealed", secret,
				"the value does not open under the active key alone: it was not re-sealed")
		},
	}
	if s.Rotation == UnchangedOnRead {
		rotation = durableCase{
			name: "a read under a retired key leaves the stored value unchanged",
			assert: func(t *testing.T) {
				secret := put(t, "unchanged")
				before := s.RawColumn(t, h.Raw, "unchanged")

				opens(t, rotated, "unchanged", secret, "a value sealed under the retired key did not open")
				assert.Equal(t, before, s.RawColumn(t, h.Raw, "unchanged"), "the read rewrote the stored value")
			},
		}
	}

	runDurableCases(t, []durableCase{
		{
			name: "the stored value, decoded, does not hold the plaintext",
			assert: func(t *testing.T) {
				secret := put(t, "at-rest")
				opens(t, underK1, "at-rest", secret, "the store does not read back what it stored")

				stored := s.RawColumn(t, h.Raw, "at-rest")
				require.NotEmpty(t, stored, "the sealed column is empty")
				assert.NotContains(t, string(stored), sealedPlaintext, "the column holds the plaintext")
				if s.Encoding == SealedBase64URL {
					decoded, err := base64.RawURLEncoding.DecodeString(string(bytes.TrimRight(stored, "=")))
					require.NoError(t, err, "the text column does not hold base64url")
					assert.NotContains(t, string(decoded), sealedPlaintext, "the decoded column holds the plaintext")
				}
			},
		},
		rotation,
		{
			name: "a read without the sealing key is an error, never absence",
			assert: func(t *testing.T) {
				put(t, "missing-key")

				got, present, err := s.Get(t.Context(), s.NewWithKeyring(t, underK2), "missing-key")
				require.Error(t, err, "a value sealed under a key the keyring lacks was read as present=%t", present)
				assert.ErrorIs(t, err, seal.ErrUnknownKeyID,
					"the read failed, but not for the key the keyring lacks")
				assert.Empty(t, got, "the failed read returned a secret")
			},
		},
		{
			name: "a sealed value copied to another record does not open there",
			assert: func(t *testing.T) {
				victim := put(t, "victim")
				put(t, "attacker")
				s.CopySealed(t, h.Raw, "victim", "attacker")

				// Through a keyring holding every key, so the read can fail
				// only for the binding: a store that loads its whole table
				// also opens the values the re-seal case moved to k2.
				got, present, err := s.Get(t.Context(), s.NewWithKeyring(t, rotated), "attacker")
				require.Error(t, err,
					"reading a value copied from another record did not fail (present=%t): "+
						"the value is not bound to its record", present)
				assert.ErrorIs(t, err, seal.ErrDecryptionFailed,
					"the read failed, but not because the value is bound to another record")
				assert.NotEqual(t, victim, got, "the failed read returned the other record's secret")
			},
		},
	})
}

// requireSealed fails t at once, naming every missing input, when h or s is
// missing one. An encoding or rotation that is not one of the constants is
// missing.
func requireSealed[S any](t testing.TB, h DurableHarness[S], s Sealed[S]) {
	t.Helper()

	h.requireWith(t,
		input{"Sealed.Encoding", s.Encoding == SealedBytes || s.Encoding == SealedBase64URL},
		input{"Sealed.Rotation", s.Rotation == ResealOnRead || s.Rotation == UnchangedOnRead},
		input{"Sealed.NewWithKeyring", s.NewWithKeyring != nil},
		input{"Sealed.Put", s.Put != nil},
		input{"Sealed.Get", s.Get != nil},
		input{"Sealed.RawColumn", s.RawColumn != nil},
		input{"Sealed.CopySealed", s.CopySealed != nil},
	)
}

// sealKey returns a fresh random key of the size the default cipher takes.
func sealKey(t *testing.T) []byte {
	t.Helper()

	key := make([]byte, seal.KeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

// sealRing returns a keyring of opts, failing t if it is refused.
func sealRing(t *testing.T, opts ...seal.KeyringOption) seal.Keyring {
	t.Helper()

	kr, err := seal.NewKeyring(opts...)
	require.NoError(t, err)
	return kr
}
