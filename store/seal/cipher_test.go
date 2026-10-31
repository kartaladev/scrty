package seal_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/must"
	pkgid "github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/seal"
)

const secretPlaintext = "TOTP-SENTINEL-plaintext-that-must-never-leak"

var (
	boundAAD = []byte("scrty/test:field:row-1")
	otherAAD = []byte("scrty/test:field:row-2")
)

// mustSeal seals plaintext under c, failing the test on error.
func mustSeal(t *testing.T, c seal.Cipher, plaintext string, aad []byte) []byte {
	t.Helper()

	sealed, err := c.Seal([]byte(plaintext), aad)
	require.NoError(t, err)

	return sealed
}

// assertOpenFailed checks a failed open: the opaque error, no plaintext, and
// no trace of the secret in the error's text.
func assertOpenFailed(t *testing.T, plaintext []byte, keyID string, err error) {
	t.Helper()

	require.ErrorIs(t, err, seal.ErrDecryptionFailed)
	assert.NotErrorIs(t, err, seal.ErrUnknownKeyID)
	assert.Nil(t, plaintext)
	assert.Empty(t, keyID)
	assert.NotContains(t, err.Error(), secretPlaintext)
}

func TestNewAEADCipher(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		keyring func(t *testing.T) seal.Keyring
		assert  func(t *testing.T, c seal.Cipher, err error)
	}

	// A cipher wired without a keyring is a wiring mistake, reported before
	// traffic rather than on the first seal or open, which may be hours later.
	assertRefused := func(t *testing.T, c seal.Cipher, err error) {
		require.ErrorIs(t, err, seal.ErrConfig)
		assert.Nil(t, c)
	}

	cases := []testCase{
		{
			name:    "a nil keyring is refused",
			keyring: func(*testing.T) seal.Keyring { return nil },
			assert:  assertRefused,
		},
		{
			name:    "a typed-nil keyring is refused",
			keyring: func(*testing.T) seal.Keyring { return (*MockKeyring)(nil) },
			assert:  assertRefused,
		},
		{
			name: "a keyring builds a cipher that seals under its active key",
			keyring: func(t *testing.T) seal.Keyring {
				kr, err := seal.NewKeyring(seal.WithKeyringEncryptionKey("k2", keyTwo))
				require.NoError(t, err)

				return kr
			},
			assert: func(t *testing.T, c seal.Cipher, err error) {
				require.NoError(t, err)
				require.NotNil(t, c)

				id, err := c.ActiveKeyID()
				require.NoError(t, err)
				assert.Equal(t, "k2", id)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := seal.NewAEADCipher(tc.keyring(t))
			tc.assert(t, c, err)
		})
	}
}

func TestAEADCipher(t *testing.T) {
	t.Parallel()

	// current rotated from k1 to k2; previous only ever knew k1.
	current := mustCipher(t,
		seal.WithKeyringEncryptionKey("k2", keyTwo),
		seal.WithKeyringRetiredEncryptionKey("k1", keyOne),
	)
	previous := mustCipher(t, seal.WithKeyringEncryptionKey("k1", keyOne))
	impostor := mustCipher(t, seal.WithKeyringEncryptionKey("k2", keyThree))
	unknown := mustCipher(t, seal.WithKeyringEncryptionKey("gone", keyThree))

	type testCase struct {
		name   string
		sealed func(t *testing.T) []byte
		aad    []byte // nil means boundAAD
		opener seal.Cipher
		assert func(t *testing.T, plaintext []byte, keyID string, err error)
	}

	sealedByCurrent := func(t *testing.T) []byte { return mustSeal(t, current, secretPlaintext, boundAAD) }

	cases := []testCase{
		{
			name:   "round trip under the active key",
			sealed: sealedByCurrent,
			assert: func(t *testing.T, plaintext []byte, keyID string, err error) {
				require.NoError(t, err)
				assert.Equal(t, secretPlaintext, string(plaintext))
				assert.Equal(t, "k2", keyID)
			},
		},
		{
			name:   "an empty plaintext round-trips",
			sealed: func(t *testing.T) []byte { return mustSeal(t, current, "", boundAAD) },
			assert: func(t *testing.T, plaintext []byte, keyID string, err error) {
				require.NoError(t, err)
				assert.Empty(t, plaintext)
				assert.Equal(t, "k2", keyID)
			},
		},
		{
			name:   "wrong additional data",
			sealed: sealedByCurrent,
			aad:    otherAAD,
			assert: assertOpenFailed,
		},
		{
			name:   "a different key under the same id",
			sealed: sealedByCurrent,
			opener: impostor,
			assert: assertOpenFailed,
		},
		{
			name: "a tampered last byte",
			sealed: func(t *testing.T) []byte {
				v := sealedByCurrent(t)
				v[len(v)-1] ^= 0x01

				return v
			},
			assert: assertOpenFailed,
		},
		{
			name: "a tampered nonce byte",
			sealed: func(t *testing.T) []byte {
				v := sealedByCurrent(t)
				v[4+1+len("k2")] ^= 0x01

				return v
			},
			assert: assertOpenFailed,
		},
		{
			// A key id rewritten to the retired key selects different key
			// bytes, so the tag fails whether or not the header is
			// authenticated. This row pins the refusal only; the aliasing case
			// in TestAEADCipher_ConsumerKeyring shows the header is under the tag.
			name: "a key id rewritten to the retired key",
			sealed: func(t *testing.T) []byte {
				v := sealedByCurrent(t)
				require.Equal(t, "k2", string(v[5:7]))
				v[6] = '1'

				return v
			},
			assert: assertOpenFailed,
		},
		{
			name:   "truncated to 10 bytes",
			sealed: func(t *testing.T) []byte { return sealedByCurrent(t)[:10] },
			assert: assertOpenFailed,
		},
		{
			name: "truncated by one byte",
			sealed: func(t *testing.T) []byte {
				v := sealedByCurrent(t)

				return v[:len(v)-1]
			},
			assert: assertOpenFailed,
		},
		{
			name: "missing magic",
			sealed: func(t *testing.T) []byte {
				v := sealedByCurrent(t)
				v[0] ^= 0xff

				return v
			},
			assert: assertOpenFailed,
		},
		{
			name: "a key-id length byte past the end of a 30-byte value",
			sealed: func(*testing.T) []byte {
				v := append([]byte("SCS1"), 200)

				return append(v, bytes.Repeat([]byte{'a'}, 25)...)
			},
			assert: assertOpenFailed,
		},
		{
			name: "a zero key-id length",
			sealed: func(t *testing.T) []byte {
				v := append([]byte("SCS1"), 0)

				return append(v, sealedByCurrent(t)[7:]...)
			},
			assert: assertOpenFailed,
		},
		{
			name: "a key id outside the allowed characters",
			sealed: func(t *testing.T) []byte {
				v := sealedByCurrent(t)
				v[5] = '/'

				return v
			},
			assert: assertOpenFailed,
		},
		{
			name:   "an empty value",
			sealed: func(*testing.T) []byte { return []byte{} },
			assert: assertOpenFailed,
		},
		{
			name:   "a nil value",
			sealed: func(*testing.T) []byte { return nil },
			assert: assertOpenFailed,
		},
		{
			name:   "a value sealed under the retired key opens and names it",
			sealed: func(t *testing.T) []byte { return mustSeal(t, previous, secretPlaintext, boundAAD) },
			assert: func(t *testing.T, plaintext []byte, keyID string, err error) {
				require.NoError(t, err)
				assert.Equal(t, secretPlaintext, string(plaintext))
				assert.Equal(t, "k1", keyID)
			},
		},
		{
			name:   "a key id the ring no longer holds is distinguishable",
			sealed: func(t *testing.T) []byte { return mustSeal(t, unknown, secretPlaintext, boundAAD) },
			assert: func(t *testing.T, plaintext []byte, keyID string, err error) {
				require.ErrorIs(t, err, seal.ErrUnknownKeyID)
				assert.False(t, errors.Is(err, seal.ErrDecryptionFailed))
				assert.Nil(t, plaintext)
				assert.Equal(t, "gone", keyID, "the missing key is named, so an operator can restore it")
				assert.NotContains(t, err.Error(), "gone",
					"the id is read from the stored value, so it stays out of the error's text")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sealed := tc.sealed(t)

			aad := tc.aad
			if aad == nil {
				aad = boundAAD
			}
			opener := tc.opener
			if opener == nil {
				opener = current
			}

			plaintext, keyID, err := opener.Open(sealed, aad)
			tc.assert(t, plaintext, keyID, err)
		})
	}
}

// It stands apart from the TestAEADCipher table: it seals twice with one cipher
// and compares the two results.
func TestAEADCipher_Randomised(t *testing.T) {
	t.Parallel()

	c := mustCipher(t, seal.WithKeyringEncryptionKey("k2", keyTwo))

	first := mustSeal(t, c, secretPlaintext, boundAAD)
	second := mustSeal(t, c, secretPlaintext, boundAAD)

	assert.NotEqual(t, first, second)
	assert.NotContains(t, string(first), secretPlaintext)
	assert.NotContains(t, string(second), secretPlaintext)
}

func TestAEADCipher_ActiveKeyID(t *testing.T) {
	t.Parallel()

	c := mustCipher(t,
		seal.WithKeyringRetiredEncryptionKey("k1", keyOne),
		seal.WithKeyringEncryptionKey("k2", keyTwo),
	)

	id, err := c.ActiveKeyID()
	require.NoError(t, err)
	assert.Equal(t, "k2", id)
}

// TestAEADCipher_ConsumerKeyring covers a keyring the consumer implements:
// what the cipher does with what that ring hands back, well formed or not.
func TestAEADCipher_ConsumerKeyring(t *testing.T) {
	t.Parallel()

	errKMS := errors.New("kms: key key-two-0123456789abcdefghijklmn unavailable")

	// A value sealed under "k2" by the default ring, for the open cases.
	sealedK2 := mustSeal(t, mustCipher(t, seal.WithKeyringEncryptionKey("k2", keyTwo)), secretPlaintext, boundAAD)

	type testCase struct {
		name   string
		expect func(kr *MockKeyring)
		call   func(c seal.Cipher) error
		assert func(t *testing.T, err error)
	}

	sealCall := func(c seal.Cipher) error {
		_, err := c.Seal([]byte(secretPlaintext), boundAAD)

		return err
	}
	openCall := func(c seal.Cipher) error {
		_, _, err := c.Open(sealedK2, boundAAD)

		return err
	}
	// sealedK2 with its header's key id rewritten to "k1", the same length,
	// as someone with write access to the column but no key could.
	rewrittenK1 := bytes.Clone(sealedK2)
	require.Equal(t, "k2", string(rewrittenK1[5:7]))
	rewrittenK1[6] = '1'

	openRewrittenCall := func(c seal.Cipher) error {
		plaintext, keyID, err := c.Open(rewrittenK1, boundAAD)
		if err == nil {
			return fmt.Errorf("opened as %q under %q", plaintext, keyID)
		}

		return err
	}
	activeCall := func(c seal.Cipher) error {
		_, err := c.ActiveKeyID()

		return err
	}

	assertKMS := func(t *testing.T, err error) {
		require.ErrorIs(t, err, errKMS)
		assert.NotErrorIs(t, err, seal.ErrDecryptionFailed)
		assert.NotContains(t, err.Error(), "kms:", "a dependency's text stays out of the error's text")
	}

	cases := []testCase{
		{
			name: "a 16-byte active key is refused rather than sealing with AES-128",
			expect: func(kr *MockKeyring) {
				kr.EXPECT().Active().Return("k2", keyTwo[:16], nil)
			},
			call: sealCall,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, seal.ErrConfig)
				assert.NotContains(t, err.Error(), string(keyTwo[:16]))
			},
		},
		{
			name: "an active key id the envelope cannot carry is refused",
			expect: func(kr *MockKeyring) {
				kr.EXPECT().Active().Return("bad/id", keyTwo, nil)
			},
			call: sealCall,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, seal.ErrConfig)
			},
		},
		{
			name: "an active key id the envelope cannot carry is refused when naming the active key",
			expect: func(kr *MockKeyring) {
				kr.EXPECT().Active().Return("bad/id", keyTwo, nil)
			},
			call: activeCall,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, seal.ErrConfig)
			},
		},
		{
			name: "an active-key failure propagates when sealing",
			expect: func(kr *MockKeyring) {
				kr.EXPECT().Active().Return("", nil, errKMS)
			},
			call:   sealCall,
			assert: assertKMS,
		},
		{
			name: "an active-key failure propagates when naming the active key",
			expect: func(kr *MockKeyring) {
				kr.EXPECT().Active().Return("", nil, errKMS)
			},
			call:   activeCall,
			assert: assertKMS,
		},
		{
			name: "a lookup failure propagates when opening and is not a decryption failure",
			expect: func(kr *MockKeyring) {
				kr.EXPECT().ByID("k2").Return(nil, errKMS)
			},
			call:   openCall,
			assert: assertKMS,
		},
		{
			name: "a wrapped unknown key id from the ring is an unknown key id",
			expect: func(kr *MockKeyring) {
				kr.EXPECT().ByID("k2").Return(nil, errors.Join(errKMS, seal.ErrUnknownKeyID))
			},
			call: openCall,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, seal.ErrUnknownKeyID)
				assert.NotErrorIs(t, err, seal.ErrDecryptionFailed)
				assert.NotContains(t, err.Error(), "kms:")
				assert.NotContains(t, err.Error(), "k2", "the id read from the stored value stays out of the error's text")
			},
		},
		{
			name: "a 16-byte key from a lookup is refused rather than opening with AES-128",
			expect: func(kr *MockKeyring) {
				kr.EXPECT().ByID("k2").Return(keyTwo[:16], nil)
			},
			call: openCall,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, seal.ErrConfig)
			},
		},
		{
			// The header is authenticated, so a rewritten key id fails the tag
			// even when the ring hands back the same bytes for both ids — which
			// NewKeyring refuses, but a consumer ring may do.
			name: "a key id rewritten to an id the ring aliases to the same key is refused",
			expect: func(kr *MockKeyring) {
				kr.EXPECT().ByID("k1").Return(bytes.Clone(keyTwo), nil)
			},
			call: openRewrittenCall,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, seal.ErrDecryptionFailed)
				assert.NotErrorIs(t, err, seal.ErrUnknownKeyID)
			},
		},
		{
			name: "a ring that returns the right key opens",
			expect: func(kr *MockKeyring) {
				kr.EXPECT().ByID("k2").Return(bytes.Clone(keyTwo), nil)
			},
			call: openCall,
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			kr := NewMockKeyring(gomock.NewController(t))
			tc.expect(kr)

			c, err := seal.NewAEADCipher(kr)
			require.NoError(t, err)

			tc.assert(t, tc.call(c))
		})
	}
}

// fuzzSealed is a value sealed once under keyTwo as "k2" with boundAAD. It
// is fixed rather than sealed in the fuzz target, because every fuzz worker
// runs the target's setup again, and a value sealed there would carry a nonce
// of its own.
const fuzzSealed = "53435331026b32c1e93120085d80695e9a392a37a613523eba16eb3ad0d111d954048d3974331853" +
	"ca4f2b1ae529fb79127bd7f1b90efedefd60863db212001765dc8260cc3b4cae5739b0e9c6c8bd"

// FuzzAEADCipherOpen pins that no stored value, however malformed, panics or
// opens: anything but the one genuine value is refused as a decryption failure
// or an unknown key id.
func FuzzAEADCipherOpen(f *testing.F) {
	kr, err := seal.NewKeyring(seal.WithKeyringEncryptionKey("k2", keyTwo))
	require.NoError(f, err)
	c, err := seal.NewAEADCipher(kr)
	require.NoError(f, err)

	valid, err := hex.DecodeString(fuzzSealed)
	require.NoError(f, err)

	f.Add(valid)
	f.Add([]byte("SCS1"))
	f.Add(append([]byte("SCS1"), 200))
	f.Add(append([]byte("SCS1\x02k3"), make([]byte, 28)...))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, sealed []byte) {
		plaintext, keyID, err := c.Open(sealed, boundAAD)
		if bytes.Equal(sealed, valid) {
			require.NoError(t, err)
			assert.Equal(t, secretPlaintext, string(plaintext))
			assert.Equal(t, "k2", keyID)

			return
		}

		if err == nil {
			t.Fatalf("a value that was never sealed opened: %x -> %q", sealed, plaintext)
		}
		if !errors.Is(err, seal.ErrDecryptionFailed) && !errors.Is(err, seal.ErrUnknownKeyID) {
			t.Fatalf("unexpected error kind: %v", err)
		}
	})
}

// TestAADGolden pins the additional data each sealed column is bound to. The
// strings are part of the stored format: changing one makes every stored value
// unopenable, indistinguishable from tampering, so a change here must be a
// deliberate migration, never an edit.
func TestAADGolden(t *testing.T) {
	t.Parallel()

	gen := pkgid.MustParse("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b")

	type testCase struct {
		name   string
		got    func() []byte
		assert func(t *testing.T, got []byte)
	}

	cases := []testCase{
		{
			name: "signing-key private material is bound to its key id",
			got:  func() []byte { return seal.SigningKeyAAD("k-1") },
			assert: func(t *testing.T, got []byte) {
				assert.Equal(t, []byte("scrty/signingkey:private:k-1"), got)
			},
		},
		{
			// The generation's canonical text comes first, at a fixed length,
			// then the user reference byte for byte: never trimmed or folded.
			name: "an MFA secret is bound to its generation and user reference",
			got:  func() []byte { return seal.MFASecretAAD(gen, "Alice ") },
			assert: func(t *testing.T, got []byte) {
				assert.Equal(t, []byte("scrty/mfa:secret:0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b:Alice "), got)
			},
		},
		{
			name: "an MFA secret is not bound like the same user's secret of another generation",
			got:  func() []byte { return seal.MFASecretAAD(gen, "Alice ") },
			assert: func(t *testing.T, got []byte) {
				assert.NotEqual(t, seal.MFASecretAAD(pkgid.MustParse("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c"), "Alice "), got)
			},
		},
		{
			// The generation's canonical text comes first, at a fixed length,
			// then the user reference byte for byte.
			name: "an emailed MFA code is bound to its generation and user reference",
			got:  func() []byte { return seal.MFAEmailCodeAAD(gen, "Alice ") },
			assert: func(t *testing.T, got []byte) {
				assert.Equal(t, []byte("scrty/mfa:email-code:0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b:Alice "), got)
			},
		},
		{
			name: "an emailed MFA code is not bound like the same user's secret",
			got:  func() []byte { return seal.MFAEmailCodeAAD(gen, "Alice ") },
			assert: func(t *testing.T, got []byte) {
				assert.NotEqual(t, seal.MFASecretAAD(gen, "Alice "), got)
			},
		},
		{
			// The credential's canonical text comes first, at a fixed length,
			// then the user reference byte for byte.
			name: "an emailed passkey code is bound to its credential and user reference",
			got:  func() []byte { return seal.PasskeyEmailCodeAAD(gen, "Alice ") },
			assert: func(t *testing.T, got []byte) {
				assert.Equal(t, []byte("scrty/passkey:email-code:0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b:Alice "), got)
			},
		},
		{
			name: "an emailed passkey code is not bound like an emailed MFA code",
			got:  func() []byte { return seal.PasskeyEmailCodeAAD(gen, "Alice ") },
			assert: func(t *testing.T, got []byte) {
				assert.NotEqual(t, seal.MFAEmailCodeAAD(gen, "Alice "), got)
			},
		},
		{
			name: "the signing-key prefix",
			got:  func() []byte { return []byte(seal.AADSigningKeyPrefix) },
			assert: func(t *testing.T, got []byte) {
				assert.Equal(t, "scrty/signingkey:private:", string(got))
			},
		},
		{
			name: "the MFA secret prefix",
			got:  func() []byte { return []byte(seal.AADMFASecretPrefix) },
			assert: func(t *testing.T, got []byte) {
				assert.Equal(t, "scrty/mfa:secret:", string(got))
			},
		},
		{
			name: "the emailed passkey code prefix",
			got:  func() []byte { return []byte(seal.AADPasskeyEmailCodePrefix) },
			assert: func(t *testing.T, got []byte) {
				assert.Equal(t, "scrty/passkey:email-code:", string(got))
			},
		},
		{
			name: "the emailed MFA code prefix",
			got:  func() []byte { return []byte(seal.AADMFAEmailCodePrefix) },
			assert: func(t *testing.T, got []byte) {
				assert.Equal(t, "scrty/mfa:email-code:", string(got))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.got())
		})
	}
}

const idToken = "eyJhbGciOiJSUzI1NiJ9.ID-TOKEN-SENTINEL.signature" //nolint:gosec // G101: a fixture, not a credential

// federated returns a live session carrying a provider ID token.
func federated(id, token string) *session.Session {
	now := time.Now().UTC()

	return &session.Session{
		ID:                id,
		UserID:            "alice",
		CreatedAt:         now,
		LastAccessedAt:    now,
		IdleExpiresAt:     now.Add(30 * time.Minute),
		AbsoluteExpiresAt: now.Add(12 * time.Hour),
		// Every stored session belongs to a family; the stores refuse one with none.
		FamilyID:         pkgid.MustParse("01926a4e-0000-7000-8000-0000000000f1"),
		FamilyCreatedAt:  now,
		ExternalProvider: "okta",
		ExternalIssuer:   "https://issuer.example",
		ExternalIDToken:  token,
	}
}

func TestSessionCipher(t *testing.T) {
	t.Parallel()

	c := mustCipher(t, seal.WithKeyringEncryptionKey("k2", keyTwo))

	type testCase struct {
		name   string
		cipher seal.Cipher
		assert func(t *testing.T, sealing session.Store, inner *session.MemoryStore, err error)
	}

	cases := []testCase{
		{
			name:   "a sealed ID token round-trips",
			cipher: c,
			assert: func(t *testing.T, sealing session.Store, _ *session.MemoryStore, err error) {
				require.NoError(t, err)
				require.NoError(t, sealing.Create(t.Context(), federated("sess-a", idToken)))

				got, err := sealing.Load(t.Context(), "sess-a")
				require.NoError(t, err)
				assert.Equal(t, idToken, got.ExternalIDToken)
			},
		},
		{
			name:   "the inner store holds a sealed value, not the token",
			cipher: c,
			assert: func(t *testing.T, sealing session.Store, inner *session.MemoryStore, err error) {
				require.NoError(t, err)
				require.NoError(t, sealing.Create(t.Context(), federated("sess-a", idToken)))

				raw, err := inner.Load(t.Context(), "sess-a")
				require.NoError(t, err)
				assert.NotEqual(t, idToken, raw.ExternalIDToken)
				assert.NotContains(t, raw.ExternalIDToken, "ID-TOKEN-SENTINEL")

				envelope, err := base64.RawURLEncoding.DecodeString(raw.ExternalIDToken)
				require.NoError(t, err)
				assert.NotContains(t, string(envelope), "ID-TOKEN-SENTINEL")
			},
		},
		{
			name:   "an ID token moved to another session is unreadable",
			cipher: c,
			assert: func(t *testing.T, sealing session.Store, inner *session.MemoryStore, err error) {
				require.NoError(t, err)
				require.NoError(t, sealing.Create(t.Context(), federated("sess-victim", idToken)))
				require.NoError(t, sealing.Create(t.Context(), federated("sess-attacker", "attacker-token")))

				victim, err := inner.Load(t.Context(), "sess-victim")
				require.NoError(t, err)
				attacker, err := inner.Load(t.Context(), "sess-attacker")
				require.NoError(t, err)

				// Written straight into the inner store, as someone with write
				// access to the table but no key would.
				attacker.ExternalIDToken = victim.ExternalIDToken
				require.NoError(t, inner.Save(t.Context(), attacker))

				got, err := sealing.Load(t.Context(), "sess-attacker")
				require.ErrorIs(t, err, session.ErrUnreadable)
				assert.NotErrorIs(t, err, session.ErrNotFound)
				assert.Nil(t, got)
				assert.NotContains(t, err.Error(), idToken)
			},
		},
		{
			name: "a nil cipher leaves the sealing store unbuilt",
			assert: func(t *testing.T, sealing session.Store, _ *session.MemoryStore, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, sealing)
			},
		},
		{
			name:   "a typed-nil cipher leaves the sealing store unbuilt",
			cipher: (*MockCipher)(nil),
			assert: func(t *testing.T, sealing session.Store, _ *session.MemoryStore, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, sealing)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inner := must.Must(session.NewMemoryStore())
			sealing, err := session.NewEncryptedStore(inner, seal.SessionCipher(tc.cipher))
			tc.assert(t, sealing, inner, err)
		})
	}
}
