package seal_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
)

// TestAADGolden pins the additional data each sealed column is bound to. The
// strings are part of the stored format: changing one makes every stored value
// unopenable, indistinguishable from tampering, so a change here must be a
// deliberate migration, never an edit.
func TestAADGolden(t *testing.T) {
	t.Parallel()

	gen := id.MustParse("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b")

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
			// The user reference is used byte for byte: never trimmed or folded.
			name: "an MFA secret is bound to its user reference",
			got:  func() []byte { return seal.MFASecretAAD("Alice ") },
			assert: func(t *testing.T, got []byte) {
				assert.Equal(t, []byte("scrty/mfa:secret:Alice "), got)
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
				assert.NotEqual(t, seal.MFASecretAAD("Alice "), got)
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
