package seal_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/seal"
)

// TestAADGolden pins the additional data each sealed column is bound to. The
// strings are part of the stored format: changing one makes every stored value
// unopenable, indistinguishable from tampering, so a change here must be a
// deliberate migration, never an edit.
func TestAADGolden(t *testing.T) {
	t.Parallel()

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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.got())
		})
	}
}
