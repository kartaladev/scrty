package seal

import "github.com/kartaladev/scrty/identity"

// The additional authenticated data each sealed column is bound to. A value
// opens only with the exact data it was sealed with, so a sealed value copied
// to another row, or to another table, will not open there.
//
// They follow the scrty/<package>:<field>: form the sealing session store
// already binds provider ID tokens with ("scrty/session:external-id-token:"
// followed by the session identifier), so the three read as one convention.
//
// They are part of the stored format, not configuration: changing one makes
// every stored value unopenable, which cannot be told apart from tampering.
// A consumer cipher receives the full additional data and may use it, but
// must not rewrite it.
const (
	// AADSigningKeyPrefix is followed by the signing key's id.
	AADSigningKeyPrefix = "scrty/signingkey:private:"

	// AADMFASecretPrefix is followed by the enrolled user's reference.
	AADMFASecretPrefix = "scrty/mfa:secret:" //nolint:gosec // G101: an additional-data prefix, not a credential
)

// SigningKeyAAD returns the additional data a signing key's private material
// is sealed against: AADSigningKeyPrefix followed by kid, byte for byte.
func SigningKeyAAD(kid string) []byte {
	return []byte(AADSigningKeyPrefix + kid)
}

// MFASecretAAD returns the additional data a user's MFA secret is sealed
// against: AADMFASecretPrefix followed by the user reference, byte for byte,
// never trimmed or case-folded.
func MFASecretAAD(user identity.UserID) []byte {
	return []byte(AADMFASecretPrefix + string(user))
}
