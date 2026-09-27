package seal

// The envelope is the stored form of a sealed value:
//
//	magic(4) | keyIDLen(1) | keyID | nonce(12) | ciphertext‖tag(16)
//
// The magic turns "this was never a sealed value" into a refusal before any
// key is looked up. The key id says which key opens the value, which is what
// lets a keyring keep old keys for reading after a rotation.
//
// The header (magic‖keyIDLen‖keyID) is covered by the GCM tag: it is
// authenticated as additional data ahead of the caller's aad, so an altered
// key id fails the tag even when a consumer keyring returns the same bytes for
// two ids, and an altered nonce fails it too. The one alteration reported
// before any tag check is a key id the keyring does not hold, which is
// ErrUnknownKeyID; the id it reports is read from the stored value.
const (
	envelopeMagic = "SCS1"
	nonceSize     = 12
	tagSize       = 16

	// minBody is the shortest nonce‖ciphertext‖tag: an empty plaintext.
	minBody = nonceSize + tagSize
)

// encodeHeader returns a slice holding the envelope header for keyID, with
// capacity for a body sealing bodyPlaintext bytes. keyID must already be
// valid, so its length fits the one-byte field.
func encodeHeader(keyID string, bodyPlaintext int) []byte {
	out := make([]byte, 0, len(envelopeMagic)+1+len(keyID)+minBody+bodyPlaintext)
	out = append(out, envelopeMagic...)
	out = append(out, byte(len(keyID))) //nolint:gosec // G115: callers pass a validated id of at most 64 bytes

	return append(out, keyID...)
}

// decodeEnvelope splits sealed into its key id, its header
// (magic‖keyIDLen‖keyID) and its body (nonce‖ciphertext‖tag). ok is false for
// anything that is not a well-formed envelope: no magic, a key-id length of
// zero or past the end, a key id outside the allowed characters, or a body too
// short to hold a nonce and a tag. Every length is checked before the slice it
// bounds is taken.
func decodeEnvelope(sealed []byte) (keyID string, header, body []byte, ok bool) {
	const fixed = len(envelopeMagic) + 1

	if len(sealed) < fixed || string(sealed[:len(envelopeMagic)]) != envelopeMagic {
		return "", nil, nil, false
	}

	n := int(sealed[len(envelopeMagic)])
	if n == 0 || len(sealed)-fixed < n+minBody {
		return "", nil, nil, false
	}

	keyID = string(sealed[fixed : fixed+n])
	if !validKeyID(keyID) {
		return "", nil, nil, false
	}

	return keyID, sealed[:fixed+n], sealed[fixed+n:], true
}

// additionalData returns the GCM additional data for a value: the envelope
// header followed by the caller's aad, in a new slice so neither is aliased.
// Covering the header binds the key id to the ciphertext, so a value whose id
// was rewritten fails the tag even under a keyring that returns the same bytes
// for both ids. The header has a fixed-width magic and a length-prefixed id,
// so no header‖aad pair can be read as a different split of the same bytes.
func additionalData(header, aad []byte) []byte {
	out := make([]byte, 0, len(header)+len(aad))
	out = append(out, header...)

	return append(out, aad...)
}
