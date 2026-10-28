// Package seal encrypts the long-lived secrets that security state keeps at
// rest, so that a database dump, or write access to a table, is not enough to
// use them.
//
// Three secrets are sealed: signing-key private material, MFA secrets, and the
// provider ID token a federated session retains. Each is bound to the record
// it belongs to through additional authenticated data (see
// AADSigningKeyPrefix and AADMFASecretPrefix; sessions bind theirs inside
// package session), so a sealed value copied to another row or another table
// will not open.
//
// # Defaults
//
// NewAEADCipher is the default Cipher: AES-256-GCM with a random nonce for
// every seal, over a Keyring. NewKeyring is the default Keyring: exactly one
// active key, named with WithEncryptionKey, which seals and opens, and any
// number of retired keys, named with WithRetiredEncryptionKey, which only
// open. There is no default key and no unsealed mode: a keyring without an
// active key is a configuration error.
//
//	kr, err := seal.NewKeyring(
//		seal.WithEncryptionKey("2026-09", activeKey),
//		seal.WithRetiredEncryptionKey("2026-03", previousKey),
//	)
//	if err != nil {
//		return err
//	}
//	c, err := seal.NewAEADCipher(kr)
//	if err != nil {
//		return err
//	}
//
// A sealed value is stored as an envelope naming the key that sealed it:
//
//	magic "SCS1" | key-id length (1 byte) | key id | nonce (12) | ciphertext‖tag
//
// so rotating keys never makes stored values unreadable while the old key is
// kept as retired. The header is authenticated with the value, so rewriting
// its key id makes the value fail to open. Each key should seal well under
// 2^32 values, the limit of a random 96-bit nonce; rotate before that. A
// retired key is provably unused only once every value sealed under it has
// been re-sealed; removing it earlier makes those values fail with
// ErrUnknownKeyID.
//
// # Replacing the defaults
//
// A consumer replaces the cipher wholesale by implementing Cipher (for
// example over a key management service), or keeps the default cipher and
// supplies their own Keyring. SessionCipher adapts any Cipher to the port
// package session consumes.
//
// # Failing closed
//
// A value that will not open is an error, never an absent value.
// ErrDecryptionFailed is deliberately opaque. ErrUnknownKeyID is distinct from
// it, and Open returns the missing key's id with it, because it usually points
// at an operator who removed a key. That id is read from the stored value, so
// the error is not proof a key was removed. No error carries key bytes or
// plaintext, and no error from Open carries the id a stored value names.
package seal
