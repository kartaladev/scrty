package seal

import "errors"

var (
	// ErrInvalidConfiguration reports a keyring or cipher that was wired
	// wrongly: no active key or more than one, a key that is not 32 bytes, an
	// empty, malformed or duplicated key id, two ids naming the same key
	// bytes, or a nil option or keyring. Its text never contains key bytes.
	ErrInvalidConfiguration = errors.New("seal: invalid configuration")

	// ErrDecryptionFailed reports a value that would not open. It is opaque on
	// purpose: a wrong key, wrong additional data, an altered byte, a
	// truncated value and a value that was never sealed all look the same, so
	// the error tells an attacker probing stored values nothing about which
	// guess was closer.
	ErrDecryptionFailed = errors.New("seal: decryption failed")

	// ErrUnknownKeyID reports a value that names a key id the keyring does
	// not hold. It is distinct from ErrDecryptionFailed, and never matches
	// it, because it usually points at an operator who removed a key that
	// stored values still need.
	//
	// It is not proof that a key was removed. The id is read from the stored
	// value before any tag is checked, so anyone with write access to the
	// column can produce this error, with an id of their choosing, by
	// rewriting the value's header. The id is limited to
	// [A-Za-z0-9._-]{1,64} and never appears in the error's text; treat the id
	// Open returns alongside this error as a claim made by the stored value.
	ErrUnknownKeyID = errors.New("seal: unknown key id")
)
