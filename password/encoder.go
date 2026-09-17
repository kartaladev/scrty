// Package password hashes passwords and checks them against a stored hash.
//
// Argon2id is the default algorithm. Every parameter is replaceable, and the
// encoded form carries the parameters it was produced with, so a hash written
// years ago still verifies after the defaults have moved on.
//
// Matching performs the full key derivation the stored hash specifies whether or
// not the password matches, and whatever the password's length. That is what
// lets a caller equalise the cost of a login for an unknown user: encode a decoy
// hash once at construction and match the presented password against it whenever
// the user lookup misses, and the two paths take the same time. Without it, a
// fast rejection tells an attacker the username does not exist.
//
// Passwords are hashed exactly as given — no trimming, case folding or Unicode
// normalization — because any of those would silently let a different string
// through.
package password

import (
	"encoding/base64"
	"errors"
)

// ErrWeakParameters is returned by an encoder's constructor when a parameter is
// below the floor for its algorithm. The message names the parameter.
//
// The floors are the OWASP password-storage minimums. They are checked at
// construction rather than at first use, so a deployment configured too low
// fails while someone is watching, instead of quietly storing weak hashes.
var ErrWeakParameters = errors.New("password: parameters below the supported floor")

// ErrPasswordTooLong is returned when a password exceeds what its algorithm can
// hash. Only bcrypt has such a limit: 72 bytes.
//
// It is an error rather than a silent truncation because truncating is a
// authentication bypass in disguise — two passwords sharing a 72-byte prefix
// would become the same credential.
var ErrPasswordTooLong = errors.New("password: password exceeds the algorithm's maximum length")

// Encoder hashes passwords and checks them against a stored hash.
type Encoder interface {
	// Encode hashes input with a freshly read random salt.
	Encode(input string) ([]byte, error)

	// Match reports whether input produces encoded.
	//
	// It derives the key with the parameters recorded in encoded rather than the
	// encoder's current ones, so raising a cost does not invalidate stored
	// hashes. A malformed hash, or one belonging to another algorithm, reports no
	// match rather than an error: a caller checking a password has nothing useful
	// to do with the difference, and treating it as an error invites a branch
	// that accidentally admits the user.
	Match(input string, encoded []byte) bool
}

// b64 encodes the salt and derived key. Unpadded, so the encoded form has no '='
// to confuse the '$' field split.
var b64 = base64.RawStdEncoding
