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
// The length half of that holds for the Argon2id and scrypt encoders. bcrypt is
// the stated exception: it refuses an input over 72 bytes before deriving
// anything, because the alternative is matching by truncation, so above that
// length it returns in nanoseconds. What this reveals is the length of the
// password the caller just supplied, which the caller already knows, so the
// exception costs nothing an attacker can use — but the equal-cost claim is
// Argon2id's and scrypt's, not bcrypt's. See [ErrPasswordTooLong].
//
// Passwords are hashed exactly as given — no trimming, case folding or Unicode
// normalization — because any of those would silently let a different string
// through. "café" written as one code point and as "e" plus a combining accent
// are two different passwords, as are "hunter2" and " hunter2".
//
// Every encoder's parameters have a floor, taken from the OWASP password-storage
// minimums; see [ErrWeakParameters]. The floors are the only limit on how a
// consumer configures an encoder — anything at or above them is accepted,
// including parameters far stronger than the defaults.
//
// Memory is the parameter worth planning for, because verification costs as much
// of it as encoding does and concurrent logins multiply it; see
// [NewArgon2idEncoder] for the sizing.
package password

import (
	"encoding/base64"
	"errors"
	"io"
	"reflect"
)

// ErrWeakParameters is returned by an encoder's constructor when a parameter is
// below the floor for its algorithm. The message names the parameter.
//
// The floors are the OWASP password-storage minimums. They are checked at
// construction rather than at first use, so a deployment configured too low
// fails while someone is watching, instead of quietly storing weak hashes.
var ErrWeakParameters = errors.New("password: parameters below the supported floor")

// ErrInvalidParameters is returned by an encoder's constructor when a parameter
// is not weak but meaningless — a value the algorithm itself will refuse.
//
// It is distinct from ErrWeakParameters because the operator's response differs:
// a weak parameter is a policy decision to raise, while an invalid one is a
// wiring mistake to correct. Both are refused at construction rather than at the
// first Encode, which for a password encoder is the first registration or
// password change — late enough that a deployment can look healthy until someone
// signs up.
var ErrInvalidParameters = errors.New("password: parameters the algorithm will refuse")

// ErrNoRandomSource is returned by an encoder's constructor when the salt source
// it was given is nil.
//
// That is meaningless configuration rather than a weak parameter — a nil source
// produces no salt at all — so it is refused at construction. Left to be
// discovered later, it would panic inside the first Encode, which is to say at
// the first login after deployment.
var ErrNoRandomSource = errors.New("password: salt source is nil")

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

// isNilReader reports whether r is nil, or a non-nil interface holding a nil
// pointer, map, slice, channel or function.
//
// == nil alone is not enough: the shape a wiring mistake actually produces is a
// typed nil — `var r *bytes.Reader; WithArgon2idRandom(r)`, or a helper that
// returns a typed nil on error — and such an interface is not equal to nil. It
// passes construction and then panics inside the first Encode, which is the
// failure ErrNoRandomSource exists to prevent.
func isNilReader(r io.Reader) bool {
	if r == nil {
		return true
	}

	rv := reflect.ValueOf(r)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.Interface:
		return rv.IsNil()
	default:
		return false
	}
}

// b64 encodes the salt and derived key. Unpadded, so the encoded form has no '='
// to confuse the '$' field split.
var b64 = base64.RawStdEncoding
