package password

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// defaultBcryptCost is both the default and the floor: 10 is the OWASP minimum,
// and scrty does not ship a default that sits below what it will accept.
const defaultBcryptCost = 10

// bcryptMaxInput is the longest input bcrypt hashes. The algorithm ignores
// everything past it, and golang.org/x/crypto/bcrypt applies no length check of
// its own, so this encoder enforces one.
const bcryptMaxInput = 72

// maxRecordCost is the highest cost a stored bcrypt record may demand, and the
// highest the encoder accepts, so it never writes a hash it would refuse to
// verify. The cost is read from the record, which is data this package did not
// write, and Match runs on the login path: bcrypt's own maximum of 31 is a
// process-wide stall per attempt. It is a stated limit with no override.
//
// 16 is far above every published recommendation (OWASP's floor is 10), and the
// default stays at the floor.
const maxRecordCost = 16

// ErrPasswordContainsNUL is returned by the bcrypt encoder's Encode for a
// password containing a NUL byte. Match reports no match for one.
//
// bcrypt appends a NUL to the key and its key schedule cycles the key, so
// "hunter2" and "hunter2\x00hunter2" expand to the same schedule: one
// credential under two spellings. Refusing every NUL, rather than only the
// 72-byte shape, closes the whole family.
var ErrPasswordContainsNUL = errors.New("password: password contains a NUL byte")

type bcryptEncoder struct {
	cost int
}

// BcryptOption configures the bcrypt encoder.
type BcryptOption func(*bcryptEncoder)

// WithBcryptCost sets the cost. Default: 10, which is also the floor; the
// ceiling is 16, a limit with no override (a stored record is held to it too).
//
// Each step doubles the work, so raising it is the only dial bcrypt offers.
func WithBcryptCost(cost int) BcryptOption {
	return func(e *bcryptEncoder) { e.cost = cost }
}

// NewBcryptEncoder returns a bcrypt encoder with a default cost of 10.
//
// Prefer NewArgon2idEncoder, which is scrty's default: bcrypt is memory-cheap by
// comparison, so it resists parallel cracking less well. This exists for
// consumers with stored bcrypt hashes to verify, or a policy that requires it.
func NewBcryptEncoder(opts ...BcryptOption) (Encoder, error) {
	e := &bcryptEncoder{cost: defaultBcryptCost}

	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}

	if e.cost < defaultBcryptCost {
		// Returned as an untyped nil: handing back the typed pointer would give
		// the caller a non-nil Encoder built from parameters just refused.
		return nil, fmt.Errorf("%w: cost %d; need at least %d",
			ErrWeakParameters, e.cost, defaultBcryptCost)
	}

	// Above the record ceiling the cost is not strong but unusable: Match would
	// refuse every hash this encoder wrote.
	if e.cost > maxRecordCost {
		return nil, fmt.Errorf("%w: cost %d; at most %d",
			ErrInvalidParameters, e.cost, maxRecordCost)
	}

	return e, nil
}

// Encode hashes input at the configured cost.
//
// bcrypt generates and embeds its own salt, so unlike the Argon2id and scrypt
// encoders there is no salt to read here and no read to fail.
//
// A password longer than 72 bytes is refused with [ErrPasswordTooLong], and one
// containing a NUL byte with [ErrPasswordContainsNUL].
func (e *bcryptEncoder) Encode(input string) ([]byte, error) {
	if len(input) > bcryptMaxInput {
		return nil, fmt.Errorf("%w: %d bytes; bcrypt hashes at most %d",
			ErrPasswordTooLong, len(input), bcryptMaxInput)
	}

	if strings.IndexByte(input, 0) >= 0 {
		return nil, ErrPasswordContainsNUL
	}

	encoded, err := bcrypt.GenerateFromPassword([]byte(input), e.cost)
	if err != nil {
		return nil, fmt.Errorf("password: bcrypt encode: %w", err)
	}

	return encoded, nil
}

// Match reports whether input produces encoded.
//
// bcrypt reads the cost and salt from the record itself, so a hash written at an
// older cost keeps verifying. A record belonging to another algorithm fails to
// parse and reports no match rather than an error.
//
// A record whose cost is above the ceiling reports no match without running
// bcrypt, so a stored hash cannot choose how long a login takes. An input
// containing a NUL byte reports no match too, as Encode refuses to write one.
//
// An input longer than the limit reports no match without consulting bcrypt at
// all. This check is the load-bearing half of the pair: bcrypt compares only the
// first 72 bytes, so without it any longer string sharing a stored password's
// first 72 bytes verifies as that password. Refusing the input in Encode is not
// enough, because a hash written before that check existed — or by another tool
// — is still on the other side of this comparison.
func (e *bcryptEncoder) Match(input string, encoded []byte) bool {
	if len(input) > bcryptMaxInput || strings.IndexByte(input, 0) >= 0 {
		return false
	}

	// Not a derivation: Cost only parses the record's prefix. A malformed record
	// is no match here as it would be inside CompareHashAndPassword.
	if cost, err := bcrypt.Cost(encoded); err != nil || cost > maxRecordCost {
		return false
	}

	return bcrypt.CompareHashAndPassword(encoded, []byte(input)) == nil
}

var _ Encoder = (*bcryptEncoder)(nil)

// Recognizes reports whether encoded is a bcrypt record whose cost Match would
// run: one bcrypt can parse, with a salt in bcrypt's alphabet, at a cost no higher than the ceiling. It derives
// nothing.
//
// It speaks only of the record. Match also refuses, unread, an input over 72
// bytes or containing a NUL byte; that depends on the password the caller
// presented, not on the stored hash, and is bcrypt's stated length exception.
func (e *bcryptEncoder) Recognizes(encoded []byte) bool {
	cost, err := bcrypt.Cost(encoded)
	if err != nil || cost > maxRecordCost {
		return false
	}

	// bcrypt refuses a salt outside its base64 alphabet before it derives
	// anything, so such a record is no more usable than a malformed one.
	if len(encoded) < bcryptSaltEnd {
		return false
	}

	for _, c := range encoded[bcryptSaltStart:bcryptSaltEnd] {
		if !bcryptAlphabet(c) {
			return false
		}
	}

	return true
}

// The 22 salt characters of a bcrypt record follow its "$2a$NN$" prefix.
const (
	bcryptSaltStart = 7
	bcryptSaltEnd   = bcryptSaltStart + 22
)

// bcryptAlphabet reports whether c is in bcrypt's base64 alphabet, which is
// "./" followed by the letters and digits, not the standard one.
func bcryptAlphabet(c byte) bool {
	return c == '.' || c == '/' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

var _ Recognizer = (*bcryptEncoder)(nil)
