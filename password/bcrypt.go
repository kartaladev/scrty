package password

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// defaultBcryptCost is both the default and the floor: 10 is the OWASP minimum,
// and scrty does not ship a default that sits below what it will accept.
const defaultBcryptCost = 10

// bcryptMaxInput is the longest input bcrypt hashes. The algorithm ignores
// everything past it, and golang.org/x/crypto/bcrypt applies no length check of
// its own, so this encoder enforces one.
const bcryptMaxInput = 72

type bcryptEncoder struct {
	cost int
}

// BcryptOption configures the bcrypt encoder.
type BcryptOption func(*bcryptEncoder)

// WithBcryptCost sets the cost. Default: 10, which is also the floor.
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

	return e, nil
}

// Encode hashes input at the configured cost.
//
// bcrypt generates and embeds its own salt, so unlike the Argon2id and scrypt
// encoders there is no salt to read here and no read to fail.
func (e *bcryptEncoder) Encode(input string) ([]byte, error) {
	if len(input) > bcryptMaxInput {
		return nil, fmt.Errorf("%w: %d bytes; bcrypt hashes at most %d",
			ErrPasswordTooLong, len(input), bcryptMaxInput)
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
// An input longer than the limit reports no match without consulting bcrypt at
// all. This check is the load-bearing half of the pair: bcrypt compares only the
// first 72 bytes, so without it any longer string sharing a stored password's
// first 72 bytes verifies as that password. Refusing the input in Encode is not
// enough, because a hash written before that check existed — or by another tool
// — is still on the other side of this comparison.
func (e *bcryptEncoder) Match(input string, encoded []byte) bool {
	if len(input) > bcryptMaxInput {
		return false
	}

	return bcrypt.CompareHashAndPassword(encoded, []byte(input)) == nil
}

var _ Encoder = (*bcryptEncoder)(nil)
