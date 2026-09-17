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

	// Above bcrypt's own maximum the cost is not strong but unusable: every
	// Encode would fail, and the first one happens at a registration.
	if e.cost > bcrypt.MaxCost {
		return nil, fmt.Errorf("%w: cost %d; bcrypt accepts at most %d",
			ErrInvalidParameters, e.cost, bcrypt.MaxCost)
	}

	return e, nil
}

// Encode hashes input at the configured cost.
//
// bcrypt generates and embeds its own salt, so unlike the Argon2id and scrypt
// encoders there is no salt to read here and no read to fail.
// collidesByNulPadding reports whether input is a 72-byte value that bcrypt
// cannot tell apart from its own first 71 bytes.
//
// x/crypto appends a NUL to the key and blowfish's key schedule consumes exactly
// 72 bytes, so a 71-byte password expands from pw71+NUL, and the 72-byte
// password pw71+NUL expands from the first 72 bytes of pw71+NUL+NUL — the same
// schedule. The two are one credential, inside the range this encoder otherwise
// declares safe.
//
// Refusing this one shape rather than lowering the limit to 71 keeps the
// documented 72-byte maximum true for every password that is genuinely distinct.
func collidesByNulPadding(input string) bool {
	return len(input) == bcryptMaxInput && input[bcryptMaxInput-1] == 0
}

func (e *bcryptEncoder) Encode(input string) ([]byte, error) {
	if len(input) > bcryptMaxInput {
		return nil, fmt.Errorf("%w: %d bytes; bcrypt hashes at most %d",
			ErrPasswordTooLong, len(input), bcryptMaxInput)
	}

	if collidesByNulPadding(input) {
		return nil, fmt.Errorf(
			"%w: a %d-byte password ending in a NUL byte is indistinguishable to "+
				"bcrypt from its own first %d bytes",
			ErrPasswordTooLong, bcryptMaxInput, bcryptMaxInput-1)
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
	if len(input) > bcryptMaxInput || collidesByNulPadding(input) {
		return false
	}

	return bcrypt.CompareHashAndPassword(encoded, []byte(input)) == nil
}

var _ Encoder = (*bcryptEncoder)(nil)
