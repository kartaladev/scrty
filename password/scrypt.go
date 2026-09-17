package password

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// The scrypt defaults, and the floors, which are the same values: scrty ships no
// default below what it will accept.
const (
	defaultScryptN          = 32768
	defaultScryptR          = 8
	defaultScryptP          = 1
	defaultScryptSaltLength = 16
	defaultScryptKeyLength  = 32
)

// scryptFields is the number of '$'-separated fields in an encoded record: the
// algorithm name, N, r, p, salt and derived key.
const scryptFields = 6

type scryptEncoder struct {
	n          int
	r          int
	p          int
	saltLength int
	keyLength  int
	random     io.Reader
}

// ScryptOption configures the scrypt encoder.
type ScryptOption func(*scryptEncoder)

// WithScryptN sets the CPU and memory cost. Default: 32768.
//
// It must be a power of two, and it is the dial that makes cracking expensive.
func WithScryptN(n int) ScryptOption {
	return func(e *scryptEncoder) { e.n = n }
}

// WithScryptR sets the block size. Default: 8.
func WithScryptR(r int) ScryptOption {
	return func(e *scryptEncoder) { e.r = r }
}

// WithScryptP sets the parallelisation factor. Default: 1.
func WithScryptP(p int) ScryptOption {
	return func(e *scryptEncoder) { e.p = p }
}

// WithScryptSaltLength sets the salt length in bytes. Default: 16.
func WithScryptSaltLength(n int) ScryptOption {
	return func(e *scryptEncoder) { e.saltLength = n }
}

// WithScryptKeyLength sets the derived key length in bytes. Default: 32.
func WithScryptKeyLength(n int) ScryptOption {
	return func(e *scryptEncoder) { e.keyLength = n }
}

// WithScryptRandom sets the source every salt is read from.
// Default: crypto/rand.Reader.
//
// Replace it to read salts from a hardware module or a seeded source under test.
// A source that cannot deliver is reported by [Encoder.Encode] rather than
// worked around, so this option cannot weaken the guarantee that every stored
// hash carries an unpredictable salt.
func WithScryptRandom(r io.Reader) ScryptOption {
	return func(e *scryptEncoder) { e.random = r }
}

// NewScryptEncoder returns a scrypt encoder with N = 32768, r = 8, p = 1, a
// 16-byte salt and a 32-byte derived key.
//
// Prefer NewArgon2idEncoder, which is scrty's default. This exists for consumers
// with stored scrypt hashes to verify, or a policy that requires it.
func NewScryptEncoder(opts ...ScryptOption) (Encoder, error) {
	e := &scryptEncoder{
		n:          defaultScryptN,
		r:          defaultScryptR,
		p:          defaultScryptP,
		saltLength: defaultScryptSaltLength,
		keyLength:  defaultScryptKeyLength,
		random:     rand.Reader,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}

	if err := e.validate(); err != nil {
		// Untyped nil, not e: a typed pointer would hand back a non-nil Encoder
		// built from parameters that were just refused.
		return nil, err
	}

	return e, nil
}

// validate refuses a configuration below the floor, naming the parameter so the
// operator knows which dial to turn.
func (e *scryptEncoder) validate() error {
	if e.random == nil {
		return ErrNoRandomSource
	}

	if e.n < defaultScryptN {
		return fmt.Errorf("%w: N=%d; need at least %d", ErrWeakParameters, e.n, defaultScryptN)
	}

	if e.r < defaultScryptR {
		return fmt.Errorf("%w: r=%d; need at least %d", ErrWeakParameters, e.r, defaultScryptR)
	}

	if e.p < defaultScryptP {
		return fmt.Errorf("%w: p=%d; need at least %d", ErrWeakParameters, e.p, defaultScryptP)
	}

	if e.saltLength < defaultScryptSaltLength {
		return fmt.Errorf("%w: salt length %d bytes; need at least %d",
			ErrWeakParameters, e.saltLength, defaultScryptSaltLength)
	}

	if e.keyLength < defaultScryptKeyLength {
		return fmt.Errorf("%w: derived key length %d bytes; need at least %d",
			ErrWeakParameters, e.keyLength, defaultScryptKeyLength)
	}

	return nil
}

// Encode hashes input with a fresh salt, recording the parameters alongside it.
func (e *scryptEncoder) Encode(input string) ([]byte, error) {
	salt := make([]byte, e.saltLength)
	if _, err := io.ReadFull(e.random, salt); err != nil {
		return nil, fmt.Errorf("password: read salt: %w", err)
	}

	key, err := scrypt.Key([]byte(input), salt, e.n, e.r, e.p, e.keyLength)
	if err != nil {
		return nil, fmt.Errorf("password: scrypt derive: %w", err)
	}

	return fmt.Appendf(nil, "scrypt$%d$%d$%d$%s$%s",
		e.n, e.r, e.p, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Match reports whether input produces encoded.
//
// The parameters and salt come from the record, not from this encoder, so a hash
// written at a lower cost keeps verifying after the cost is raised. The
// comparison is constant-time.
func (e *scryptEncoder) Match(input string, encoded []byte) bool {
	n, r, p, salt, want, ok := parseScrypt(encoded)
	if !ok {
		return false
	}

	got, err := scrypt.Key([]byte(input), salt, n, r, p, len(want))
	if err != nil {
		// Parameters the record claims but scrypt rejects: no match, not an error.
		return false
	}

	return subtle.ConstantTimeCompare(got, want) == 1
}

// parseScrypt reads an encoded record, reporting false for anything it does not
// recognise — including a record belonging to another algorithm.
func parseScrypt(encoded []byte) (n, r, p int, salt, key []byte, ok bool) {
	parts := strings.Split(string(encoded), "$")
	if len(parts) != scryptFields || parts[0] != "scrypt" {
		return 0, 0, 0, nil, nil, false
	}

	var err error

	if n, err = strconv.Atoi(parts[1]); err != nil {
		return 0, 0, 0, nil, nil, false
	}

	if r, err = strconv.Atoi(parts[2]); err != nil {
		return 0, 0, 0, nil, nil, false
	}

	if p, err = strconv.Atoi(parts[3]); err != nil {
		return 0, 0, 0, nil, nil, false
	}

	if salt, err = b64.DecodeString(parts[4]); err != nil || len(salt) == 0 {
		return 0, 0, 0, nil, nil, false
	}

	if key, err = b64.DecodeString(parts[5]); err != nil || len(key) == 0 {
		return 0, 0, 0, nil, nil, false
	}

	return n, r, p, salt, key, true
}

var _ Encoder = (*scryptEncoder)(nil)
