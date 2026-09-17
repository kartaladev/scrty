package password

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// The Argon2id defaults. Memory is in KiB, so 65536 is 64 MiB.
const (
	defaultArgon2idMemory     uint32 = 64 * 1024
	defaultArgon2idIterations uint32 = 1
	defaultArgon2idThreads    uint8  = 4
	defaultArgon2idSaltLength int    = 16
	defaultArgon2idKeyLength  uint32 = 32
)

// argon2idFields is the number of '$'-separated fields in an encoded hash:
// the algorithm name, memory, iterations, threads, salt and derived key.
const argon2idFields = 6

type argon2idEncoder struct {
	memory     uint32
	iterations uint32
	threads    uint8
	saltLength int
	keyLength  uint32
	random     io.Reader
}

// Argon2idOption configures the Argon2id encoder.
type Argon2idOption func(*argon2idEncoder)

// WithArgon2idMemory sets the memory cost in KiB. Default: 65536, which is
// 64 MiB.
//
// Memory is the parameter that makes parallel cracking expensive, so it is the
// one worth raising first.
func WithArgon2idMemory(kib uint32) Argon2idOption {
	return func(e *argon2idEncoder) { e.memory = kib }
}

// WithArgon2idIterations sets the number of passes. Default: 1.
//
// Iterations buy strength when memory cannot be raised — on a host that cannot
// spare 46 MiB per concurrent verification, two iterations at 19 MiB is the
// accepted trade.
func WithArgon2idIterations(n uint32) Argon2idOption {
	return func(e *argon2idEncoder) { e.iterations = n }
}

// WithArgon2idThreads sets the parallelism. Default: 4.
func WithArgon2idThreads(n uint8) Argon2idOption {
	return func(e *argon2idEncoder) { e.threads = n }
}

// WithArgon2idSaltLength sets the salt length in bytes. Default: 16.
func WithArgon2idSaltLength(n int) Argon2idOption {
	return func(e *argon2idEncoder) { e.saltLength = n }
}

// WithArgon2idKeyLength sets the derived key length in bytes. Default: 32.
func WithArgon2idKeyLength(n uint32) Argon2idOption {
	return func(e *argon2idEncoder) { e.keyLength = n }
}

// WithArgon2idRandom sets the source every salt is read from.
// Default: crypto/rand.Reader.
//
// Replace it to read salts from a hardware module or a seeded source under test.
// A source that cannot deliver is reported by [Encoder.Encode] rather than
// worked around, so this option cannot weaken the guarantee that every stored
// hash carries an unpredictable salt.
func WithArgon2idRandom(r io.Reader) Argon2idOption {
	return func(e *argon2idEncoder) { e.random = r }
}

// The ceilings on what a STORED RECORD may demand. They are not configuration:
// the parameters in a record are data this package did not write, and Match runs
// on the login path, so the work one record can ask for has to be bounded.
//
// The fields are 32 bits wide, so without a ceiling a single row can demand
// 4 TiB of memory — a fatal, unrecoverable allocation failure rather than a
// panic a server can recover — or roughly 190 days of derivation per attempt.
// Both are reachable by anyone who can influence a stored hash: a migration, an
// import, a sync job.
//
// These are the stated line on flexibility rather than an option, because a
// bound the caller can raise is not a bound. They sit far above any plausible
// deployment: OWASP suggests 64 MiB at 1 to 3 iterations, and these allow 1 GiB
// at 16. A record beyond them reports no match, exactly as a malformed one does.
const (
	maxRecordMemory     uint64 = 1024 * 1024 // 1 GiB, expressed in KiB
	maxRecordIterations uint64 = 16
)

// The OWASP floors for Argon2id. Memory and iterations trade against each other,
// so neither has a single minimum.
const (
	floorMemoryAtOneIteration   uint32 = 46 * 1024 // 46 MiB, when iterations is 1
	floorMemoryAtTwoIterations  uint32 = 19 * 1024 // 19 MiB, when iterations is 2 or more
	floorArgon2idThreads        uint8  = 1
	floorArgon2idSaltLength     int    = 16
	floorArgon2idKeyLength      uint32 = 32
	iterationsForTheLowerMemory uint32 = 2
)

// validate refuses a configuration below the floor.
//
// The memory message names iterations too: the two trade against each other, so
// an operator told only that memory is too low might raise the wrong dial.
func (e *argon2idEncoder) validate() error {
	if isNilReader(e.random) {
		return ErrNoRandomSource
	}

	switch {
	case e.iterations >= iterationsForTheLowerMemory && e.memory >= floorMemoryAtTwoIterations:
	case e.iterations >= 1 && e.memory >= floorMemoryAtOneIteration:
	default:
		return fmt.Errorf(
			"%w: memory %d KiB at %d iterations; need at least %d KiB at 1 iteration, "+
				"or %d KiB at %d iterations or more",
			ErrWeakParameters, e.memory, e.iterations,
			floorMemoryAtOneIteration, floorMemoryAtTwoIterations, iterationsForTheLowerMemory)
	}

	if e.threads < floorArgon2idThreads {
		return fmt.Errorf("%w: threads %d; need at least %d",
			ErrWeakParameters, e.threads, floorArgon2idThreads)
	}

	if e.saltLength < floorArgon2idSaltLength {
		return fmt.Errorf("%w: salt length %d bytes; need at least %d",
			ErrWeakParameters, e.saltLength, floorArgon2idSaltLength)
	}

	if e.keyLength < floorArgon2idKeyLength {
		return fmt.Errorf("%w: derived key length %d bytes; need at least %d",
			ErrWeakParameters, e.keyLength, floorArgon2idKeyLength)
	}

	return nil
}

// NewArgon2idEncoder returns scrty's default password encoder: Argon2id with
// 64 MiB of memory, 1 iteration, 4 threads, a 16-byte salt and a 32-byte derived
// key.
//
// Sizing: each concurrent verification allocates the configured memory, 64 MiB by
// default, for the duration of the call — verification costs as much as encoding.
// Ten logins at once therefore want 640 MiB. What bounds the total is the rate
// limit on login attempts, not this encoder.
func NewArgon2idEncoder(opts ...Argon2idOption) (Encoder, error) {
	e := &argon2idEncoder{
		memory:     defaultArgon2idMemory,
		iterations: defaultArgon2idIterations,
		threads:    defaultArgon2idThreads,
		saltLength: defaultArgon2idSaltLength,
		keyLength:  defaultArgon2idKeyLength,
		random:     rand.Reader,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}

	if err := e.validate(); err != nil {
		// Returned as an untyped nil, not as e: handing back the typed pointer
		// would give the caller a non-nil Encoder wrapping a rejected encoder.
		return nil, err
	}

	return e, nil
}

// Encode hashes input with a fresh salt, returning the algorithm, parameters,
// salt and derived key as one record.
//
// A salt that cannot be read is returned as an error and never silently replaced
// with a zero or reused value: every stored hash depends on that salt being
// unpredictable.
func (e *argon2idEncoder) Encode(input string) ([]byte, error) {
	salt := make([]byte, e.saltLength)
	if _, err := io.ReadFull(e.random, salt); err != nil {
		return nil, fmt.Errorf("password: read salt: %w", err)
	}

	key := argon2.IDKey([]byte(input), salt, e.iterations, e.memory, e.threads, e.keyLength)

	return fmt.Appendf(nil, "argon2id$%d$%d$%d$%s$%s",
		e.memory, e.iterations, e.threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Match reports whether input produces encoded.
//
// The parameters and salt come from encoded, not from this encoder, and the key
// is derived at the stored key's own length. The comparison is constant-time: a
// byte-by-byte one returns sooner the earlier it finds a difference, which leaks
// how much of a guess was right.
func (e *argon2idEncoder) Match(input string, encoded []byte) bool {
	memory, iterations, threads, salt, want, ok := parseArgon2id(encoded)
	if !ok {
		return false
	}

	// The derived key is as long as the stored one, so a hash written with a
	// different key length still verifies. The bound makes the narrowing provably
	// safe rather than merely unreachable: len is an int, and nothing here has
	// established that it fits in the uint32 the derivation takes.
	keyLength := len(want)
	if uint64(keyLength) > math.MaxUint32 {
		return false
	}

	got := argon2.IDKey([]byte(input), salt, iterations, memory, threads, uint32(keyLength))

	return subtle.ConstantTimeCompare(got, want) == 1
}

// parseArgon2id reads an encoded hash. It reports false for anything it does not
// recognise, including a hash belonging to another algorithm.
func parseArgon2id(encoded []byte) (
	memory, iterations uint32, threads uint8, salt, key []byte, ok bool,
) {
	parts := strings.Split(string(encoded), "$")
	if len(parts) != argon2idFields || parts[0] != "argon2id" {
		return 0, 0, 0, nil, nil, false
	}

	memory64, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || memory64 > maxRecordMemory {
		return 0, 0, 0, nil, nil, false
	}

	// Below argon2's own minimums this would panic rather than error, and above
	// the ceiling one record decides how long the login path runs.
	iterations64, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil || iterations64 < 1 || iterations64 > maxRecordIterations {
		return 0, 0, 0, nil, nil, false
	}

	threads64, err := strconv.ParseUint(parts[3], 10, 8)
	if err != nil || threads64 < 1 {
		return 0, 0, 0, nil, nil, false
	}

	salt, err = b64.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return 0, 0, 0, nil, nil, false
	}

	key, err = b64.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return 0, 0, 0, nil, nil, false
	}

	// ParseUint bounded each value to its field width above, so these conversions
	// cannot truncate.
	return uint32(memory64), uint32(iterations64), uint8(threads64), salt, key, true
}

var _ Encoder = (*argon2idEncoder)(nil)
