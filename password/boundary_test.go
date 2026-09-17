package password_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/crypto/argon2"

	"github.com/kartaladev/scrty/password"
)

// --- Finding 1: a stored record with a zero cost field panics inside Match ---
//
// parseArgon2id accepts "0" for iterations and for threads (ParseUint succeeds),
// and hands them to argon2.IDKey, which panics on either. The Encoder contract
// says a malformed record "reports no match rather than an error".
func TestArgon2idMatchReportsNoMatchForAZeroCostRecord(t *testing.T) {
	t.Parallel()

	enc, err := password.NewArgon2idEncoder()
	require.NoError(t, err)

	// A real record, so only the one field under test is unusual.
	real1, err := enc.Encode("hunter2")
	require.NoError(t, err)

	parts := strings.Split(string(real1), "$")
	require.Len(t, parts, 6)

	type testCase struct {
		name   string
		record string
	}

	cases := []testCase{
		{
			name:   "zero iterations",
			record: strings.Join([]string{parts[0], parts[1], "0", parts[3], parts[4], parts[5]}, "$"),
		},
		{
			name:   "zero threads",
			record: strings.Join([]string{parts[0], parts[1], parts[2], "0", parts[4], parts[5]}, "$"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.False(t, enc.Match("hunter2", []byte(tc.record)),
				"a record the parser accepted but the derivation cannot honour must "+
					"report no match, not take the process down")
		})
	}
}

// --- Finding 2: ErrNoRandomSource is bypassed by a typed nil ---
//
// validate checks `e.random == nil`, which is false for an interface holding a
// nil *bytes.Reader. Construction succeeds and the first Encode panics, which is
// exactly what ErrNoRandomSource's godoc promises cannot happen.
func TestConstructionRefusesATypedNilRandomSource(t *testing.T) {
	t.Parallel()

	var typedNil *bytes.Reader // nil pointer in a non-nil io.Reader

	type testCase struct {
		name string
		new  func(io.Reader) (password.Encoder, error)
	}

	cases := []testCase{
		{name: "argon2id", new: func(r io.Reader) (password.Encoder, error) {
			return password.NewArgon2idEncoder(password.WithArgon2idRandom(r))
		}},
		{name: "scrypt", new: func(r io.Reader) (password.Encoder, error) {
			return password.NewScryptEncoder(password.WithScryptRandom(r))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := tc.new(typedNil)
			require.ErrorIs(t, err, password.ErrNoRandomSource,
				"a salt source that cannot deliver is meaningless configuration and is "+
					"refused at construction, whether the nil is typed or not")
			assert.Nil(t, enc)
		})
	}
}

// --- Finding 3: bcrypt's 71/72 NUL boundary collision ---
//
// x/crypto/bcrypt appends a NUL to the key, and blowfish consumes exactly 72
// key bytes. A 71-byte password and the 72-byte password formed by appending a
// NUL therefore expand to the identical key schedule. Both are within the
// 72-byte limit, so the encoder's length check never sees them.
func TestBcryptTreatsANulSuffixAsADifferentPassword(t *testing.T) {
	t.Parallel()

	enc, err := password.NewBcryptEncoder()
	require.NoError(t, err)

	const shorter = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 71 bytes
	longer := shorter + "\x00"                                                                // 72 bytes

	require.Len(t, shorter, 71)
	require.Len(t, longer, 72)

	storedShorter, err := enc.Encode(shorter)
	require.NoError(t, err)

	storedLonger, longerErr := enc.Encode(longer)
	if longerErr == nil {
		assert.False(t, enc.Match(shorter, storedLonger),
			"and not in the other direction either: these are two distinct passwords")
	}

	assert.False(t, enc.Match(longer, storedShorter),
		"a user who enrolled 71 bytes must not be signed in by a 72-byte string "+
			"that merely appends a NUL")
}

// --- Finding 4: the record dictates unbounded work in Match ---
//
// parseArgon2id bounds memory and iterations only by their field widths, so one
// record can make every verification against it cost arbitrarily more than the
// encoder that is configured to run it. Measured here with a modest multiplier;
// the field admits 4294967295.
func TestArgon2idMatchDoesNotLetTheRecordDictateUnboundedWork(t *testing.T) {
	t.Parallel()

	enc, err := password.NewArgon2idEncoder(
		password.WithArgon2idMemory(mib19),
		password.WithArgon2idIterations(2),
	)
	require.NoError(t, err)

	honest, err := enc.Encode("hunter2")
	require.NoError(t, err)

	parts := strings.Split(string(honest), "$")
	require.Len(t, parts, 6)

	// Same record, one field rewritten: 4096 iterations instead of 2.
	hostile := strings.Join([]string{parts[0], parts[1], "4096", parts[3], parts[4], parts[5]}, "$")

	baseline := timeMatch(t, enc, honest)
	inflated := timeMatch(t, enc, []byte(hostile))

	t.Logf("baseline %v, record-dictated %v, ratio %.0fx", baseline, inflated, float64(inflated)/float64(baseline))

	assert.Less(t, float64(inflated)/float64(baseline), 10.0,
		"a single record must not be able to multiply the cost of verifying against "+
			"it without limit: this is the login path")
}

func timeMatch(t *testing.T, enc password.Encoder, record []byte) time.Duration {
	t.Helper()

	start := time.Now()
	_ = enc.Match("wrong-password", record)

	return time.Since(start)
}

// --- Finding 5: above-floor but meaningless parameters are accepted ---
//
// The constructors check only the floor, so a configuration the algorithm itself
// rejects is accepted at construction and fails at the first login instead.
func TestConstructionRefusesParametersTheAlgorithmWillReject(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		new  func() (password.Encoder, error)
	}

	cases := []testCase{
		{
			name: "scrypt N above the floor but not a power of two",
			new: func() (password.Encoder, error) {
				return password.NewScryptEncoder(password.WithScryptN(40000))
			},
		},
		{
			name: "bcrypt cost above what bcrypt accepts",
			new: func() (password.Encoder, error) {
				return password.NewBcryptEncoder(password.WithBcryptCost(32))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := tc.new()
			if err != nil {
				return // refused at construction, which is the rule
			}

			_, encErr := enc.Encode("hunter2")
			require.NoError(t, encErr,
				"a configuration the constructor accepted must not fail at the first "+
					"login: a wiring mistake is a construction error")
		})
	}
}

// --- The parser's salt and key guards ---
//
// Both are reachable only through a record this package did not write, and both
// were previously uncovered: three separate mutations of them compiled and left
// the whole suite green. A row that merely feeds in a broken record cannot pin
// them, because a broken record yields a non-matching key whether the guard runs
// or not. So each row below is built so that IGNORING the guard would produce a
// match, or a panic, rather than the same false.

func TestArgon2idRejectsARecordWithNoSalt(t *testing.T) {
	t.Parallel()

	enc, err := password.NewArgon2idEncoder(
		password.WithArgon2idMemory(mib19),
		password.WithArgon2idIterations(2),
	)
	require.NoError(t, err)

	// The key this record carries is genuinely derived with an empty salt, so a
	// parser that accepted the empty salt field would derive the same bytes and
	// report a match. That is what makes this row fail when the guard is removed,
	// rather than failing for some incidental reason.
	key := argon2.IDKey([]byte("hunter2"), nil, 2, mib19, 4, 32)
	record := fmt.Appendf(nil, "argon2id$%d$%d$%d$$%s",
		mib19, 2, 4, base64.RawStdEncoding.EncodeToString(key))

	assert.False(t, enc.Match("hunter2", record),
		"a salt is what stops two users who chose the same password sharing a "+
			"hash, so a record that carries none is not a record this encoder "+
			"produced and must never verify")
}

func TestArgon2idRejectsARecordWithNoDerivedKey(t *testing.T) {
	t.Parallel()

	enc, err := password.NewArgon2idEncoder(
		password.WithArgon2idMemory(mib19),
		password.WithArgon2idIterations(2),
	)
	require.NoError(t, err)

	honest, err := enc.Encode("hunter2")
	require.NoError(t, err)

	parts := strings.Split(string(honest), "$")
	require.Len(t, parts, 6)

	type testCase struct {
		name string
		key  string
	}

	// Both shapes leave the parser with nothing to compare against. Without the
	// guard the derivation is asked for a zero-length key, which panics inside
	// argon2 rather than returning anything, so asserting a plain false here is
	// enough to make the guard load-bearing.
	cases := []testCase{
		{name: "the derived key field is empty", key: ""},
		{name: "the derived key field is not base64", key: "!!!"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			record := strings.Join(
				[]string{parts[0], parts[1], parts[2], parts[3], parts[4], tc.key}, "$")

			assert.NotPanics(t, func() {
				assert.False(t, enc.Match("hunter2", []byte(record)),
					"a record with no derived key reports no match, and reports it "+
						"rather than crashing the process that asked")
			})
		})
	}
}
