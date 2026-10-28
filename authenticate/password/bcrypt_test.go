package password_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/kartaladev/scrty/authenticate/password"
)

// bcryptMaxInput is the longest input bcrypt hashes. Anything beyond this is
// ignored by the algorithm itself.
const bcryptMaxInput = 72

func TestBcryptMatch(t *testing.T) {
	t.Parallel()

	atLimit := strings.Repeat("a", bcryptMaxInput)
	overLimit := atLimit + "b" // 73 bytes, identical for the first 72

	// Well formed in shape, with a cost the record claims: bcrypt reads the cost
	// from the record and runs it before it compares anything.
	const body = "abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890"

	// excessiveCost refuses a stored record whose cost is above the ceiling.
	excessiveCost := func(cost int) func(t *testing.T, enc password.Encoder) {
		return func(t *testing.T, enc password.Encoder) {
			record := fmt.Appendf(nil, "$2a$%02d$%s", cost, body[:53])
			require.Len(t, record, 60)

			start := time.Now()
			matched := enc.Match("hunter2", record)
			elapsed := time.Since(start)

			assert.False(t, matched)
			assert.Less(t, elapsed, fastMatch, "the record's cost must be refused without running bcrypt")
		}
	}

	type testCase struct {
		name   string
		assert func(t *testing.T, enc password.Encoder)
	}

	cases := []testCase{
		// The truncation cases cover departure D5.
		//
		// bcrypt hashes only the first 72 bytes of its input and applies no length check
		// of its own: golang.org/x/crypto/bcrypt.CompareHashAndPassword will happily
		// report a match for a longer password whose first 72 bytes are right. That is
		// an authentication bypass — a user whose password is 72 bytes can be signed in
		// with any longer string that starts the same way — so this encoder refuses such
		// inputs instead of passing them through.
		{
			name: "a password at the limit encodes and matches",
			assert: func(t *testing.T, enc password.Encoder) {
				encoded, err := enc.Encode(atLimit)
				require.NoError(t, err, "72 bytes is within what bcrypt hashes")
				assert.True(t, enc.Match(atLimit, encoded))
			},
		},
		{
			name: "a password over the limit is refused rather than truncated",
			assert: func(t *testing.T, enc password.Encoder) {
				encoded, err := enc.Encode(overLimit)

				require.ErrorIs(t, err, password.ErrTooLong,
					"storing a truncated hash would silently make this password equal to its "+
						"own first 72 bytes")
				assert.Nil(t, encoded, "no hash may be returned alongside the refusal")
			},
		},
		{
			name: "a longer password sharing the stored password's first 72 bytes does not match",
			assert: func(t *testing.T, enc password.Encoder) {
				encoded, err := enc.Encode(atLimit)
				require.NoError(t, err)

				assert.False(t, enc.Match(overLimit, encoded),
					"bcrypt compares only the first 72 bytes, so without a length check this "+
						"signs in as the 72-byte user with a password they never chose")
			},
		},
		{
			name: "a NUL-joined repetition does not match the password it repeats",
			assert: func(t *testing.T, enc password.Encoder) {
				stored, err := enc.Encode("hunter2")
				require.NoError(t, err)

				assert.False(t, enc.Match("hunter2\x00hunter2", stored),
					"bcrypt's key schedule repeats the key, so this is the same credential")
			},
		},
		{
			name: "a password with a NUL at either end does not match",
			assert: func(t *testing.T, enc password.Encoder) {
				stored, err := enc.Encode("hunter2")
				require.NoError(t, err)

				assert.False(t, enc.Match("hunter2\x00", stored))
				assert.False(t, enc.Match("\x00hunter2", stored))
			},
		},
		{
			name: "Encode refuses a NUL with an identifiable error",
			assert: func(t *testing.T, enc password.Encoder) {
				encoded, err := enc.Encode("hunter2\x00hunter2")

				require.ErrorIs(t, err, password.ErrContainsNUL)
				assert.Nil(t, encoded)
			},
		},
		{
			name: "a password without a NUL still matches",
			assert: func(t *testing.T, enc password.Encoder) {
				stored, err := enc.Encode("hunter2")
				require.NoError(t, err)

				assert.True(t, enc.Match("hunter2", stored))
			},
		},
		{
			// x/crypto/bcrypt appends a NUL to the key, and blowfish consumes exactly 72
			// key bytes. A 71-byte password and the 72-byte password formed by appending a
			// NUL therefore expand to the identical key schedule. Both are within the
			// 72-byte limit, so the encoder's length check never sees them.
			name: "treats a nul suffix as a different password",
			assert: func(t *testing.T, enc password.Encoder) {
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
			},
		},
		{name: "one above the ceiling", assert: excessiveCost(17)},
		{name: "cost 20", assert: excessiveCost(20)},
		{name: "bcrypt's own maximum", assert: excessiveCost(31)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := password.NewBcryptEncoder()
			require.NoError(t, err)

			tc.assert(t, enc)
		})
	}
}

func TestBcryptCost(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []password.BcryptOption
		assert func(t *testing.T, enc password.Encoder, err error)
	}

	// storedCost reads the cost back out of the hash rather than trusting the
	// encoder's configuration: the cost is what a future verification will use,
	// so it is the stored value that matters.
	storedCost := func(t *testing.T, encoded []byte) int {
		t.Helper()

		cost, err := bcrypt.Cost(encoded)
		require.NoError(t, err, "the encoder must produce a hash bcrypt itself can read")

		return cost
	}

	cases := []testCase{
		{
			name: "the default cost is 10",
			assert: func(t *testing.T, enc password.Encoder, err error) {
				require.NoError(t, err)
				require.NotNil(t, enc)

				encoded, encErr := enc.Encode("hunter2")
				require.NoError(t, encErr)

				assert.Equal(t, 10, storedCost(t, encoded))
				assert.True(t, enc.Match("hunter2", encoded))
			},
		},
		{
			name: "a consumer can raise the cost, and it reaches the stored hash",
			opts: []password.BcryptOption{password.WithBcryptCost(12)},
			assert: func(t *testing.T, enc password.Encoder, err error) {
				require.NoError(t, err)
				require.NotNil(t, enc)

				encoded, encErr := enc.Encode("hunter2")
				require.NoError(t, encErr)

				assert.Equal(t, 12, storedCost(t, encoded),
					"a raised cost that never reaches the hash protects nobody")
				assert.True(t, enc.Match("hunter2", encoded))
			},
		},
		{
			name: "a cost below the floor is refused at construction",
			opts: []password.BcryptOption{password.WithBcryptCost(8)},
			assert: func(t *testing.T, enc password.Encoder, err error) {
				require.ErrorIs(t, err, password.ErrWeakParameters)
				assert.Contains(t, err.Error(), "cost",
					"the operator has to be told which dial is too low")
				assert.Nil(t, enc, "a refused configuration must not yield a usable encoder")
			},
		},
		{
			name: "a wrong password does not match",
			assert: func(t *testing.T, enc password.Encoder, err error) {
				require.NoError(t, err)

				encoded, encErr := enc.Encode("hunter2")
				require.NoError(t, encErr)

				assert.False(t, enc.Match("hunter3", encoded))
			},
		},
		{
			name: "a hash from another algorithm does not match",
			assert: func(t *testing.T, enc password.Encoder, err error) {
				require.NoError(t, err)

				argon, argonErr := password.NewArgon2idEncoder()
				require.NoError(t, argonErr)

				foreign, encErr := argon.Encode("hunter2")
				require.NoError(t, encErr)

				assert.False(t, enc.Match("hunter2", foreign),
					"bcrypt must refuse an Argon2id record rather than interpreting it")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := password.NewBcryptEncoder(tc.opts...)
			tc.assert(t, enc, err)
		})
	}
}
