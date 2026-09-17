package password_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/kartaladev/scrty/password"
)

// bcryptMaxInput is the longest input bcrypt hashes. Anything beyond this is
// ignored by the algorithm itself.
const bcryptMaxInput = 72

// TestBcryptNeverMatchesByTruncation covers departure D5.
//
// bcrypt hashes only the first 72 bytes of its input and applies no length check
// of its own: golang.org/x/crypto/bcrypt.CompareHashAndPassword will happily
// report a match for a longer password whose first 72 bytes are right. That is
// an authentication bypass — a user whose password is 72 bytes can be signed in
// with any longer string that starts the same way — so this encoder refuses such
// inputs instead of passing them through.
func TestBcryptNeverMatchesByTruncation(t *testing.T) {
	t.Parallel()

	atLimit := strings.Repeat("a", bcryptMaxInput)
	overLimit := atLimit + "b" // 73 bytes, identical for the first 72

	type testCase struct {
		name   string
		assert func(t *testing.T, enc password.Encoder)
	}

	cases := []testCase{
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

				require.ErrorIs(t, err, password.ErrPasswordTooLong,
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
