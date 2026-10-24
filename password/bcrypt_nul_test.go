package password_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/password"
)

func TestBcryptMatch_RefusesNulJoinedRepetitionOfPassword(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, enc password.Encoder)
	}

	cases := []testCase{
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

				require.ErrorIs(t, err, password.ErrPasswordContainsNUL)
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
