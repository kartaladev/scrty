package password_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/password"
)

func TestScryptEncode(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, enc password.Encoder)
	}

	cases := []testCase{
		{
			name: "the default encoding names its algorithm and parameters",
			assert: func(t *testing.T, enc password.Encoder) {
				encoded, err := enc.Encode("hunter2")
				require.NoError(t, err)

				assert.True(t, strings.HasPrefix(string(encoded), "scrypt$32768$8$1$"),
					"the stored form carries N, r and p, so a hash survives a change of "+
						"defaults; got %q", encoded)
				assert.True(t, enc.Match("hunter2", encoded))
			},
		},
		{
			name: "every encoding is salted",
			assert: func(t *testing.T, enc password.Encoder) {
				first, err := enc.Encode("hunter2")
				require.NoError(t, err)

				second, err := enc.Encode("hunter2")
				require.NoError(t, err)

				assert.NotEqual(t, first, second,
					"two users sharing a password must not share a hash")
				assert.True(t, enc.Match("hunter2", first))
				assert.True(t, enc.Match("hunter2", second))
			},
		},
		{
			name: "a wrong password does not match",
			assert: func(t *testing.T, enc password.Encoder) {
				encoded, err := enc.Encode("hunter2")
				require.NoError(t, err)

				assert.False(t, enc.Match("hunter3", encoded))
			},
		},
		{
			// Only the algorithm label is rewritten, so the parameters, salt and key
			// still belong to this encoder: if Match ignored the label it would
			// derive the identical key and report a match. A hand-written foreign
			// record would fail to match either way and prove nothing.
			name: "a record labelled with another algorithm does not match",
			assert: func(t *testing.T, enc password.Encoder) {
				valid, err := enc.Encode("hunter2")
				require.NoError(t, err)

				relabelled := append([]byte("argon2id"), bytes.TrimPrefix(valid, []byte("scrypt"))...)

				assert.False(t, enc.Match("hunter2", relabelled),
					"the algorithm label is part of the record")
			},
		},
		{
			name: "a malformed record reports no match rather than erroring",
			assert: func(t *testing.T, enc password.Encoder) {
				assert.False(t, enc.Match("hunter2", []byte("scrypt$32768$8$1$!!!$AAAA")))
				assert.False(t, enc.Match("hunter2", []byte("scrypt$32768$8")))
				assert.False(t, enc.Match("hunter2", nil))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := password.NewScryptEncoder()
			require.NoError(t, err, "the scrypt encoder takes no configuration")
			require.NotNil(t, enc)

			tc.assert(t, enc)
		})
	}
}

func TestScryptParameters(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []password.ScryptOption
		assert func(t *testing.T, enc password.Encoder, err error)
	}

	// named must be a distinctive token, not a bare letter: ErrWeakParameters
	// already reads "password: parameters below the supported floor", which
	// contains r, p and several other letters, so asserting on one of those
	// would hold against any error at all.
	requireWeak := func(t *testing.T, err error, named string) {
		t.Helper()

		require.ErrorIs(t, err, password.ErrWeakParameters)
		assert.Contains(t, err.Error(), named,
			"the error has to say which parameter is too low")
	}

	cases := []testCase{
		{
			name: "an N below the floor is refused",
			opts: []password.ScryptOption{password.WithScryptN(16384)},
			assert: func(t *testing.T, enc password.Encoder, err error) {
				requireWeak(t, err, "N=16384")
				assert.Nil(t, enc, "a refused configuration must not yield a usable encoder")
			},
		},
		{
			name: "an r below the floor is refused",
			opts: []password.ScryptOption{password.WithScryptR(4)},
			assert: func(t *testing.T, _ password.Encoder, err error) {
				requireWeak(t, err, "r=4")
			},
		},
		{
			name: "a p below the floor is refused",
			opts: []password.ScryptOption{password.WithScryptP(0)},
			assert: func(t *testing.T, _ password.Encoder, err error) {
				requireWeak(t, err, "p=0")
			},
		},
		{
			name: "a salt shorter than 16 bytes is refused",
			opts: []password.ScryptOption{password.WithScryptSaltLength(15)},
			assert: func(t *testing.T, _ password.Encoder, err error) {
				requireWeak(t, err, "salt")
			},
		},
		{
			name: "a derived key shorter than 32 bytes is refused",
			opts: []password.ScryptOption{password.WithScryptKeyLength(31)},
			assert: func(t *testing.T, _ password.Encoder, err error) {
				requireWeak(t, err, "key")
			},
		},
		{
			name: "a consumer raising N gets it recorded in the hash",
			opts: []password.ScryptOption{password.WithScryptN(65536)},
			assert: func(t *testing.T, enc password.Encoder, err error) {
				require.NoError(t, err)
				require.NotNil(t, enc)

				encoded, encErr := enc.Encode("hunter2")
				require.NoError(t, encErr)

				assert.True(t, strings.HasPrefix(string(encoded), "scrypt$65536$8$1$"),
					"a raised cost that never reaches the stored form protects nobody; got %q",
					encoded)
				assert.True(t, enc.Match("hunter2", encoded))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := password.NewScryptEncoder(tc.opts...)
			tc.assert(t, enc, err)
		})
	}
}
