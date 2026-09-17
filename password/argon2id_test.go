package password_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/password"
)

func TestArgon2idEncode(t *testing.T) {
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

				assert.True(t, strings.HasPrefix(string(encoded), "argon2id$65536$1$4$"),
					"the stored form carries what verification needs — 64 MiB, 1 iteration, "+
						"4 threads — so a hash made today still verifies after the defaults "+
						"change; got %q", encoded)
				assert.True(t, enc.Match("hunter2", encoded),
					"the default encoder must verify what it just produced")
			},
		},
		{
			name: "every encoding is salted, so one password never yields one hash",
			assert: func(t *testing.T, enc password.Encoder) {
				first, err := enc.Encode("hunter2")
				require.NoError(t, err)

				second, err := enc.Encode("hunter2")
				require.NoError(t, err)

				assert.NotEqual(t, first, second,
					"two users who choose the same password must not share a stored hash: "+
						"identical hashes reveal that they match, and cracking one cracks both")

				assert.True(t, enc.Match("hunter2", first),
					"a fresh salt must not cost the encoder the ability to verify")
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := password.NewArgon2idEncoder()
			require.NoError(t, err, "the default encoder takes no configuration")
			require.NotNil(t, enc)

			tc.assert(t, enc)
		})
	}
}

func TestArgon2idMatch(t *testing.T) {
	t.Parallel()

	encodeWith := func(t *testing.T, opts []password.Argon2idOption, pw string) []byte {
		t.Helper()

		enc, err := password.NewArgon2idEncoder(opts...)
		require.NoError(t, err)

		encoded, err := enc.Encode(pw)
		require.NoError(t, err)

		return encoded
	}

	type testCase struct {
		name   string
		opts   []password.Argon2idOption
		stored func(t *testing.T) []byte
		input  string
		assert func(t *testing.T, matched bool)
	}

	cases := []testCase{
		{
			name: "a hash made with the old cost still verifies under a raised one",
			opts: []password.Argon2idOption{password.WithArgon2idMemory(mib128)},
			stored: func(t *testing.T) []byte {
				// Written at the 64 MiB default, verified by a 128 MiB encoder.
				return encodeWith(t, nil, "hunter2")
			},
			input: "hunter2",
			assert: func(t *testing.T, matched bool) {
				assert.True(t, matched,
					"the parameters come from the stored hash; reading them from the encoder "+
						"would lock every user out the day an operator raises the cost")
			},
		},
		{
			name:   "a wrong password does not match",
			stored: func(t *testing.T) []byte { return encodeWith(t, nil, "hunter2") },
			input:  "hunter3",
			assert: func(t *testing.T, matched bool) { assert.False(t, matched) },
		},
		{
			name: "a malformed hash reports no match rather than erroring",
			stored: func(_ *testing.T) []byte {
				return []byte("argon2id$65536$1$4$!!!$AAAA")
			},
			input: "hunter2",
			assert: func(t *testing.T, matched bool) {
				assert.False(t, matched, "an unreadable salt must never be treated as a match")
			},
		},
		{
			// Only the algorithm label is rewritten, so the parameters, salt and
			// derived key all still belong to this encoder. If Match ignored the
			// label it would derive the identical key and report a match, so this
			// row fails exactly when the check is removed. A hand-written foreign
			// hash would not do: its key would fail to match whether the label was
			// checked or not, and the row would prove nothing.
			name: "a record labelled with another algorithm does not match",
			stored: func(t *testing.T) []byte {
				valid := encodeWith(t, nil, "hunter2")

				return append([]byte("scrypt"), bytes.TrimPrefix(valid, []byte("argon2id"))...)
			},
			input: "hunter2",
			assert: func(t *testing.T, matched bool) {
				assert.False(t, matched,
					"the algorithm label is part of the record: ignoring it would let a hash "+
						"stored for one algorithm satisfy another algorithm's encoder")
			},
		},
		// The three rows below are robustness assertions rather than proofs. No
		// plausible mutation makes them fail — a record this broken yields a
		// non-matching key however the parser mishandles it — so they exist to
		// pin that Match answers false rather than panicking or erroring on input
		// a corrupted or hand-edited store might hold.
		{
			name: "a truncated record does not match",
			stored: func(_ *testing.T) []byte {
				return []byte("argon2id$65536$1$4")
			},
			input:  "hunter2",
			assert: func(t *testing.T, matched bool) { assert.False(t, matched) },
		},
		{
			name:   "an empty record does not match",
			stored: func(_ *testing.T) []byte { return nil },
			input:  "hunter2",
			assert: func(t *testing.T, matched bool) { assert.False(t, matched) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := password.NewArgon2idEncoder(tc.opts...)
			require.NoError(t, err)

			tc.assert(t, enc.Match(tc.input, tc.stored(t)))
		})
	}
}

// Memory is configured in KiB, so these are the sizes the floors talk about.
const (
	mib19  = 19 * 1024
	mib46  = 46 * 1024
	mib128 = 128 * 1024
)

func TestArgon2idParameters(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []password.Argon2idOption
		assert func(t *testing.T, enc password.Encoder, err error)
	}

	requireWeak := func(t *testing.T, err error, named ...string) {
		t.Helper()

		require.ErrorIs(t, err, password.ErrWeakParameters)

		for _, n := range named {
			assert.Contains(t, err.Error(), n,
				"the error has to say which parameter is too low, or the operator cannot fix it")
		}
	}

	cases := []testCase{
		{
			name: "19 MiB with one iteration is below the floor",
			opts: []password.Argon2idOption{
				password.WithArgon2idMemory(mib19),
				password.WithArgon2idIterations(1),
			},
			assert: func(t *testing.T, enc password.Encoder, err error) {
				requireWeak(t, err, "memory", "iteration")
				assert.Nil(t, enc, "a refused configuration must not yield a usable encoder")
			},
		},
		{
			name: "19 MiB is acceptable once iterations make up for it",
			opts: []password.Argon2idOption{
				password.WithArgon2idMemory(mib19),
				password.WithArgon2idIterations(2),
			},
			assert: func(t *testing.T, enc password.Encoder, err error) {
				require.NoError(t, err, "the floor trades memory against iterations, it is not a single number")
				assert.NotNil(t, enc)
			},
		},
		{
			name: "46 MiB is acceptable at one iteration",
			opts: []password.Argon2idOption{
				password.WithArgon2idMemory(mib46),
				password.WithArgon2idIterations(1),
			},
			assert: func(t *testing.T, enc password.Encoder, err error) {
				require.NoError(t, err)
				assert.NotNil(t, enc)
			},
		},
		{
			name: "no threads is refused",
			opts: []password.Argon2idOption{password.WithArgon2idThreads(0)},
			assert: func(t *testing.T, _ password.Encoder, err error) {
				requireWeak(t, err, "thread")
			},
		},
		{
			name: "a salt shorter than 16 bytes is refused",
			opts: []password.Argon2idOption{password.WithArgon2idSaltLength(15)},
			assert: func(t *testing.T, _ password.Encoder, err error) {
				requireWeak(t, err, "salt")
			},
		},
		{
			name: "a derived key shorter than 32 bytes is refused",
			opts: []password.Argon2idOption{password.WithArgon2idKeyLength(31)},
			assert: func(t *testing.T, _ password.Encoder, err error) {
				requireWeak(t, err, "key")
			},
		},
		{
			name: "a consumer raising the cost gets it recorded in the hash",
			opts: []password.Argon2idOption{
				password.WithArgon2idMemory(mib128),
				password.WithArgon2idIterations(3),
			},
			assert: func(t *testing.T, enc password.Encoder, err error) {
				require.NoError(t, err)
				require.NotNil(t, enc)

				encoded, encErr := enc.Encode("hunter2")
				require.NoError(t, encErr)
				assert.True(t, strings.HasPrefix(string(encoded), "argon2id$131072$3$"),
					"the raised cost must reach the stored form, or verification would "+
						"silently use the old one; got %q", encoded)
				assert.True(t, enc.Match("hunter2", encoded))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := password.NewArgon2idEncoder(tc.opts...)
			tc.assert(t, enc, err)
		})
	}
}
