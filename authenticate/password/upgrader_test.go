package password_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/password"
)

func TestEncoder_NeedsUpgrade(t *testing.T) {
	t.Parallel()

	argon := func(t *testing.T, kib uint32, iterations uint32) *password.Argon2idEncoder {
		t.Helper()

		enc, err := password.NewArgon2idEncoder(
			password.WithArgon2idMemory(kib), password.WithArgon2idIterations(iterations))
		require.NoError(t, err)

		return enc
	}
	bcryptAt := func(t *testing.T, cost int) *password.BcryptEncoder {
		t.Helper()

		enc, err := password.NewBcryptEncoder(password.WithBcryptCost(cost))
		require.NoError(t, err)

		return enc
	}
	scryptAt := func(t *testing.T, n int) *password.ScryptEncoder {
		t.Helper()

		enc, err := password.NewScryptEncoder(password.WithScryptN(n))
		require.NoError(t, err)

		return enc
	}
	encode := func(t *testing.T, enc password.Encoder) []byte {
		t.Helper()

		out, err := enc.Encode("hunter2")
		require.NoError(t, err)

		return out
	}

	type testCase struct {
		name    string
		current func(t *testing.T) password.Upgrader
		stored  func(t *testing.T) []byte
		assert  func(t *testing.T, needs bool)
	}

	upgrade := func(t *testing.T, got bool) {
		t.Helper()
		assert.True(t, got, "a hash weaker than the encoder's own must be upgraded")
	}
	keep := func(t *testing.T, got bool) {
		t.Helper()
		assert.False(t, got, "this hash must be left alone")
	}

	cases := []testCase{
		{
			name:    "argon2id memory below the encoder's",
			current: func(t *testing.T) password.Upgrader { return argon(t, mib128, 1) },
			stored:  func(t *testing.T) []byte { return encode(t, argon(t, 64*1024, 1)) },
			assert:  upgrade,
		},
		{
			name:    "argon2id iterations below the encoder's",
			current: func(t *testing.T) password.Upgrader { return argon(t, mib46, 2) },
			stored:  func(t *testing.T) []byte { return encode(t, argon(t, mib46, 1)) },
			assert:  upgrade,
		},
		{
			name:    "argon2id at the encoder's own parameters",
			current: func(t *testing.T) password.Upgrader { return argon(t, 64*1024, 1) },
			stored:  func(t *testing.T) []byte { return encode(t, argon(t, 64*1024, 1)) },
			assert:  keep,
		},
		{
			name:    "argon2id stronger than the encoder's",
			current: func(t *testing.T) password.Upgrader { return argon(t, 64*1024, 1) },
			stored:  func(t *testing.T) []byte { return encode(t, argon(t, mib128, 1)) },
			assert:  keep,
		},
		{
			name:    "a bcrypt hash under an argon2id encoder",
			current: func(t *testing.T) password.Upgrader { return argon(t, 64*1024, 1) },
			stored:  func(t *testing.T) []byte { return encode(t, bcryptAt(t, 10)) },
			assert:  upgrade,
		},
		{
			name:    "an argon2id hash under a bcrypt encoder",
			current: func(t *testing.T) password.Upgrader { return bcryptAt(t, 10) },
			stored:  func(t *testing.T) []byte { return encode(t, argon(t, 64*1024, 1)) },
			assert:  upgrade,
		},
		{
			name:    "unparseable under argon2id",
			current: func(t *testing.T) password.Upgrader { return argon(t, 64*1024, 1) },
			stored:  func(*testing.T) []byte { return []byte("garbage") },
			assert:  keep,
		},
		{
			name:    "empty under argon2id",
			current: func(t *testing.T) password.Upgrader { return argon(t, 64*1024, 1) },
			stored:  func(*testing.T) []byte { return nil },
			assert:  keep,
		},
		{
			name:    "bcrypt cost below the encoder's",
			current: func(t *testing.T) password.Upgrader { return bcryptAt(t, 12) },
			stored:  func(t *testing.T) []byte { return encode(t, bcryptAt(t, 10)) },
			assert:  upgrade,
		},
		{
			name:    "bcrypt at the encoder's cost",
			current: func(t *testing.T) password.Upgrader { return bcryptAt(t, 10) },
			stored:  func(t *testing.T) []byte { return encode(t, bcryptAt(t, 10)) },
			assert:  keep,
		},
		{
			name:    "bcrypt stronger than the encoder's",
			current: func(t *testing.T) password.Upgrader { return bcryptAt(t, 10) },
			stored:  func(t *testing.T) []byte { return encode(t, bcryptAt(t, 11)) },
			assert:  keep,
		},
		{
			name:    "unparseable under bcrypt",
			current: func(t *testing.T) password.Upgrader { return bcryptAt(t, 10) },
			stored:  func(*testing.T) []byte { return []byte("garbage") },
			assert:  keep,
		},
		{
			name:    "scrypt N below the encoder's",
			current: func(t *testing.T) password.Upgrader { return scryptAt(t, 65536) },
			stored:  func(t *testing.T) []byte { return encode(t, scryptAt(t, 32768)) },
			assert:  upgrade,
		},
		{
			name:    "scrypt at the encoder's N",
			current: func(t *testing.T) password.Upgrader { return scryptAt(t, 32768) },
			stored:  func(t *testing.T) []byte { return encode(t, scryptAt(t, 32768)) },
			assert:  keep,
		},
		{
			name:    "scrypt stronger than the encoder's",
			current: func(t *testing.T) password.Upgrader { return scryptAt(t, 32768) },
			stored:  func(t *testing.T) []byte { return encode(t, scryptAt(t, 65536)) },
			assert:  keep,
		},
		{
			name:    "unparseable under scrypt",
			current: func(t *testing.T) password.Upgrader { return scryptAt(t, 32768) },
			stored:  func(*testing.T) []byte { return []byte("garbage") },
			assert:  keep,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.current(t).NeedsUpgrade(tc.stored(t)))
		})
	}
}
