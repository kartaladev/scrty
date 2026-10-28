package password_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"

	"github.com/kartaladev/scrty/authenticate/password"
)

// fastMatch is how long a record above a ceiling may take to be refused. The
// refusal derives nothing, so anything near it means a key was derived.
const fastMatch = 100 * time.Millisecond

func TestScryptMatch_RecordParallelismBoundsDerivationTime(t *testing.T) {
	t.Parallel()

	enc, err := password.NewScryptEncoder()
	require.NoError(t, err)

	salt := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	key := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	record := fmt.Appendf(nil, "scrypt$32768$8$128$%s$%s", salt, key)

	start := time.Now()
	matched := enc.Match("hunter2", record)
	elapsed := time.Since(start)

	assert.False(t, matched)
	assert.Less(t, elapsed, fastMatch,
		"p=128 at N=32768 is over a hundred derivations; the record must be refused unread")
}

func TestBcrypt_RefusesStoredRecordWithExcessiveCost(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		cost int
	}

	cases := []testCase{
		{name: "one above the ceiling", cost: 17},
		{name: "cost 20", cost: 20},
		{name: "bcrypt's own maximum", cost: 31},
	}

	// Well formed in shape, with a cost the record claims: bcrypt reads the cost
	// from the record and runs it before it compares anything.
	const body = "abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890"

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := password.NewBcryptEncoder()
			require.NoError(t, err)

			record := fmt.Appendf(nil, "$2a$%02d$%s", tc.cost, body[:53])
			require.Len(t, record, 60)

			start := time.Now()
			matched := enc.Match("hunter2", record)
			elapsed := time.Since(start)

			assert.False(t, matched)
			assert.Less(t, elapsed, fastMatch, "the record's cost must be refused without running bcrypt")
		})
	}
}

func TestArgon2idMatch_RefusesRecordAboveCeiling(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		iterations uint32
		threads    uint8
		saltLen    int
		keyLen     uint32
		assert     func(t *testing.T, matched bool)
	}

	const kib = 1024 // small, so the cases that do derive stay fast

	refused := func(t *testing.T, matched bool) {
		t.Helper()
		assert.False(t, matched, "a record above a ceiling is refused even when its key is right")
	}

	cases := []testCase{
		{name: "threads above the ceiling", iterations: 1, threads: 64, saltLen: 16, keyLen: 32, assert: refused},
		{name: "threads one above the ceiling", iterations: 1, threads: 17, saltLen: 16, keyLen: 32, assert: refused},
		{name: "iterations above the ceiling", iterations: 17, threads: 1, saltLen: 16, keyLen: 32, assert: refused},
		{name: "salt above the ceiling", iterations: 1, threads: 1, saltLen: 65, keyLen: 32, assert: refused},
		{name: "key above the ceiling", iterations: 1, threads: 1, saltLen: 16, keyLen: 65, assert: refused},
		{
			name: "every parameter at its ceiling", iterations: 16, threads: 16, saltLen: 64, keyLen: 64,
			assert: func(t *testing.T, matched bool) { assert.True(t, matched) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := password.NewArgon2idEncoder()
			require.NoError(t, err)

			salt := make([]byte, tc.saltLen)
			for i := range salt {
				salt[i] = byte(i + 1)
			}

			key := argon2.IDKey([]byte("hunter2"), salt, tc.iterations, kib, tc.threads, tc.keyLen)
			record := fmt.Appendf(nil, "argon2id$%d$%d$%d$%s$%s", kib, tc.iterations, tc.threads,
				base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))

			tc.assert(t, enc.Match("hunter2", record))
		})
	}
}

func TestEncoders_RefuseParametersAboveCeiling(t *testing.T) {
	t.Parallel()

	const twoGiBInKiB = 2 * 1024 * 1024

	type testCase struct {
		name  string
		param string // the parameter the error must name
		build func() (password.Encoder, error)
	}

	cases := []testCase{
		{"scrypt p above the ceiling", "p=32",
			func() (password.Encoder, error) { return password.NewScryptEncoder(password.WithScryptP(32)) }},
		{"scrypt working memory above the ceiling", "N=",
			func() (password.Encoder, error) { return password.NewScryptEncoder(password.WithScryptN(1 << 20)) }},
		{"bcrypt cost above the ceiling", "cost 17",
			func() (password.Encoder, error) { return password.NewBcryptEncoder(password.WithBcryptCost(17)) }},
		{"Argon2id memory above the ceiling", "memory",
			func() (password.Encoder, error) {
				return password.NewArgon2idEncoder(password.WithArgon2idMemory(twoGiBInKiB))
			}},
		{"Argon2id iterations above the ceiling", "iterations",
			func() (password.Encoder, error) {
				return password.NewArgon2idEncoder(password.WithArgon2idIterations(17))
			}},
		{"Argon2id threads above the ceiling", "threads",
			func() (password.Encoder, error) { return password.NewArgon2idEncoder(password.WithArgon2idThreads(17)) }},
		{"Argon2id salt above the ceiling", "salt",
			func() (password.Encoder, error) {
				return password.NewArgon2idEncoder(password.WithArgon2idSaltLength(65))
			}},
		{"Argon2id key above the ceiling", "derived key",
			func() (password.Encoder, error) {
				return password.NewArgon2idEncoder(password.WithArgon2idKeyLength(65))
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := tc.build()

			require.ErrorIs(t, err, password.ErrInvalidParameters)
			assert.True(t, strings.Contains(err.Error(), tc.param), "the error must name the parameter: %v", err)
			assert.Nil(t, enc)
		})
	}
}

func TestEncoders_AcceptParametersAtCeiling(t *testing.T) {
	t.Parallel()

	cases := map[string]func() (password.Encoder, error){
		"scrypt p=16": func() (password.Encoder, error) { return password.NewScryptEncoder(password.WithScryptP(16)) },
		"bcrypt cost 16": func() (password.Encoder, error) {
			return password.NewBcryptEncoder(password.WithBcryptCost(16))
		},
		"Argon2id at every ceiling": func() (password.Encoder, error) {
			return password.NewArgon2idEncoder(
				password.WithArgon2idMemory(1024*1024), password.WithArgon2idIterations(16),
				password.WithArgon2idThreads(16), password.WithArgon2idSaltLength(64),
				password.WithArgon2idKeyLength(64))
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			enc, err := build()
			require.NoError(t, err)
			assert.NotNil(t, enc)
		})
	}
}
