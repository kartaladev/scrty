package password_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/password"
)

func TestRecognizer_BuiltInEncodersRecognizeOnlyWhatTheyWouldVerify(t *testing.T) {
	t.Parallel()

	encoders := map[string]func() (password.Encoder, error){
		"argon2id": func() (password.Encoder, error) { return password.NewArgon2idEncoder() },
		"bcrypt":   func() (password.Encoder, error) { return password.NewBcryptEncoder() },
		"scrypt":   func() (password.Encoder, error) { return password.NewScryptEncoder() },
	}

	// One hash of each algorithm, produced by the real encoders, so each
	// encoder can be shown the others' formats.
	hashes := map[string][]byte{}
	for name, build := range encoders {
		enc, err := build()
		require.NoError(t, err)

		hashes[name], err = enc.Encode("hunter2")
		require.NoError(t, err)
	}

	b64 := base64.RawStdEncoding
	salt := b64.EncodeToString(make([]byte, 16))
	key := b64.EncodeToString(make([]byte, 32))

	type testCase struct {
		name    string
		encoder string
		encoded []byte
		assert  func(t *testing.T, recognized bool)
	}

	recognized := func(t *testing.T, got bool) {
		t.Helper()
		assert.True(t, got, "a hash the encoder verifies was reported unrecognised")
	}
	unrecognized := func(t *testing.T, got bool) {
		t.Helper()
		assert.False(t, got, "a hash Match refuses unread was reported recognised")
	}

	var cases []testCase
	for name := range encoders {
		cases = append(cases,
			testCase{name: name + " recognises its own hash", encoder: name, encoded: hashes[name], assert: recognized},
			testCase{name: name + " does not recognise an empty hash", encoder: name, encoded: []byte{}, assert: unrecognized},
			testCase{name: name + " does not recognise a nil hash", encoder: name, encoded: nil, assert: unrecognized},
			testCase{name: name + " does not recognise garbage", encoder: name, encoded: []byte("not a hash"), assert: unrecognized},
		)
		for other := range encoders {
			if other != name {
				cases = append(cases, testCase{
					name: name + " does not recognise a " + other + " hash", encoder: name,
					encoded: hashes[other], assert: unrecognized,
				})
			}
		}
	}

	cases = append(cases,
		testCase{
			name: "argon2id does not recognise a record demanding memory above the ceiling", encoder: "argon2id",
			encoded: fmt.Appendf(nil, "argon2id$%d$3$1$%s$%s", 1<<30, salt, key), assert: unrecognized,
		},
		testCase{
			name: "scrypt does not recognise a record demanding parallelism above the ceiling", encoder: "scrypt",
			encoded: fmt.Appendf(nil, "scrypt$32768$8$128$%s$%s", salt, key), assert: unrecognized,
		},
		testCase{
			name: "bcrypt does not recognise a record whose cost is above the ceiling", encoder: "bcrypt",
			encoded: []byte("$2a$20$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890"), assert: unrecognized,
		},
		testCase{
			name: "bcrypt does not recognise a record whose salt is outside bcrypt's alphabet", encoder: "bcrypt",
			encoded: []byte("$2a$10$!bcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[:60]), assert: unrecognized,
		},
		testCase{
			name: "scrypt does not recognise a record whose N is not a power of two", encoder: "scrypt",
			encoded: fmt.Appendf(nil, "scrypt$3$8$1$%s$%s", salt, key), assert: unrecognized,
		},
		testCase{
			name: "scrypt does not recognise a record whose N is one", encoder: "scrypt",
			encoded: fmt.Appendf(nil, "scrypt$1$8$1$%s$%s", salt, key), assert: unrecognized,
		},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := encoders[tc.encoder]()
			require.NoError(t, err)

			rec, ok := enc.(password.Recognizer)
			require.True(t, ok, "the built-in %s encoder does not implement Recognizer", tc.encoder)

			tc.assert(t, rec.Recognizes(tc.encoded))
		})
	}
}
