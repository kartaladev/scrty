package seal_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/seal"
)

// Recognisable key material, so a key leaking into an error's text is obvious
// in both its raw and its hex form.
var (
	keyOne   = []byte("key-one-0123456789abcdefghijklmn")
	keyTwo   = []byte("key-two-0123456789abcdefghijklmn")
	keyThree = []byte("key-three-23456789abcdefghijklmn")
)

// assertConfigError checks that err is a configuration error whose text
// carries none of the keys in any form.
func assertConfigError(t *testing.T, kr seal.Keyring, err error) {
	t.Helper()

	require.ErrorIs(t, err, seal.ErrInvalidConfiguration)
	assert.Nil(t, kr)

	for _, key := range [][]byte{keyOne, keyTwo, keyThree} {
		text := err.Error()
		assert.NotContains(t, text, string(key))
		assert.NotContains(t, strings.ToLower(text), hex.EncodeToString(key))
		assert.NotContains(t, text, string(key[:16]))
	}
}

func TestNewKeyring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []seal.KeyringOption
		assert func(t *testing.T, kr seal.Keyring, err error)
	}

	cases := []testCase{
		{
			name:   "no active key",
			opts:   []seal.KeyringOption{seal.WithRetiredEncryptionKey("k1", keyOne)},
			assert: assertConfigError,
		},
		{
			name:   "no options at all",
			assert: assertConfigError,
		},
		{
			name: "two active keys",
			opts: []seal.KeyringOption{
				seal.WithEncryptionKey("k1", keyOne),
				seal.WithEncryptionKey("k2", keyTwo),
			},
			assert: assertConfigError,
		},
		{
			name:   "a 16-byte active key",
			opts:   []seal.KeyringOption{seal.WithEncryptionKey("k1", keyOne[:16])},
			assert: assertConfigError,
		},
		{
			name: "a 33-byte retired key",
			opts: []seal.KeyringOption{
				seal.WithEncryptionKey("k2", keyTwo),
				seal.WithRetiredEncryptionKey("k1", append(bytes.Clone(keyOne), 'x')),
			},
			assert: assertConfigError,
		},
		{
			name:   "an empty key id",
			opts:   []seal.KeyringOption{seal.WithEncryptionKey("", keyOne)},
			assert: assertConfigError,
		},
		{
			name: "a key id used by both the active and a retired key",
			opts: []seal.KeyringOption{
				seal.WithEncryptionKey("k1", keyOne),
				seal.WithRetiredEncryptionKey("k1", keyTwo),
			},
			assert: assertConfigError,
		},
		{
			name: "a key id used by two retired keys",
			opts: []seal.KeyringOption{
				seal.WithEncryptionKey("k3", keyThree),
				seal.WithRetiredEncryptionKey("k1", keyOne),
				seal.WithRetiredEncryptionKey("k1", keyTwo),
			},
			assert: assertConfigError,
		},
		{
			name:   "a key id with a character outside the allowed set",
			opts:   []seal.KeyringOption{seal.WithEncryptionKey("bad/id", keyOne)},
			assert: assertConfigError,
		},
		{
			name:   "a 65-character key id",
			opts:   []seal.KeyringOption{seal.WithEncryptionKey(strings.Repeat("a", 65), keyOne)},
			assert: assertConfigError,
		},
		{
			// A retired key equal to the active key hides a rotation that never
			// happened: values "sealed under k1" open, and nothing says k1 was
			// never replaced.
			name: "two key ids naming identical key bytes",
			opts: []seal.KeyringOption{
				seal.WithEncryptionKey("k2", keyOne),
				seal.WithRetiredEncryptionKey("k1", bytes.Clone(keyOne)),
			},
			assert: assertConfigError,
		},
		{
			name: "a nil option",
			opts: []seal.KeyringOption{
				seal.WithEncryptionKey("k2", keyTwo),
				nil,
			},
			assert: assertConfigError,
		},
		{
			name: "a 64-character id with every allowed character class is accepted",
			opts: []seal.KeyringOption{
				seal.WithEncryptionKey("Az09._-"+strings.Repeat("x", 57), keyOne),
			},
			assert: func(t *testing.T, kr seal.Keyring, err error) {
				require.NoError(t, err)

				id, _, err := kr.Active()
				require.NoError(t, err)
				assert.Equal(t, "Az09._-"+strings.Repeat("x", 57), id)
			},
		},
		{
			name: "an active key and a retired key",
			opts: []seal.KeyringOption{
				seal.WithRetiredEncryptionKey("k1", keyOne),
				seal.WithEncryptionKey("k2", keyTwo),
			},
			assert: func(t *testing.T, kr seal.Keyring, err error) {
				require.NoError(t, err)

				id, key, err := kr.Active()
				require.NoError(t, err)
				assert.Equal(t, "k2", id)
				assert.Equal(t, keyTwo, key)

				retired, err := kr.ByID("k1")
				require.NoError(t, err)
				assert.Equal(t, keyOne, retired)

				active, err := kr.ByID("k2")
				require.NoError(t, err)
				assert.Equal(t, keyTwo, active)

				_, err = kr.ByID("gone")
				require.ErrorIs(t, err, seal.ErrUnknownKeyID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			kr, err := seal.NewKeyring(tc.opts...)
			tc.assert(t, kr, err)
		})
	}
}

// TestKeyring_CopiesKeys pins that the ring owns its key bytes: neither the
// slice a caller configured with nor a slice the ring handed out can change
// what it seals with.
func TestKeyring_CopiesKeys(t *testing.T) {
	t.Parallel()

	configured := bytes.Clone(keyTwo)
	opt := seal.WithEncryptionKey("k2", configured)
	configured[0] ^= 0xff // after the option, before the ring

	kr, err := seal.NewKeyring(opt)
	require.NoError(t, err)

	configured[1] ^= 0xff // after the ring

	_, key, err := kr.Active()
	require.NoError(t, err)
	require.Equal(t, keyTwo, key)

	key[2] ^= 0xff // a slice the ring handed out

	_, again, err := kr.Active()
	require.NoError(t, err)
	assert.Equal(t, keyTwo, again)

	byID, err := kr.ByID("k2")
	require.NoError(t, err)
	require.Len(t, byID, len(keyTwo))
	byID[3] ^= 0xff

	byIDAgain, err := kr.ByID("k2")
	require.NoError(t, err)
	assert.Equal(t, keyTwo, byIDAgain)
}
