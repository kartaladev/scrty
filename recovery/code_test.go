package recovery_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/recovery"
)

// codeShape is the only shape a generated code may take: 26 Crockford base32
// characters grouped in fours with dashes, the first in 0–7 because 128 bits
// fill 130 bits of capacity with two leading zeros.
var codeShape = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{3}(-[0-9A-HJKMNP-TV-Z]{4}){5}-[0-9A-HJKMNP-TV-Z]{2}$`)

// TestCodeBytesPinned pins the entropy of a saved code. The constant is the
// whole guarantee that codes carry 128 bits, so a change that shortens it must
// fail here rather than ship.
func TestCodeBytesPinned(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 16, recovery.CodeBytes)
}

func TestNewCode(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		random io.Reader
		assert func(t *testing.T, text string, hash [32]byte, err error)
	}

	fixed := func(b ...byte) []byte {
		out := make([]byte, 16)
		copy(out[16-len(b):], b)

		return out
	}
	allOnes := bytes.Repeat([]byte{0xFF}, 16)

	cases := []testCase{
		{
			name:   "all zero bytes encode to all zeros",
			random: bytes.NewReader(fixed()),
			assert: func(t *testing.T, text string, hash [32]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, "0000-0000-0000-0000-0000-0000-00", text)
				assert.Equal(t, sha256.Sum256(fixed()), hash)
			},
		},
		{
			name:   "a value of one encodes to a trailing one",
			random: bytes.NewReader(fixed(0x01)),
			assert: func(t *testing.T, text string, hash [32]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, "0000-0000-0000-0000-0000-0000-01", text)
				assert.Equal(t, sha256.Sum256(fixed(0x01)), hash)
			},
		},
		{
			name:   "all one bits start with 7 and fill with Z",
			random: bytes.NewReader(allOnes),
			assert: func(t *testing.T, text string, hash [32]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, "7ZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZ", text)
				assert.Equal(t, sha256.Sum256(allOnes), hash)
			},
		},
		{
			name:   "the hash is SHA-256 of the 16 bytes read, not of the text",
			random: bytes.NewReader([]byte("0123456789abcdef")),
			assert: func(t *testing.T, text string, hash [32]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, sha256.Sum256([]byte("0123456789abcdef")), hash)
				assert.NotEqual(t, sha256.Sum256([]byte(text)), hash)
			},
		},
		{
			name:   "a failing random source is an error with no code",
			random: iotest.ErrReader(errors.New("entropy exhausted")),
			assert: func(t *testing.T, text string, hash [32]byte, err error) {
				require.Error(t, err)
				assert.Empty(t, text)
				assert.Equal(t, [32]byte{}, hash)
			},
		},
		{
			name:   "a random source that runs short is an error with no code",
			random: bytes.NewReader(make([]byte, 10)),
			assert: func(t *testing.T, text string, hash [32]byte, err error) {
				require.Error(t, err)
				assert.Empty(t, text)
				assert.Equal(t, [32]byte{}, hash)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			text, hash, err := recovery.NewCode(tc.random)
			tc.assert(t, text, hash, err)
		})
	}
}

// TestNewCode_Shape generates many codes from the real random source and holds
// every one to the pinned shape: grouped, 26 alphabet characters, decoding to
// the 16 bytes whose hash it was stored under.
func TestNewCode_Shape(t *testing.T) {
	t.Parallel()

	for range 1000 {
		text, hash, err := recovery.NewCode(rand.Reader)
		require.NoError(t, err)

		require.Regexp(t, codeShape, text)
		assert.Len(t, strings.ReplaceAll(text, "-", ""), 26)

		parsed, err := recovery.ParseCode(text)
		require.NoError(t, err)
		require.Equal(t, hash, parsed)
	}
}

func TestParseCode(t *testing.T) {
	t.Parallel()

	// A code built from a value of one holds both 0 and 1, which is what the
	// look-alike row needs.
	oneBytes := make([]byte, 16)
	oneBytes[15] = 0x01
	oneText, oneHash, err := recovery.NewCode(bytes.NewReader(oneBytes))
	require.NoError(t, err)
	require.Equal(t, "0000-0000-0000-0000-0000-0000-01", oneText)

	text, hash, err := recovery.NewCode(rand.Reader)
	require.NoError(t, err)

	dashless := strings.ReplaceAll(text, "-", "")

	type testCase struct {
		name      string
		presented string
		assert    func(t *testing.T, got [32]byte, err error)
	}

	matches := func(want [32]byte) func(t *testing.T, got [32]byte, err error) {
		return func(t *testing.T, got [32]byte, err error) {
			require.NoError(t, err)
			assert.Equal(t, want, got)
		}
	}
	refused := func(t *testing.T, got [32]byte, err error) {
		require.ErrorIs(t, err, recovery.ErrRefused)
		require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
		assert.Equal(t, [32]byte{}, got)
	}

	cases := []testCase{
		{name: "canonical", presented: text, assert: matches(hash)},
		{name: "lower case, no dashes", presented: strings.ToLower(dashless), assert: matches(hash)},
		{name: "dashes anywhere", presented: "-" + dashless[:2] + "-" + dashless[2:7] + "--" + dashless[7:] + "-", assert: matches(hash)},
		{name: "O for 0 and l for 1", presented: "oooo-OOOO-0000-oOoO-0000-0000-Ol", assert: matches(oneHash)},
		{name: "I for 1", presented: "0000-0000-0000-0000-0000-0000-0I", assert: matches(oneHash)},
		{name: "25 characters", presented: dashless[:25], assert: refused},
		{name: "27 characters", presented: dashless + "0", assert: refused},
		{name: "contains U", presented: "U" + dashless[1:], assert: refused},
		{name: "contains u", presented: "0000-0000-0000-0000-0000-0000-0u", assert: refused},
		{name: "first character 8", presented: "8" + dashless[1:], assert: refused},
		{name: "first character Z", presented: "Z" + dashless[1:], assert: refused},
		{name: "empty", presented: "", assert: refused},
		{name: "only dashes", presented: "----", assert: refused},
		{name: "space inside", presented: dashless[:13] + " " + dashless[13:], assert: refused},
		{name: "non-ASCII look-alike", presented: "０" + dashless[1:], assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := recovery.ParseCode(tc.presented)
			tc.assert(t, got, err)

			// No spelling of a presented code may reach a refusal's text.
			if err != nil && tc.presented != "" {
				assert.NotContains(t, err.Error(), tc.presented)
			}
		})
	}
}
