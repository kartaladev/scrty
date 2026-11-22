package oidcprovider

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingReader yields one byte forever, and counts what it was asked for.
type countingReader struct {
	b    byte
	read int
}

func (r *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	r.read += len(p)

	return len(p), nil
}

func TestUserCode_RejectionSampling(t *testing.T) {
	t.Parallel()

	def, err := newUserCodeFormat(DefaultUserCodeAlphabet, DefaultUserCodeLength)
	require.NoError(t, err)

	// accepted are the bytes the default draw keeps, each below 256 - 256%20 = 240.
	accepted := []byte{0, 19, 20, 239, 100, 7, 58, 221}
	var want strings.Builder
	var script []byte
	for i, b := range accepted {
		want.WriteByte(DefaultUserCodeAlphabet[int(b)%20])
		// Before each kept byte, i+1 bytes of the rejection zone, 240 among them.
		for j := range i + 1 {
			script = append(script, byte(240+(i*3+j)%16))
		}
		script = append(script, b)
	}

	errOutage := errors.New("entropy outage")

	type testCase struct {
		name   string
		format userCodeFormat
		random func() io.Reader
		assert func(t *testing.T, raw string, err error, random io.Reader)
	}

	cases := []testCase{
		{
			name:   "bytes in the rejection zone are drawn again, and kept bytes map by remainder",
			format: def,
			random: func() io.Reader { return bytes.NewReader(script) },
			assert: func(t *testing.T, raw string, err error, random io.Reader) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, want.String(), raw)
				assert.Zero(t, random.(*bytes.Reader).Len(), "the draw reads no byte past the last one it keeps")
			},
		},
		{
			name:   "a reader that yields a byte at a time gives the same code",
			format: def,
			random: func() io.Reader { return iotest.OneByteReader(bytes.NewReader(script)) },
			assert: func(t *testing.T, raw string, err error, _ io.Reader) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, want.String(), raw)
			},
		},
		{
			name:   "a two-character alphabet has no rejection zone",
			format: userCodeFormat{alphabet: "XY", length: 8},
			random: func() io.Reader { return bytes.NewReader([]byte{255, 254, 0, 1, 128, 129, 2, 3}) },
			assert: func(t *testing.T, raw string, err error, _ io.Reader) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "YXXYXYXY", raw)
			},
		},
		{
			name:   "a reader that fails part way is wrapped, with no partial code",
			format: def,
			random: func() io.Reader {
				return io.MultiReader(bytes.NewReader([]byte{1, 2, 3}), iotest.ErrReader(errOutage))
			},
			assert: func(t *testing.T, raw string, err error, _ io.Reader) {
				t.Helper()
				require.ErrorIs(t, err, errOutage)
				assert.Empty(t, raw)
			},
		},
		{
			name:   "a reader that runs dry is an error, with no partial code",
			format: def,
			random: func() io.Reader { return bytes.NewReader([]byte{1, 2, 3, 250}) },
			assert: func(t *testing.T, raw string, err error, _ io.Reader) {
				t.Helper()
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				assert.Empty(t, raw)
			},
		},
		{
			name:   "a reader that yields only rejected bytes ends in an error at the bound",
			format: def,
			random: func() io.Reader { return &countingReader{b: 0xff} },
			assert: func(t *testing.T, raw string, err error, random io.Reader) {
				t.Helper()
				require.ErrorIs(t, err, errUserCodeDrawExhausted)
				assert.Empty(t, raw)
				assert.Equal(t, maxUserCodeDraw, random.(*countingReader).read)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			random := tc.random()
			raw, err := tc.format.generate(random)
			tc.assert(t, raw, err, random)
		})
	}
}

// Over every byte value in turn, each letter of the default alphabet is drawn equally
// often, and the 16 bytes of the rejection zone are drawn and dropped: the draw is
// uniform. The last cycle's zone follows the last kept byte, and is never read.
func TestUserCode_UniformOverEveryByte(t *testing.T) {
	t.Parallel()

	f, err := newUserCodeFormat(DefaultUserCodeAlphabet, DefaultUserCodeLength)
	require.NoError(t, err)

	const cycles = 8 // 8 × 240 kept bytes are exactly 240 codes of 8
	var all []byte
	for range cycles {
		for b := range 256 {
			all = append(all, byte(b))
		}
	}
	random := bytes.NewReader(all)

	counts := map[rune]int{}
	for range cycles * 240 / DefaultUserCodeLength {
		raw, err := f.generate(random)
		require.NoError(t, err)
		for _, c := range raw {
			counts[c]++
		}
	}

	assert.Equal(t, 16, random.Len())
	require.Len(t, counts, len(DefaultUserCodeAlphabet))
	for _, c := range DefaultUserCodeAlphabet {
		assert.Equal(t, cycles*12, counts[c], "letter %q", c)
	}
}

// A minted device code is read back by the same rule the package reads every other
// secret it mints, so that the token endpoint can refuse a malformed one with no lookup.
func TestMintDeviceCode_ReadAsHandlesAre(t *testing.T) {
	t.Parallel()

	code, digest, err := mintDeviceCode(rand.Reader)
	require.NoError(t, err)

	again, ok := digestEncoded(code)
	require.True(t, ok)
	assert.Equal(t, digest, again)
}

func TestHoldsAtLeast(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name           string
		n, length, min int
		want           bool
	}

	cases := []testCase{
		{name: "93 characters over 5 positions pass 2^31", n: 93, length: 5, min: minUserCodeSpace, want: true},
		{name: "6 characters over 12 positions pass 2^31", n: 6, length: 12, min: minUserCodeSpace, want: true},
		{name: "2 characters over 29 positions reach the floor exactly", n: 2, length: 29, min: minUserCodeSpace, want: true},
		{name: "2 characters over 28 positions fall short", n: 2, length: 28, min: minUserCodeSpace, want: false},
		{name: "93 characters over 32 positions do not overflow", n: 93, length: 32, min: minUserCodeSpace, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, holdsAtLeast(tc.n, tc.length, tc.min))
		})
	}
}

func TestDeviceConfigDoesNotPrintTheKey(t *testing.T) {
	t.Parallel()

	key := make([]byte, MinUserCodeKeyBytes)
	for i := range key {
		key[i] = byte(0xA0 + i)
	}
	d := &deviceConfig{}
	WithUserCodeKey(key)(d)

	var logged strings.Builder
	slog.New(slog.NewTextHandler(&logged, nil)).Info("cfg", "device", d, "key", d.userCodeKey)
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("cfg", "device", d, "key", d.userCodeKey)

	outputs := []string{
		fmt.Sprintf("%v", d), fmt.Sprintf("%+v", d), fmt.Sprintf("%#v", d),
		fmt.Sprintf("%v", *d), fmt.Sprintf("%+v", *d), fmt.Sprintf("%#v", *d),
		fmt.Sprintf("%v", d.userCodeKey), fmt.Sprintf("%+v", d.userCodeKey), fmt.Sprintf("%#v", d.userCodeKey),
		logged.String(),
	}
	forms := []string{
		string(key), hex.EncodeToString(key), fmt.Sprintf("%v", key),
		base64.StdEncoding.EncodeToString(key), base64.URLEncoding.EncodeToString(key),
		base64.RawStdEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key),
	}
	for _, out := range outputs {
		for _, form := range forms {
			assert.NotContains(t, out, form)
		}
	}
}
