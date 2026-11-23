package oidcprovider_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// deviceProvider builds a provider with the device grant on, and the device options given.
func deviceProvider(t *testing.T, opts []oidcprovider.Option, device ...oidcprovider.DeviceOption) (*oidcprovider.Provider, error) {
	t.Helper()

	all := append([]oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer+"/activate", device...)}, opts...)

	return oidcprovider.New(validDeps(t), all...)
}

func TestMintDeviceCode(t *testing.T) {
	t.Parallel()

	errOutage := errors.New("entropy outage")

	type testCase struct {
		name   string
		random func() io.Reader
		assert func(t *testing.T, code string, digest []byte, err error)
	}

	cases := []testCase{
		{
			name:   "32 random bytes, base64url without padding, kept as the digest of those bytes",
			random: func() io.Reader { return rand.Reader },
			assert: func(t *testing.T, code string, digest []byte, err error) {
				t.Helper()
				require.NoError(t, err)
				raw, decErr := base64.RawURLEncoding.Strict().DecodeString(code)
				require.NoError(t, decErr)
				assert.Len(t, raw, 32)
				assert.NotContains(t, code, "=")
				sum := sha256.Sum256(raw)
				assert.Equal(t, sum[:], digest)
				assert.NotContains(t, string(digest), code)
			},
		},
		{
			name:   "a reader that fails is wrapped, with no code and no digest",
			random: func() io.Reader { return iotest.ErrReader(errOutage) },
			assert: func(t *testing.T, code string, digest []byte, err error) {
				t.Helper()
				require.ErrorIs(t, err, errOutage)
				assert.Empty(t, code)
				assert.Nil(t, digest)
			},
		},
		{
			name:   "a reader that runs short is an error, never a shorter code",
			random: func() io.Reader { return bytes.NewReader(make([]byte, 31)) },
			assert: func(t *testing.T, code string, digest []byte, err error) {
				t.Helper()
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				assert.Empty(t, code)
				assert.Nil(t, digest)
			},
		},
		{
			name:   "a reader that yields a byte at a time still fills the code",
			random: func() io.Reader { return iotest.OneByteReader(bytes.NewReader(bytes.Repeat([]byte{7}, 32))) },
			assert: func(t *testing.T, code string, digest []byte, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), code)
				sum := sha256.Sum256(bytes.Repeat([]byte{7}, 32))
				assert.Equal(t, sum[:], digest)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			code, digest, err := oidcprovider.MintDeviceCodeForTest(tc.random())
			tc.assert(t, code, digest, err)
		})
	}
}

func TestUserCode_DefaultFormat(t *testing.T) {
	t.Parallel()

	p, err := deviceProvider(t, nil)
	require.NoError(t, err)

	shape := regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`)
	seen := map[string]bool{}
	for range 1000 {
		code, err := p.GenerateUserCodeForTest()
		require.NoError(t, err)
		require.Regexp(t, shape, code)
		seen[code] = true
	}
	// 1000 draws from about 2^34.6 codes repeat with a chance near 2^-15: a run of
	// repeats means the draw is not random.
	assert.Greater(t, len(seen), 990)
}

func TestWithUserCodeFormat(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		device []oidcprovider.DeviceOption
		assert func(t *testing.T, p *oidcprovider.Provider, err error)
	}

	refused := func(leaks ...string) func(t *testing.T, p *oidcprovider.Provider, err error) {
		return func(t *testing.T, p *oidcprovider.Provider, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.ErrorContains(t, err, "WithUserCodeFormat")
			assert.Nil(t, p)
			for _, leak := range leaks {
				assert.NotContains(t, err.Error(), leak)
			}
		}
	}
	// shown asserts the raw code displays as given, and that a drawn code has the shape.
	shown := func(raw, display string, shape *regexp.Regexp) func(t *testing.T, p *oidcprovider.Provider, err error) {
		return func(t *testing.T, p *oidcprovider.Provider, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, display, p.DisplayUserCodeForTest(raw))
			for range 50 {
				code, genErr := p.GenerateUserCodeForTest()
				require.NoError(t, genErr)
				require.Regexp(t, shape, code)
			}
		}
	}

	printable := func() string {
		var b strings.Builder
		for c := byte('!'); c <= '~'; c++ {
			if c != '-' {
				b.WriteByte(c)
			}
		}

		return b.String()
	}()

	cases := []testCase{
		{
			name:   "the default without the option",
			assert: shown("BCDFGHJK", "BCDF-GHJK", regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`)),
		},
		{
			name:   "9 digits are shown in groups of three",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("0123456789", 9)},
			assert: shown("123456789", "123-456-789", regexp.MustCompile(`^\d{3}-\d{3}-\d{3}$`)),
		},
		{
			name:   "10 digits divide by neither 4 nor 3 and are shown ungrouped",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("0123456789", 10)},
			assert: shown("0123456789", "0123456789", regexp.MustCompile(`^\d{10}$`)),
		},
		{
			name:   "two characters and 29 positions hold exactly 2^29 codes",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("XY", 29)},
			assert: shown(strings.Repeat("X", 29), strings.Repeat("X", 29), regexp.MustCompile(`^[XY]{29}$`)),
		},
		{
			name:   "every printable character but the dash, 32 long, does not overflow the count",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat(printable, 32)},
			assert: shown(strings.Repeat("!", 32), strings.Repeat("!!!!-", 7)+"!!!!", regexp.MustCompile(`^(?:[!-~]{4}-){7}[!-~]{4}$`)),
		},
		{
			name:   "93 printable characters and 5 positions hold 93^5 codes, which a 32-bit int cannot count",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat(printable, 5)},
			assert: shown("!!!!!", "!!!!!", regexp.MustCompile(`^[!-~]{5}$`)),
		},
		{
			name: "given twice, the last one wins",
			device: []oidcprovider.DeviceOption{
				oidcprovider.WithUserCodeFormat("01", 3),
				oidcprovider.WithUserCodeFormat("0123456789", 9),
			},
			assert: shown("123456789", "123-456-789", regexp.MustCompile(`^\d{3}-\d{3}-\d{3}$`)),
		},
		{
			name:   "6 digits hold fewer than 2^29 codes",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("0123456789", 6)},
			assert: refused(),
		},
		{
			name:   "two characters and 28 positions hold fewer than 2^29 codes",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("XY", 28)},
			assert: refused(),
		},
		{
			name:   "a repeated character",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("AABCDEFGHJKLMNPQRSTUVWXYZ", 8)},
			assert: refused(),
		},
		{
			name:   "a non-printable character",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("\x01BCDFGHJKLMNPQRSTVWXZ", 8)},
			assert: refused("\x01"),
		},
		{
			name:   "the delete character",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("\x7fBCDFGHJKLMNPQRSTVWXZ", 8)},
			assert: refused("\x7f"),
		},
		{
			name:   "a non-ASCII character",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("BCDFGHJKLMNPQRSTVWXZÉ", 8)},
			assert: refused("É"),
		},
		{
			name:   "invalid UTF-8",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("BCDFGHJKLMNPQRSTVWXZ\xff", 8)},
			assert: refused("\xff"),
		},
		{
			name:   "a dash, which normalisation strips",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("BCDFGHJKLMNPQRSTVWXZ-", 8)},
			assert: refused(),
		},
		{
			name:   "a space, which normalisation strips",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("BCDFGHJKLMNPQRSTVWXZ ", 8)},
			assert: refused(),
		},
		{
			name:   "a tab, which normalisation strips",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("BCDFGHJKLMNPQRSTVWXZ\t", 8)},
			assert: refused(),
		},
		{
			name:   "a length of 0",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("BCDFGHJKLMNPQRSTVWXZ", 0)},
			assert: refused(),
		},
		{
			name:   "a negative length",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("BCDFGHJKLMNPQRSTVWXZ", -8)},
			assert: refused(),
		},
		{
			name:   "a length of 33",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("BCDFGHJKLMNPQRSTVWXZ", 33)},
			assert: refused(),
		},
		{
			name:   "an alphabet of 1 character",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("X", 32)},
			assert: refused(),
		},
		{
			name:   "an empty alphabet",
			device: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("", 8)},
			assert: refused(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := deviceProvider(t, nil, tc.device...)
			tc.assert(t, p, err)
		})
	}
}

func TestUserCodeKey(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x5a}, oidcprovider.MinUserCodeKeyBytes)
	const raw = "BCDFGHJK"
	// mac is the digest a code has under a key.
	mac := func(key []byte) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(raw))

		return m.Sum(nil)
	}

	type testCase struct {
		name string
		// providers lists the device options of each provider the row builds.
		providers [][]oidcprovider.DeviceOption
		opts      []oidcprovider.Option
		assert    func(t *testing.T, ps []*oidcprovider.Provider, errs []error)
	}

	refused := func(t *testing.T, ps []*oidcprovider.Provider, errs []error) {
		t.Helper()
		require.ErrorIs(t, errs[0], oidcprovider.ErrConfig)
		assert.ErrorContains(t, errs[0], "WithUserCodeKey")
		assert.NotContains(t, errs[0].Error(), string(key[:4]))
		assert.Nil(t, ps[0])
	}

	cases := []testCase{
		{
			name:      "with no key, two providers digest one code differently",
			providers: [][]oidcprovider.DeviceOption{nil, nil},
			assert: func(t *testing.T, ps []*oidcprovider.Provider, errs []error) {
				t.Helper()
				require.NoError(t, errs[0])
				require.NoError(t, errs[1])
				a, b := ps[0].UserCodeDigestForTest(raw), ps[1].UserCodeDigestForTest(raw)
				assert.Len(t, a, sha256.Size)
				assert.NotEqual(t, a, b)
				assert.Equal(t, a, ps[0].UserCodeDigestForTest(raw), "one provider digests one code the same each time")
			},
		},
		{
			name: "two providers given one key digest a code identically, as HMAC-SHA-256 under it",
			providers: [][]oidcprovider.DeviceOption{
				{oidcprovider.WithUserCodeKey(key)},
				{oidcprovider.WithUserCodeKey(bytes.Clone(key))},
			},
			assert: func(t *testing.T, ps []*oidcprovider.Provider, errs []error) {
				t.Helper()
				require.NoError(t, errs[0])
				require.NoError(t, errs[1])
				assert.Equal(t, mac(key), ps[0].UserCodeDigestForTest(raw))
				assert.Equal(t, mac(key), ps[1].UserCodeDigestForTest(raw))
				assert.NotEqual(t, mac(key), ps[0].UserCodeDigestForTest("BCDFGHJL"))
			},
		},
		{
			name:      "a 31-byte key",
			providers: [][]oidcprovider.DeviceOption{{oidcprovider.WithUserCodeKey(key[:31])}},
			assert:    refused,
		},
		{
			name:      "a nil key",
			providers: [][]oidcprovider.DeviceOption{{oidcprovider.WithUserCodeKey(nil)}},
			assert:    refused,
		},
		{
			name: "given twice, the last one wins",
			providers: [][]oidcprovider.DeviceOption{{
				oidcprovider.WithUserCodeKey(key[:3]),
				oidcprovider.WithUserCodeKey(key),
			}},
			assert: func(t *testing.T, ps []*oidcprovider.Provider, errs []error) {
				t.Helper()
				require.NoError(t, errs[0])
				assert.Equal(t, mac(key), ps[0].UserCodeDigestForTest(raw))
			},
		},
		{
			name: "a key the caller changes after giving it digests as given",
			providers: func() [][]oidcprovider.DeviceOption {
				mutable := bytes.Clone(key)
				opt := oidcprovider.WithUserCodeKey(mutable)
				mutable[0] ^= 0xff

				return [][]oidcprovider.DeviceOption{{opt}}
			}(),
			assert: func(t *testing.T, ps []*oidcprovider.Provider, errs []error) {
				t.Helper()
				require.NoError(t, errs[0])
				assert.Equal(t, mac(key), ps[0].UserCodeDigestForTest(raw))
			},
		},
		{
			name:      "a random source that fails while the default key is drawn fails New",
			providers: [][]oidcprovider.DeviceOption{nil},
			opts: []oidcprovider.Option{
				oidcprovider.WithRandom(iotest.ErrReader(errors.New("entropy outage"))),
				oidcprovider.WithRefreshSuccessorKey(key),
			},
			assert: func(t *testing.T, ps []*oidcprovider.Provider, errs []error) {
				t.Helper()
				require.ErrorIs(t, errs[0], oidcprovider.ErrConfig)
				assert.ErrorContains(t, errs[0], "WithUserCodeKey")
				assert.NotContains(t, errs[0].Error(), "entropy outage")
				assert.Nil(t, ps[0])
			},
		},
		{
			name:      "a key given draws nothing from the random source",
			providers: [][]oidcprovider.DeviceOption{{oidcprovider.WithUserCodeKey(key)}},
			opts: []oidcprovider.Option{
				oidcprovider.WithRandom(iotest.ErrReader(errors.New("entropy outage"))),
				oidcprovider.WithRefreshSuccessorKey(key),
			},
			assert: func(t *testing.T, ps []*oidcprovider.Provider, errs []error) {
				t.Helper()
				require.NoError(t, errs[0])
				assert.Equal(t, mac(key), ps[0].UserCodeDigestForTest(raw))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ps := make([]*oidcprovider.Provider, len(tc.providers))
			errs := make([]error, len(tc.providers))
			for i, device := range tc.providers {
				ps[i], errs[i] = deviceProvider(t, tc.opts, device...)
			}
			tc.assert(t, ps, errs)
		})
	}
}

func TestUserCode_Normalise(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		device  []oidcprovider.DeviceOption
		entered string
		assert  func(t *testing.T, raw string, ok bool)
	}

	accepted := func(want string) func(t *testing.T, raw string, ok bool) {
		return func(t *testing.T, raw string, ok bool) {
			t.Helper()
			assert.True(t, ok)
			assert.Equal(t, want, raw)
		}
	}
	refused := func(t *testing.T, raw string, ok bool) {
		t.Helper()
		assert.False(t, ok)
		assert.Empty(t, raw)
	}
	lowerAlphabet := []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("bcdfghjkmnpqrstvwxz", 8)}

	cases := []testCase{
		{name: "lower case and a space", entered: "bcdf ghjk", assert: accepted("BCDFGHJK")},
		{name: "as shown", entered: "BCDF-GHJK", assert: accepted("BCDFGHJK")},
		{name: "spaces and dashes anywhere", entered: " bc-df gh jk ", assert: accepted("BCDFGHJK")},
		{name: "tabs, newlines and repeated dashes", entered: "\tBCDF--GHJK\r\n", assert: accepted("BCDFGHJK")},
		{name: "a no-break space", entered: "BCDF GHJK", assert: accepted("BCDFGHJK")},
		{name: "a vowel outside the alphabet", entered: "BCDA-GHJK", assert: refused},
		{name: "7 letters", entered: "BCDF-GHJ", assert: refused},
		{name: "9 letters", entered: "BCDF-GHJKL", assert: refused},
		{name: "empty", entered: "", assert: refused},
		{name: "only dashes and spaces", entered: " - - ", assert: refused},
		{name: "a non-ASCII letter", entered: "BCDF-GHJÉ", assert: refused},
		{name: "a long s, which Unicode upper-cases to S", entered: "BCDF-GHJſ", assert: refused},
		{name: "a Kelvin sign, which Unicode folds to K", entered: "BCDF-GHJK", assert: refused},
		{name: "invalid UTF-8", entered: "BCDF-GHJ\xff", assert: refused},
		{name: "a NUL", entered: "BCDF-GHJ\x00", assert: refused},
		{name: "a megabyte of a valid letter", entered: strings.Repeat("B", 1<<20), assert: refused},
		{name: "a lower-case alphabet is not upper-cased", device: lowerAlphabet, entered: "BCDFGHJK", assert: refused},
		{name: "a lower-case alphabet reads its own letters", device: lowerAlphabet, entered: "bcdf-ghjk", assert: accepted("bcdfghjk")},
		{
			name:    "a mixed-case alphabet is compared as entered",
			device:  []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("BCDFGHJKbcdfghjk", 8)},
			entered: "BCDF-ghjk",
			assert:  accepted("BCDFghjk"),
		},
		{
			name:    "digits pass through",
			device:  []oidcprovider.DeviceOption{oidcprovider.WithUserCodeFormat("0123456789", 9)},
			entered: "123-456-789",
			assert:  accepted("123456789"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := deviceProvider(t, nil, tc.device...)
			require.NoError(t, err)
			raw, ok := p.NormaliseUserCodeForTest(tc.entered)
			tc.assert(t, raw, ok)
		})
	}
}

func TestDeviceCodeHelpersWithoutTheGrant(t *testing.T) {
	t.Parallel()

	p, err := oidcprovider.New(validDeps(t))
	require.NoError(t, err)
	require.False(t, p.DeviceEnabled())

	code, err := p.GenerateUserCodeForTest()
	require.Error(t, err)
	assert.Empty(t, code)
	assert.Empty(t, p.DisplayUserCodeForTest("ABCDEFGH"))
	raw, ok := p.NormaliseUserCodeForTest("ABCD-EFGH")
	assert.False(t, ok)
	assert.Empty(t, raw)
	assert.Nil(t, p.UserCodeDigestForTest("ABCDEFGH"))
}
