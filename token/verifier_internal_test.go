// These tests are white-box, in package token: each pins one header check on its
// own. Through the public path another check, or the JOSE stack's own algorithm
// match, refuses the same token, so no public test fails when one of them goes.
package token

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token/signingkey"
)

func TestTokenHeader_MatchesKey(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		header tokenHeader
		keys   []signingkey.PublicKey
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorIs(t, err, errOtherAlgorithm)
	}
	passed := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err)
	}

	cases := []testCase{
		{
			name:   "an algorithm equal to the key's passes",
			header: tokenHeader{alg: "RS256", kid: "k1"},
			keys:   []signingkey.PublicKey{{Kid: "k1", Alg: "RS256"}},
			assert: passed,
		},
		{
			name:   "an algorithm differing from the key's under the kid is refused",
			header: tokenHeader{alg: "RS384", kid: "k1"},
			keys:   []signingkey.PublicKey{{Kid: "k1", Alg: "RS256"}},
			assert: refused,
		},
		{
			name:   "two keys under one kid, one differing, is refused",
			header: tokenHeader{alg: "RS256", kid: "k1"},
			keys:   []signingkey.PublicKey{{Kid: "k1", Alg: "RS256"}, {Kid: "k1", Alg: "ES256"}},
			assert: refused,
		},
		{
			name:   "a differing key under another kid is left alone",
			header: tokenHeader{alg: "RS256", kid: "k1"},
			keys:   []signingkey.PublicKey{{Kid: "k1", Alg: "RS256"}, {Kid: "k2", Alg: "ES256"}},
			assert: passed,
		},
		{
			name:   "an unknown kid is left to the JOSE stack",
			header: tokenHeader{alg: "RS384", kid: "unknown"},
			keys:   []signingkey.PublicKey{{Kid: "k1", Alg: "RS256"}},
			assert: passed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.header.matchesKey(tc.keys))
		})
	}
}

func TestReadHeader_RequiresAlgorithm(t *testing.T) {
	t.Parallel()

	compact := func(header string) string {
		enc := base64.RawURLEncoding
		return enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString([]byte(`{}`)) + "." + enc.EncodeToString([]byte("sig"))
	}

	type testCase struct {
		name   string
		header string
		assert func(t *testing.T, h tokenHeader, err error)
	}

	cases := []testCase{
		{
			name:   "a header naming its algorithm is read",
			header: `{"alg":"RS256","kid":"k1","typ":"JWT"}`,
			assert: func(t *testing.T, h tokenHeader, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "RS256", h.alg)
				assert.Equal(t, "k1", h.kid)
			},
		},
		{
			name:   "a header with no alg is refused",
			header: `{"kid":"k1","typ":"JWT"}`,
			assert: func(t *testing.T, _ tokenHeader, err error) {
				t.Helper()
				require.ErrorIs(t, err, ErrInvalid)
				require.ErrorIs(t, err, errNoAlgorithm)
			},
		},
		{
			name:   "a header with an empty alg is refused",
			header: `{"alg":"","kid":"k1","typ":"JWT"}`,
			assert: func(t *testing.T, _ tokenHeader, err error) {
				t.Helper()
				require.ErrorIs(t, err, ErrInvalid)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h, err := readHeader(compact(tc.header))
			tc.assert(t, h, err)
		})
	}
}
