package passkey_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/passkey"
)

func TestNormaliseName(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 10, 1, 23, 30, 0, 0, time.UTC)
	const dateName = "Passkey 2026-10-01"

	type testCase struct {
		name   string
		raw    string
		assert func(t *testing.T, got string)
	}

	is := func(want string) func(t *testing.T, got string) {
		return func(t *testing.T, got string) {
			t.Helper()
			assert.Equal(t, want, got)
		}
	}

	sixtyFour := strings.Repeat("é", 64)

	cases := []testCase{
		{name: "trimmed", raw: " Work laptop ", assert: is("Work laptop")},
		{name: "64 runes kept", raw: sixtyFour, assert: is(sixtyFour)},
		{name: "65 runes replaced", raw: sixtyFour + "x", assert: is(dateName)},
		{name: "200 characters replaced", raw: strings.Repeat("a", 200), assert: is(dateName)},
		{name: "newline replaced", raw: "a\nb", assert: is(dateName)},
		{name: "other control character replaced", raw: "a\u007fb", assert: is(dateName)},
		{name: "invalid UTF-8 replaced", raw: "a\xffb", assert: is(dateName)},
		{name: "empty replaced", raw: "", assert: is(dateName)},
		{name: "blank replaced", raw: " \t ", assert: is(dateName)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, passkey.NormaliseName(tc.raw, created))
		})
	}
}

func TestDecodeChallenge(t *testing.T) {
	t.Parallel()

	// A token string whose bytes encode to '-' and '_' in base64url, and to
	// '+' and '/' in standard base64, and that needs padding.
	const token = "pk~>?\xfb\xff"

	type testCase struct {
		name   string
		in     string
		assert func(t *testing.T, got string, err error)
	}

	refused := func(t *testing.T, got string, err error) {
		t.Helper()
		require.Error(t, err)
		assert.Empty(t, got)
	}

	cases := []testCase{
		{
			name: "round trips raw base64url",
			in:   base64.RawURLEncoding.EncodeToString([]byte("passkey-registration.abc")),
			assert: func(t *testing.T, got string, err error) {
				require.NoError(t, err)
				assert.Equal(t, "passkey-registration.abc", got)
			},
		},
		{
			name: "round trips URL alphabet",
			in:   base64.RawURLEncoding.EncodeToString([]byte(token)),
			assert: func(t *testing.T, got string, err error) {
				require.NoError(t, err)
				assert.Equal(t, token, got)
			},
		},
		{name: "padded refused", in: base64.URLEncoding.EncodeToString([]byte(token)), assert: refused},
		{name: "standard alphabet refused", in: base64.RawStdEncoding.EncodeToString([]byte(token)), assert: refused},
		{name: "empty refused", in: "", assert: refused},
		{name: "garbage refused", in: "not base64!", assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := passkey.DecodeChallenge(tc.in)
			tc.assert(t, got, err)
		})
	}
}
