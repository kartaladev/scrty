package session_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

func TestValidIdentifier(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		value  func(t *testing.T) string
		assert func(t *testing.T, valid bool)
	}

	valid := func(t *testing.T, ok bool) {
		t.Helper()
		assert.True(t, ok)
	}

	invalid := func(t *testing.T, ok bool) {
		t.Helper()
		assert.False(t, ok)
	}

	fixed := func(v string) func(*testing.T) string {
		return func(*testing.T) string { return v }
	}

	cases := []testCase{
		{
			name: "an identifier the manager issued",
			value: func(t *testing.T) string {
				s, err := managerFor(t).Create(t.Context(), testUser)
				require.NoError(t, err)

				return s.ID
			},
			assert: valid,
		},
		{name: "43 characters of the URL-safe alphabet", value: fixed(strings.Repeat("A-_z", 10) + "Az0"), assert: valid},
		{name: "empty", value: fixed(""), assert: invalid},
		{name: "one character short", value: fixed(strings.Repeat("A", 42)), assert: invalid},
		{name: "one character long", value: fixed(strings.Repeat("A", 44)), assert: invalid},
		{name: "standard base64's plus", value: fixed(strings.Repeat("A", 42) + "+"), assert: invalid},
		{name: "standard base64's slash", value: fixed("/" + strings.Repeat("A", 42)), assert: invalid},
		{name: "padding", value: fixed(strings.Repeat("A", 42) + "="), assert: invalid},
		{name: "a space", value: fixed(strings.Repeat("A", 21) + " " + strings.Repeat("A", 21)), assert: invalid},
		{name: "a dot, as in a signed token", value: fixed(strings.Repeat("A", 21) + "." + strings.Repeat("A", 21)), assert: invalid},
		{name: "a line feed, which the decoder skips", value: fixed(strings.Repeat("A", 21) + "\n" + strings.Repeat("A", 21)), assert: invalid},
		{name: "a multi-byte character", value: fixed(strings.Repeat("A", 41) + "é"), assert: invalid},
		{
			// The last character carries 4 bits of the 32nd byte and 2 zero
			// bits; a strict decoder refuses one whose spare bits are set.
			name:   "a final character with its spare bits set",
			value:  fixed(strings.Repeat("A", 42) + "B"),
			assert: invalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, session.ValidIdentifier(tc.value(t)))
		})
	}
}
