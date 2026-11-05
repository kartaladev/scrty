package token_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token"
)

// TestGenerator_TokenType pins the typ header a generator declares, and that a
// first-party token cannot be given the type of another kind of token, however
// that type is spelled.
func TestGenerator_TokenType(t *testing.T) {
	t.Parallel()

	declares := func(typ string) func(t *testing.T, raw string, err error) {
		return func(t *testing.T, raw string, err error) {
			t.Helper()

			require.NoError(t, err)
			assert.Equal(t, typ, decodeHeader(t, raw)["typ"])
		}
	}
	refused := func(t *testing.T, raw string, err error) {
		t.Helper()

		require.ErrorIs(t, err, token.ErrConfig)
		assert.Empty(t, raw)
	}

	type testCase struct {
		name   string
		opts   []token.Option
		assert func(t *testing.T, raw string, err error)
	}

	cases := []testCase{
		{name: "the default is the first-party type", assert: declares("scrty+jwt")},
		{
			name:   "the default option names the same type",
			opts:   []token.Option{token.WithTokenType(token.TypeFirstParty)},
			assert: declares("scrty+jwt"),
		},
		{
			name:   "a consumer's own type replaces it",
			opts:   []token.Option{token.WithTokenType("app+jwt")},
			assert: declares("app+jwt"),
		},
		{name: "the access token's type is reserved", opts: []token.Option{token.WithTokenType("at+jwt")}, assert: refused},
		{name: "the ID token's type is reserved", opts: []token.Option{token.WithTokenType("JWT")}, assert: refused},
		{name: "the logout token's type is reserved", opts: []token.Option{token.WithTokenType("logout+jwt")}, assert: refused},
		{name: "a reserved type in another case is reserved", opts: []token.Option{token.WithTokenType("AT+JWT")}, assert: refused},
		{name: "the ID token's type in lower case is reserved", opts: []token.Option{token.WithTokenType("jwt")}, assert: refused},
		{
			name:   "a reserved type behind the media-type prefix is reserved",
			opts:   []token.Option{token.WithTokenType("application/at+jwt")},
			assert: refused,
		},
		{name: "an empty type is refused", opts: []token.Option{token.WithTokenType("")}, assert: refused},
		{name: "a blank type is refused", opts: []token.Option{token.WithTokenType(" \t")}, assert: refused},
		{name: "the media-type prefix alone is refused", opts: []token.Option{token.WithTokenType("application/")}, assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gen, err := token.NewGenerator(newKeySource(t), append([]token.Option{
				token.WithoutIssuer(), token.WithoutAudience(),
			}, tc.opts...)...)
			if err != nil {
				tc.assert(t, "", err)

				return
			}

			raw, err := gen.Generate(t.Context(), "s-1", alice())
			tc.assert(t, raw, err)
		})
	}
}
