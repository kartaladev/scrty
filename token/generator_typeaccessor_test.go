package token_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token"
)

// TestGenerator_TokenTypeAccessor pins that a generator reports the type it declares, as given.
func TestGenerator_TokenTypeAccessor(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []token.Option
		assert func(t *testing.T, g *token.JWTGenerator)
	}

	cases := []testCase{
		{
			name: "the default is the session token type",
			assert: func(t *testing.T, g *token.JWTGenerator) {
				assert.Equal(t, token.TypeSessionToken, g.TokenType())
			},
		},
		{
			name: "a consumer's own type is reported as given",
			opts: []token.Option{token.WithTokenType("App+JWT")},
			assert: func(t *testing.T, g *token.JWTGenerator) {
				assert.Equal(t, "App+JWT", g.TokenType())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g, err := token.NewGenerator(newKeySource(t), append([]token.Option{token.WithoutIssuer(), token.WithoutAudience()}, tc.opts...)...)
			require.NoError(t, err)
			tc.assert(t, g)
		})
	}
}
