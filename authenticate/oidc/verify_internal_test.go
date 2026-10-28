package oidc

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The signed-token path cannot carry invalid UTF-8 into readAssurance, because
// the token parser refuses such a payload first. readAssurance still defends
// itself, since a value no durable store can hold must never read as asserted,
// so it is tested here on a token built in memory.
func TestReadAssurance_UnstorableValues(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		claims map[string]any
		assert func(t *testing.T, amr []string, acr string, badAMR, badACR bool)
	}

	cases := []testCase{
		{
			name:   "an amr element that is invalid UTF-8 is malformed and asserts nothing",
			claims: map[string]any{"amr": []any{"pwd", "mfa\xff\xfe"}},
			assert: func(t *testing.T, amr []string, acr string, badAMR, badACR bool) {
				assert.Nil(t, amr)
				assert.Empty(t, acr)
				assert.True(t, badAMR)
				assert.False(t, badACR)
			},
		},
		{
			name:   "an acr that is invalid UTF-8 is malformed and asserts nothing",
			claims: map[string]any{"acr": "gold\xff"},
			assert: func(t *testing.T, amr []string, acr string, badAMR, badACR bool) {
				assert.Nil(t, amr)
				assert.Empty(t, acr)
				assert.False(t, badAMR)
				assert.True(t, badACR)
			},
		},
		{
			name:   "valid multi-byte UTF-8 is still asserted",
			claims: map[string]any{"amr": []any{"mfä"}, "acr": "gold-é"},
			assert: func(t *testing.T, amr []string, acr string, badAMR, badACR bool) {
				assert.Equal(t, []string{"mfä"}, amr)
				assert.Equal(t, "gold-é", acr)
				assert.False(t, badAMR)
				assert.False(t, badACR)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tok := jwt.New()
			for k, v := range tc.claims {
				require.NoError(t, tok.Set(k, v))
			}

			amr, acr, badAMR, badACR := readAssurance(tok)
			tc.assert(t, amr, acr, badAMR, badACR)
		})
	}
}
