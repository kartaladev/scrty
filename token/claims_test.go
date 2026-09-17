package token_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token"
)

// fakeVerifier is the shape a consumer's own Verifier takes: a fake in their
// tests, a shim over a different JOSE stack, or a wrapper around a remote
// introspection endpoint. It is written here, in the external test package,
// because that is the only view that shows what a consumer can actually build.
type fakeVerifier struct{ claims *token.Claims }

func (f fakeVerifier) Verify(context.Context, string) (*token.Claims, error) {
	return f.claims, nil
}

// TestConsumerCanSubstituteTheVerifierPort pins that Verifier is a port a
// consumer can actually implement. It is exported, and the design names a
// consumer's own Verifier as the override point, so a consumer has to be able
// to produce the Claims their own code then reads.
func TestConsumerCanSubstituteTheVerifierPort(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		claims func() *token.Claims
		assert func(t *testing.T, claims *token.Claims)
	}

	cases := []testCase{
		{
			// The zero value of an exported type must be usable, and this one
			// is reachable from outside the package whether or not it is
			// meant to be.
			name:   "the zero value reports empty rather than panicking",
			claims: func() *token.Claims { return &token.Claims{} },
			assert: func(t *testing.T, claims *token.Claims) {
				assert.Empty(t, claims.Subject())
				assert.Empty(t, claims.ID())
			},
		},
		{
			name:   "claims an alternative verifier reports are readable",
			claims: func() *token.Claims { return token.NewClaims("alice", "s-1") },
			assert: func(t *testing.T, claims *token.Claims) {
				assert.Equal(t, "alice", claims.Subject())
				assert.Equal(t, "s-1", claims.ID())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var ver token.Verifier = fakeVerifier{claims: tc.claims()}

			claims, err := ver.Verify(t.Context(), "whatever the substitute accepts")
			require.NoError(t, err)
			require.NotNil(t, claims)

			assert.NotPanics(t, func() { tc.assert(t, claims) })
		})
	}
}
