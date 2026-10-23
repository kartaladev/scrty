package token_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/token"
)

// nilKeyVerificationSource is a consumer key source whose published key is a
// nil value inside a non-nil interface: the shape an unchecked constructor
// error leaves behind.
type nilKeyVerificationSource struct {
	signingkey.KeySource

	alg signingkey.Alg
	key any
}

func (s nilKeyVerificationSource) VerificationKeys() ([]signingkey.PublicKey, error) {
	return []signingkey.PublicKey{{Kid: "k-1", Alg: s.alg, Key: s.key}}, nil
}

func TestVerify_NilPublicKeyIsAnUnusableKeySet(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		source nilKeyVerificationSource
		assert func(t *testing.T, claims *token.Claims, err error)
	}

	unusable := func(t *testing.T, claims *token.Claims, err error) {
		require.Error(t, err)
		assert.NotErrorIs(t, err, token.ErrTokenInvalid,
			"an unusable key set is an outage, not a verdict on the token")
		assert.Nil(t, claims)
	}

	cases := []testCase{
		{
			name:   "a typed-nil RSA public key",
			source: nilKeyVerificationSource{alg: signingkey.RS256, key: (*rsa.PublicKey)(nil)},
			assert: unusable,
		},
		{
			name:   "a typed-nil ECDSA public key",
			source: nilKeyVerificationSource{alg: signingkey.ES256, key: (*ecdsa.PublicKey)(nil)},
			assert: unusable,
		},
		{
			name:   "a nil Ed25519 public key",
			source: nilKeyVerificationSource{alg: signingkey.EdDSA, key: ed25519.PublicKey(nil)},
			assert: unusable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gen, err := token.NewGenerator(newKeySource(t))
			require.NoError(t, err)
			raw, err := gen.Generate(t.Context(), "s-1", alice())
			require.NoError(t, err)

			ver, err := token.NewVerifier(token.VerifyWithKeySource(tc.source))
			require.NoError(t, err)

			var (
				claims *token.Claims
				verr   error
			)
			require.NotPanics(t, func() { claims, verr = ver.Verify(t.Context(), raw) })

			tc.assert(t, claims, verr)
		})
	}
}
