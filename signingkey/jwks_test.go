package signingkey_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

// TestJWKSPublishesPublicKeysOnly asserts on the serialized set — the bytes a
// verifier would actually receive — and on the structure of each key. A
// rendering check alone would not do: a published private JWK satisfies every
// kid, alg and use claim, so the private-parameter names and jwk.IsPrivateKey
// are what catch it.
func TestJWKSPublishesPublicKeysOnly(t *testing.T) {
	t.Parallel()

	km, err := signingkey.NewKeyManager(
		signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
		signingkey.WithAlgs(signingkey.RS256, signingkey.ES256),
	)
	require.NoError(t, err)

	set, err := km.JWKS()
	require.NoError(t, err)
	require.Equal(t, 2, set.Len())

	for _, key := range set.All() {
		isPrivate, privErr := jwk.IsPrivateKey(key)
		require.NoError(t, privErr)
		assert.False(t, isPrivate, "no published key is a private key")
	}

	raw, err := json.Marshal(set)
	require.NoError(t, err)

	var published struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(raw, &published))
	require.Len(t, published.Keys, 2)

	algs := make([]string, 0, len(published.Keys))
	for _, key := range published.Keys {
		assert.NotEmpty(t, key["kid"], "every entry carries its key identifier")
		assert.NotEmpty(t, key["alg"], "every entry declares its algorithm")
		assert.Equal(t, "sig", key["use"], "every entry declares signature use")

		alg, ok := key["alg"].(string)
		require.True(t, ok, "alg is a string, got %T", key["alg"])
		algs = append(algs, alg)

		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			assert.NotContains(t, key, private,
				"no private parameter may be published, found %q in %v", private, key["kid"])
		}
	}
	assert.ElementsMatch(t, []string{signingkey.RS256, signingkey.ES256}, algs)
}
