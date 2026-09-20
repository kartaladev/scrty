package signingkey_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

// rfc7638 computes the base64url-encoded SHA-256 JWK thumbprint of pub from
// first principles: the required members of the key's JWK, in lexicographic
// order, with no whitespace, hashed with SHA-256 (RFC 7638 section 3.1). It
// deliberately uses neither the library the implementation hashes with nor any
// helper the implementation calls, so agreement means the implementation is
// right, not merely self-consistent.
func rfc7638(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()

	b64 := base64.RawURLEncoding.EncodeToString

	var canonical string
	switch key := pub.(type) {
	case *rsa.PublicKey:
		canonical = `{"e":"` + b64(big.NewInt(int64(key.E)).Bytes()) +
			`","kty":"RSA","n":"` + b64(key.N.Bytes()) + `"}`
	case *ecdsa.PublicKey:
		// Bytes returns the uncompressed point 0x04 || x || y, which is where
		// a JWK's fixed-width coordinates come from.
		point, err := key.Bytes()
		require.NoError(t, err)
		require.Len(t, point, 65, "an uncompressed P-256 point")
		canonical = `{"crv":"P-256","kty":"EC","x":"` + b64(point[1:33]) +
			`","y":"` + b64(point[33:]) + `"}`
	case ed25519.PublicKey:
		canonical = `{"crv":"Ed25519","kty":"OKP","x":"` + b64(key) + `"}`
	default:
		t.Fatalf("unexpected public key type %T", pub)
	}

	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:])
}

func TestKidIsThumbprint(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		alg  signingkey.Alg
	}

	cases := []testCase{
		{name: "RS256", alg: signingkey.RS256},
		{name: "ES256", alg: signingkey.ES256},
		{name: "EdDSA", alg: signingkey.EdDSA},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			km, err := signingkey.NewKeyManager(t.Context(),
				signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
				signingkey.WithAlgs(tc.alg),
			)
			require.NoError(t, err)

			kid, signer, ok := km.GetSigner(tc.alg)
			require.True(t, ok)
			assert.Equal(t, rfc7638(t, signer.Public()), kid,
				"the key identifier is the RFC 7638 SHA-256 thumbprint of the public key")

			set := publishedSet(t, km)
			require.Equal(t, 1, set.Len())

			published, found := set.LookupKeyID(kid)
			require.True(t, found, "the published key is found by its thumbprint")

			publishedKid, hasKid := published.KeyID()
			require.True(t, hasKid)
			assert.Equal(t, rfc7638(t, signer.Public()), publishedKid)

			alg, hasAlg := published.Algorithm()
			require.True(t, hasAlg, "a published key declares its algorithm")
			assert.Equal(t, tc.alg, alg.String())

			use, hasUse := published.KeyUsage()
			require.True(t, hasUse, "a published key declares its use")
			assert.Equal(t, "sig", use)

			isPrivate, err := jwk.IsPrivateKey(published)
			require.NoError(t, err)
			assert.False(t, isPrivate, "a published key carries no private material")
		})
	}
}
