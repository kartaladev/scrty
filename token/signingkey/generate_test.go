// F2 to F4 are boundary tests for the stored rows this package does not
// control, which another writer may have produced. Each one was written against
// a defect it reproduced, and each is proven by a mutation that makes it fail.
package signingkey_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token/signingkey"
)

func auditStore(t *testing.T, recs ...signingkey.Record) signingkey.KeyStore {
	t.Helper()
	store := signingkey.NewMemoryKeyStore()
	for _, rec := range recs {
		require.NoError(t, store.Store(t.Context(), rec))
	}
	return store
}

func auditDER(t *testing.T, key any) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return b
}

// TestStoredRecord constructs a manager over a store holding one record another
// writer produced, and pins that a record the manager cannot honour is refused
// or never signs. Not parallel, like the other boundary tests.
func TestStoredRecord(t *testing.T) {
	type testCase struct {
		name string
		// record returns the one record the store holds.
		record func(t *testing.T) signingkey.Record
		opts   []signingkey.Option
		assert func(t *testing.T, rec signingkey.Record, km *signingkey.Keys, err error)
	}

	cases := []testCase{
		{
			// F2 — a stored record's Alg is never checked against the key it
			// names, so the manager becomes current with a key it cannot sign
			// with.
			name: "alg must match its key",
			record: func(t *testing.T) signingkey.Record {
				rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return signingkey.Record{
					Kid: "lies", Alg: signingkey.ES256, Private: auditDER(t, rsaKey),
					CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
				}
			},
			opts: []signingkey.Option{signingkey.WithAlgs(signingkey.ES256)},
			assert: func(t *testing.T, _ signingkey.Record, km *signingkey.Keys, err error) {
				require.Error(t, err,
					"an RSA key recorded as ES256 must be refused at construction")
				assert.Nil(t, km)
			},
		},
		{
			// F2b — the same gap for the curve: ES256 is P-256 only, and a
			// P-384 key is adopted and signs under an "alg":"ES256" header with
			// a 96-byte signature.
			name: "es256 key must be p256",
			record: func(t *testing.T) signingkey.Record {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return signingkey.Record{
					Kid: "p384", Alg: signingkey.ES256, Private: auditDER(t, key),
					CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
				}
			},
			opts: []signingkey.Option{signingkey.WithAlgs(signingkey.ES256)},
			assert: func(t *testing.T, _ signingkey.Record, km *signingkey.Keys, err error) {
				if err != nil {
					return // refused, which is what this test asks for
				}

				_, signer, ok := km.Signer(signingkey.ES256)
				require.True(t, ok)
				signed, err := jws.Sign([]byte(`{"sub":"x"}`),
					jws.WithKey(auditAlg(t, signingkey.ES256), signer))
				require.NoError(t, err)

				parts := strings.Split(string(signed), ".")
				require.Len(t, parts, 3)
				sig, err := base64.RawURLEncoding.DecodeString(parts[2])
				require.NoError(t, err)
				assert.Len(t, sig, 64,
					"an ES256 signature is two 32-byte integers (RFC 7518 3.4); this key is not P-256")
			},
		},
		{
			// F3 — a stored record naming an algorithm scrty cannot produce is
			// adopted, made current, and published.
			name: "alg must be supported",
			record: func(t *testing.T) signingkey.Record {
				rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return signingkey.Record{
					Kid: "hs", Alg: "HS256", Private: auditDER(t, rsaKey),
					CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
				}
			},
			assert: func(t *testing.T, _ signingkey.Record, km *signingkey.Keys, err error) {
				if err != nil {
					return // refused, which is what this test asks for
				}

				_, _, ok := km.Signer("HS256")
				assert.False(t, ok,
					"the manager offers no signer for an algorithm WithAlgs would have refused")

				published, err := km.VerificationKeys()
				require.NoError(t, err)
				for _, key := range published {
					assert.NotEqual(t, "HS256", key.Alg,
						"no published key declares an algorithm scrty does not support: %q", key.Kid)
				}
			},
		},
		{
			// F4 — the private half can be swapped under a record's recorded
			// Kid and PublicJWK, and construction accepts it, republishing
			// under a different kid.
			name: "kid must match its private key",
			record: func(t *testing.T) signingkey.Record {
				genuine := realRecord(t, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))

				other, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				swapped := genuine
				swapped.Private = auditDER(t, other)
				return swapped
			},
			assert: func(t *testing.T, swapped signingkey.Record, km *signingkey.Keys, err error) {
				if err != nil {
					return // refused, which is what this test asks for
				}

				kid, _, ok := km.Signer(signingkey.RS256)
				require.True(t, ok)
				assert.Equal(t, swapped.Kid, kid,
					"a record is either refused or held under the identifier it carries; "+
						"it is never silently republished under a different one")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := tc.record(t)

			km, err := signingkey.New(t.Context(),
				append([]signingkey.Option{signingkey.WithKeyStore(auditStore(t, rec))}, tc.opts...)...)
			tc.assert(t, rec, km, err)
		})
	}
}

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

			km, err := signingkey.New(t.Context(),
				signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
				signingkey.WithAlgs(tc.alg),
			)
			require.NoError(t, err)

			kid, signer, ok := km.Signer(tc.alg)
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
