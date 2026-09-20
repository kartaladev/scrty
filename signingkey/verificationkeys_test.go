package signingkey_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

// publishes reports whether source publishes kid. It takes the port rather
// than the manager so a consumer's own key source can be asked the same
// question, and it is safe to call from a polling closure: keys that cannot
// be obtained count as not publishing it.
func publishes(source signingkey.KeySource, kid string) bool {
	keys, err := source.VerificationKeys()
	if err != nil {
		return false
	}

	for _, key := range keys {
		if key.Kid == kid {
			return true
		}
	}

	return false
}

// publishedSet renders what source publishes as the key set the JOSE stack
// verifies against, the way a consumer that speaks JOSE would.
//
// It lives in the tests because the package itself no longer builds one:
// KeySource describes its keys with standard-library types, so turning them
// into a JOSE library's own is the job of whatever needs that library.
func publishedSet(t *testing.T, source signingkey.KeySource) jwk.Set {
	t.Helper()

	published, err := source.VerificationKeys()
	require.NoError(t, err)

	set := jwk.NewSet()
	for _, pk := range published {
		key, importErr := jwk.Import[jwk.Key](pk.Key)
		require.NoError(t, importErr)
		require.NoError(t, key.Set(jwk.KeyIDKey, pk.Kid))
		require.NoError(t, key.Set(jwk.AlgorithmKey, pk.Alg))
		require.NoError(t, key.Set(jwk.KeyUsageKey, string(jwk.ForSignature)))
		require.NoError(t, set.AddKey(key))
	}

	return set
}

// kidsOf lists the identifiers a source published, in the order it published
// them, so a case can assert the order without repeating the loop.
func kidsOf(keys []signingkey.PublicKey) []string {
	kids := make([]string, 0, len(keys))
	for _, key := range keys {
		kids = append(kids, key.Kid)
	}

	return kids
}

// TestVerificationKeysPublishesThePublicHalfOfEveryHeldKey pins what the
// manager hands a verifier: one entry per key it holds, in the order it holds
// them, each naming the key and the algorithm it verifies, and each carrying
// public material only.
//
// The order matters because it is the one a consumer's own publisher would
// render a key set in, and a key that moves between two reads for no reason
// makes a cached set look stale when it is not.
func TestVerificationKeysPublishesThePublicHalfOfEveryHeldKey(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		manager func(t *testing.T) *signingkey.KeyManager
		assert  func(t *testing.T, km *signingkey.KeyManager, keys []signingkey.PublicKey, err error)
	}

	cases := []testCase{
		{
			name: "one entry per configured algorithm, naming the key that signs for it",
			manager: func(t *testing.T) *signingkey.KeyManager {
				km, err := signingkey.NewKeyManager(t.Context(),
					signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
					signingkey.WithAlgs(signingkey.RS256, signingkey.ES256),
				)
				require.NoError(t, err)

				return km
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, keys []signingkey.PublicKey, err error) {
				require.NoError(t, err)
				require.Len(t, keys, 2)

				rsaKid := currentKid(t, km, signingkey.RS256)
				ecKid := currentKid(t, km, signingkey.ES256)
				assert.Equal(t, []string{rsaKid, ecKid}, kidsOf(keys),
					"the keys are published in the order they were held")

				assert.Equal(t, signingkey.RS256, keys[0].Alg)
				assert.IsType(t, &rsa.PublicKey{}, keys[0].Key)

				assert.Equal(t, signingkey.ES256, keys[1].Alg)
				assert.IsType(t, &ecdsa.PublicKey{}, keys[1].Key)
			},
		},
		{
			name: "a key held for an algorithm this manager was not configured with is published too",
			manager: func(t *testing.T) *signingkey.KeyManager {
				// A replica configured for EdDSA wrote to the same store. Its
				// key never signs here, but publishing it is what lets this
				// manager verify the tokens that replica issued.
				foreign := realRecordFor(t, signingkey.EdDSA, epoch)
				store := signingkey.NewInMemoryKeyStore()
				require.NoError(t, store.Store(t.Context(), foreign))

				km, err := signingkey.NewKeyManager(t.Context(),
					signingkey.WithKeyStore(store),
					signingkey.WithAlgs(signingkey.RS256),
				)
				require.NoError(t, err)

				return km
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, keys []signingkey.PublicKey, err error) {
				require.NoError(t, err)
				require.Len(t, keys, 2,
					"the foreign key is published alongside the one this manager minted")

				assert.Equal(t, signingkey.EdDSA, keys[0].Alg,
					"the stored key is held before the minted one, so it is published first")
				assert.IsType(t, ed25519.PublicKey{}, keys[0].Key)

				_, _, signs := km.GetSigner(signingkey.EdDSA)
				assert.False(t, signs, "publishing a foreign key is not signing with it")

				assert.Equal(t, currentKid(t, km, signingkey.RS256), keys[1].Kid)
			},
		},
		{
			name: "no published key can sign",
			manager: func(t *testing.T) *signingkey.KeyManager {
				km, err := signingkey.NewKeyManager(t.Context(),
					signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
					signingkey.WithAlgs(signingkey.RS256, signingkey.ES256, signingkey.EdDSA),
				)
				require.NoError(t, err)

				return km
			},
			assert: func(t *testing.T, _ *signingkey.KeyManager, keys []signingkey.PublicKey, err error) {
				require.NoError(t, err)
				require.Len(t, keys, 3)

				for _, key := range keys {
					// Every private key this package can produce is a
					// crypto.Signer and no public half is, so this catches a
					// whole private key handed over where its public part was
					// meant, whatever its type.
					_, signs := key.Key.(crypto.Signer)
					assert.False(t, signs,
						"key %q is a signer, so private material left the manager", key.Kid)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			km := tc.manager(t)

			keys, err := km.VerificationKeys()
			tc.assert(t, km, keys, err)
		})
	}
}

// TestVerificationKeysDoNotShareKeyMaterialWithTheManager pins that a caller
// is handed its own copy of every key.
//
// A crypto.PublicKey is a pointer or a slice into structure the manager's own
// key is built from: an *rsa.PublicKey shares its modulus, an *ecdsa.PublicKey
// its coordinates, an ed25519.PublicKey its bytes. Handing the live value over
// lets a caller that normalises, caches or simply reuses what it was given
// rewrite the key the manager verifies with, and every token signed by that
// key then fails to verify for everyone.
//
// Each case corrupts the key it was handed and asks the manager again. The
// second answer is what the manager still publishes.
func TestVerificationKeysDoNotShareKeyMaterialWithTheManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		alg  signingkey.Alg
		// corrupt writes to the key the caller was handed, as a caller
		// reusing the value it was given would.
		corrupt func(t *testing.T, key crypto.PublicKey)
	}

	cases := []testCase{
		{
			name: "RS256 shares its modulus",
			alg:  signingkey.RS256,
			corrupt: func(t *testing.T, key crypto.PublicKey) {
				pub, ok := key.(*rsa.PublicKey)
				require.True(t, ok, "expected an *rsa.PublicKey, got %T", key)
				pub.N.SetInt64(1)
			},
		},
		{
			name: "ES256 shares its coordinates",
			alg:  signingkey.ES256,
			corrupt: func(t *testing.T, key crypto.PublicKey) {
				pub, ok := key.(*ecdsa.PublicKey)
				require.True(t, ok, "expected an *ecdsa.PublicKey, got %T", key)
				pub.X.SetInt64(1) //nolint:staticcheck // SA1019: corrupting the coordinate is the point
			},
		},
		{
			name: "EdDSA shares its bytes",
			alg:  signingkey.EdDSA,
			corrupt: func(t *testing.T, key crypto.PublicKey) {
				pub, ok := key.(ed25519.PublicKey)
				require.True(t, ok, "expected an ed25519.PublicKey, got %T", key)
				require.NotEmpty(t, pub)
				pub[0] ^= 0xFF
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			km, err := signingkey.NewKeyManager(t.Context(),
				signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
				signingkey.WithAlgs(tc.alg),
			)
			require.NoError(t, err)

			// want is read before anything is written to, and is a value, not
			// a handle, so no assertion below can be satisfied by comparing
			// corrupted material with itself.
			before, err := km.VerificationKeys()
			require.NoError(t, err)
			require.Len(t, before, 1)
			want := publicKeyBytes(t, before[0].Key)

			handed, err := km.VerificationKeys()
			require.NoError(t, err)
			require.Len(t, handed, 1)
			tc.corrupt(t, handed[0].Key)

			after, err := km.VerificationKeys()
			require.NoError(t, err,
				"a manager that shared its key material cannot publish at all once a caller has written to it")
			require.Len(t, after, 1)
			assert.Equal(t, want, publicKeyBytes(t, after[0].Key),
				"a caller writing to a key it was handed must not change the key the manager publishes")

			_, signer, ok := km.GetSigner(tc.alg)
			require.True(t, ok)
			assert.Equal(t, want, publicKeyBytes(t, signer.Public()),
				"nor the public half of the key the manager still signs with")
		})
	}
}

// publicKeyBytes renders a public key as the bytes that identify it, so an
// assertion compares material rather than two pointers into the same
// structure — which would agree however corrupted that structure is.
//
// An ECDSA key is rendered by PublicKey.Bytes, which reads the coordinates as
// they are now and refuses a point that is not on its curve. A key that fails
// to encode is therefore a key something has already written through, which is
// the very failure these cases look for, so it is reported here rather than
// compared.
func publicKeyBytes(t *testing.T, key crypto.PublicKey) []byte {
	t.Helper()

	switch pub := key.(type) {
	case *rsa.PublicKey:
		return pub.N.Bytes()
	case *ecdsa.PublicKey:
		encoded, err := pub.Bytes()
		require.NoError(t, err,
			"an ECDSA key that no longer encodes has had its coordinates rewritten")

		return encoded
	case ed25519.PublicKey:
		return []byte(pub)
	default:
		t.Fatalf("unexpected public key type %T", key)

		return nil
	}
}
