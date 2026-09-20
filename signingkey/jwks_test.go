// The JWKS tests are split by what they establish rather than folded into one
// table: the document's shape is read from the parsed JSON, the
// private-material check is derived from the records the store holds, and the
// override case renders a second document from the port. The setups do not
// share a shape, so each keeps its own table.
package signingkey_test

import (
	"crypto/x509"
	"encoding/json"
	"slices"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

// publishedKeys returns the key objects of the document, decoded as plain JSON
// rather than through a JOSE library, so what is asserted is what an endpoint
// serving these bytes would actually send — parameters a jwk.Key would not
// round-trip included.
func publishedKeys(t *testing.T, doc []byte) []map[string]any {
	t.Helper()

	var document map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc, &document),
		"the document is a JSON object")

	raw, isSet := document["keys"]
	require.True(t, isSet, "an RFC 7517 JWK Set is a JSON object with a keys array")

	var keys []map[string]any
	require.NoError(t, json.Unmarshal(raw, &keys), "keys is an array of JWKs")

	return keys
}

// publishedKids lists the identifiers the document names, in the order it
// names them.
func publishedKids(t *testing.T, doc []byte) []string {
	t.Helper()

	keys := publishedKeys(t, doc)
	kids := make([]string, 0, len(keys))
	for _, key := range keys {
		kid, isString := key["kid"].(string)
		require.True(t, isString, "every entry carries a string kid, got %T", key["kid"])
		kids = append(kids, kid)
	}

	return kids
}

// memberNames lists the JSON member names a key renders to, which is what a
// published entry can be compared against parameter by parameter.
func memberNames(t *testing.T, key jwk.Key) []string {
	t.Helper()

	raw, err := json.Marshal(key)
	require.NoError(t, err)

	var members map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &members))

	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	slices.Sort(names)

	return names
}

// privateOnlyFields returns the JWK parameters that appear only when the
// private half of rec's key is rendered: it renders that half, renders the
// public half of the same key, and takes the difference.
//
// It is derived rather than listed so the check it feeds cannot go stale. A
// fixed list — "d", "p", "q", "dp", "dq", "qi" — names the parameters of the
// algorithms supported today, and the first algorithm added whose private half
// has a parameter outside it would be published in full while the test still
// passed.
func privateOnlyFields(t *testing.T, rec signingkey.Record) []string {
	t.Helper()

	raw, err := x509.ParsePKCS8PrivateKey(rec.Private)
	require.NoError(t, err, "the record holds the key as PKCS #8 DER")

	private, err := jwk.Import[jwk.Key](raw)
	require.NoError(t, err)

	public, err := private.PublicKey()
	require.NoError(t, err)

	publicNames := memberNames(t, public)
	secret := make([]string, 0, len(publicNames))
	for _, name := range memberNames(t, private) {
		if !slices.Contains(publicNames, name) {
			secret = append(secret, name)
		}
	}

	return secret
}

// assertNoPrivateMaterial fails for every parameter of a published entry that
// only the private half of that same key has.
//
// The records are read back from the store the manager minted into, so each
// published entry is compared against the very key it was rendered from rather
// than against an expectation written here.
func assertNoPrivateMaterial(t *testing.T, store signingkey.KeyStore, doc []byte) {
	t.Helper()

	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)

	byKid := make(map[string]signingkey.Record, len(recs))
	for _, rec := range recs {
		byKid[rec.Kid] = rec
	}

	for _, key := range publishedKeys(t, doc) {
		kid, _ := key["kid"].(string)
		rec, stored := byKid[kid]
		require.True(t, stored, "published key %q is one the store holds", kid)

		secret := privateOnlyFields(t, rec)
		require.NotEmpty(t, secret,
			"rendering the private half of the %s key found no parameter the public "+
				"half lacks, so the check below would pass whatever was published",
			rec.Alg)

		for _, name := range secret {
			assert.NotContains(t, key, name,
				"published key %q carries %q, which only the private half of a %s key has",
				kid, name, rec.Alg)
		}
	}

	set, err := jwk.Parse(doc)
	require.NoError(t, err)

	for _, key := range set.All() {
		isPrivate, privErr := jwk.IsPrivateKey(key)
		require.NoError(t, privErr)
		assert.False(t, isPrivate, "no published key is a private key")
	}
}

// renderSet builds a JWK Set document from keys the way a consumer with its
// own publishing rules would: it reads the port, and the port hands over kid,
// alg and a crypto.PublicKey, so nothing about obtaining the keys needs a JOSE
// library. Turning them into a document does, and that library is then the
// consumer's own choice rather than this package's.
func renderSet(t *testing.T, keys []signingkey.PublicKey) []byte {
	t.Helper()

	set := jwk.NewSet()
	for _, pk := range keys {
		key, err := jwk.Import[jwk.Key](pk.Key)
		require.NoError(t, err)
		require.NoError(t, key.Set(jwk.KeyIDKey, pk.Kid))
		require.NoError(t, key.Set(jwk.AlgorithmKey, pk.Alg))
		require.NoError(t, key.Set(jwk.KeyUsageKey, string(jwk.ForSignature)))
		require.NoError(t, set.AddKey(key))
	}

	doc, err := json.Marshal(set)
	require.NoError(t, err)

	return doc
}

// TestJWKSPublishesTheDocumentAnEndpointServes pins what a consumer writes to
// the wire: an RFC 7517 JWK Set naming every key the manager holds, in the
// order it holds them, each entry carrying the kid a token's header names, the
// algorithm it verifies and signature use.
//
// The order matters because a verifier caches the document, and a key that
// moves between two reads for no reason makes a cached copy look stale when it
// is not.
func TestJWKSPublishesTheDocumentAnEndpointServes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		manager func(t *testing.T) *signingkey.KeyManager
		assert  func(t *testing.T, km *signingkey.KeyManager, doc []byte, err error)
	}

	cases := []testCase{
		{
			name: "one entry per configured algorithm, each naming its key and its algorithm",
			manager: func(t *testing.T) *signingkey.KeyManager {
				km, err := signingkey.NewKeyManager(t.Context(),
					signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
					signingkey.WithAlgs(signingkey.RS256, signingkey.ES256),
				)
				require.NoError(t, err)

				return km
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, doc []byte, err error) {
				require.NoError(t, err)

				keys := publishedKeys(t, doc)
				require.Len(t, keys, 2)

				rsaKid := currentKid(t, km, signingkey.RS256)
				ecKid := currentKid(t, km, signingkey.ES256)
				assert.Equal(t, []string{rsaKid, ecKid}, publishedKids(t, doc),
					"the keys are published in the order they were held")

				assert.Equal(t, signingkey.RS256, keys[0]["alg"])
				assert.Equal(t, "RSA", keys[0]["kty"])
				assert.Equal(t, signingkey.ES256, keys[1]["alg"])
				assert.Equal(t, "EC", keys[1]["kty"])

				for _, key := range keys {
					assert.Equal(t, "sig", key["use"],
						"every entry declares signature use")
				}

				set, parseErr := jwk.Parse(doc)
				require.NoError(t, parseErr, "the JOSE stack parses what is published")
				assert.Equal(t, 2, set.Len())
			},
		},
		{
			name: "a key held for an algorithm this manager was not configured with is published too",
			manager: func(t *testing.T) *signingkey.KeyManager {
				// A replica configured for EdDSA wrote to the same store. Its
				// key never signs here, and publishing it is what verifies the
				// tokens that replica issued.
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
			assert: func(t *testing.T, km *signingkey.KeyManager, doc []byte, err error) {
				require.NoError(t, err)

				keys := publishedKeys(t, doc)
				require.Len(t, keys, 2,
					"the foreign key is published alongside the one this manager minted")

				assert.Equal(t, signingkey.EdDSA, keys[0]["alg"],
					"the stored key is held before the minted one, so it is published first")
				assert.Equal(t, "OKP", keys[0]["kty"])

				_, _, signs := km.GetSigner(signingkey.EdDSA)
				assert.False(t, signs, "publishing a foreign key is not signing with it")

				assert.Equal(t, currentKid(t, km, signingkey.RS256), keys[1]["kid"])
			},
		},
		{
			name: "the document names the same keys, in the same order, as the port reports",
			manager: func(t *testing.T) *signingkey.KeyManager {
				km, err := signingkey.NewKeyManager(t.Context(),
					signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
					signingkey.WithAlgs(signingkey.RS256, signingkey.ES256, signingkey.EdDSA),
				)
				require.NoError(t, err)

				return km
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, doc []byte, err error) {
				require.NoError(t, err)

				// Two views of one set of keys. A verifier reading the
				// document and this process verifying a token in hand must
				// agree on which keys exist, so they cannot be allowed to
				// drift apart.
				reported, keysErr := km.VerificationKeys()
				require.NoError(t, keysErr)
				assert.Equal(t, kidsOf(reported), publishedKids(t, doc))

				published := publishedKeys(t, doc)
				require.Len(t, published, len(reported))
				for i, key := range reported {
					assert.Equal(t, key.Alg, published[i]["alg"],
						"both views agree on what key %q verifies", key.Kid)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			km := tc.manager(t)

			doc, err := km.JWKS()
			tc.assert(t, km, doc, err)
		})
	}
}

// TestJWKSPublishesNoPrivateMaterial is the security-critical case: the
// document goes to anyone who asks for it, so a private parameter in it hands
// out the signing key itself and every token ever issued can then be forged.
//
// A rendering check alone would not catch that. A private JWK satisfies every
// kid, alg and use claim the test above makes, and it parses as a JWK Set, so
// what is asserted here is the parameters each entry carries, derived from the
// private half of that very key rather than listed.
func TestJWKSPublishesNoPrivateMaterial(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		algs   []signingkey.Alg
		assert func(t *testing.T, store signingkey.KeyStore, doc []byte, err error)
	}

	cases := []testCase{
		{
			name: "RS256 publishes its modulus and exponent only",
			algs: []signingkey.Alg{signingkey.RS256},
			assert: func(t *testing.T, store signingkey.KeyStore, doc []byte, err error) {
				require.NoError(t, err)
				require.Len(t, publishedKeys(t, doc), 1)
				assertNoPrivateMaterial(t, store, doc)
			},
		},
		{
			name: "ES256 publishes its coordinates only",
			algs: []signingkey.Alg{signingkey.ES256},
			assert: func(t *testing.T, store signingkey.KeyStore, doc []byte, err error) {
				require.NoError(t, err)
				require.Len(t, publishedKeys(t, doc), 1)
				assertNoPrivateMaterial(t, store, doc)
			},
		},
		{
			name: "EdDSA publishes its public point only",
			algs: []signingkey.Alg{signingkey.EdDSA},
			assert: func(t *testing.T, store signingkey.KeyStore, doc []byte, err error) {
				require.NoError(t, err)
				require.Len(t, publishedKeys(t, doc), 1)
				assertNoPrivateMaterial(t, store, doc)
			},
		},
		{
			name: "every supported algorithm at once",
			algs: []signingkey.Alg{signingkey.RS256, signingkey.ES256, signingkey.EdDSA},
			assert: func(t *testing.T, store signingkey.KeyStore, doc []byte, err error) {
				require.NoError(t, err)
				require.Len(t, publishedKeys(t, doc), 3,
					"one entry per algorithm, so no entry escapes the check below")
				assertNoPrivateMaterial(t, store, doc)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := signingkey.NewInMemoryKeyStore()
			km, err := signingkey.NewKeyManager(t.Context(),
				signingkey.WithKeyStore(store),
				signingkey.WithAlgs(tc.algs...),
			)
			require.NoError(t, err)

			doc, err := km.JWKS()
			tc.assert(t, store, doc, err)
		})
	}
}

// TestAConsumerPublishesItsOwnDocumentFromThePort pins that the document this
// package produces is a default and not the only one available. A consumer
// whose infrastructure needs something else — a filtered set, another order,
// extra JWK parameters, a wrapper object — renders it from VerificationKeys,
// which hands over kid, alg and a crypto.PublicKey and obliges the consumer to
// import nothing from a JOSE library to obtain them.
//
// The cheapest honest example is a filter: the manager publishes every key it
// holds, and a consumer that wants only the key it is signing with today
// cannot ask this package for that document.
func TestAConsumerPublishesItsOwnDocumentFromThePort(t *testing.T) {
	t.Parallel()

	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
		signingkey.WithAlgs(signingkey.RS256, signingkey.ES256),
	)
	require.NoError(t, err)

	doc, err := km.JWKS()
	require.NoError(t, err)
	require.Len(t, publishedKeys(t, doc), 2, "the default publishes every key held")

	// The consumer's own rule: publish the key currently signing RS256 and
	// nothing else.
	signing := currentKid(t, km, signingkey.RS256)
	reported, err := km.VerificationKeys()
	require.NoError(t, err)

	own := make([]signingkey.PublicKey, 0, len(reported))
	for _, key := range reported {
		if key.Kid == signing {
			own = append(own, key)
		}
	}
	require.Len(t, own, 1)

	consumerDoc := renderSet(t, own)

	set, err := jwk.Parse(consumerDoc)
	require.NoError(t, err, "what the consumer renders is still a JWK Set")
	assert.Equal(t, 1, set.Len())

	assert.Equal(t, []string{signing}, publishedKids(t, consumerDoc),
		"the consumer publishes the subset it chose")
	assert.Subset(t, publishedKids(t, doc), publishedKids(t, consumerDoc),
		"and chose it out of what the default publishes")
	assert.NotEqual(t, publishedKids(t, doc), publishedKids(t, consumerDoc),
		"which is a document this package deliberately does not produce")
}
