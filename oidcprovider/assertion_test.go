package oidcprovider_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/clock"
)

const (
	keyClientID   = "key-client"
	tokenEndpoint = issuer + "/oauth2/token"
	movedEndpoint = issuer + "/api/oauth/token"
	assertionKind = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	esKid = "es-1"
	rsKid = "rs-1"
	edKid = "ed-1"
)

// The client's keys, and a stranger's, generated once because RSA takes a while.
var (
	testRSAKey = sync.OnceValue(func() *rsa.PrivateKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		return k
	})
	testECKey = sync.OnceValue(func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		return k
	})
	strangerECKey = sync.OnceValue(func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		return k
	})
	testEdKey = sync.OnceValue(func() ed25519.PrivateKey {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}

		return k
	})
)

// publicKey is one entry of a key set: a raw public key, its kid, and an optional alg.
type publicKey struct {
	raw any
	kid string
	alg string
	ops []jwk.KeyOperation // key_ops, when non-empty
}

// publicSet renders a JWKS.
func publicSet(t *testing.T, keys ...publicKey) []byte {
	t.Helper()

	encoded := make([]json.RawMessage, 0, len(keys))
	for _, k := range keys {
		key, err := jwk.Import[jwk.Key](k.raw)
		require.NoError(t, err)
		if k.kid != "" {
			require.NoError(t, key.Set(jwk.KeyIDKey, k.kid))
		}
		if k.alg != "" {
			alg, ok := jwa.LookupSignatureAlgorithm(k.alg)
			require.True(t, ok)
			require.NoError(t, key.Set(jwk.AlgorithmKey, alg))
		}
		if len(k.ops) > 0 {
			require.NoError(t, key.Set(jwk.KeyOpsKey, jwk.KeyOperationList(k.ops)))
		}
		raw, err := json.Marshal(key)
		require.NoError(t, err)
		encoded = append(encoded, raw)
	}
	out, err := json.Marshal(map[string]any{"keys": encoded})
	require.NoError(t, err)

	return out
}

// clientKeys is the registered set most rows verify against.
func clientKeys(t *testing.T) []byte {
	t.Helper()

	return publicSet(t,
		publicKey{raw: testECKey().Public(), kid: esKid},
		publicKey{raw: testRSAKey().Public(), kid: rsKid},
		publicKey{raw: testEdKey().Public(), kid: edKid},
	)
}

// claimsFor are claims that pass every check at authNow. Each call gets its own jti.
func claimsFor(client string) map[string]any {
	return map[string]any{
		"iss": client,
		"sub": client,
		"aud": issuer,
		"exp": authNow.Add(time.Minute).Unix(),
		"jti": "jti-" + rand.Text(),
	}
}

// withClaims is claimsFor with changes applied, and a nil value removing a claim.
func withClaims(changes map[string]any) map[string]any {
	claims := claimsFor(keyClientID)
	for name, value := range changes {
		if value == nil {
			delete(claims, name)

			continue
		}
		claims[name] = value
	}

	return claims
}

// signed is a compact JWS, with kid and any other header set exactly as given.
func signed(t *testing.T, alg string, key any, header, claims map[string]any) string {
	t.Helper()

	sigAlg, ok := jwa.LookupSignatureAlgorithm(alg)
	require.True(t, ok)

	hdr := jws.NewHeaders()
	for name, value := range header {
		require.NoError(t, hdr.Set(name, value))
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	out, err := jws.Sign(payload, jws.WithKey(sigAlg, key, jws.WithProtectedHeaders(hdr)))
	require.NoError(t, err)

	return string(out)
}

// signedPayload is a compact JWS over payload taken as it is, which need not be a JSON
// object.
func signedPayload(t *testing.T, alg string, key any, header map[string]any, payload []byte) string {
	t.Helper()

	sigAlg, ok := jwa.LookupSignatureAlgorithm(alg)
	require.True(t, ok)

	hdr := jws.NewHeaders()
	for name, value := range header {
		require.NoError(t, hdr.Set(name, value))
	}
	out, err := jws.Sign(payload, jws.WithKey(sigAlg, key, jws.WithProtectedHeaders(hdr)))
	require.NoError(t, err)

	return string(out)
}

// wrapped is an ES256 assertion, signed with the client's real key, whose payload is
// the compact token inner and no claims of its own.
func wrapped(t *testing.T, inner string) string {
	t.Helper()

	return signedPayload(t, "ES256", testECKey(), map[string]any{"kid": esKid}, []byte(inner))
}

// es256 is a valid ES256 assertion over claims.
func es256(t *testing.T, claims map[string]any) string {
	t.Helper()

	return signed(t, "ES256", testECKey(), map[string]any{"kid": esKid}, claims)
}

// unsigned is a compact JWS built by hand, for what no library will produce. sign gets
// the signing input, and nil leaves the signature empty.
func unsigned(t *testing.T, header, claims map[string]any, sign func(input string) []byte) string {
	t.Helper()

	h, err := json.Marshal(header)
	require.NoError(t, err)
	c, err := json.Marshal(claims)
	require.NoError(t, err)

	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	var sig []byte
	if sign != nil {
		sig = sign(input)
	}

	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// hs256 signs with the given bytes, as an attacker holding only public data would.
func hs256(secret []byte) func(string) []byte {
	return func(input string) []byte {
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(input))

		return mac.Sum(nil)
	}
}

// presenting is the form a client authenticating by assertion sends.
func presenting(assertion string) oidcprovider.ClientCredentials {
	return oidcprovider.ClientCredentials{
		Form: form("client_assertion_type", assertionKind, "client_assertion", assertion),
	}
}

// keyClient is a client registered for private_key_jwt with the given keys.
func keyClient(id string, keys []byte) oidcprovider.Client {
	return oidcprovider.Client{
		ID:           id,
		Type:         oidcprovider.Confidential,
		AuthMethod:   oidcprovider.PrivateKeyJWT,
		JWKS:         keys,
		RedirectURIs: []string{"https://rp.example.com/cb"},
	}
}

// assertionProvider holds the key client, a secret client and a public one.
func assertionProvider(t *testing.T, keys []byte, opts ...oidcprovider.Option) *oidcprovider.Provider {
	t.Helper()

	d := validDeps(t)
	d.Clients = []oidcprovider.Client{
		keyClient(keyClientID, keys),
		{
			ID:           "billing-web",
			Type:         oidcprovider.Confidential,
			Secret:       []byte(basicSecret),
			RedirectURIs: []string{"https://rp.example.com/cb"},
		},
		{
			ID:           "spa",
			Type:         oidcprovider.Public,
			RedirectURIs: []string{"https://spa.example.com/cb"},
		},
	}

	p, err := oidcprovider.New(d, append([]oidcprovider.Option{oidcprovider.WithClock(clockwork.NewFakeClockAt(authNow))}, opts...)...)
	require.NoError(t, err)

	return p
}

func TestAuthenticateClient_PrivateKeyJWT(t *testing.T) {
	t.Parallel()

	ecPublicPEM := func() []byte {
		der, err := x509.MarshalPKIXPublicKey(testECKey().Public())
		require.NoError(t, err)

		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}
	rsaPublicPEM := func() []byte {
		der, err := x509.MarshalPKIXPublicKey(testRSAKey().Public())
		require.NoError(t, err)

		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}
	rsaKeyJSON := func() []byte {
		set := publicSet(t, publicKey{raw: testRSAKey().Public(), kid: rsKid})
		var doc struct {
			Keys []json.RawMessage `json:"keys"`
		}
		require.NoError(t, json.Unmarshal(set, &doc))

		return doc.Keys[0]
	}

	type testCase struct {
		name   string
		creds  func(t *testing.T) oidcprovider.ClientCredentials
		keys   func(t *testing.T) []byte // nil means clientKeys
		opts   []oidcprovider.Option
		assert func(t *testing.T, rc *oidcprovider.RegisteredClient, err error)
	}

	authenticated := func(t *testing.T, rc *oidcprovider.RegisteredClient, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, rc)
		assert.Equal(t, keyClientID, rc.ID)
	}
	refused := func(t *testing.T, rc *oidcprovider.RegisteredClient, err error) {
		t.Helper()
		refusedAs(t, oidcprovider.CodeInvalidClient, rc, err)
	}
	// claimsRow is an ES256 assertion with these claims changed.
	claimsRow := func(changes map[string]any) func(*testing.T) oidcprovider.ClientCredentials {
		return func(t *testing.T) oidcprovider.ClientCredentials {
			t.Helper()

			return presenting(es256(t, withClaims(changes)))
		}
	}
	// headerRow is an ES256 assertion carrying these headers.
	headerRow := func(header map[string]any) func(*testing.T) oidcprovider.ClientCredentials {
		return func(t *testing.T) oidcprovider.ClientCredentials {
			t.Helper()
			header["kid"] = esKid

			return presenting(signed(t, "ES256", testECKey(), header, claimsFor(keyClientID)))
		}
	}
	// handmade is a hand-built assertion, for what no library will sign.
	handmade := func(header map[string]any, sign func() func(string) []byte) func(*testing.T) oidcprovider.ClientCredentials {
		return func(t *testing.T) oidcprovider.ClientCredentials {
			t.Helper()
			var signer func(string) []byte
			if sign != nil {
				signer = sign()
			}

			return presenting(unsigned(t, header, claimsFor(keyClientID), signer))
		}
	}
	formRow := func(pairs func(t *testing.T) []string) func(*testing.T) oidcprovider.ClientCredentials {
		return func(t *testing.T) oidcprovider.ClientCredentials {
			t.Helper()

			return oidcprovider.ClientCredentials{Form: form(pairs(t)...)}
		}
	}

	cases := []testCase{
		// Valid, one row per family of algorithm.
		{
			name:   "ES256",
			creds:  claimsRow(nil),
			assert: authenticated,
		},
		{
			name: "RS256",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(signed(t, "RS256", testRSAKey(), map[string]any{"kid": rsKid}, claimsFor(keyClientID)))
			},
			assert: authenticated,
		},
		{
			name: "PS256",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(signed(t, "PS256", testRSAKey(), map[string]any{"kid": rsKid}, claimsFor(keyClientID)))
			},
			assert: authenticated,
		},
		{
			name: "EdDSA",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(signed(t, "EdDSA", testEdKey(), map[string]any{"kid": edKid}, claimsFor(keyClientID)))
			},
			assert: authenticated,
		},
		{
			name: "no kid: the key set is tried",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(signed(t, "ES256", testECKey(), nil, claimsFor(keyClientID)))
			},
			assert: authenticated,
		},
		{
			name: "client_id naming the assertion's client",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()
				c := presenting(es256(t, claimsFor(keyClientID)))
				c.Form.Set("client_id", keyClientID)

				return c
			},
			assert: authenticated,
		},

		// The audience.
		{
			name:   "aud as an array holding only the issuer",
			creds:  claimsRow(map[string]any{"aud": []string{issuer}}),
			assert: authenticated,
		},
		{
			name:   "aud the token endpoint, under the default",
			creds:  claimsRow(map[string]any{"aud": tokenEndpoint}),
			assert: refused,
		},
		{
			name:   "aud the token endpoint, under the compatibility rule",
			creds:  claimsRow(map[string]any{"aud": tokenEndpoint}),
			opts:   []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint)},
			assert: authenticated,
		},
		{
			name:   "aud the issuer, under the compatibility rule",
			creds:  claimsRow(nil),
			opts:   []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint)},
			assert: authenticated,
		},
		{
			name:   "aud holding the issuer and another value",
			creds:  claimsRow(map[string]any{"aud": []string{issuer, "x"}}),
			assert: refused,
		},
		{
			name:   "aud holding the token endpoint and the issuer, under the default",
			creds:  claimsRow(map[string]any{"aud": []string{tokenEndpoint, issuer}}),
			assert: refused,
		},
		{
			name:   "aud holding the token endpoint and the issuer, under the compatibility rule",
			creds:  claimsRow(map[string]any{"aud": []string{tokenEndpoint, issuer}}),
			opts:   []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint)},
			assert: refused,
		},
		{
			name:   "aud holding the token endpoint and another value, under the compatibility rule",
			creds:  claimsRow(map[string]any{"aud": []string{tokenEndpoint, "x"}}),
			opts:   []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint)},
			assert: refused,
		},
		{
			name:   "aud naming the issuer twice",
			creds:  claimsRow(map[string]any{"aud": []string{issuer, issuer}}),
			assert: refused,
		},
		{
			name:   "aud missing",
			creds:  claimsRow(map[string]any{"aud": nil}),
			assert: refused,
		},
		{
			name:   "aud an empty array",
			creds:  claimsRow(map[string]any{"aud": []string{}}),
			assert: refused,
		},
		{
			name:   "aud the issuer with a trailing slash",
			creds:  claimsRow(map[string]any{"aud": issuer + "/"}),
			assert: refused,
		},
		{
			name:   "aud another server",
			creds:  claimsRow(map[string]any{"aud": "https://other.example.com"}),
			assert: refused,
		},

		// The algorithm: nothing symmetric, nothing unsigned.
		{
			name:   "alg none with an empty signature",
			creds:  handmade(map[string]any{"alg": "none", "kid": esKid}, nil),
			assert: refused,
		},
		{
			name:   "alg None, in another case",
			creds:  handmade(map[string]any{"alg": "None", "kid": esKid}, nil),
			assert: refused,
		},
		{
			name:   "no alg at all",
			creds:  handmade(map[string]any{"kid": esKid}, nil),
			assert: refused,
		},
		{
			name:   "an algorithm nobody has heard of",
			creds:  handmade(map[string]any{"alg": "XX999", "kid": esKid}, nil),
			assert: refused,
		},
		{
			name:   "HS256 keyed by a stranger's choice",
			creds:  handmade(map[string]any{"alg": "HS256", "kid": esKid}, func() func(string) []byte { return hs256([]byte("anything")) }),
			assert: refused,
		},
		{
			name:   "HS256 keyed by the EC public key's PEM",
			creds:  handmade(map[string]any{"alg": "HS256", "kid": esKid}, func() func(string) []byte { return hs256(ecPublicPEM()) }),
			assert: refused,
		},
		{
			name:   "HS256 keyed by the RSA public key's PEM",
			creds:  handmade(map[string]any{"alg": "HS256", "kid": rsKid}, func() func(string) []byte { return hs256(rsaPublicPEM()) }),
			assert: refused,
		},
		{
			name:   "HS256 keyed by the RSA public key's JWK",
			creds:  handmade(map[string]any{"alg": "HS256", "kid": rsKid}, func() func(string) []byte { return hs256(rsaKeyJSON()) }),
			assert: refused,
		},
		{
			name:   "HS256 keyed by the RSA modulus",
			creds:  handmade(map[string]any{"alg": "HS256", "kid": rsKid}, func() func(string) []byte { return hs256(testRSAKey().N.Bytes()) }),
			assert: refused,
		},
		{
			name:   "HS256 with no kid, keyed by the RSA public key's PEM",
			creds:  handmade(map[string]any{"alg": "HS256"}, func() func(string) []byte { return hs256(rsaPublicPEM()) }),
			assert: refused,
		},
		{
			name: "an RS256 signature naming the EC key",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(signed(t, "RS256", testRSAKey(), map[string]any{"kid": esKid}, claimsFor(keyClientID)))
			},
			assert: refused,
		},
		{
			name: "a key that names its algorithm is used with no other",
			keys: func(t *testing.T) []byte {
				t.Helper()

				return publicSet(t, publicKey{raw: testRSAKey().Public(), kid: rsKid, alg: "RS256"})
			},
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(signed(t, "PS256", testRSAKey(), map[string]any{"kid": rsKid}, claimsFor(keyClientID)))
			},
			assert: refused,
		},

		{
			// Ed25519 is asymmetric and the set holds the key, but it is not in the
			// list of algorithms an assertion may use.
			name: "an asymmetric algorithm outside the list, with a key the set holds",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(signed(t, "Ed25519", testEdKey(), map[string]any{"kid": edKid}, claimsFor(keyClientID)))
			},
			assert: refused,
		},

		// The key's permitted operations (RFC 7517 section 4.3).
		{
			name: "a key whose key_ops rule out verifying",
			keys: func(t *testing.T) []byte {
				t.Helper()

				return publicSet(t, publicKey{raw: testECKey().Public(), kid: esKid, ops: []jwk.KeyOperation{jwk.KeyOpEncrypt}})
			},
			creds:  claimsRow(nil),
			assert: refused,
		},
		{
			name: "a key whose key_ops rule out verifying, with no kid named",
			keys: func(t *testing.T) []byte {
				t.Helper()

				return publicSet(t, publicKey{raw: testECKey().Public(), kid: esKid, ops: []jwk.KeyOperation{jwk.KeyOpEncrypt}})
			},
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(signed(t, "ES256", testECKey(), nil, claimsFor(keyClientID)))
			},
			assert: refused,
		},
		{
			name: "a key whose key_ops name verifying",
			keys: func(t *testing.T) []byte {
				t.Helper()

				return publicSet(t, publicKey{raw: testECKey().Public(), kid: esKid, ops: []jwk.KeyOperation{jwk.KeyOpVerify}})
			},
			creds:  claimsRow(nil),
			assert: authenticated,
		},
		{
			name: "a key whose key_ops name verifying among others",
			keys: func(t *testing.T) []byte {
				t.Helper()

				return publicSet(t, publicKey{raw: testECKey().Public(), kid: esKid, ops: []jwk.KeyOperation{jwk.KeyOpEncrypt, jwk.KeyOpVerify}})
			},
			creds:  claimsRow(nil),
			assert: authenticated,
		},

		// The token endpoint (WithAssertionTokenEndpoint).
		{
			name:   "aud the moved token endpoint, under the compatibility rule",
			creds:  claimsRow(map[string]any{"aud": movedEndpoint}),
			opts:   []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint), oidcprovider.WithAssertionTokenEndpoint(movedEndpoint)},
			assert: authenticated,
		},
		{
			name:   "aud the old default endpoint, once the endpoint has moved",
			creds:  claimsRow(map[string]any{"aud": tokenEndpoint}),
			opts:   []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint), oidcprovider.WithAssertionTokenEndpoint(movedEndpoint)},
			assert: refused,
		},
		{
			name:   "aud the issuer, once the endpoint has moved",
			creds:  claimsRow(nil),
			opts:   []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint), oidcprovider.WithAssertionTokenEndpoint(movedEndpoint)},
			assert: authenticated,
		},

		// The signature.
		{
			name: "a stranger's key naming the client's kid",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(signed(t, "ES256", strangerECKey(), map[string]any{"kid": esKid}, claimsFor(keyClientID)))
			},
			assert: refused,
		},
		{
			name: "a stranger's key with no kid",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(signed(t, "ES256", strangerECKey(), nil, claimsFor(keyClientID)))
			},
			assert: refused,
		},
		{
			name: "a kid the registered set does not hold",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(signed(t, "ES256", testECKey(), map[string]any{"kid": "gone"}, claimsFor(keyClientID)))
			},
			assert: refused,
		},
		{
			name: "a stranger's key carried in the jwk header",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()
				embedded, err := jwk.Import[jwk.Key](strangerECKey().Public())
				require.NoError(t, err)

				return presenting(signed(t, "ES256", strangerECKey(), map[string]any{"jwk": embedded}, claimsFor(keyClientID)))
			},
			assert: refused,
		},
		{
			name: "a stranger's key set named by the jku header",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(signed(t, "ES256", strangerECKey(), map[string]any{"jku": "https://stranger.example.com/jwks"}, claimsFor(keyClientID)))
			},
			assert: refused,
		},
		{
			name: "a payload changed after signing",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()
				parts := strings.Split(es256(t, claimsFor("billing-web")), ".")
				changed, err := json.Marshal(claimsFor(keyClientID))
				require.NoError(t, err)
				parts[1] = base64.RawURLEncoding.EncodeToString(changed)

				return presenting(strings.Join(parts, "."))
			},
			assert: refused,
		},
		{
			name: "an empty signature on a right header",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(unsigned(t, map[string]any{"alg": "ES256", "kid": esKid}, claimsFor(keyClientID), nil))
			},
			assert: refused,
		},
		{
			name:   "a critical extension nothing here understands",
			creds:  headerRow(map[string]any{"crit": []string{"x-unknown"}, "x-unknown": "1"}),
			assert: refused,
		},

		// The serialization.
		{
			name: "the JSON serialization, which can carry several signatures",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()
				parts := strings.Split(es256(t, claimsFor(keyClientID)), ".")
				doc, err := json.Marshal(map[string]string{"protected": parts[0], "payload": parts[1], "signature": parts[2]})
				require.NoError(t, err)

				return presenting(string(doc))
			},
			assert: refused,
		},
		{
			// A JSON document reads as claims from its top level, while its signature
			// covers the payload inside. A client's old assertion must not vouch for
			// claims written beside it.
			name: "the JSON serialization with fresh claims beside an old signature",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()
				old := claimsFor(keyClientID)
				old["exp"] = authNow.Add(-time.Hour).Unix()
				parts := strings.Split(es256(t, old), ".")

				doc := claimsFor(keyClientID)
				doc["protected"], doc["payload"], doc["signature"] = parts[0], parts[1], parts[2]
				raw, err := json.Marshal(doc)
				require.NoError(t, err)

				return presenting(string(raw))
			},
			assert: refused,
		},
		{
			name: "not a JWT",
			creds: formRow(func(*testing.T) []string {
				return []string{"client_assertion_type", assertionKind, "client_assertion", "garbage"}
			}),
			assert: refused,
		},
		{
			name: "two parts",
			creds: formRow(func(*testing.T) []string {
				return []string{"client_assertion_type", assertionKind, "client_assertion", "a.b"}
			}),
			assert: refused,
		},
		{
			name: "five parts, the shape of an encrypted token",
			creds: formRow(func(*testing.T) []string {
				return []string{"client_assertion_type", assertionKind, "client_assertion", "a.b.c.d.e"}
			}),
			assert: refused,
		},
		{
			name: "a payload that is not JSON",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()
				parts := strings.Split(es256(t, claimsFor(keyClientID)), ".")
				parts[1] = base64.RawURLEncoding.EncodeToString([]byte("not json"))

				return presenting(strings.Join(parts, "."))
			},
			assert: refused,
		},

		{
			// The payload is a token of its own, and a parser that reads through it
			// takes its claims, whatever its own header says.
			name: "a payload that is an at+jwt token carrying valid claims",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()
				inner := signed(t, "ES256", testECKey(), map[string]any{"kid": esKid, "typ": "at+jwt"}, claimsFor(keyClientID))

				return presenting(wrapped(t, inner))
			},
			assert: refused,
		},
		{
			name: "a payload that is an unsigned token carrying valid claims",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()
				inner := unsigned(t, map[string]any{"alg": "none"}, claimsFor(keyClientID), nil)

				return presenting(wrapped(t, inner))
			},
			assert: refused,
		},
		{
			name: "a payload that is a JSON array",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(wrapped(t, "[]"))
			},
			assert: refused,
		},

		// The issuer and the subject.
		{
			name:   "iss and sub differing",
			creds:  claimsRow(map[string]any{"sub": "billing-web"}),
			assert: refused,
		},
		{
			name:   "iss missing",
			creds:  claimsRow(map[string]any{"iss": nil}),
			assert: refused,
		},
		{
			name:   "sub missing",
			creds:  claimsRow(map[string]any{"sub": nil}),
			assert: refused,
		},
		{
			name:   "iss not a string",
			creds:  claimsRow(map[string]any{"iss": 7}),
			assert: refused,
		},
		{
			name: "client_id naming another client than the assertion",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()
				c := presenting(es256(t, claimsFor(keyClientID)))
				c.Form.Set("client_id", "billing-web")

				return c
			},
			assert: refused,
		},

		// The client it names.
		{
			name: "an unknown client",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(es256(t, claimsFor("nobody")))
			},
			assert: refused,
		},
		{
			name: "a client registered for a secret",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(es256(t, claimsFor("billing-web")))
			},
			assert: refused,
		},
		{
			name: "a public client",
			creds: func(t *testing.T) oidcprovider.ClientCredentials {
				t.Helper()

				return presenting(es256(t, claimsFor("spa")))
			},
			assert: refused,
		},

		// The lifetime.
		{
			name:   "exp missing",
			creds:  claimsRow(map[string]any{"exp": nil}),
			assert: refused,
		},
		{
			name:   "exp past",
			creds:  claimsRow(map[string]any{"exp": authNow.Add(-time.Second).Unix()}),
			assert: refused,
		},
		{
			name:   "exp exactly now",
			creds:  claimsRow(map[string]any{"exp": authNow.Unix()}),
			assert: refused,
		},
		{
			name:   "exp not a number",
			creds:  claimsRow(map[string]any{"exp": "soon"}),
			assert: refused,
		},
		{
			name:   "exp exactly at the bound",
			creds:  claimsRow(map[string]any{"exp": authNow.Add(5 * time.Minute).Unix()}),
			assert: authenticated,
		},
		{
			name:   "exp a second past the bound",
			creds:  claimsRow(map[string]any{"exp": authNow.Add(5*time.Minute + time.Second).Unix()}),
			assert: refused,
		},
		{
			name:   "exp 10 minutes ahead",
			creds:  claimsRow(map[string]any{"exp": authNow.Add(10 * time.Minute).Unix()}),
			assert: refused,
		},
		{
			name:   "exp 10 minutes ahead, under a raised bound",
			creds:  claimsRow(map[string]any{"exp": authNow.Add(10 * time.Minute).Unix()}),
			opts:   []oidcprovider.Option{oidcprovider.WithClientAssertionMaxLifetime(time.Hour)},
			assert: authenticated,
		},
		{
			name:   "nbf 60 seconds ahead",
			creds:  claimsRow(map[string]any{"nbf": authNow.Add(60 * time.Second).Unix()}),
			assert: authenticated,
		},
		{
			name:   "nbf 120 seconds ahead",
			creds:  claimsRow(map[string]any{"nbf": authNow.Add(120 * time.Second).Unix()}),
			assert: refused,
		},

		// The jti.
		{
			name:   "jti missing",
			creds:  claimsRow(map[string]any{"jti": nil}),
			assert: refused,
		},
		{
			name:   "jti empty",
			creds:  claimsRow(map[string]any{"jti": ""}),
			assert: refused,
		},

		// The type (R13).
		{
			name:   "typ client-authentication+jwt",
			creds:  headerRow(map[string]any{"typ": "client-authentication+jwt"}),
			assert: authenticated,
		},
		{
			name:   "typ JWT",
			creds:  headerRow(map[string]any{"typ": "JWT"}),
			assert: authenticated,
		},
		{
			name:   "typ at+jwt",
			creds:  headerRow(map[string]any{"typ": "at+jwt"}),
			assert: refused,
		},
		{
			name:   "typ scrty+jwt",
			creds:  headerRow(map[string]any{"typ": "scrty+jwt"}),
			assert: refused,
		},
		{
			name:   "typ logout+jwt",
			creds:  headerRow(map[string]any{"typ": "logout+jwt"}),
			assert: refused,
		},
		{
			name:   "typ empty",
			creds:  headerRow(map[string]any{"typ": ""}),
			assert: refused,
		},

		// The request's own parameters.
		{
			name: "another client_assertion_type",
			creds: formRow(func(t *testing.T) []string {
				t.Helper()

				return []string{"client_assertion_type", "urn:other", "client_assertion", es256(t, claimsFor(keyClientID))}
			}),
			assert: refused,
		},
		{
			name: "no client_assertion_type",
			creds: formRow(func(t *testing.T) []string {
				t.Helper()

				return []string{"client_assertion", es256(t, claimsFor(keyClientID))}
			}),
			assert: refused,
		},
		{
			name:   "a client_assertion_type and no assertion",
			creds:  formRow(func(*testing.T) []string { return []string{"client_assertion_type", assertionKind} }),
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := clientKeys
			if tc.keys != nil {
				keys = tc.keys
			}
			p := assertionProvider(t, keys(t), tc.opts...)

			rc, err := p.AuthenticateClient(t.Context(), tc.creds(t))
			tc.assert(t, rc, err)
		})
	}
}

// The jti goes through the store, and only once everything else has passed, so nobody
// who cannot sign for a client can fill the store. A row with no expectation fails the
// moment Record is called.
func TestAuthenticateClient_PrivateKeyJWT_RecordsTheIdentifier(t *testing.T) {
	t.Parallel()

	errStore := errors.New("pq: connection refused to store.internal")
	exp := authNow.Add(time.Minute)

	type testCase struct {
		name   string
		tok    func(t *testing.T) string
		keys   func(t *testing.T) []byte // nil means clientKeys
		expect func(store *MockAssertionIDStore)
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, rc *oidcprovider.RegisteredClient, err error)
	}

	refused := func(t *testing.T, rc *oidcprovider.RegisteredClient, err error) {
		t.Helper()
		refusedAs(t, oidcprovider.CodeInvalidClient, rc, err)
	}
	claimsRow := func(changes map[string]any) func(*testing.T) string {
		return func(t *testing.T) string {
			t.Helper()

			return es256(t, withClaims(changes))
		}
	}

	cases := []testCase{
		{
			name: "recorded for the client until exp",
			tok:  claimsRow(map[string]any{"jti": "the-jti", "exp": exp.Unix()}),
			expect: func(s *MockAssertionIDStore) {
				s.EXPECT().Record(gomock.Any(), keyClientID, "the-jti", gomock.Cond(func(until time.Time) bool {
					return until.Equal(exp)
				})).Return(true, nil).Times(1)
			},
			assert: func(t *testing.T, rc *oidcprovider.RegisteredClient, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, keyClientID, rc.ID)
			},
		},
		{
			name: "a store that has seen it refuses the replay",
			tok:  claimsRow(nil),
			expect: func(s *MockAssertionIDStore) {
				s.EXPECT().Record(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)
			},
			assert: refused,
		},
		{
			name: "a failing store is a dependency failure, not a refusal",
			tok:  claimsRow(nil),
			expect: func(s *MockAssertionIDStore) {
				s.EXPECT().Record(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(false, errStore)
			},
			assert: func(t *testing.T, rc *oidcprovider.RegisteredClient, err error) {
				t.Helper()
				assert.Nil(t, rc)
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				var refusal *oidcprovider.Error
				assert.False(t, errors.As(err, &refusal))
				assert.NotContains(t, err.Error(), "store.internal")
			},
		},
		{
			name: "a caller who left matches its own context",
			tok:  claimsRow(nil),
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			expect: func(s *MockAssertionIDStore) {
				s.EXPECT().Record(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(false, context.Canceled)
			},
			assert: func(t *testing.T, rc *oidcprovider.RegisteredClient, err error) {
				t.Helper()
				assert.Nil(t, rc)
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, oidcprovider.ErrDependency)
			},
		},

		{
			name: "an identifier of exactly the longest accepted length",
			tok:  claimsRow(map[string]any{"jti": strings.Repeat("j", 1024)}),
			expect: func(s *MockAssertionIDStore) {
				s.EXPECT().Record(gomock.Any(), keyClientID, strings.Repeat("j", 1024), gomock.Any()).Return(true, nil).Times(1)
			},
			assert: func(t *testing.T, rc *oidcprovider.RegisteredClient, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, keyClientID, rc.ID)
			},
		},

		// Nothing below may reach the store.
		{
			name:   "an identifier one byte over the longest accepted length",
			tok:    claimsRow(map[string]any{"jti": strings.Repeat("j", 1025)}),
			assert: refused,
		},
		{
			name: "a stranger's signature",
			tok: func(t *testing.T) string {
				t.Helper()

				return signed(t, "ES256", strangerECKey(), map[string]any{"kid": esKid}, claimsFor(keyClientID))
			},
			assert: refused,
		},
		{
			name: "HS256",
			tok: func(t *testing.T) string {
				t.Helper()

				return unsigned(t, map[string]any{"alg": "HS256", "kid": esKid}, claimsFor(keyClientID), hs256([]byte("x")))
			},
			assert: refused,
		},
		{
			name: "alg none",
			tok: func(t *testing.T) string {
				t.Helper()

				return unsigned(t, map[string]any{"alg": "none", "kid": esKid}, claimsFor(keyClientID), nil)
			},
			assert: refused,
		},
		{
			name:   "exp past",
			tok:    claimsRow(map[string]any{"exp": authNow.Add(-time.Minute).Unix()}),
			assert: refused,
		},
		{
			name:   "another audience",
			tok:    claimsRow(map[string]any{"aud": "https://other.example.com"}),
			assert: refused,
		},
		{
			name:   "nbf ahead",
			tok:    claimsRow(map[string]any{"nbf": authNow.Add(time.Hour).Unix()}),
			assert: refused,
		},
		{
			name: "a wrong type",
			tok: func(t *testing.T) string {
				t.Helper()

				return signed(t, "ES256", testECKey(), map[string]any{"kid": esKid, "typ": "at+jwt"}, claimsFor(keyClientID))
			},
			assert: refused,
		},
		{
			name: "a token wrapped in the assertion, typed at+jwt inside",
			tok: func(t *testing.T) string {
				t.Helper()
				inner := signed(t, "ES256", testECKey(), map[string]any{"kid": esKid, "typ": "at+jwt"}, claimsFor(keyClientID))

				return wrapped(t, inner)
			},
			assert: refused,
		},
		{
			name: "a token wrapped in the assertion, alg none inside",
			tok: func(t *testing.T) string {
				t.Helper()

				return wrapped(t, unsigned(t, map[string]any{"alg": "none"}, claimsFor(keyClientID), nil))
			},
			assert: refused,
		},
		{
			name: "a key whose key_ops rule out verifying",
			tok:  claimsRow(nil),
			keys: func(t *testing.T) []byte {
				t.Helper()

				return publicSet(t, publicKey{raw: testECKey().Public(), kid: esKid, ops: []jwk.KeyOperation{jwk.KeyOpEncrypt}})
			},
			assert: refused,
		},
		{
			name: "a client registered for a secret",
			tok: func(t *testing.T) string {
				t.Helper()

				return es256(t, claimsFor("billing-web"))
			},
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			store := NewMockAssertionIDStore(gomock.NewController(t))
			if tc.expect != nil {
				tc.expect(store)
			}
			keys := clientKeys
			if tc.keys != nil {
				keys = tc.keys
			}
			p := assertionProvider(t, keys(t), oidcprovider.WithAssertionIDStore(store))

			rc, err := p.AuthenticateClient(ctx, presenting(tc.tok(t)))
			tc.assert(t, rc, err)
		})
	}
}

// stallingClock reads as the fake it wraps, and once told to, moves to a later time right
// after its next read: the exp check reads the old time and everything after it the new
// one, as a request stalled between the two would see.
type stallingClock struct {
	*clockwork.FakeClock

	to atomic.Pointer[time.Time]
}

// stallAfterNextRead moves the clock to to, right after its next read.
func (c *stallingClock) stallAfterNextRead(to time.Time) { c.to.Store(&to) }

func (c *stallingClock) Now() time.Time {
	now := c.FakeClock.Now()
	if to := c.to.Swap(nil); to != nil {
		c.Advance(to.Sub(now))
	}

	return now
}

// The provider's default store, with no store wired.
func TestAuthenticateClient_PrivateKeyJWT_DefaultStore(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, p *oidcprovider.Provider, clk *stallingClock)
	}

	// exp is when claimsFor's assertions expire.
	exp := authNow.Add(time.Minute)

	// replayStallingTo accepts an assertion, then replays it from just before its exp, to
	// a request that reads the clock as to from its exp check on.
	replayStallingTo := func(to time.Time) func(*testing.T, *oidcprovider.Provider, *stallingClock) {
		return func(t *testing.T, p *oidcprovider.Provider, clk *stallingClock) {
			t.Helper()
			tok := es256(t, claimsFor(keyClientID))

			_, err := p.AuthenticateClient(t.Context(), presenting(tok))
			require.NoError(t, err)

			clk.Advance(exp.Add(-time.Second).Sub(clk.FakeClock.Now()))
			clk.stallAfterNextRead(to)
			rc, err := p.AuthenticateClient(t.Context(), presenting(tok))
			refusedAs(t, oidcprovider.CodeInvalidClient, rc, err)
		}
	}
	// replayAt accepts an assertion, then replays it at at.
	replayAt := func(at time.Time) func(*testing.T, *oidcprovider.Provider, *stallingClock) {
		return func(t *testing.T, p *oidcprovider.Provider, clk *stallingClock) {
			t.Helper()
			tok := es256(t, claimsFor(keyClientID))

			_, err := p.AuthenticateClient(t.Context(), presenting(tok))
			require.NoError(t, err)

			clk.Advance(at.Sub(clk.FakeClock.Now()))
			rc, err := p.AuthenticateClient(t.Context(), presenting(tok))
			refusedAs(t, oidcprovider.CodeInvalidClient, rc, err)
		}
	}

	cases := []testCase{
		{
			name: "a replay of an accepted assertion is refused",
			assert: func(t *testing.T, p *oidcprovider.Provider, _ *stallingClock) {
				t.Helper()
				tok := es256(t, claimsFor(keyClientID))

				_, err := p.AuthenticateClient(t.Context(), presenting(tok))
				require.NoError(t, err)

				rc, err := p.AuthenticateClient(t.Context(), presenting(tok))
				refusedAs(t, oidcprovider.CodeInvalidClient, rc, err)
			},
		},
		{
			name: "a refused assertion's jti stays unspent",
			assert: func(t *testing.T, p *oidcprovider.Provider, _ *stallingClock) {
				t.Helper()
				claims := claimsFor(keyClientID)

				forged := signed(t, "ES256", strangerECKey(), map[string]any{"kid": esKid}, claims)
				rc, err := p.AuthenticateClient(t.Context(), presenting(forged))
				refusedAs(t, oidcprovider.CodeInvalidClient, rc, err)

				_, err = p.AuthenticateClient(t.Context(), presenting(es256(t, claims)))
				require.NoError(t, err, "a forgery must not burn the client's jti")
			},
		},
		{
			name: "the same jti from another client is its own",
			assert: func(t *testing.T, p *oidcprovider.Provider, _ *stallingClock) {
				t.Helper()
				first := claimsFor(keyClientID)
				second := claimsFor("second-key-client")
				second["jti"] = first["jti"]

				_, err := p.AuthenticateClient(t.Context(), presenting(es256(t, first)))
				require.NoError(t, err)
				_, err = p.AuthenticateClient(t.Context(), presenting(es256(t, second)))
				require.NoError(t, err)
			},
		},
		{
			name:   "a replay straddling exp is refused, reaching the store at exp",
			assert: replayStallingTo(exp),
		},
		{
			name:   "a replay straddling exp is refused, reaching the store just past it",
			assert: replayStallingTo(exp.Add(time.Second)),
		},
		{
			name:   "a replay straddling exp is refused, stalled so long that its pair was swept",
			assert: replayStallingTo(exp.Add(10 * time.Minute)),
		},
		{
			name:   "a replay at exp is refused",
			assert: replayAt(exp),
		},
		{
			name:   "a replay after expiry is refused",
			assert: replayAt(exp.Add(10 * time.Minute)),
		},
		{
			name: "a jti stays held for a minute past its assertion's exp, with a sweep due",
			assert: func(t *testing.T, p *oidcprovider.Provider, clk *stallingClock) {
				t.Helper()
				claims := claimsFor(keyClientID)

				_, err := p.AuthenticateClient(t.Context(), presenting(es256(t, claims)))
				require.NoError(t, err)

				clk.Advance(exp.Add(time.Minute).Sub(clk.FakeClock.Now()))
				claims["exp"] = clk.FakeClock.Now().Add(time.Minute).Unix()
				rc, err := p.AuthenticateClient(t.Context(), presenting(es256(t, claims)))
				refusedAs(t, oidcprovider.CodeInvalidClient, rc, err)
			},
		},
		{
			name: "a jti is free again once a minute past its assertion's exp has gone",
			assert: func(t *testing.T, p *oidcprovider.Provider, clk *stallingClock) {
				t.Helper()
				claims := claimsFor(keyClientID)

				_, err := p.AuthenticateClient(t.Context(), presenting(es256(t, claims)))
				require.NoError(t, err)

				clk.Advance(exp.Add(time.Minute + time.Second).Sub(clk.FakeClock.Now()))
				claims["exp"] = clk.FakeClock.Now().Add(time.Minute).Unix()
				_, err = p.AuthenticateClient(t.Context(), presenting(es256(t, claims)))
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := &stallingClock{FakeClock: clockwork.NewFakeClockAt(authNow)}
			d := validDeps(t)
			d.Clients = []oidcprovider.Client{
				keyClient(keyClientID, clientKeys(t)),
				keyClient("second-key-client", clientKeys(t)),
			}
			p, err := oidcprovider.New(d, oidcprovider.WithClock(clk))
			require.NoError(t, err)

			tc.assert(t, p, clk)
		})
	}
}

// forgetsAtUntil is what a consumer's store may do for all the library controls: it holds
// a pair only while its own clock is before the pair's until, and so answers new for a
// pair it has held, from that moment on.
func forgetsAtUntil(now func() time.Time) func(context.Context, string, string, time.Time) (bool, error) {
	var (
		mu   sync.Mutex
		held = make(map[string]time.Time)
	)

	return func(_ context.Context, clientID, jti string, until time.Time) (bool, error) {
		mu.Lock()
		defer mu.Unlock()

		key := clientID + "\x00" + jti
		if first, ok := held[key]; ok && now().Before(first) {
			return false, nil
		}
		held[key] = until

		return true, nil
	}
}

// A store the library does not control may forget a pair the moment it expires, and the
// provider's second read of the clock is what refuses the replay that finds it so.
func TestAuthenticateClient_PrivateKeyJWT_StoreForgettingAtExpiry(t *testing.T) {
	t.Parallel()

	exp := authNow.Add(time.Minute)

	type testCase struct {
		name   string
		to     time.Time
		assert func(t *testing.T, rc *oidcprovider.RegisteredClient, err error)
	}

	refused := func(t *testing.T, rc *oidcprovider.RegisteredClient, err error) {
		t.Helper()
		refusedAs(t, oidcprovider.CodeInvalidClient, rc, err)
	}

	cases := []testCase{
		{name: "reaching the store at exp", to: exp, assert: refused},
		{name: "reaching the store past exp", to: exp.Add(time.Hour), assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := &stallingClock{FakeClock: clockwork.NewFakeClockAt(authNow)}
			store := NewMockAssertionIDStore(gomock.NewController(t))
			store.EXPECT().Record(gomock.Any(), keyClientID, gomock.Any(), gomock.Any()).
				DoAndReturn(forgetsAtUntil(clk.FakeClock.Now)).Times(2)
			p := assertionProvider(t, clientKeys(t), oidcprovider.WithClock(clk), oidcprovider.WithAssertionIDStore(store))
			tok := es256(t, claimsFor(keyClientID))

			_, err := p.AuthenticateClient(t.Context(), presenting(tok))
			require.NoError(t, err)

			clk.Advance(exp.Add(-time.Second).Sub(clk.FakeClock.Now()))
			clk.stallAfterNextRead(tc.to)
			rc, err := p.AuthenticateClient(t.Context(), presenting(tok))
			tc.assert(t, rc, err)
		})
	}
}

// One assertion presented by many callers across its exp, on the system clock with nothing
// injected, where the gap between the exp check and the store is the signature check.
func TestAuthenticateClient_PrivateKeyJWT_ReplayAcrossExpiry(t *testing.T) {
	t.Parallel()

	const (
		callers = 8
		// pastExp is how long the callers keep presenting after exp.
		pastExp = 150 * time.Millisecond
	)

	type testCase struct {
		name  string
		store func(t *testing.T) []oidcprovider.Option
	}

	cases := []testCase{
		{
			name:  "the default store",
			store: func(*testing.T) []oidcprovider.Option { return nil },
		},
		{
			name: "a consumer's store forgetting at expiry",
			store: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				store := NewMockAssertionIDStore(gomock.NewController(t))
				store.EXPECT().Record(gomock.Any(), keyClientID, gomock.Any(), gomock.Any()).
					DoAndReturn(forgetsAtUntil(clock.System().Now)).AnyTimes()

				return []oidcprovider.Option{oidcprovider.WithAssertionIDStore(store)}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := append([]oidcprovider.Option{oidcprovider.WithClock(clock.System())}, tc.store(t)...)
			p := assertionProvider(t, clientKeys(t), opts...)

			// exp is a whole second, between one and two seconds off, so the first
			// presentation is well before it and the loop stays short.
			exp := time.Now().Add(2 * time.Second).Truncate(time.Second)
			claims := claimsFor(keyClientID)
			claims["exp"] = exp.Unix()
			tok := es256(t, claims)

			var (
				wg       sync.WaitGroup
				accepted atomic.Int64
				others   atomic.Int64
			)
			for range callers {
				wg.Go(func() {
					for time.Now().Before(exp.Add(pastExp)) {
						_, err := p.AuthenticateClient(t.Context(), presenting(tok))

						var refusal *oidcprovider.Error
						switch {
						case err == nil:
							accepted.Add(1)
						case errors.As(err, &refusal) && refusal.Code == oidcprovider.CodeInvalidClient:
						default:
							others.Add(1)
						}
					}
				})
			}
			wg.Wait()

			assert.EqualValues(t, 1, accepted.Load(), "one assertion, accepted this many times")
			assert.Zero(t, others.Load())
		})
	}
}

// The default store forgets what expired more than its margin ago, so what it holds is
// bounded by the assertions accepted within their lifetime and not by the life of the
// process.
func TestAuthenticateClient_PrivateKeyJWT_DefaultStoreForgets(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(authNow)
	d := validDeps(t)
	d.Clients = []oidcprovider.Client{keyClient(keyClientID, clientKeys(t))}
	p, err := oidcprovider.New(d, oidcprovider.WithClock(clk))
	require.NoError(t, err)

	for range 5 {
		_, err := p.AuthenticateClient(t.Context(), presenting(es256(t, claimsFor(keyClientID))))
		require.NoError(t, err)
	}
	require.Equal(t, 5, p.AssertionIDsHeldForTest())

	clk.Advance(10 * time.Minute)
	claims := claimsFor(keyClientID)
	claims["exp"] = clk.Now().Add(time.Minute).Unix()
	_, err = p.AuthenticateClient(t.Context(), presenting(es256(t, claims)))
	require.NoError(t, err)

	assert.Equal(t, 1, p.AssertionIDsHeldForTest())
}

// One assertion raced against itself: exactly one wins, in every round.
func TestAuthenticateClient_PrivateKeyJWT_ReplayRace(t *testing.T) {
	t.Parallel()

	const (
		rounds  = 20
		callers = 16
	)

	p := assertionProvider(t, clientKeys(t))

	for round := range rounds {
		t.Run(fmt.Sprintf("round %d", round), func(t *testing.T) {
			tok := es256(t, claimsFor(keyClientID))

			var (
				start     = make(chan struct{})
				wg        sync.WaitGroup
				successes atomic.Int64
				refusals  atomic.Int64
				others    atomic.Int64
			)
			for range callers {
				wg.Go(func() {
					<-start
					_, err := p.AuthenticateClient(t.Context(), presenting(tok))

					var refusal *oidcprovider.Error
					switch {
					case err == nil:
						successes.Add(1)
					case errors.As(err, &refusal) && refusal.Code == oidcprovider.CodeInvalidClient:
						refusals.Add(1)
					default:
						others.Add(1)
					}
				})
			}
			close(start)
			wg.Wait()

			assert.EqualValues(t, 1, successes.Load(), "exactly one use may win")
			assert.EqualValues(t, callers-1, refusals.Load())
			assert.Zero(t, others.Load())
		})
	}
}
