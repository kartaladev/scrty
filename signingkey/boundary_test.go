// Tests for the boundaries this package does not control: the store's rows,
// which another writer may have produced, the keys it hands callers, and the
// configuration a consumer supplies. Each one was written against a defect it
// reproduced, and each is proven by a mutation that makes it fail.
package signingkey_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

func auditStore(t *testing.T, recs ...signingkey.Record) signingkey.KeyStore {
	t.Helper()
	store := signingkey.NewInMemoryKeyStore()
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

func auditAlg(t *testing.T, alg signingkey.Alg) jwa.SignatureAlgorithm {
	t.Helper()
	a, ok := jwa.LookupSignatureAlgorithm(alg)
	require.True(t, ok)
	return a
}

// F1 — JWKS() hands out the manager's own live jwk.Key values, so a caller
// writing to what it was given breaks the manager's verification.
func TestJWKSDoesNotShareKeysWithTheManager(t *testing.T) {
	km, err := signingkey.NewKeyManager(
		signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
		signingkey.WithAlgs(signingkey.EdDSA),
	)
	require.NoError(t, err)

	kid, signer, ok := km.GetSigner(signingkey.EdDSA)
	require.True(t, ok)

	exported, err := km.JWKS()
	require.NoError(t, err)
	handed, found := exported.LookupKeyID(kid)
	require.True(t, found)
	require.NoError(t, handed.Set(jwk.KeyIDKey, kid+"-exported"))

	hdr := jws.NewHeaders()
	require.NoError(t, hdr.Set(jws.KeyIDKey, kid))
	token, err := jws.Sign([]byte(`{"sub":"alice"}`),
		jws.WithKey(auditAlg(t, signingkey.EdDSA), signer, jws.WithProtectedHeaders(hdr)))
	require.NoError(t, err)

	verifySet, err := km.JWKS()
	require.NoError(t, err)
	_, verr := jws.Verify(token, jws.WithKeySet(verifySet))
	assert.NoError(t, verr,
		"a caller writing to a key it was handed must not break the manager's own verification")
}

// F2 — a stored record's Alg is never checked against the key it names, so the
// manager becomes current with a key it cannot sign with.
func TestStoredRecordAlgMustMatchItsKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	km, err := signingkey.NewKeyManager(
		signingkey.WithKeyStore(auditStore(t, signingkey.Record{
			Kid: "lies", Alg: signingkey.ES256, Private: auditDER(t, rsaKey),
			CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		})),
		signingkey.WithAlgs(signingkey.ES256),
	)
	require.Error(t, err,
		"an RSA key recorded as ES256 must be refused at construction")
	assert.Nil(t, km)
}

// F2b — the same gap for the curve: ES256 is P-256 only, and a P-384 key is
// adopted and signs under an "alg":"ES256" header with a 96-byte signature.
func TestES256KeyMustBeP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	km, err := signingkey.NewKeyManager(
		signingkey.WithKeyStore(auditStore(t, signingkey.Record{
			Kid: "p384", Alg: signingkey.ES256, Private: auditDER(t, key),
			CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		})),
		signingkey.WithAlgs(signingkey.ES256),
	)
	if err != nil {
		return // refused, which is what this test asks for
	}

	_, signer, ok := km.GetSigner(signingkey.ES256)
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
}

// F3 — a stored record naming an algorithm scrty cannot produce is adopted,
// made current, and published.
func TestStoredRecordAlgMustBeSupported(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	km, err := signingkey.NewKeyManager(
		signingkey.WithKeyStore(auditStore(t, signingkey.Record{
			Kid: "hs", Alg: "HS256", Private: auditDER(t, rsaKey),
			CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		})),
	)
	if err != nil {
		return // refused, which is what this test asks for
	}

	_, _, ok := km.GetSigner("HS256")
	assert.False(t, ok,
		"the manager offers no signer for an algorithm WithAlgs would have refused")

	set, err := km.JWKS()
	require.NoError(t, err)
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"HS256"`,
		"no published key declares an algorithm scrty does not support: %s", raw)
}

// F4 — the private half can be swapped under a record's recorded Kid and
// PublicJWK, and construction accepts it, republishing under a different kid.
func TestStoredRecordKidMustMatchItsPrivateKey(t *testing.T) {
	genuine := realRecord(t, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	swapped := genuine
	swapped.Private = auditDER(t, other)

	km, err := signingkey.NewKeyManager(signingkey.WithKeyStore(auditStore(t, swapped)))
	if err != nil {
		return // refused, which is what this test asks for
	}

	kid, _, ok := km.GetSigner(signingkey.RS256)
	require.True(t, ok)
	assert.Equal(t, swapped.Kid, kid,
		"a record is either refused or held under the identifier it carries; "+
			"it is never silently republished under a different one")
}

// F5 — the default store keeps no copy of the private bytes it is handed, so
// the caller's slice and every loaded slice alias one backing array.
func TestInMemoryStoreCopiesPrivateBytes(t *testing.T) {
	ctx := t.Context()
	store := signingkey.NewInMemoryKeyStore()

	secret := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	want := slices.Clone(secret)

	require.NoError(t, store.Store(ctx, signingkey.Record{
		Kid: "k", Alg: signingkey.RS256, Private: secret,
		CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}))

	for i := range secret {
		secret[i] = 0 // the caller wipes its own copy after handing it off
	}

	got, err := store.LoadAll(ctx)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, want, got[0].Private,
		"the store persists the bytes it was given, not a window onto the caller's slice")

	first, err := store.LoadAll(ctx)
	require.NoError(t, err)
	for i := range first[0].Private {
		first[0].Private[i] = 0xAA
	}
	second, err := store.LoadAll(ctx)
	require.NoError(t, err)
	assert.Equal(t, want, second[0].Private,
		"one reader must not be able to overwrite the key another reader loads")
}

// F6 — one algorithm named twice is accepted and mints one key per mention on
// every rotation.
func TestDuplicateAlgsAreRefused(t *testing.T) {
	store := signingkey.NewInMemoryKeyStore()
	clock := newFakeClock(epoch)

	km, err := signingkey.NewKeyManager(
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clock),
		signingkey.WithAlgs(signingkey.EdDSA, signingkey.EdDSA, signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(30*time.Minute),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithLifetime(24*time.Hour),
	)
	if err != nil {
		require.ErrorIs(t, err, signingkey.ErrConfig)
		return // refused, which is what this test asks for
	}
	t.Cleanup(func() { _ = km.Stop() })

	assert.Len(t, km.SupportedAlgs(), 1,
		"one algorithm named three times is one algorithm")

	require.NoError(t, km.Start(t.Context()))
	clock.Advance(time.Hour)
	require.Eventually(t, func() bool {
		recs, lerr := store.LoadAll(t.Context())
		return lerr == nil && len(recs) > 1
	}, 5*time.Second, 5*time.Millisecond)
	time.Sleep(200 * time.Millisecond)

	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)
	assert.Len(t, recs, 2,
		"one rotation of one algorithm mints one key, not one per mention")
}

// F7 — a housekeeping interval longer than the key lifetime silently extends
// how long a key stays published, with no error and no documented limit.
func TestHousekeepingIntervalMustHonourTheLifetime(t *testing.T) {
	km, err := signingkey.NewKeyManager(
		signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithLifetime(2*time.Hour),
		signingkey.WithHousekeepingInterval(1000*time.Hour),
	)
	require.ErrorIs(t, err, signingkey.ErrConfig,
		"a housekeeping interval 500x the lifetime cannot honour the lifetime it is asked to enforce")
	assert.Nil(t, km)
}

// F8 — a non-nil KeyStore interface holding a nil pointer gets past validate().
type auditNilStore struct{ records []signingkey.Record }

func (s *auditNilStore) Store(context.Context, signingkey.Record) error { return nil }

func (s *auditNilStore) LoadAll(context.Context) ([]signingkey.Record, error) {
	return s.records, nil
}

func TestTypedNilPortIsAConfigurationError(t *testing.T) {
	var store *auditNilStore

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("construction panicked rather than reporting a wiring mistake: %v", r)
		}
	}()

	km, err := signingkey.NewKeyManager(signingkey.WithKeyStore(store))
	require.Error(t, err, "a nil store is a configuration error whatever its static type")
	assert.Nil(t, km)
}
