// The reload tests are not parallel: goleak counts goroutines process-wide.
package signingkey_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

// signWithCurrent issues a real EdDSA JWS with the source's current key, so a
// test can check that another replica, or another implementation of the port,
// is able to verify it.
func signWithCurrent(t *testing.T, source signingkey.KeySource, payload string) []byte {
	t.Helper()

	kid, signer, ok := source.GetSigner(signingkey.EdDSA)
	require.True(t, ok)

	private, err := jwk.Import[jwk.Key](signer)
	require.NoError(t, err)
	require.NoError(t, private.Set(jwk.KeyIDKey, kid))

	signature, err := jws.Sign([]byte(payload), jws.WithKey(jwa.EdDSA(), private))
	require.NoError(t, err)
	return signature
}

func TestReloadPublishesAnotherReplicasKeys(t *testing.T) {
	clock := newFakeClock(epoch)
	store := signingkey.NewInMemoryKeyStore()
	shared := []signingkey.Option{
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clock),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithReloadInterval(10 * time.Second), // the consumer's interval
		signingkey.WithHousekeepingInterval(12 * time.Hour),
	}

	// Replica A is the one that rotates. Replica B rotates so rarely that
	// everything it publishes beyond its own first key came from the store.
	replicaA, err := signingkey.NewKeyManager(t.Context(), append(shared,
		signingkey.WithRotateInterval(time.Minute),
		signingkey.WithLifetime(24*time.Hour))...)
	require.NoError(t, err)
	replicaB, err := signingkey.NewKeyManager(t.Context(), append(shared,
		signingkey.WithRotateInterval(24*time.Hour),
		signingkey.WithLifetime(48*time.Hour))...)
	require.NoError(t, err)

	k1 := currentKid(t, replicaA, signingkey.EdDSA)
	require.Equal(t, k1, currentKid(t, replicaB, signingkey.EdDSA),
		"both replicas start on the one stored key")

	require.NoError(t, replicaA.Start(t.Context()))
	stopAndVerify(t, replicaA)

	clock.Advance(time.Minute)
	k2 := waitForRotation(t, replicaA, signingkey.EdDSA, k1)
	token := signWithCurrent(t, replicaA, "issued by replica A")

	// Replica B starts only now, so its reload ticker is due exactly one
	// reload interval after the rotation it has to pick up — not part of it.
	require.NoError(t, replicaB.Start(t.Context()))
	stopAndVerify(t, replicaB)
	require.Equal(t, k1, currentKid(t, replicaB, signingkey.EdDSA),
		"replica B has not reloaded yet")

	clock.Advance(9 * time.Second)
	assert.Never(t, func() bool { return publishes(replicaB, k2) },
		200*time.Millisecond, 20*time.Millisecond,
		"nothing is reloaded before the consumer's 10-second interval has elapsed")

	clock.Advance(time.Second) // ten seconds since replica A rotated
	require.Eventually(t, func() bool {
		kid, _, ok := replicaB.GetSigner(signingkey.EdDSA)
		return publishes(replicaB, k2) && ok && kid == k2
	}, 10*time.Second, 5*time.Millisecond,
		"within one reload interval replica B publishes k2 and adopts it as current")

	setB := publishedSet(t, replicaB)
	payload, err := jws.Verify(token, jws.WithKeySet(setB))
	require.NoError(t, err, "replica B verifies a token replica A signed with k2")
	assert.Equal(t, "issued by replica A", string(payload))

	assert.True(t, publishes(replicaB, k1), "and keeps publishing the key k2 replaced")
}

func TestReloadSkipsExpiredKeysAndRepicksCurrent(t *testing.T) {
	clock := newFakeClock(epoch)
	store := signingkey.NewInMemoryKeyStore()
	held := realRecord(t, epoch)
	require.NoError(t, store.Store(t.Context(), held))

	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clock),
		signingkey.WithReloadInterval(10*time.Second),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)

	require.Equal(t, held.Kid, currentKid(t, km, signingkey.RS256))

	// Another replica writes one key past the lifetime and one newer than
	// anything held.
	expired := realRecord(t, epoch.Add(-25*time.Hour))
	newest := realRecord(t, epoch.Add(5*time.Second))
	require.NoError(t, store.Store(t.Context(), expired))
	require.NoError(t, store.Store(t.Context(), newest))

	require.NoError(t, km.Start(t.Context()))

	clock.Advance(10 * time.Second)
	require.Eventually(t, func() bool {
		kid, _, ok := km.GetSigner(signingkey.RS256)
		return publishes(km, newest.Kid) && ok && kid == newest.Kid
	}, 10*time.Second, 5*time.Millisecond,
		"a reload publishes the stored key and re-picks the latest CreatedAt as current")

	assert.False(t, publishes(km, expired.Kid),
		"a non-current key older than the lifetime is never republished")
	assert.True(t, publishes(km, held.Kid), "the key it replaced is still published")

	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)
	assert.Len(t, recs, 3, "a reload writes nothing")
}

func TestReloadFailureKeepsHeldKeys(t *testing.T) {
	clock := newFakeClock(epoch)
	report := &failureReport{}
	recorder, logger := newLogRecorder()

	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(failingStore(t, report, opReload)),
		signingkey.WithClock(clock),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithLogger(logger),
		signingkey.WithErrorHook(report.hook),
		signingkey.WithReloadInterval(10*time.Second),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)

	held := currentKid(t, km, signingkey.EdDSA)
	token := signWithCurrent(t, km, "issued before the outage")

	require.NoError(t, km.Start(t.Context()))

	clock.Advance(10 * time.Second)
	require.Eventually(t, func() bool { return report.hooks() >= 1 },
		10*time.Second, 5*time.Millisecond,
		"the reload failure reaches the consumer's error hook")

	hooked, _ := report.snapshot()
	assert.ErrorIs(t, hooked[0], errStoreUnreachable,
		"the hook receives an error wrapping the store's error")

	assert.Equal(t, held, currentKid(t, km, signingkey.EdDSA),
		"the manager keeps signing with the keys it already holds")
	assert.True(t, publishes(km, held))

	set := publishedSet(t, km)
	payload, err := jws.Verify(token, jws.WithKeySet(set))
	require.NoError(t, err, "and keeps verifying the tokens they signed")
	assert.Equal(t, "issued before the outage", string(payload))

	records := recorder.records(t)
	require.NotEmpty(t, records, "the failure reaches the configured logger")
	assert.Equal(t, "ERROR", records[0]["level"])
	assert.Contains(t, records[0]["error"], errStoreUnreachable.Error())
}
