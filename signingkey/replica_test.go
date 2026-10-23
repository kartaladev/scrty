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
	clk := newClock()
	store := signingkey.NewInMemoryKeyStore()
	shared := []signingkey.Option{
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
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

	advance(t, clk, time.Minute, loopCount)
	k2 := currentKid(t, replicaA, signingkey.EdDSA)
	require.NotEqual(t, k1, k2, "replica A rotated")
	token := signWithCurrent(t, replicaA, "issued by replica A")

	// Replica B starts only now, so its reload is due exactly one reload
	// interval after the rotation it has to pick up — not part of it.
	require.NoError(t, replicaB.Start(t.Context()))
	stopAndVerify(t, replicaB)
	require.Equal(t, k1, currentKid(t, replicaB, signingkey.EdDSA),
		"replica B has not reloaded yet")

	// Both replicas share the clock, so both sets of loops are parked on it.
	const bothReplicas = 2 * loopCount

	advance(t, clk, 9*time.Second, bothReplicas)
	assert.False(t, publishes(replicaB, k2),
		"nothing is reloaded before the consumer's 10-second interval has elapsed")

	advance(t, clk, time.Second, bothReplicas) // ten seconds since replica A rotated
	kid, _, ok := replicaB.GetSigner(signingkey.EdDSA)
	require.True(t, publishes(replicaB, k2) && ok && kid == k2,
		"within one reload interval replica B publishes k2 and adopts it as current")

	setB := publishedSet(t, replicaB)
	payload, err := jws.Verify(token, jws.WithKeySet(setB))
	require.NoError(t, err, "replica B verifies a token replica A signed with k2")
	assert.Equal(t, "issued by replica A", string(payload))

	assert.True(t, publishes(replicaB, k1), "and keeps publishing the key k2 replaced")
}

func TestReloadSkipsExpiredKeysAndRepicksCurrent(t *testing.T) {
	clk := newClock()
	store := signingkey.NewInMemoryKeyStore()
	held := realRecord(t, epoch)
	require.NoError(t, store.Store(t.Context(), held))

	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
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

	advance(t, clk, 10*time.Second, loopCount)
	kid, _, ok := km.GetSigner(signingkey.RS256)
	require.True(t, publishes(km, newest.Kid) && ok && kid == newest.Kid,
		"a reload publishes the stored key and re-picks the latest CreatedAt as current")

	assert.False(t, publishes(km, expired.Kid),
		"a non-current key older than the lifetime is never republished")
	assert.True(t, publishes(km, held.Kid), "the key it replaced is still published")

	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)
	assert.Len(t, recs, 3, "a reload writes nothing")
}

func TestReloadFailureKeepsHeldKeys(t *testing.T) {
	clk := newClock()
	report := &failureReport{}
	recorder, logger := newLogRecorder()

	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(failingStore(t, report, opReload)),
		signingkey.WithClock(clk),
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

	advance(t, clk, 10*time.Second, loopCount)
	require.Equal(t, 1, report.hooks(), "the reload failure reaches the consumer's error hook")
	require.Equal(t, 1, recorder.written(), "the reload failure reaches the configured logger")

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
	assert.NotContains(t, records[0], "error",
		"the record no longer carries the store's own error text")
	assert.Equal(t, "signing-key-store", records[0]["reason"],
		"the record names the failed dependency by a fixed reason")
	assert.NotEmpty(t, records[0]["error_type"],
		"the record carries the error's type, never its text")
}

func TestReloadAfterClockStepBackKeepsASigner(t *testing.T) {
	clk := &steppedClock{FakeClock: newClock()}
	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.RS256),
		signingkey.WithRotateInterval(24*time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithLifetime(48*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)
	held := currentKid(t, km, signingkey.RS256)
	require.NoError(t, km.Start(t.Context()))

	// The reading steps back an hour, so the held key is dated further ahead
	// than one reload interval, then a reload runs.
	clk.back.Store(int64(time.Hour))
	advance(t, clk.FakeClock, time.Minute, loopCount)

	kid, signer, ok := km.GetSigner(signingkey.RS256)
	require.True(t, ok, "a reload never leaves a configured algorithm without a current key")
	assert.NotNil(t, signer)
	assert.Equal(t, held, kid, "the previous current key stays current")
}

func TestConstructionOverOnlyAFarFutureKeyMintsACurrentKey(t *testing.T) {
	clk := newClock()
	store := signingkey.NewInMemoryKeyStore()
	future := realRecord(t, epoch.Add(365*24*time.Hour))
	require.NoError(t, store.Store(t.Context(), future))

	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.RS256),
	)
	require.NoError(t, err)

	kid := currentKid(t, km, signingkey.RS256)
	assert.NotEqual(t, future.Kid, kid, "the far-future key does not sign")
	assert.False(t, publishes(km, future.Kid), "and is not published")
	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)
	assert.Len(t, recs, 2, "a new key was stored")
}

func TestReloadAdoptsAKeyStoredJustAhead(t *testing.T) {
	clk := newClock()
	store := signingkey.NewInMemoryKeyStore()
	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.RS256),
		signingkey.WithRotateInterval(24*time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithLifetime(48*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)
	require.NoError(t, km.Start(t.Context()))

	// A replica whose clock runs 90 seconds fast stores a key, so at the first
	// reload it is dated 30 seconds ahead, within the reload interval.
	ahead := realRecord(t, epoch.Add(90*time.Second))
	require.NoError(t, store.Store(t.Context(), ahead))

	advance(t, clk, time.Minute, loopCount)

	kid, _, ok := km.GetSigner(signingkey.RS256)
	require.True(t, ok)
	assert.Equal(t, ahead.Kid, kid, "a key within one reload interval ahead is adopted as current")
}
