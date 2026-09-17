// The algorithm-scope tests are not parallel: goleak counts goroutines
// process-wide.
package signingkey_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

// realRecordFor returns a genuine record for alg, created at the given time. It
// is minted by a throwaway manager so the private bytes and the thumbprint are
// real: only CreatedAt is rewritten. It is how a test stands in for another
// replica that wrote to the same store.
func realRecordFor(t *testing.T, alg signingkey.Alg, createdAt time.Time) signingkey.Record {
	t.Helper()

	store := signingkey.NewInMemoryKeyStore()
	_, err := signingkey.NewKeyManager(
		signingkey.WithKeyStore(store),
		signingkey.WithAlgs(alg),
	)
	require.NoError(t, err)

	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)
	require.Len(t, recs, 1)

	rec := recs[0]
	rec.CreatedAt = createdAt
	return rec
}

// TestForeignAlgorithmKeysVerifyButNeverSign pins where the configured
// algorithms bind. Two replicas may share a store while being configured
// differently, so the store holds keys for algorithms this manager was never
// asked about.
//
// Publishing them is useful: it is what lets this replica verify the other's
// tokens. Signing with them is not: SupportedAlgs would deny the algorithm
// while GetSigner handed out a working key for it, and a foreign key made
// current would be exempt from housekeeping for as long as the process lived.
func TestForeignAlgorithmKeysVerifyButNeverSign(t *testing.T) {
	clock := newFakeClock(epoch)
	store := signingkey.NewInMemoryKeyStore()

	// A replica configured for ES256 shares the store: one key past the
	// lifetime, one inside it.
	stale := realRecordFor(t, signingkey.ES256, epoch.Add(-25*time.Hour))
	fresh := realRecordFor(t, signingkey.ES256, epoch)
	require.NoError(t, store.Store(t.Context(), stale))
	require.NoError(t, store.Store(t.Context(), fresh))

	// This manager is configured for RS256 only.
	km, err := signingkey.NewKeyManager(
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clock),
		signingkey.WithAlgs(signingkey.RS256),
		signingkey.WithLifetime(24*time.Hour),
		signingkey.WithRotateInterval(6*time.Hour),
		signingkey.WithReloadInterval(30*time.Minute),
		signingkey.WithHousekeepingInterval(time.Second),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)

	require.Equal(t, []signingkey.Alg{signingkey.RS256}, km.SupportedAlgs())

	kid, signer, ok := km.GetSigner(signingkey.ES256)
	assert.False(t, ok, "GetSigner answers only for the configured algorithms")
	assert.Empty(t, kid)
	assert.Nil(t, signer)

	require.NotEmpty(t, currentKid(t, km, signingkey.RS256),
		"and the manager minted its own RS256 key rather than counting the stored ES256 one")

	require.True(t, jwksHas(km, fresh.Kid),
		"another replica's key is published, so the tokens it signed verify here")
	require.True(t, jwksHas(km, stale.Kid))

	require.NoError(t, km.Start(t.Context()))

	clock.Advance(time.Second)
	require.Eventually(t, func() bool { return !jwksHas(km, stale.Kid) },
		10*time.Second, 5*time.Millisecond,
		"housekeeping retires a foreign key past its lifetime")
	require.True(t, jwksHas(km, fresh.Kid), "the one inside the lifetime is kept")

	// The newest foreign key is the one a current-key exemption would protect
	// for the life of the process.
	clock.Advance(25 * time.Hour)
	assert.Eventually(t, func() bool { return !jwksHas(km, fresh.Kid) },
		10*time.Second, 5*time.Millisecond,
		"no foreign key is current, so none is exempt from housekeeping")

	_, _, ok = km.GetSigner(signingkey.ES256)
	assert.False(t, ok, "and none of it made the manager an ES256 signer")
}
