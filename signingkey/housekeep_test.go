// The housekeeping tests are not parallel: goleak counts goroutines
// process-wide.
package signingkey_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

// TestHousekeeping drives housekeeping under a controlled clock.
//
// The housekeeping interval is shorter than the reload and rotation intervals,
// so one small advance runs housekeeping and nothing else. That isolation is
// what makes the assertions falsifiable: a reload in the same advance would
// republish the current key, and so would mask housekeeping having dropped it.
//
// Every case waits for the expired non-current key to disappear before
// asserting anything else. That is the only observable proof that housekeeping
// ran, so a claim about what it kept cannot pass merely because nothing
// happened.
func TestHousekeeping(t *testing.T) {
	type testCase struct {
		name string
		// seed returns the stored keys, oldest first. The last one is the
		// current key, and the first is the expired non-current key the case
		// waits on.
		seed   func(t *testing.T) []signingkey.Record
		assert func(t *testing.T, km *signingkey.KeyManager, store signingkey.KeyStore, current string)
	}

	cases := []testCase{
		{
			name: "a non-current key past its lifetime stops being published",
			seed: func(t *testing.T) []signingkey.Record {
				return []signingkey.Record{
					realRecord(t, epoch.Add(-25*time.Hour)),
					realRecord(t, epoch),
				}
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, store signingkey.KeyStore, current string) {
				assert.True(t, publishes(km, current), "the current key is untouched")
				assert.Equal(t, current, currentKid(t, km, signingkey.RS256))

				recs, err := store.LoadAll(t.Context())
				require.NoError(t, err)
				assert.Len(t, recs, 2,
					"housekeeping stops publishing a key; it does not prune the store")
			},
		},
		{
			name: "the current key is kept however old it is",
			seed: func(t *testing.T) []signingkey.Record {
				// Rotation is six hours away, so the newest stored key is
				// still current at twenty-five hours old.
				return []signingkey.Record{
					realRecord(t, epoch.Add(-30*time.Hour)),
					realRecord(t, epoch.Add(-25*time.Hour)),
				}
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, _ signingkey.KeyStore, current string) {
				assert.True(t, publishes(km, current),
					"a current key created 25 hours ago is still published")
				assert.Equal(t, current, currentKid(t, km, signingkey.RS256),
					"and is still the key that signs")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := newClock()
			store := signingkey.NewInMemoryKeyStore()
			seed := tc.seed(t)
			for _, rec := range seed {
				require.NoError(t, store.Store(t.Context(), rec))
			}

			km, err := signingkey.NewKeyManager(t.Context(),
				signingkey.WithKeyStore(store),
				signingkey.WithClock(clk),
				signingkey.WithLifetime(24*time.Hour),
				signingkey.WithHousekeepingInterval(time.Second),
				signingkey.WithReloadInterval(30*time.Minute),
				signingkey.WithRotateInterval(6*time.Hour),
			)
			require.NoError(t, err)
			stopAndVerify(t, km)

			expired, current := seed[0].Kid, seed[len(seed)-1].Kid
			require.Equal(t, current, currentKid(t, km, signingkey.RS256))
			require.True(t, publishes(km, expired), "the expired key is published to begin with")

			require.NoError(t, km.Start(t.Context()))

			advance(t, clk, time.Second, loopCount)
			require.False(t, publishes(km, expired),
				"housekeeping should have stopped publishing the expired key")

			tc.assert(t, km, store, current)
		})
	}
}

// TestHousekeepingAndRotationNeverDeadlock runs rotation and housekeeping
// together, over and over. Housekeeping takes the keyring lock itself, so being
// called while rotation held that lock would deadlock; the loops would then
// never park again, and the bounded wait for them is what turns that into a
// failure instead of a hang.
func TestHousekeepingAndRotationNeverDeadlock(t *testing.T) {
	clk := newClock()
	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithHousekeepingInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithLifetime(2*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)

	require.NoError(t, km.Start(t.Context()))

	kid := currentKid(t, km, signingkey.EdDSA)
	for round := range 12 {
		advance(t, clk, time.Hour, loopCount)
		next := currentKid(t, km, signingkey.EdDSA)
		require.NotEqual(t, kid, next, "round %d rotates", round)
		kid = next
	}

	keys, err := km.VerificationKeys()
	require.NoError(t, err)
	assert.LessOrEqual(t, len(keys), 3,
		"keys past the 2-hour lifetime stopped being published as the rounds went by")
}

// TestHousekeepingKeepsAKeyUntilItHasOutlivedTheLifetime pins the boundary
// itself. A key is published for the lifetime it was given, so one whose age is
// exactly that lifetime is still published, and one any older is not.
//
// The interval is what makes the boundary reachable: the sweep that runs at
// epoch+1s is the one that sees boundary at exactly 24 hours old. stale is an
// hour further on and is the case's proof that the sweep ran at all.
func TestHousekeepingKeepsAKeyUntilItHasOutlivedTheLifetime(t *testing.T) {
	const (
		lifetime = 24 * time.Hour
		sweep    = time.Second
	)

	clk := newClock()
	store := signingkey.NewInMemoryKeyStore()

	stale := realRecord(t, epoch.Add(sweep-lifetime-time.Hour))
	boundary := realRecord(t, epoch.Add(sweep-lifetime))
	newest := realRecord(t, epoch)
	for _, rec := range []signingkey.Record{stale, boundary, newest} {
		require.NoError(t, store.Store(t.Context(), rec))
	}

	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithLifetime(lifetime),
		signingkey.WithHousekeepingInterval(sweep),
		signingkey.WithReloadInterval(30*time.Minute),
		signingkey.WithRotateInterval(6*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)

	require.Equal(t, newest.Kid, currentKid(t, km, signingkey.RS256))
	require.NoError(t, km.Start(t.Context()))

	advance(t, clk, sweep, loopCount)
	require.False(t, publishes(km, stale.Kid),
		"the sweep ran: a key an hour past its lifetime stopped being published")
	assert.True(t, publishes(km, boundary.Kid),
		"a key whose age is exactly the lifetime has not outlived it")

	advance(t, clk, sweep, loopCount)
	assert.False(t, publishes(km, boundary.Kid), "and one a sweep older has")
	assert.True(t, publishes(km, newest.Kid), "the current key is kept throughout")
}
