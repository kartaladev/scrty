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
				assert.True(t, jwksHas(km, current), "the current key is untouched")
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
				assert.True(t, jwksHas(km, current),
					"a current key created 25 hours ago is still published")
				assert.Equal(t, current, currentKid(t, km, signingkey.RS256),
					"and is still the key that signs")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeClock(epoch)
			store := signingkey.NewInMemoryKeyStore()
			seed := tc.seed(t)
			for _, rec := range seed {
				require.NoError(t, store.Store(t.Context(), rec))
			}

			km, err := signingkey.NewKeyManager(
				signingkey.WithKeyStore(store),
				signingkey.WithClock(clock),
				signingkey.WithLifetime(24*time.Hour),
				signingkey.WithHousekeepingInterval(time.Second),
				signingkey.WithReloadInterval(30*time.Minute),
				signingkey.WithRotateInterval(6*time.Hour),
			)
			require.NoError(t, err)
			stopAndVerify(t, km)

			expired, current := seed[0].Kid, seed[len(seed)-1].Kid
			require.Equal(t, current, currentKid(t, km, signingkey.RS256))
			require.True(t, jwksHas(km, expired), "the expired key is published to begin with")

			require.NoError(t, km.Start(t.Context()))

			clock.Advance(time.Second)
			require.Eventually(t, func() bool { return !jwksHas(km, expired) },
				10*time.Second, 5*time.Millisecond,
				"housekeeping should have stopped publishing the expired key")

			tc.assert(t, km, store, current)
		})
	}
}

// TestHousekeepingAndRotationNeverDeadlock ticks rotation and housekeeping
// together, over and over. Housekeeping takes the keyring lock itself, so being
// called while rotation held that lock would deadlock; the test's timeout is
// what turns that into a failure instead of a hang.
func TestHousekeepingAndRotationNeverDeadlock(t *testing.T) {
	clock := newFakeClock(epoch)
	km, err := signingkey.NewKeyManager(
		signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
		signingkey.WithClock(clock),
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
		clock.Advance(time.Hour)
		kid = waitForRotation(t, km, signingkey.EdDSA, kid)
		require.NotEmpty(t, kid, "round %d", round)
	}

	set, err := km.JWKS()
	require.NoError(t, err)
	assert.LessOrEqual(t, set.Len(), 3,
		"keys past the 2-hour lifetime stopped being published as the rounds went by")
}
