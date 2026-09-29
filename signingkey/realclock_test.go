// The system-clock tests are not parallel: goleak counts goroutines
// process-wide. They are the only tests that wait on real time, because they
// are the only ones asserting on the clock a consumer actually ships with.
package signingkey_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/kartaladev/scrty/signingkey"
)

// TestSystemClockDrivesTheLoops runs the loops on the default clock, which is
// what every consumer that configures no clock gets, and the one path a
// controlled clock can never exercise.
//
// The intervals are milliseconds so the test finishes, but nothing else is
// faked: a real interval has to rotate, has to stop publishing a key past its
// lifetime, and has to reload a key another replica wrote.
func TestSystemClockDrivesTheLoops(t *testing.T) {
	type testCase struct {
		name string
		// intervals are the case's rotation, reload, housekeeping and lifetime
		// options, short where the case waits on that loop and long enough to
		// pass validation elsewhere.
		intervals []signingkey.Option
		assert    func(t *testing.T, km *signingkey.KeyManager, store signingkey.KeyStore)
	}

	cases := []testCase{
		{
			name: "rotation and housekeeping",
			intervals: []signingkey.Option{
				signingkey.WithRotateInterval(50 * time.Millisecond),
				signingkey.WithReloadInterval(10 * time.Millisecond),
				signingkey.WithHousekeepingInterval(10 * time.Millisecond),
				signingkey.WithLifetime(120 * time.Millisecond),
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, _ signingkey.KeyStore) {
				first := currentKid(t, km, signingkey.EdDSA)
				require.NoError(t, km.Start(t.Context()))

				second := waitForRotation(t, km, signingkey.EdDSA, first)
				require.NotEqual(t, first, second, "a real interval rotates")

				assert.Eventually(t, func() bool { return !publishes(km, first) },
					10*time.Second, 5*time.Millisecond,
					"and a real interval stops publishing the replaced key once it is past its lifetime")
			},
		},
		{
			name: "reload",
			intervals: []signingkey.Option{
				signingkey.WithRotateInterval(time.Hour),
				signingkey.WithReloadInterval(20 * time.Millisecond),
				signingkey.WithHousekeepingInterval(time.Hour),
				signingkey.WithLifetime(24 * time.Hour),
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, store signingkey.KeyStore) {
				// Another replica, configured for an algorithm this one does not
				// sign with, writes its first key after this one was built.
				other, err := signingkey.NewKeyManager(t.Context(),
					signingkey.WithKeyStore(store),
					signingkey.WithAlgs(signingkey.ES256),
				)
				require.NoError(t, err)
				written := currentKid(t, other, signingkey.ES256)
				require.False(t, publishes(km, written), "this replica has not reloaded yet")

				require.NoError(t, km.Start(t.Context()))
				assert.Eventually(t, func() bool { return publishes(km, written) },
					2*time.Second, 5*time.Millisecond,
					"a real interval reloads the key the other replica wrote")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ignore := goleak.IgnoreCurrent()

			store := signingkey.NewInMemoryKeyStore()
			km, err := signingkey.NewKeyManager(t.Context(), append([]signingkey.Option{
				signingkey.WithKeyStore(store),
				signingkey.WithAlgs(signingkey.EdDSA),
			}, tc.intervals...)...)
			require.NoError(t, err)

			tc.assert(t, km, store)

			require.NoError(t, km.Stop())
			assert.True(t, publishes(km, currentKid(t, km, signingkey.EdDSA)),
				"whatever is current when Stop returns is still published")
			goleak.VerifyNone(t, ignore)
		})
	}
}
