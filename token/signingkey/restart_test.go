// The restart tests are not parallel: goleak counts goroutines process-wide.
package signingkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// restartable returns a manager on clk and store, configured so one clock
// advance of an hour rotates.
func restartable(t *testing.T, clk *clockwork.FakeClock, store signingkey.KeyStore) *signingkey.KeyManager {
	t.Helper()

	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithClock(clk),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(time.Hour),
		signingkey.WithLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	return km
}

// TestStartRelaunchesAfterItsContextWasCancelled pins what a consumer gets
// after the shutdown path Start's own godoc documents: cancelling the context
// ends the loops, and because Stop was never called the manager is not stopped,
// so a Start under a fresh context has to launch the loops again.
//
// Without that, Start returns nil having launched nothing, and the manager goes
// on serving one key that never rotates — with no error to notice.
func TestStartRelaunchesAfterItsContextWasCancelled(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	clk := newClock()
	store := newCountingStore()
	km := restartable(t, clk, store)
	store.zero()

	ctx, cancel := context.WithCancel(t.Context())
	require.NoError(t, km.Start(ctx))
	awaitParked(t, clk, loopCount)

	cancel()
	require.NoError(t, km.Start(t.Context()))

	// Six, not three. A loop ended by its context leaves its pending After
	// registered on the clock until that After fires, so the cancelled run's
	// three waiters are still counted. Waiting for three would return at once,
	// before the relaunched loops had parked, and the advance below could move
	// time past an interval they never saw begin.
	awaitParked(t, clk, 2*loopCount)
	kid := currentKid(t, km, signingkey.EdDSA)
	clk.Advance(time.Hour)

	// The advance fired the three stale waiters, which nobody receives from and
	// which do not return; only the relaunched loops park again.
	awaitParked(t, clk, loopCount)
	assert.NotEqual(t, kid, currentKid(t, km, signingkey.EdDSA), "a relaunched manager rotates again")
	assert.Equal(t, 1, store.stores(),
		"exactly one rotation: the cancelled run's loops ended and did not rotate too")

	require.NoError(t, km.Stop())
	goleak.VerifyNone(t, ignore)
}

// TestRestartedManager pins what construction publishes from a store that
// already holds keys, which is the whole of what a replica that never calls
// Start — one that only verifies — will ever publish. Construction applies the
// rule reload and housekeeping apply: a key past the lifetime is published only
// while it is the newest key of a configured algorithm.
func TestRestartedManager(t *testing.T) {
	type testCase struct {
		name string
		// seed returns the stored records and the one the case is about.
		seed func(t *testing.T) (recs []signingkey.Record, subject signingkey.Record)
		// start runs the manager's loops before the assertions.
		start  bool
		assert func(t *testing.T, km *signingkey.KeyManager, store signingkey.KeyStore, subject signingkey.Record)
	}

	cases := []testCase{
		{
			name: "refuses tokens from a key past its lifetime",
			seed: func(t *testing.T) ([]signingkey.Record, signingkey.Record) {
				old := realRecord(t, epoch.Add(-30*24*time.Hour))
				return []signingkey.Record{old, realRecord(t, epoch)}, old
			},
			start: true,
			assert: func(t *testing.T, km *signingkey.KeyManager, _ signingkey.KeyStore, old signingkey.Record) {
				// Whoever still holds the 30-day-old private key issues a fresh
				// token with it.
				holder, err := signingkey.NewKeyManager(t.Context(),
					signingkey.WithKeyStore(&listingStore{recs: []signingkey.Record{old}}),
					signingkey.WithClock(clockwork.NewFakeClockAt(old.CreatedAt)),
				)
				require.NoError(t, err)
				issuer, err := token.NewGenerator(holder, token.WithClock(newClock()))
				require.NoError(t, err)
				issued, err := issuer.Generate(t.Context(), "jti-1",
					&identity.Principal{ID: "u-1", Username: "alice"})
				require.NoError(t, err)

				verifier, err := token.NewVerifier(
					token.VerifyWithKeySource(km), token.VerifyWithClock(newClock()))
				require.NoError(t, err)

				_, err = verifier.Verify(t.Context(), issued)
				require.ErrorIs(t, err, token.ErrTokenInvalid,
					"a key 30 days past its 24h lifetime does not verify after a restart")
			},
		},
		{
			name: "keeps a stale sole key and mints no replacement",
			seed: func(t *testing.T) ([]signingkey.Record, signingkey.Record) {
				sole := realRecord(t, epoch.Add(-3*24*time.Hour))
				return []signingkey.Record{sole}, sole
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, store signingkey.KeyStore, sole signingkey.Record) {
				assert.Equal(t, sole.Kid, currentKid(t, km, signingkey.RS256),
					"the newest key of a configured algorithm is current whatever its age")
				assert.True(t, publishes(km, sole.Kid), "and it is published")

				recs, err := store.LoadAll(t.Context())
				require.NoError(t, err)
				assert.Len(t, recs, 1, "an algorithm that has a stored key gets no replacement")
			},
		},
		{
			name: "manager never started drops a past-lifetime key",
			seed: func(t *testing.T) ([]signingkey.Record, signingkey.Record) {
				old := realRecord(t, epoch.Add(-25*time.Hour))
				return []signingkey.Record{old, realRecord(t, epoch)}, old
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, _ signingkey.KeyStore, old signingkey.Record) {
				published, err := km.VerificationKeys()
				require.NoError(t, err)
				t.Logf("published keys after restart: %d", len(published))
				assert.False(t, publishes(km, old.Kid),
					"a non-current key past its lifetime is not published, with no housekeeping run")
				assert.Len(t, published, 1, "only the current key is published")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recs, subject := tc.seed(t)
			store := signingkey.NewInMemoryKeyStore()
			for _, rec := range recs {
				require.NoError(t, store.Store(t.Context(), rec))
			}

			km, err := signingkey.NewKeyManager(t.Context(),
				signingkey.WithKeyStore(store),
				signingkey.WithClock(newClock()),
			)
			require.NoError(t, err)
			if tc.start {
				stopAndVerify(t, km)
				require.NoError(t, km.Start(t.Context()))
			}

			tc.assert(t, km, store, subject)
		})
	}
}
