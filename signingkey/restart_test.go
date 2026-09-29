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

	"github.com/kartaladev/scrty/signingkey"
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
