// The error-hook tests are not parallel: goleak counts goroutines
// process-wide.
package signingkey_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/kartaladev/scrty/signingkey"
)

// TestErrorHookMayReadTheManagerBack pins the half of WithErrorHook's contract
// a consumer can act on. The hook runs on the loop goroutine, so it must not
// call Start or Stop — that is documented, not enforceable — but reading the
// manager back is safe, which is what a hook needs in order to decide whether
// an outage has cost it its keys.
//
// The manager therefore must not hold the keyring lock across the hook, and
// nothing else in the suite observes that: a hook that only counts failures is
// happy either way. The loop must also go on reporting afterwards, and Stop
// must still return.
func TestErrorHookMayReadTheManagerBack(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	const attempts = 3

	var (
		km     *signingkey.KeyManager
		report = &failureReport{}
		reads  atomic.Int32
	)

	// hook does everything WithErrorHook's godoc names as safe from the hook,
	// and counts the times all of it answered.
	hook := func(err error) {
		kid, signer, ok := km.GetSigner(signingkey.EdDSA)
		published, keysErr := km.VerificationKeys()
		if ok && signer != nil && kid != "" &&
			keysErr == nil && len(published) > 0 &&
			len(km.SupportedAlgs()) == 1 && km.KeyLifetime() > 0 {
			reads.Add(1)
		}
		report.hook(err)
	}

	clk := newClock()

	var err error
	km, err = signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(failingStore(t, report, opRotate)),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithErrorHook(hook),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, km.Start(t.Context()))

	for attempt := 1; attempt <= attempts; attempt++ {
		// A hook that stalled its loop would keep it from parking again, which
		// advance reports as a failure rather than a hang.
		advance(t, clk, time.Hour, loopCount)
		require.Equal(t, attempt, report.hooks(),
			"rotation failure %d should have been reported: a hook that reads the "+
				"manager back must not stall the loop it runs on", attempt)
	}

	assert.GreaterOrEqual(t, reads.Load(), int32(attempts),
		"every call to the hook could read the manager back")

	// Stop is what the hook may not call; the consumer's own goroutine still
	// can, and it has to return.
	stopped := make(chan error, 1)
	go func() { stopped <- km.Stop() }()
	select {
	case stopErr := <-stopped:
		require.NoError(t, stopErr)
	case <-time.After(30 * time.Second):
		t.Fatal("Stop never returned after the error hook had read the manager back")
	}

	goleak.VerifyNone(t, ignore)
}
