// The restart tests are not parallel: goleak counts goroutines process-wide.
package signingkey_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/kartaladev/scrty/signingkey"
)

// restartable returns a manager and its clock, configured so one clock advance
// of an hour rotates.
func restartable(t *testing.T, clock signingkey.Clock) *signingkey.KeyManager {
	t.Helper()

	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithClock(clock),
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

	clock := newFakeClock(epoch)
	km := restartable(t, clock)

	ctx, cancel := context.WithCancel(t.Context())
	require.NoError(t, km.Start(ctx))
	require.Equal(t, 3, clock.tickerCount())

	cancel()
	// Every loop releases its ticker as it ends, so no live ticker is the
	// observable proof that the run is over.
	require.Eventually(t, func() bool { return clock.tickerCount() == 0 },
		10*time.Second, time.Millisecond,
		"cancelling the Start context ends the loops")

	require.NoError(t, km.Start(t.Context()))
	assert.Equal(t, 3, clock.tickerCount(),
		"a Start under a fresh context relaunches every loop")

	kid := currentKid(t, km, signingkey.EdDSA)
	clock.Advance(time.Hour)
	assert.NotEqual(t, kid, waitForRotation(t, km, signingkey.EdDSA, kid),
		"a relaunched manager rotates again")

	require.NoError(t, km.Stop())
	goleak.VerifyNone(t, ignore)
}

// panickyClock is a consumer TickerClock — WithClock and TickerClock advertise
// it as an override point — whose nth call to NewTicker panics. Its tickers are
// a fakeClock's, so a test can still see how many the manager holds.
type panickyClock struct {
	*fakeClock

	mu      sync.Mutex
	panicOn int // 1-based NewTicker call that panics; 0 panics on none
	calls   int
}

func newPanickyClock(panicOn int) *panickyClock {
	return &panickyClock{fakeClock: newFakeClock(epoch), panicOn: panicOn}
}

func (c *panickyClock) NewTicker(d time.Duration) signingkey.Ticker {
	c.mu.Lock()
	c.calls++
	boom := c.calls == c.panicOn
	c.mu.Unlock()

	if boom {
		panic("consumer clock exploded")
	}
	return c.fakeClock.NewTicker(d)
}

// disarm stops the clock panicking, so a test can go on to start the manager
// for real.
func (c *panickyClock) disarm() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.panicOn = 0
}

// stopWithin stops km and fails the test if that takes longer than a shutdown
// ever should. A Stop that cannot return is the failure mode being tested, so
// it must show up as a failed assertion rather than as a hung package.
func stopWithin(t *testing.T, km *signingkey.KeyManager, why string) {
	t.Helper()

	stopped := make(chan error, 1)
	go func() { stopped <- km.Stop() }()

	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatalf("Stop never returned: %s", why)
	}
}

// TestStartLeavesNoRunBehindWhenTheClockPanics starts a manager on a consumer
// clock that panics partway through handing out the loops' tickers.
//
// A panic inside Start must leave the manager exactly as it was: no ticker
// held, no run for Stop to wait for, and no goroutine counted that was never
// launched. Counting the loops before they are launched breaks the last of
// those, and it is the next Start that pays: its Stop waits for six loop
// goroutines where three are running, forever, holding the lock every later
// Start and Stop needs.
func TestStartLeavesNoRunBehindWhenTheClockPanics(t *testing.T) {
	type testCase struct {
		name string
		// assert is what the consumer does once it has recovered from the
		// panic, and what that has to be worth.
		assert func(t *testing.T, km *signingkey.KeyManager, clock *panickyClock)
	}

	cases := []testCase{
		{
			name: "the consumer recovers and shuts down",
			assert: func(t *testing.T, km *signingkey.KeyManager, _ *panickyClock) {
				stopWithin(t, km, "a Start that panicked left a run behind to wait for")
			},
		},
		{
			name: "the consumer recovers and starts again",
			assert: func(t *testing.T, km *signingkey.KeyManager, clock *panickyClock) {
				clock.disarm()

				require.NoError(t, km.Start(t.Context()))
				require.Equal(t, 3, clock.tickerCount(),
					"the Start after the panic launches every loop")

				kid := currentKid(t, km, signingkey.EdDSA)
				clock.Advance(time.Hour)
				assert.NotEqual(t, kid, waitForRotation(t, km, signingkey.EdDSA, kid),
					"and those loops run")

				stopWithin(t, km, "the Start that panicked counted loops it never launched")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ignore := goleak.IgnoreCurrent()

			// The rotation loop's ticker is handed out; the reload loop's panics.
			clock := newPanickyClock(2)
			km := restartable(t, clock)

			func() {
				defer func() {
					require.NotNil(t, recover(), "the consumer's clock panicked, so Start did")
				}()
				_ = km.Start(t.Context())
			}()

			require.Zero(t, clock.tickerCount(),
				"a Start that panicked releases the tickers it had already taken")

			tc.assert(t, km, clock)

			require.NoError(t, km.Stop())
			goleak.VerifyNone(t, ignore)
		})
	}
}
