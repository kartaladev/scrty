// The lifecycle tests are not parallel: goleak counts goroutines
// process-wide, so a parallel sibling's goroutine would look like a leak.
package signingkey_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/kartaladev/scrty/signingkey"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// fakeClock is a Clock whose time moves only when a test moves it, and which
// also makes the tickers the key manager's loops run on. Advancing it fires
// every ticker whose interval has elapsed, so a test drives rotation, reload
// and housekeeping at their configured intervals without waiting for them.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	tickers []*fakeTicker
}

func newFakeClock(now time.Time) *fakeClock { return &fakeClock{now: now} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *fakeClock) NewTicker(d time.Duration) signingkey.Ticker {
	c.mu.Lock()
	defer c.mu.Unlock()

	ticker := &fakeTicker{clock: c, every: d, next: c.now.Add(d), ch: make(chan time.Time, 1)}
	c.tickers = append(c.tickers, ticker)
	return ticker
}

// Advance moves time forward and fires every ticker due at the new time. Like
// time.Ticker, a ticker whose previous tick has not been consumed drops the new
// one, so advancing past several intervals delivers a single tick.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
	for _, ticker := range c.tickers {
		if ticker.stopped || c.now.Before(ticker.next) {
			continue
		}
		ticker.next = c.now.Add(ticker.every)
		select {
		case ticker.ch <- c.now:
		default:
		}
	}
}

// tickerCount reports how many tickers the manager asked for, which is how a
// test sees that Start launched every loop and Stop released them.
func (c *fakeClock) tickerCount() (live int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, ticker := range c.tickers {
		if !ticker.stopped {
			live++
		}
	}
	return live
}

type fakeTicker struct {
	clock   *fakeClock
	every   time.Duration
	next    time.Time
	ch      chan time.Time
	stopped bool // guarded by clock.mu
}

func (t *fakeTicker) C() <-chan time.Time { return t.ch }

func (t *fakeTicker) Stop() {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()

	t.stopped = true
}

// TestKeyManagerLifecycle drives one Start/Stop sequence per case. The assert
// closure both drives the sequence and asserts on it, because the sequence of
// calls is what varies; noLeak reports that no goroutine the case started is
// still running.
func TestKeyManagerLifecycle(t *testing.T) {
	type testCase struct {
		name   string
		assert func(t *testing.T, km *signingkey.KeyManager, noLeak func())
	}

	cases := []testCase{
		{
			name: "construction starts no goroutine",
			assert: func(_ *testing.T, _ *signingkey.KeyManager, noLeak func()) {
				noLeak()
			},
		},
		{
			name: "start is idempotent and stop leaves no goroutine",
			assert: func(t *testing.T, km *signingkey.KeyManager, noLeak func()) {
				require.NoError(t, km.Start(t.Context()))
				require.NoError(t, km.Start(t.Context()), "starting again launches nothing")
				require.NoError(t, km.Stop())
				noLeak()
				require.NoError(t, km.Stop(), "stopping again is a no-op")
			},
		},
		{
			name: "stop before start returns at once and start then launches nothing",
			assert: func(t *testing.T, km *signingkey.KeyManager, noLeak func()) {
				require.NoError(t, km.Stop())
				require.NoError(t, km.Start(t.Context()))
				noLeak()
			},
		},
		{
			name: "concurrent start and stop",
			assert: func(t *testing.T, km *signingkey.KeyManager, _ func()) {
				var wg sync.WaitGroup
				gate := make(chan struct{})
				for range 8 {
					wg.Add(2)
					go func() { defer wg.Done(); <-gate; _ = km.Start(t.Context()) }()
					go func() { defer wg.Done(); <-gate; _ = km.Stop() }()
				}
				close(gate)
				wg.Wait()
			},
		},
		{
			name: "cancelling the start context ends the work",
			assert: func(t *testing.T, km *signingkey.KeyManager, noLeak func()) {
				ctx, cancel := context.WithCancel(t.Context())
				require.NoError(t, km.Start(ctx))
				cancel()
				noLeak()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ignore := goleak.IgnoreCurrent()
			noLeak := func() { goleak.VerifyNone(t, ignore) }

			km, err := signingkey.NewKeyManager(
				signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
				signingkey.WithAlgs(signingkey.EdDSA),
			)
			require.NoError(t, err)

			tc.assert(t, km, noLeak)

			require.NoError(t, km.Stop())
			noLeak()
		})
	}
}

// TestStartLaunchesEveryLoop pins that Start launches all three loops and Stop
// releases them: each loop owns one ticker, taken from the configured clock.
func TestStartLaunchesEveryLoop(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	clock := newFakeClock(epoch)
	km, err := signingkey.NewKeyManager(
		signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithClock(clock),
	)
	require.NoError(t, err)
	require.Zero(t, clock.tickerCount(), "construction runs no loop, so it needs no ticker")

	require.NoError(t, km.Start(t.Context()))
	require.Equal(t, 3, clock.tickerCount(),
		"rotation, reload and housekeeping each run on their own ticker")

	require.NoError(t, km.Stop())
	require.Zero(t, clock.tickerCount(), "every loop releases its ticker when it ends")
	goleak.VerifyNone(t, ignore)
}
