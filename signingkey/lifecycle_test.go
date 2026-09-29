// The lifecycle tests are not parallel: goleak counts goroutines
// process-wide, so a parallel sibling's goroutine would look like a leak.
package signingkey_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/kartaladev/scrty/signingkey"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// loopCount is how many background loops one started manager runs: rotation,
// reload and housekeeping, each parked on its own After between runs.
const loopCount = 3

// parkTimeout bounds how long a test waits for the loops to park on the
// controlled clock. It is a failure bound, never a way of synchronising: every
// wait returns the moment the loops have parked, and only a loop that never
// parks — one not driven by the clock at all — waits it out.
const parkTimeout = 10 * time.Second

// newClock returns a controlled clock at epoch. Its time moves only when a
// test advances it, and advancing it fires every After that has come due.
func newClock() *clockwork.FakeClock { return clockwork.NewFakeClockAt(epoch) }

// awaitParked returns once n Afters are pending on clk, which for a started
// manager is the proof that its loops are waiting for their next interval.
// Every Advance must be preceded by it: advancing before a loop has asked for
// its After would move time past an interval the loop never saw begin.
func awaitParked(t *testing.T, clk *clockwork.FakeClock, n int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), parkTimeout)
	defer cancel()
	require.NoError(t, clk.BlockUntilContext(ctx, n),
		"%d background loops should be parked on the clock", n)
}

// advance moves clk on by d once n loops are parked, and returns once they are
// parked again. A loop re-parks only after its run has finished, so on return
// every run the advance started has completed, and a test can assert on what
// it did without polling.
func advance(t *testing.T, clk *clockwork.FakeClock, d time.Duration, n int) {
	t.Helper()

	awaitParked(t, clk, n)
	clk.Advance(d)
	awaitParked(t, clk, n)
}

// countingStore is the in-memory key store, counting the writes and loads the
// manager makes of it, and able to hold the next load until the test releases
// it.
type countingStore struct {
	signingkey.KeyStore

	mu          sync.Mutex
	storeCalls  int
	loadCalls   int
	holdNext    bool          // the next LoadAll waits for hold to close
	hold        chan struct{} // closed by releaseLoad
	loadStarted chan struct{} // closed when the held LoadAll has begun
}

func newCountingStore() *countingStore {
	return &countingStore{KeyStore: signingkey.NewInMemoryKeyStore()}
}

func (s *countingStore) Store(ctx context.Context, rec signingkey.Record) error {
	s.mu.Lock()
	s.storeCalls++
	s.mu.Unlock()

	return s.KeyStore.Store(ctx, rec)
}

func (s *countingStore) LoadAll(ctx context.Context) ([]signingkey.Record, error) {
	s.mu.Lock()
	s.loadCalls++
	held, hold, started := s.holdNext, s.hold, s.loadStarted
	s.holdNext = false
	s.mu.Unlock()

	if held {
		close(started)
		select {
		case <-hold:
		case <-ctx.Done(): // a failed test's Stop must not wait on the hold
		}
	}
	return s.KeyStore.LoadAll(ctx)
}

// zero forgets the calls made so far, so a test counts only what the loops do
// and not what construction did.
func (s *countingStore) zero() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.storeCalls, s.loadCalls = 0, 0
}

func (s *countingStore) stores() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.storeCalls
}

func (s *countingStore) loads() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.loadCalls
}

// holdNextLoad makes the next LoadAll wait until releaseLoad is called.
func (s *countingStore) holdNextLoad() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.holdNext = true
	s.hold, s.loadStarted = make(chan struct{}), make(chan struct{})
}

// awaitLoadStarted returns once the held LoadAll has begun.
func (s *countingStore) awaitLoadStarted(t *testing.T) {
	t.Helper()

	s.mu.Lock()
	started := s.loadStarted
	s.mu.Unlock()

	select {
	case <-started:
	case <-time.After(parkTimeout):
		t.Fatal("the held reload never began")
	}
}

// releaseLoad lets the held LoadAll finish.
func (s *countingStore) releaseLoad() {
	s.mu.Lock()
	defer s.mu.Unlock()

	close(s.hold)
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

			km, err := signingkey.NewKeyManager(t.Context(),
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

// TestLifecycleLoopsRunOnTheClock drives the background loops through a
// controlled clock. Nothing waits on real time: each case parks the loops,
// advances the clock, and asserts on what the store saw once the loops have
// parked again.
//
// The manager runs RS256 only, rotates hourly, reloads every minute and sweeps
// hourly. Housekeeping touches no store, so the counts are rotation's writes
// and reload's loads; construction's own load and write are zeroed first.
func TestLifecycleLoopsRunOnTheClock(t *testing.T) {
	type testCase struct {
		name   string
		assert func(t *testing.T, clk *clockwork.FakeClock, km *signingkey.KeyManager, store *countingStore)
	}

	cases := []testCase{
		{
			name: "one interval runs rotation, reload and housekeeping once each",
			assert: func(t *testing.T, clk *clockwork.FakeClock, km *signingkey.KeyManager, store *countingStore) {
				require.NoError(t, km.Start(t.Context()))

				advance(t, clk, time.Hour, loopCount)
				assert.Equal(t, 1, store.stores(), "one rotation for the one configured algorithm")
				assert.Equal(t, 1, store.loads(), "one reload: the minute intervals inside the hour did not each run")
			},
		},
		{
			name: "the interval is measured from the end of a run",
			assert: func(t *testing.T, clk *clockwork.FakeClock, km *signingkey.KeyManager, store *countingStore) {
				store.holdNextLoad()
				require.NoError(t, km.Start(t.Context()))

				awaitParked(t, clk, loopCount)
				clk.Advance(time.Minute) // the reload starts at +1m
				store.awaitLoadStarted(t)
				clk.Advance(3 * time.Second) // and is still running at +1m3s
				store.releaseLoad()
				awaitParked(t, clk, loopCount)

				clk.Advance(time.Minute - time.Nanosecond) // +2m3s less 1ns: not yet
				awaitParked(t, clk, loopCount)
				assert.Equal(t, 1, store.loads(), "the next reload is a full interval after the last one finished")

				advance(t, clk, time.Nanosecond, loopCount) // +2m3s
				assert.Equal(t, 2, store.loads(), "and runs as soon as that interval has elapsed")
			},
		},
		{
			name: "a long jump runs each loop once",
			assert: func(t *testing.T, clk *clockwork.FakeClock, km *signingkey.KeyManager, store *countingStore) {
				require.NoError(t, km.Start(t.Context()))

				advance(t, clk, 5*time.Hour, loopCount)
				assert.Equal(t, 1, store.stores(), "five hourly intervals at once rotate once, not five times")
				assert.Equal(t, 1, store.loads(), "and reload once, not three hundred times")

				advance(t, clk, time.Hour-time.Nanosecond, loopCount)
				assert.Equal(t, 1, store.stores(), "the next rotation is a full interval after the jump")

				advance(t, clk, time.Nanosecond, loopCount)
				assert.Equal(t, 2, store.stores(), "and runs once that interval has elapsed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ignore := goleak.IgnoreCurrent()

			clk := newClock()
			store := newCountingStore()
			km, err := signingkey.NewKeyManager(t.Context(),
				signingkey.WithKeyStore(store),
				signingkey.WithClock(clk),
				signingkey.WithAlgs(signingkey.RS256),
				signingkey.WithRotateInterval(time.Hour),
				signingkey.WithReloadInterval(time.Minute),
				signingkey.WithHousekeepingInterval(time.Hour),
			)
			require.NoError(t, err)
			store.zero()

			tc.assert(t, clk, km, store)

			require.NoError(t, km.Stop())
			goleak.VerifyNone(t, ignore)
		})
	}
}
