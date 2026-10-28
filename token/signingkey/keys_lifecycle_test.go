// The lifecycle, restart, stop and system-clock tests are not parallel: goleak
// counts goroutines process-wide, so a parallel sibling's goroutine would look
// like a leak. The system-clock tests are the only tests that wait on real
// time, because they are the only ones asserting on the clock a consumer
// actually ships with.
package signingkey_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

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
	return &countingStore{KeyStore: signingkey.NewMemoryKeyStore()}
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
		assert func(t *testing.T, km *signingkey.Keys, noLeak func())
	}

	cases := []testCase{
		{
			name: "construction starts no goroutine",
			assert: func(_ *testing.T, _ *signingkey.Keys, noLeak func()) {
				noLeak()
			},
		},
		{
			name: "start is idempotent and stop leaves no goroutine",
			assert: func(t *testing.T, km *signingkey.Keys, noLeak func()) {
				require.NoError(t, km.Start(t.Context()))
				require.NoError(t, km.Start(t.Context()), "starting again launches nothing")
				require.NoError(t, km.Stop())
				noLeak()
				require.NoError(t, km.Stop(), "stopping again is a no-op")
			},
		},
		{
			name: "stop before start returns at once and start then launches nothing",
			assert: func(t *testing.T, km *signingkey.Keys, noLeak func()) {
				require.NoError(t, km.Stop())
				require.NoError(t, km.Start(t.Context()))
				noLeak()
			},
		},
		{
			name: "concurrent start and stop",
			assert: func(t *testing.T, km *signingkey.Keys, _ func()) {
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
			assert: func(t *testing.T, km *signingkey.Keys, noLeak func()) {
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

			km, err := signingkey.New(t.Context(),
				signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
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
// Standalone: its manager runs on a controlled clock over a counting store.
func TestLifecycleLoopsRunOnTheClock(t *testing.T) {
	type testCase struct {
		name   string
		assert func(t *testing.T, clk *clockwork.FakeClock, km *signingkey.Keys, store *countingStore)
	}

	cases := []testCase{
		{
			name: "one interval runs rotation, reload and housekeeping once each",
			assert: func(t *testing.T, clk *clockwork.FakeClock, km *signingkey.Keys, store *countingStore) {
				require.NoError(t, km.Start(t.Context()))

				advance(t, clk, time.Hour, loopCount)
				assert.Equal(t, 1, store.stores(), "one rotation for the one configured algorithm")
				assert.Equal(t, 1, store.loads(), "one reload: the minute intervals inside the hour did not each run")
			},
		},
		{
			name: "the interval is measured from the end of a run",
			assert: func(t *testing.T, clk *clockwork.FakeClock, km *signingkey.Keys, store *countingStore) {
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
			assert: func(t *testing.T, clk *clockwork.FakeClock, km *signingkey.Keys, store *countingStore) {
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
			km, err := signingkey.New(t.Context(),
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

// waitForRotation returns the kid that replaced was as the current key for alg.
func waitForRotation(t *testing.T, km *signingkey.Keys, alg signingkey.Alg, was string) string {
	t.Helper()

	var replacement string
	require.Eventually(t, func() bool {
		kid, _, ok := km.Signer(alg)
		if ok && kid != was {
			replacement = kid
			return true
		}
		return false
	}, 10*time.Second, 5*time.Millisecond, "a rotation should have made a new %s key current", alg)
	return replacement
}

// TestSystemClockDrivesTheLoops runs the loops on the default clock, which is
// what every consumer that configures no clock gets, and the one path a
// controlled clock can never exercise.
//
// The intervals are milliseconds so the test finishes, but nothing else is
// faked: a real interval has to rotate, has to stop publishing a key past its
// lifetime, and has to reload a key another replica wrote.
// Standalone: its manager runs on the system clock.
func TestSystemClockDrivesTheLoops(t *testing.T) {
	type testCase struct {
		name string
		// intervals are the case's rotation, reload, housekeeping and lifetime
		// options, short where the case waits on that loop and long enough to
		// pass validation elsewhere.
		intervals []signingkey.Option
		assert    func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore)
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
			assert: func(t *testing.T, km *signingkey.Keys, _ signingkey.KeyStore) {
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
			assert: func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore) {
				// Another replica, configured for an algorithm this one does not
				// sign with, writes its first key after this one was built.
				other, err := signingkey.New(t.Context(),
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

			store := signingkey.NewMemoryKeyStore()
			km, err := signingkey.New(t.Context(), append([]signingkey.Option{
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

// restartable returns a manager on clk and store, configured so one clock
// advance of an hour rotates.
func restartable(t *testing.T, clk *clockwork.FakeClock, store signingkey.KeyStore) *signingkey.Keys {
	t.Helper()

	km, err := signingkey.New(t.Context(),
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
// Standalone: it starts under a context it then cancels.
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
// Standalone: each case seeds the store the manager restarts over.
func TestRestartedManager(t *testing.T) {
	type testCase struct {
		name string
		// seed returns the stored records and the one the case is about.
		seed func(t *testing.T) (recs []signingkey.Record, subject signingkey.Record)
		// start runs the manager's loops before the assertions.
		start  bool
		assert func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, subject signingkey.Record)
	}

	cases := []testCase{
		{
			name: "refuses tokens from a key past its lifetime",
			seed: func(t *testing.T) ([]signingkey.Record, signingkey.Record) {
				old := realRecord(t, epoch.Add(-30*24*time.Hour))
				return []signingkey.Record{old, realRecord(t, epoch)}, old
			},
			start: true,
			assert: func(t *testing.T, km *signingkey.Keys, _ signingkey.KeyStore, old signingkey.Record) {
				// Whoever still holds the 30-day-old private key issues a fresh
				// token with it.
				holder, err := signingkey.New(t.Context(),
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
					token.WithVerifyKeySource(km), token.WithVerifyClock(newClock()))
				require.NoError(t, err)

				_, err = verifier.Verify(t.Context(), issued)
				require.ErrorIs(t, err, token.ErrInvalid,
					"a key 30 days past its 24h lifetime does not verify after a restart")
			},
		},
		{
			name: "keeps a stale sole key and mints no replacement",
			seed: func(t *testing.T) ([]signingkey.Record, signingkey.Record) {
				sole := realRecord(t, epoch.Add(-3*24*time.Hour))
				return []signingkey.Record{sole}, sole
			},
			assert: func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, sole signingkey.Record) {
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
			assert: func(t *testing.T, km *signingkey.Keys, _ signingkey.KeyStore, old signingkey.Record) {
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
			store := signingkey.NewMemoryKeyStore()
			for _, rec := range recs {
				require.NoError(t, store.Store(t.Context(), rec))
			}

			km, err := signingkey.New(t.Context(),
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

// TestStopWaitsForAnInFlightStoreWrite holds a rotation inside the store write
// and then stops the manager. Stop has to block until that write has landed:
// returning earlier would let a write escape a manager the consumer has already
// shut down.
// Standalone: it holds a store write open while Stop runs.
func TestStopWaitsForAnInFlightStoreWrite(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	var (
		writing      = make(chan struct{}) // closed once a rotation is inside the write
		release      = make(chan struct{}) // closed to let that write finish
		writes       atomic.Int32
		stopReturned atomic.Bool
		lateWrite    atomic.Bool
	)

	store := NewMockKeyStore(gomock.NewController(t))
	store.EXPECT().LoadAll(gomock.Any()).Return(nil, nil).AnyTimes()
	store.EXPECT().Store(gomock.Any(), gomock.Any()).DoAndReturn(
		func(context.Context, signingkey.Record) error {
			if stopReturned.Load() {
				lateWrite.Store(true)
			}
			// The first write is construction's, which must not block; the
			// second is the first rotation's, which is the one held.
			if writes.Add(1) == 2 {
				close(writing)
				<-release
			}
			return nil
		}).AnyTimes()

	clk := newClock()
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, km.Start(t.Context()))

	awaitParked(t, clk, loopCount)
	clk.Advance(time.Hour)
	<-writing // a rotation is now inside the store write

	stopped := make(chan error, 1)
	go func() { stopped <- km.Stop() }()

	select {
	case err := <-stopped:
		t.Fatalf("Stop returned while a store write was in flight: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	require.NoError(t, <-stopped)
	stopReturned.Store(true)

	clk.Advance(24 * time.Hour) // every loop has ended, so nothing receives what fires
	assert.Never(t, lateWrite.Load, 100*time.Millisecond, 10*time.Millisecond,
		"no store write may land after Stop has returned")

	assert.GreaterOrEqual(t, writes.Load(), int32(2), "the held write did complete")
	require.NoError(t, km.Stop(), "stopping again is a no-op")
	goleak.VerifyNone(t, ignore)
}

// TestStopAfterSeveralLoopRuns pins that Stop returns only once the loops have
// ended, after they have each run several times.
//
// What a loop does last, as it ends, is account for the failures the sampler
// still holds back. The reloads here keep failing inside one sampling window,
// so there is always something to account for, and the record that does so is
// the loops' own proof of having ended. It is read at once, with no retry, the
// moment Stop returns: a Stop that returned before its loops had ended would
// find it not yet written. goleak then confirms that nothing else was left.
// Standalone: its reloads keep failing inside one sampling window.
func TestStopAfterSeveralLoopRuns(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	const rounds = 3

	clk := newClock()
	recorder, logger := newLogRecorder()
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(failingStore(t, &failureReport{}, opReload)),
		signingkey.WithClock(clk),
		signingkey.WithLogger(logger),
		signingkey.WithLogSampleWindow(24*time.Hour),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(30*time.Minute),
		signingkey.WithLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, km.Start(t.Context()))

	kid := currentKid(t, km, signingkey.EdDSA)
	for round := range rounds {
		advance(t, clk, time.Hour, loopCount) // returns with every loop parked
		next := currentKid(t, km, signingkey.EdDSA)
		require.NotEqual(t, kid, next, "round %d rotates", round)
		kid = next
	}
	require.Equal(t, 1, recorder.written(),
		"only the first reload failure is written; the later ones are held back")

	require.NoError(t, km.Stop())
	require.Equal(t, 2, recorder.written(),
		"when Stop returns, the loops have ended and accounted for what was held back")

	records := recorder.records(t)
	assert.Equal(t, opReload, records[1]["op"])
	assert.Equal(t, float64(rounds-1), records[1]["suppressed"])
	goleak.VerifyNone(t, ignore) // and nothing else was left running
}

// neverClock is a consumer Timed whose After returns a nil channel, which never
// delivers. It is a legal value of the type, so the manager has to survive it.
type neverClock struct{}

func (neverClock) Now() time.Time { return epoch }

func (neverClock) After(time.Duration) <-chan time.Time { return nil }

// TestStopReturnsOnANilAfterClock pins that a consumer clock whose After never
// fires leaves the loops idle, and that Stop still ends them promptly: the
// context, not the clock, is what a loop waits on to end.
// Standalone: its clock's After never fires.
func TestStopReturnsOnANilAfterClock(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	store := newCountingStore()
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(neverClock{}),
		signingkey.WithAlgs(signingkey.EdDSA),
	)
	require.NoError(t, err)
	store.zero()

	require.NoError(t, km.Start(t.Context()))
	stopWithin(t, km, 2*time.Second, "a loop waiting on a nil channel must still see its context end")

	assert.Zero(t, store.stores(), "the clock never fired, so nothing rotated")
	assert.Zero(t, store.loads(), "and nothing reloaded")
	goleak.VerifyNone(t, ignore)
}

// stopWithin stops km and fails the test if that takes longer than bound. A
// Stop that cannot return is the failure being tested for, so it must show up
// as a failed assertion rather than as a hung package.
func stopWithin(t *testing.T, km *signingkey.Keys, bound time.Duration, why string) {
	t.Helper()

	stopped := make(chan error, 1)
	go func() { stopped <- km.Stop() }()

	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(bound):
		t.Fatalf("Stop did not return within %s: %s", bound, why)
	}
}
