// The lifecycle, shutdown and system-clock tests are not parallel: goleak
// counts goroutines process-wide, so a parallel sibling's goroutine would look
// like a leak. The system-clock tests are the only tests that wait on real
// time, because they are the only ones asserting on the clock a consumer
// actually ships with.
package signingkey_test

import (
	"context"
	"errors"
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
		case <-ctx.Done(): // a failed test's Shutdown must not wait on the hold
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

// gatedStore is the in-memory key store, able to hold the next write until the
// test releases it, or to refuse every write. It records what the last write's
// context carried, so a test can tell what context the background work runs
// under.
type gatedStore struct {
	signingkey.KeyStore

	mu        sync.Mutex
	writes    int
	holdNext  bool
	hold      chan struct{} // closed by release
	writing   chan struct{} // closed when the held write has begun
	refuse    bool
	lastValue any   // the last write's ctx.Value(traceKey{})
	lastErr   error // the last write's ctx.Err() as it began
	released  sync.Once
}

// traceKey is the context key a test sets on the start context, standing in
// for the trace and log fields a consumer's context carries.
type traceKey struct{}

func newGatedStore() *gatedStore {
	return &gatedStore{KeyStore: signingkey.NewMemoryKeyStore()}
}

func (s *gatedStore) Store(ctx context.Context, rec signingkey.Record) error {
	s.mu.Lock()
	s.writes++
	s.lastValue, s.lastErr = ctx.Value(traceKey{}), ctx.Err()
	held, hold, writing, refuse := s.holdNext, s.hold, s.writing, s.refuse
	s.holdNext = false
	s.mu.Unlock()

	if refuse {
		return errStoreWrite
	}
	if held {
		close(writing)
		// The held write ignores ctx on purpose: it is the in-flight write a
		// shutdown has to wait for, however its context ends. Every test that
		// holds one releases it in a cleanup, so it can never hang the package.
		<-hold
	}
	return s.KeyStore.Store(ctx, rec)
}

// writeCount reports how many writes the store has seen.
func (s *gatedStore) writeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.writes
}

// lastWrite reports the value and error the last write's context carried.
func (s *gatedStore) lastWrite() (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.lastValue, s.lastErr
}

// holdNextWrite makes the next Store wait until release is called.
func (s *gatedStore) holdNextWrite() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.holdNext = true
	s.hold, s.writing = make(chan struct{}), make(chan struct{})
}

// refuseWrites makes every later Store fail.
func (s *gatedStore) refuseWrites() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.refuse = true
}

// awaitWriting returns once the held write has begun.
func (s *gatedStore) awaitWriting(t *testing.T) {
	t.Helper()

	s.mu.Lock()
	writing := s.writing
	s.mu.Unlock()

	select {
	case <-writing:
	case <-time.After(parkTimeout):
		t.Fatal("the held store write never began")
	}
}

// release lets the held write finish. It is safe to call more than once, and
// when nothing was held.
func (s *gatedStore) release() {
	s.mu.Lock()
	hold := s.hold
	s.mu.Unlock()

	if hold != nil {
		s.released.Do(func() { close(hold) })
	}
}

// lifecycleFixture is one case's manager and what drives it.
type lifecycleFixture struct {
	km    *signingkey.Keys
	clk   *clockwork.FakeClock
	store *gatedStore
	// onError, when set before Start, is what the manager's error hook calls.
	onError func(error)
	// noLeak reports any goroutine started since the case began.
	noLeak func()
}

// rotatedFrom reports whether the current EdDSA key is no longer was, waiting up
// to parkTimeout for a rotation to land.
func (f *lifecycleFixture) rotatedFrom(t *testing.T, was string) bool {
	t.Helper()

	deadline := time.Now().Add(parkTimeout)
	for time.Now().Before(deadline) {
		if kid, _, ok := f.km.Signer(signingkey.EdDSA); ok && kid != was {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// TestKeys_Lifecycle drives one Start/Shutdown sequence per case. The assert
// closure both drives the sequence and asserts on it, because the sequence of
// calls is what varies. Every case ends with a bounded Shutdown and a leak
// check, run as a cleanup so a failed case still releases what it holds.
//
// The manager runs EdDSA only on a controlled clock, rotates hourly, reloads
// every minute and sweeps hourly; construction's own write is counted as the
// store's first.
func TestKeys_Lifecycle(t *testing.T) {
	type testCase struct {
		name   string
		assert func(t *testing.T, f *lifecycleFixture)
	}

	cases := []testCase{
		{
			name: "constructed but not started",
			assert: func(_ *testing.T, f *lifecycleFixture) {
				f.noLeak()
			},
		},
		{
			name: "double start",
			assert: func(t *testing.T, f *lifecycleFixture) {
				require.NoError(t, f.km.Start(t.Context()))
				require.ErrorIs(t, f.km.Start(t.Context()), signingkey.ErrAlreadyStarted,
					"starting a manager whose work is running fails")
				require.NoError(t, f.km.Shutdown(t.Context()))
				f.noLeak()
			},
		},
		{
			name: "cancelled start context",
			assert: func(t *testing.T, f *lifecycleFixture) {
				ctx, cancel := context.WithCancel(context.WithValue(t.Context(), traceKey{}, "trace-1"))
				require.NoError(t, f.km.Start(ctx))
				awaitParked(t, f.clk, loopCount)
				cancel()

				was := currentKid(t, f.km, signingkey.EdDSA)
				f.clk.Advance(time.Hour)
				require.True(t, f.rotatedFrom(t, was),
					"the rotation still runs after the start context was cancelled")

				value, err := f.store.lastWrite()
				assert.Equal(t, "trace-1", value, "the work carries the start context's values")
				assert.NoError(t, err, "and not its cancellation")
			},
		},
		{
			name: "already-cancelled start context",
			assert: func(t *testing.T, f *lifecycleFixture) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				require.NoError(t, f.km.Start(ctx))
				awaitParked(t, f.clk, loopCount)

				was := currentKid(t, f.km, signingkey.EdDSA)
				f.clk.Advance(time.Hour)
				require.True(t, f.rotatedFrom(t, was),
					"work started under an already-cancelled context still rotates")
			},
		},
		{
			name: "start after shutdown",
			assert: func(t *testing.T, f *lifecycleFixture) {
				require.NoError(t, f.km.Start(t.Context()))
				require.NoError(t, f.km.Shutdown(t.Context()))
				f.noLeak()

				require.ErrorIs(t, f.km.Start(t.Context()), signingkey.ErrAlreadyShutdown)
				f.noLeak()
			},
		},
		{
			name: "consumer bounds the shutdown",
			assert: func(t *testing.T, f *lifecycleFixture) {
				f.store.holdNextWrite()
				require.NoError(t, f.km.Start(t.Context()))
				awaitParked(t, f.clk, loopCount)
				f.clk.Advance(time.Hour)
				f.store.awaitWriting(t) // a rotation is now inside the store write

				ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- f.km.Shutdown(ctx) }()

				select {
				case err := <-done:
					require.ErrorIs(t, err, context.DeadlineExceeded,
						"a shutdown whose context expires first returns that context's error")
				case <-time.After(5 * time.Second):
					t.Fatal("Shutdown did not return when its context expired; it waited for the held write")
				}

				f.store.release()
				require.NoError(t, f.km.Shutdown(t.Context()),
					"a later shutdown waits again and returns nil once the write has completed")
				f.noLeak()
			},
		},
		{
			name: "shutdown twice",
			assert: func(t *testing.T, f *lifecycleFixture) {
				require.NoError(t, f.km.Start(t.Context()))
				require.NoError(t, f.km.Shutdown(t.Context()))
				require.NoError(t, f.km.Shutdown(t.Context()))
				f.noLeak()
			},
		},
		{
			name: "stop before start",
			assert: func(t *testing.T, f *lifecycleFixture) {
				shutdownWithin(t, f.km, time.Second, "a manager never started has nothing to wait for")
				require.ErrorIs(t, f.km.Start(t.Context()), signingkey.ErrAlreadyShutdown)
				f.noLeak()
			},
		},
		{
			name: "completion wins",
			assert: func(t *testing.T, f *lifecycleFixture) {
				require.NoError(t, f.km.Start(t.Context()))
				require.NoError(t, f.km.Shutdown(t.Context()))

				done, cancel := context.WithCancel(t.Context())
				cancel()
				for range 100 { // a coin-flip select would lose some of these
					require.NoError(t, f.km.Shutdown(done),
						"the work has ended, so an already-done context does not turn that into an error")
				}
			},
		},
		{
			name: "shutdown from error hook",
			assert: func(t *testing.T, f *lifecycleFixture) {
				type outcome struct {
					err     error
					elapsed time.Duration
				}
				hooked := make(chan outcome, 1)
				var once sync.Once
				f.onError = func(error) {
					once.Do(func() {
						ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 100*time.Millisecond)
						defer cancel()
						began := time.Now()
						err := f.km.Shutdown(ctx)
						hooked <- outcome{err, time.Since(began)}
					})
				}
				f.store.refuseWrites()
				require.NoError(t, f.km.Start(t.Context()))
				awaitParked(t, f.clk, loopCount)
				f.clk.Advance(time.Hour) // the rotation fails and calls the hook

				select {
				case got := <-hooked:
					require.ErrorIs(t, got.err, context.DeadlineExceeded,
						"a shutdown from inside the work cannot wait for itself, so it returns its context's error")
					assert.Less(t, got.elapsed, time.Second)
				case <-time.After(2 * time.Second):
					t.Fatal("Shutdown called from the error hook did not return: it deadlocked on its own loop")
				}

				require.NoError(t, f.km.Shutdown(t.Context()),
					"a shutdown from outside the work then returns once the work has ended")
				f.noLeak()
			},
		},
		{
			name: "concurrent start and shutdown",
			assert: func(t *testing.T, f *lifecycleFixture) {
				const pairs = 8
				starts := make(chan error, pairs)
				shutdowns := make(chan error, pairs)

				var wg sync.WaitGroup
				gate := make(chan struct{})
				for range pairs {
					wg.Add(2)
					go func() { defer wg.Done(); <-gate; starts <- f.km.Start(t.Context()) }()
					go func() { defer wg.Done(); <-gate; shutdowns <- f.km.Shutdown(t.Context()) }()
				}
				close(gate)
				wg.Wait()
				close(starts)
				close(shutdowns)

				launched := 0
				for err := range starts {
					if err == nil {
						launched++
						continue
					}
					if !errors.Is(err, signingkey.ErrAlreadyStarted) {
						require.ErrorIs(t, err, signingkey.ErrAlreadyShutdown)
					}
				}
				assert.LessOrEqual(t, launched, 1, "at most one start launches the work")
				for err := range shutdowns {
					require.NoError(t, err)
				}
				f.noLeak()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ignore := goleak.IgnoreCurrent()
			f := &lifecycleFixture{
				clk:    newClock(),
				store:  newGatedStore(),
				noLeak: func() { goleak.VerifyNone(t, ignore) },
			}

			km, err := signingkey.New(t.Context(),
				signingkey.WithKeyStore(f.store),
				signingkey.WithClock(f.clk),
				signingkey.WithAlgs(signingkey.EdDSA),
				signingkey.WithRotateInterval(time.Hour),
				signingkey.WithReloadInterval(time.Minute),
				signingkey.WithHousekeepingInterval(time.Hour),
				signingkey.WithKeyLifetime(24*time.Hour),
				signingkey.WithErrorHook(func(err error) {
					if f.onError != nil {
						f.onError(err)
					}
				}),
			)
			require.NoError(t, err)
			f.km = km

			// Cleanups run last-registered first: the held write is released
			// before the final shutdown waits for it.
			t.Cleanup(func() {
				shutdownWithin(t, km, parkTimeout, "the case's work should end once shut down")
				f.noLeak()
			})
			t.Cleanup(f.store.release)

			tc.assert(t, f)
		})
	}
}

// TestKeys_ServedAfterShutdown pins that shutdown ends the background work
// only: a shut-down manager goes on issuing and verifying with the keys it held,
// and rotates nothing however much time passes.
// Standalone: it issues and verifies a real token through the token package.
func TestKeys_ServedAfterShutdown(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	clk := newClock()
	store := newGatedStore()
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(time.Hour),
		signingkey.WithKeyLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, km.Start(t.Context()))
	advance(t, clk, time.Hour, loopCount) // one rotation, so the held key is not construction's

	require.NoError(t, km.Shutdown(t.Context()))
	goleak.VerifyNone(t, ignore)

	held := currentKid(t, km, signingkey.EdDSA)
	require.True(t, publishes(km, held), "the held key is still published")
	writes := store.writeCount()

	issuer, err := token.NewGenerator(km, token.WithClock(newClock()), token.WithSigningAlg(signingkey.EdDSA),
		token.WithoutIssuer(), token.WithoutAudience())
	require.NoError(t, err)
	issued, err := issuer.Generate(t.Context(), "jti-1", &identity.Principal{ID: "u-1", Username: "alice"})
	require.NoError(t, err, "a shut-down manager still signs")

	verifier, err := token.NewVerifier(
		token.WithVerifyKeySource(km), token.WithVerifyClock(newClock()),
		token.WithoutVerifyIssuer(), token.WithoutVerifyAudience())
	require.NoError(t, err)
	_, err = verifier.Verify(t.Context(), issued)
	require.NoError(t, err, "and what it signed still verifies against what it publishes")

	for range 3 {
		clk.Advance(48 * time.Hour) // every loop has ended, so nothing receives what fires
	}
	assert.Equal(t, held, currentKid(t, km, signingkey.EdDSA), "no rotation after shutdown")
	assert.Equal(t, writes, store.writeCount(), "and no store write")
	assert.True(t, publishes(km, held), "the held key is still published")
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

			require.NoError(t, km.Shutdown(t.Context()))
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
				signingkey.WithKeyLifetime(120 * time.Millisecond),
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
				signingkey.WithKeyLifetime(24 * time.Hour),
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

			require.NoError(t, km.Shutdown(t.Context()))
			assert.True(t, publishes(km, currentKid(t, km, signingkey.EdDSA)),
				"whatever is current when Shutdown returns is still published")
			goleak.VerifyNone(t, ignore)
		})
	}
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
				issuer, err := token.NewGenerator(holder, token.WithClock(newClock()),
					token.WithoutIssuer(), token.WithoutAudience())
				require.NoError(t, err)
				issued, err := issuer.Generate(t.Context(), "jti-1",
					&identity.Principal{ID: "u-1", Username: "alice"})
				require.NoError(t, err)

				verifier, err := token.NewVerifier(
					token.WithVerifyKeySource(km), token.WithVerifyClock(newClock()),
					token.WithoutVerifyIssuer(), token.WithoutVerifyAudience())
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
				shutdownAndVerify(t, km)
				require.NoError(t, km.Start(t.Context()))
			}

			tc.assert(t, km, store, subject)
		})
	}
}

// TestShutdownWaitsForAnInFlightStoreWrite holds a rotation inside the store
// write and then shuts the manager down. Shutdown has to block until that write
// has landed: returning earlier would let a write escape a manager the consumer
// has already shut down.
// Standalone: it holds a store write open while Shutdown runs.
func TestShutdownWaitsForAnInFlightStoreWrite(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	var (
		writing          = make(chan struct{}) // closed once a rotation is inside the write
		release          = make(chan struct{}) // closed to let that write finish
		writes           atomic.Int32
		shutdownReturned atomic.Bool
		lateWrite        atomic.Bool
	)

	store := NewMockKeyStore(gomock.NewController(t))
	store.EXPECT().LoadAll(gomock.Any()).Return(nil, nil).AnyTimes()
	store.EXPECT().Store(gomock.Any(), gomock.Any()).DoAndReturn(
		func(context.Context, signingkey.Record) error {
			if shutdownReturned.Load() {
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
		signingkey.WithKeyLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, km.Start(t.Context()))

	awaitParked(t, clk, loopCount)
	clk.Advance(time.Hour)
	<-writing // a rotation is now inside the store write

	stopped := make(chan error, 1)
	go func() { stopped <- km.Shutdown(t.Context()) }()

	select {
	case err := <-stopped:
		t.Fatalf("Shutdown returned while a store write was in flight: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	require.NoError(t, <-stopped)
	shutdownReturned.Store(true)

	clk.Advance(24 * time.Hour) // every loop has ended, so nothing receives what fires
	assert.Never(t, lateWrite.Load, 100*time.Millisecond, 10*time.Millisecond,
		"no store write may land after Shutdown has returned")

	assert.GreaterOrEqual(t, writes.Load(), int32(2), "the held write did complete")
	require.NoError(t, km.Shutdown(t.Context()), "shutting down again returns nil")
	goleak.VerifyNone(t, ignore)
}

// TestShutdownAfterSeveralLoopRuns pins that Shutdown returns only once the
// loops have ended, after they have each run several times.
//
// What a loop does last, as it ends, is account for the failures the sampler
// still holds back. The reloads here keep failing inside one sampling window,
// so there is always something to account for, and the record that does so is
// the loops' own proof of having ended. It is read at once, with no retry, the
// moment Shutdown returns: a Shutdown that returned before its loops had ended
// would find it not yet written. goleak then confirms that nothing else was left.
// Standalone: its reloads keep failing inside one sampling window.
func TestShutdownAfterSeveralLoopRuns(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	const rounds = 3

	clk := newClock()
	recorder, logger := newLogRecorder()
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(failingStore(t, &failureReport{}, opReload)),
		signingkey.WithClock(clk),
		signingkey.WithLogger(logger),
		signingkey.WithLogInterval(24*time.Hour),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(30*time.Minute),
		signingkey.WithKeyLifetime(24*time.Hour),
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

	require.NoError(t, km.Shutdown(t.Context()))
	require.Equal(t, 2, recorder.written(),
		"when Shutdown returns, the loops have ended and accounted for what was held back")

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

// TestShutdownReturnsOnANilAfterClock pins that a consumer clock whose After never
// fires leaves the loops idle, and that Shutdown still ends them promptly: the
// context, not the clock, is what a loop waits on to end.
// Standalone: its clock's After never fires.
func TestShutdownReturnsOnANilAfterClock(t *testing.T) {
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
	shutdownWithin(t, km, 2*time.Second, "a loop waiting on a nil channel must still see its context end")

	assert.Zero(t, store.stores(), "the clock never fired, so nothing rotated")
	assert.Zero(t, store.loads(), "and nothing reloaded")
	goleak.VerifyNone(t, ignore)
}
