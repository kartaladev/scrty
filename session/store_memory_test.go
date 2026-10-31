// The goroutine-exit and lifecycle tests here are not parallel: goleak counts
// goroutines process-wide. The goroutine-exit test and the default-clock row
// of the controlled-clock table wait on real time, because they assert on the
// system clock a consumer actually ships with, and the bounded-shutdown
// lifecycle case waits briefly for its shutdown context to expire. The other
// tests drive housekeeping
// either through a synctest bubble or through a clockwork fake given to the
// store, never both in one test.
package session_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// seedForHousekeeping puts one already-expiring session and one long-lived one
// in store, both dated from the clock the store is reading.
func seedForHousekeeping(t *testing.T, store *session.MemoryStore) (expiredID, liveID string) {
	t.Helper()

	now := time.Now()
	expired := &session.Session{
		ID:                "expiring",
		FamilyID:          storedFamily,
		FamilyCreatedAt:   createdAt,
		UserID:            testUser,
		CreatedAt:         now,
		LastAccessedAt:    now,
		IdleExpiresAt:     now.Add(10 * time.Second),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}
	live := &session.Session{
		ID:                "live",
		FamilyID:          storedFamily,
		FamilyCreatedAt:   createdAt,
		UserID:            testUser,
		CreatedAt:         now,
		LastAccessedAt:    now,
		IdleExpiresAt:     now.Add(time.Hour),
		AbsoluteExpiresAt: now.Add(12 * time.Hour),
	}
	require.NoError(t, store.Create(t.Context(), expired))
	require.NoError(t, store.Create(t.Context(), live))

	return expired.ID, live.ID
}

func TestMemoryStoreHousekeeping(t *testing.T) {
	t.Parallel()

	t.Run("a started store sweeps expired sessions once per interval", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			store := must.Must(session.NewMemoryStore(session.WithMemoryStoreHousekeepingInterval(time.Minute)))
			_, liveID := seedForHousekeeping(t, store)

			require.NoError(t, store.Start(t.Context()))
			require.Equal(t, 2, store.Len(), "housekeeping swept before its first interval")

			time.Sleep(90 * time.Second)
			synctest.Wait()

			assert.Equal(t, 1, store.Len(), "housekeeping did not run")
			_, err := store.Load(t.Context(), liveID)
			assert.NoError(t, err, "housekeeping swept a live session")

			require.NoError(t, store.Shutdown(t.Context()))
		})
	})

	t.Run("the interval defaults to one minute", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			store := must.Must(session.NewMemoryStore())
			seedForHousekeeping(t, store)

			require.NoError(t, store.Start(t.Context()))

			time.Sleep(30 * time.Second)
			synctest.Wait()
			require.Equal(t, 2, store.Len(), "the default interval is shorter than a minute")

			time.Sleep(31 * time.Second)
			synctest.Wait()
			assert.Equal(t, 1, store.Len(), "the default interval is longer than a minute")

			require.NoError(t, store.Shutdown(t.Context()))
		})
	})
}

// TestHousekeepingExitsAtShutdown runs on the system clock, because a
// goroutine that outlives Shutdown is exactly what a faked clock cannot show.
// It also cancels the start context first, which must not be what ends it.
// Standalone: it is not parallel, so goleak counts only its own goroutines.
func TestHousekeepingExitsAtShutdown(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	ctx, cancel := context.WithCancel(t.Context())
	store := must.Must(session.NewMemoryStore(session.WithMemoryStoreHousekeepingInterval(5 * time.Millisecond)))

	now := time.Now()
	require.NoError(t, store.Create(ctx, &session.Session{
		ID:                "expiring",
		FamilyID:          storedFamily,
		FamilyCreatedAt:   createdAt,
		UserID:            testUser,
		CreatedAt:         now,
		IdleExpiresAt:     now.Add(20 * time.Millisecond),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}))
	require.NoError(t, store.Start(ctx))
	cancel()

	require.Eventually(t, func() bool { return store.Len() == 0 },
		5*time.Second, time.Millisecond, "housekeeping on the system clock never swept")

	require.NoError(t, store.Shutdown(t.Context()))
	goleak.VerifyNone(t, ignore)

	// A record that expires after Shutdown stays: the loop is gone, not
	// merely idle.
	stale := time.Now()
	require.NoError(t, store.Create(t.Context(), &session.Session{
		ID:                "after-shutdown",
		FamilyID:          storedFamily,
		FamilyCreatedAt:   createdAt,
		UserID:            testUser,
		CreatedAt:         stale,
		IdleExpiresAt:     stale.Add(-time.Second),
		AbsoluteExpiresAt: stale.Add(time.Hour),
	}))
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 1, store.Len(), "housekeeping kept running after Shutdown")
}

// lifecycleInterval is the housekeeping interval of the lifecycle tests.
const lifecycleInterval = 10 * time.Second

// gatedClock is a controlled clock on which one sweep can be held in
// progress. Only a sweep reads Now on a store the test does not load from, so
// once armed, the next Now is a sweep starting: it signals entered and blocks
// until release is closed. Nothing about the store changes: it is slowed from
// its clock, the one dependency a consumer supplies.
type gatedClock struct {
	*clockwork.FakeClock

	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func newGatedClock() *gatedClock {
	return &gatedClock{
		FakeClock: clockwork.NewFakeClockAt(createdAt),
		entered:   make(chan struct{}, 1),
		release:   make(chan struct{}),
	}
}

func (c *gatedClock) Now() time.Time {
	if c.armed.CompareAndSwap(true, false) {
		c.entered <- struct{}{}
		<-c.release
	}

	return c.FakeClock.Now()
}

// lifecycleFixture is one lifecycle case's store, its clock, and the
// goroutines that were running before the case began.
type lifecycleFixture struct {
	store  *session.MemoryStore
	clk    *gatedClock
	ignore goleak.Option
}

// noHousekeeping asserts that the store's housekeeping is gone, not merely
// idle: no goroutine of the case is left, and advancing past two intervals
// sweeps nothing.
func (fx lifecycleFixture) noHousekeeping(t *testing.T) {
	t.Helper()

	goleak.VerifyNone(t, fx.ignore)
	fx.clk.Advance(2 * lifecycleInterval)
	assert.Equal(t, 2, fx.store.Len(), "housekeeping swept a store that is not running it")
}

// sweepsOnce advances one interval and asserts that housekeeping swept the
// expired session and waited again.
func (fx lifecycleFixture) sweepsOnce(t *testing.T, why string) {
	t.Helper()

	fx.clk.Advance(lifecycleInterval)
	blockUntil(t, fx.clk.FakeClock, 1, why)
	assert.Equal(t, 1, fx.store.Len(), "the expired session is still held")
}

// shutdownWithin calls Shutdown with no deadline of its own, bounded by the
// test so that a Shutdown that never returns fails rather than hangs.
func shutdownWithin(t *testing.T, store *session.MemoryStore) error {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
	defer cancel()

	return store.Shutdown(ctx)
}

// TestMemoryStore_Lifecycle pins the sessions lifecycle scenarios on a
// controlled clock: housekeeping is detached from the start context, a second
// start and a start after shutdown are refused, and Shutdown is terminal,
// idempotent and bounded by its own context.
// Not parallel: goleak counts goroutines process-wide, so each case checks
// only its own while no other test runs.
func TestMemoryStore_Lifecycle(t *testing.T) {
	type testCase struct {
		name   string
		assert func(t *testing.T, fx lifecycleFixture)
	}

	cases := []testCase{
		{
			name: "a start context cancelled after start leaves housekeeping running",
			assert: func(t *testing.T, fx lifecycleFixture) {
				ctx, cancel := context.WithCancel(t.Context())
				require.NoError(t, fx.store.Start(ctx))
				blockUntil(t, fx.clk.FakeClock, 1, "housekeeping never waited on the store's clock")

				cancel()

				fx.sweepsOnce(t, "housekeeping ended with its start context")
			},
		},
		{
			name: "an already-cancelled start context still launches housekeeping",
			assert: func(t *testing.T, fx lifecycleFixture) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				require.NoError(t, fx.store.Start(ctx))
				blockUntil(t, fx.clk.FakeClock, 1, "housekeeping never waited on the store's clock")

				fx.sweepsOnce(t, "housekeeping ended with its already-cancelled start context")
			},
		},
		{
			name: "a second start is refused and both shutdowns return nil",
			assert: func(t *testing.T, fx lifecycleFixture) {
				require.NoError(t, fx.store.Start(t.Context()))
				blockUntil(t, fx.clk.FakeClock, 1, "housekeeping never waited on the store's clock")

				require.ErrorIs(t, fx.store.Start(t.Context()), session.ErrAlreadyStarted)
				require.NoError(t, fx.store.Shutdown(t.Context()))
				require.NoError(t, fx.store.Shutdown(t.Context()))

				fx.noHousekeeping(t)
			},
		},
		{
			name: "a start after shutdown is refused",
			assert: func(t *testing.T, fx lifecycleFixture) {
				require.NoError(t, fx.store.Start(t.Context()))
				blockUntil(t, fx.clk.FakeClock, 1, "housekeeping never waited on the store's clock")
				require.NoError(t, fx.store.Shutdown(t.Context()))

				require.ErrorIs(t, fx.store.Start(t.Context()), session.ErrAlreadyShutdown)

				fx.noHousekeeping(t)
			},
		},
		{
			name: "a start after a shutdown of a store never started is refused",
			assert: func(t *testing.T, fx lifecycleFixture) {
				require.NoError(t, fx.store.Shutdown(t.Context()))

				require.ErrorIs(t, fx.store.Start(t.Context()), session.ErrAlreadyShutdown)

				fx.noHousekeeping(t)
			},
		},
		{
			name: "a shutdown is bounded by its context, and a later one waits again",
			assert: func(t *testing.T, fx lifecycleFixture) {
				require.NoError(t, fx.store.Start(t.Context()))
				blockUntil(t, fx.clk.FakeClock, 1, "housekeeping never waited on the store's clock")

				fx.clk.armed.Store(true)
				fx.clk.Advance(lifecycleInterval)
				select {
				case <-fx.clk.entered:
				case <-time.After(5 * time.Second):
					require.FailNow(t, "housekeeping never began its sweep")
				}
				release := sync.OnceFunc(func() { close(fx.clk.release) })
				t.Cleanup(release)

				bounded, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
				defer cancel()
				result := make(chan error, 1)
				go func() { result <- fx.store.Shutdown(bounded) }()

				select {
				case err := <-result:
					require.ErrorIs(t, err, context.DeadlineExceeded,
						"a shutdown outlasted by a sweep did not return its context's error")
				case <-time.After(5 * time.Second):
					release()
					require.NoError(t, <-result, "the shutdown left waiting failed once the sweep ended")
					require.FailNow(t, "a shutdown waited past its context for a sweep in progress")
				}
				require.Equal(t, 2, fx.store.Len(), "the held sweep finished before it was released")

				release()
				require.NoError(t, shutdownWithin(t, fx.store), "a later shutdown did not wait for the sweep")
				assert.Equal(t, 1, fx.store.Len(), "a later shutdown returned before the sweep it waited for ended")
			},
		},
		{
			name: "completion wins over a shutdown context already done",
			assert: func(t *testing.T, fx lifecycleFixture) {
				require.NoError(t, fx.store.Start(t.Context()))
				blockUntil(t, fx.clk.FakeClock, 1, "housekeeping never waited on the store's clock")
				require.NoError(t, fx.store.Shutdown(t.Context()))
				goleak.VerifyNone(t, fx.ignore)

				done, cancel := context.WithCancel(t.Context())
				cancel()

				assert.NoError(t, fx.store.Shutdown(done), "a shutdown of ended work reported its context's error")
			},
		},
		{
			name: "concurrent starts and shutdowns launch housekeeping at most once",
			assert: func(t *testing.T, fx lifecycleFixture) {
				var (
					wg      sync.WaitGroup
					started atomic.Int32
				)
				for range 8 {
					wg.Go(func() {
						err := fx.store.Start(t.Context())
						switch {
						case err == nil:
							started.Add(1)
						case errors.Is(err, session.ErrAlreadyStarted), errors.Is(err, session.ErrAlreadyShutdown):
						default:
							assert.Fail(t, "Start returned an unexpected error", "%v", err)
						}
					})
					wg.Go(func() { assert.NoError(t, shutdownWithin(t, fx.store)) })
				}
				wg.Wait()

				assert.LessOrEqual(t, started.Load(), int32(1), "more than one start launched housekeeping")
				require.ErrorIs(t, fx.store.Start(t.Context()), session.ErrAlreadyShutdown)

				fx.noHousekeeping(t)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := lifecycleFixture{clk: newGatedClock(), ignore: goleak.IgnoreCurrent()}
			fx.store = must.Must(session.NewMemoryStore(
				session.WithMemoryStoreClock(fx.clk),
				session.WithMemoryStoreHousekeepingInterval(lifecycleInterval),
			))
			require.NoError(t, fx.store.Create(t.Context(), sessionExpiringAt("expiring", createdAt.Add(5*time.Second))))
			require.NoError(t, fx.store.Create(t.Context(), sessionExpiringAt("live", createdAt.Add(time.Hour))))
			t.Cleanup(func() {
				assert.NoError(t, shutdownWithin(t, fx.store))
				goleak.VerifyNone(t, fx.ignore)
			})

			tc.assert(t, fx)
		})
	}
}

// TestMemoryStore_ServesAfterShutdown pins sessions "Store serves after
// shutdown": Shutdown ends housekeeping only, so the store keeps saving,
// loading and deleting sessions, and sweeps nothing on its own.
// Standalone: it drives one store through shutdown and then serves from it.
func TestMemoryStore_ServesAfterShutdown(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	store := must.Must(session.NewMemoryStore(
		session.WithMemoryStoreClock(clk),
		session.WithMemoryStoreHousekeepingInterval(lifecycleInterval),
	))
	require.NoError(t, store.Create(t.Context(), storedSession("served")))
	require.NoError(t, store.Start(t.Context()))
	blockUntil(t, clk, 1, "housekeeping never waited on the store's clock")
	require.NoError(t, store.Shutdown(t.Context()))

	saved := storedSession("served")
	saved.Data = map[string]string{"k": "after-shutdown"}
	require.NoError(t, store.Save(t.Context(), saved), "a shut-down store refused a save")
	loaded, err := store.Load(t.Context(), "served")
	require.NoError(t, err, "a shut-down store refused a load")
	assert.Equal(t, "after-shutdown", loaded.Data["k"])

	require.NoError(t, store.Create(t.Context(), sessionExpiringAt("expiring", createdAt.Add(5*time.Second))))
	clk.Advance(2 * lifecycleInterval)
	assert.Equal(t, 2, store.Len(), "housekeeping swept after shutdown")

	require.NoError(t, store.Delete(t.Context(), "served"))
	_, err = store.Load(t.Context(), "served")
	require.ErrorIs(t, err, session.ErrNotFound, "a shut-down store did not delete")
}

// countingClock is a controlled clock that counts how often a loop waited on
// it. Each wait is one pass of a housekeeping loop, so a count taken once the
// loop has parked again says how many sweeps ran.
type countingClock struct {
	*clockwork.FakeClock

	waits atomic.Int32
}

func (c *countingClock) After(d time.Duration) <-chan time.Time {
	c.waits.Add(1)

	return c.FakeClock.After(d)
}

// slowSweepClock is a controlled clock on which a sweep takes time. Only a
// sweep reads Now on a store nothing else is using, so each read is one sweep:
// it is recorded at the instant it starts, and the first one moves the clock
// on by took before returning, as a slow sweep would. Each wait is recorded
// by the instant it is due, which is when the loop's next sweep will run.
type slowSweepClock struct {
	*clockwork.FakeClock

	took time.Duration

	mu     sync.Mutex
	sweeps []time.Time
	dues   []time.Time
}

func (c *slowSweepClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.dues = append(c.dues, c.FakeClock.Now().Add(d))
	c.mu.Unlock()

	return c.FakeClock.After(d)
}

func (c *slowSweepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.FakeClock.Now()
	c.sweeps = append(c.sweeps, now)
	if len(c.sweeps) == 1 {
		c.Advance(c.took)
	}

	return now
}

func (c *slowSweepClock) sweepStarts() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]time.Time(nil), c.sweeps...)
}

func (c *slowSweepClock) waitsDue() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]time.Time(nil), c.dues...)
}

// sessionExpiringAt is a session whose idle deadline is at, and whose absolute
// deadline is well after it.
func sessionExpiringAt(id string, at time.Time) *session.Session {
	return &session.Session{
		ID:                id,
		FamilyID:          storedFamily,
		FamilyCreatedAt:   createdAt,
		UserID:            testUser,
		CreatedAt:         createdAt,
		LastAccessedAt:    createdAt,
		IdleExpiresAt:     at,
		AbsoluteExpiresAt: at.Add(time.Hour),
	}
}

// blockUntil waits until n waiters are parked on clk. The watchdog only bounds
// a failure: on a passing run the loop parks at once, and nothing here sleeps.
func blockUntil(t *testing.T, clk *clockwork.FakeClock, n int, why string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	require.NoError(t, clk.BlockUntilContext(ctx, n), why)
}

// TestMemoryStoreHousekeepingOnItsClock pins sessions "Housekeeping on a
// controlled time source": the store waits between sweeps on its own clock, so
// advancing a controlled clock runs housekeeping with no real waiting. Each
// case builds its own store because each drives a different lifecycle.
func TestMemoryStoreHousekeepingOnItsClock(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	cases := []testCase{
		{
			name: "advancing a controlled clock by one interval sweeps once",
			assert: func(t *testing.T) {
				clk := clockwork.NewFakeClockAt(createdAt)
				store := must.Must(session.NewMemoryStore(
					session.WithMemoryStoreClock(clk),
					session.WithMemoryStoreHousekeepingInterval(10*time.Second),
				))
				require.NoError(t, store.Create(t.Context(), sessionExpiringAt("expiring", createdAt.Add(5*time.Second))))
				require.NoError(t, store.Create(t.Context(), sessionExpiringAt("live", createdAt.Add(time.Hour))))
				require.NoError(t, store.Start(t.Context()))
				t.Cleanup(func() { assert.NoError(t, shutdownWithin(t, store)) })

				blockUntil(t, clk, 1, "housekeeping never waited on the store's clock")
				require.Equal(t, 2, store.Len(), "housekeeping swept before its first interval")

				clk.Advance(10 * time.Second)
				blockUntil(t, clk, 1, "housekeeping did not wait again after its sweep")

				assert.Equal(t, 1, store.Len(), "the expired session is still held")
				_, err := store.Load(t.Context(), "live")
				assert.NoError(t, err, "housekeeping swept a live session")
			},
		},
		{
			// A manager reads a Clock and its store a Timed; one fake is both,
			// so expiry means the same instant on either side.
			name: "a manager and its store share one controlled clock",
			assert: func(t *testing.T) {
				clk := clockwork.NewFakeClockAt(createdAt)
				store := must.Must(session.NewMemoryStore(
					session.WithMemoryStoreClock(clk),
					session.WithMemoryStoreHousekeepingInterval(time.Hour),
				))
				m, err := session.New(session.WithClock(clk), session.WithStore(store))
				require.NoError(t, err)

				s, err := m.Create(t.Context(), testUser)
				require.NoError(t, err)
				require.Equal(t, createdAt.Add(30*time.Minute), s.IdleExpiresAt, "the manager did not read the shared clock")

				require.NoError(t, store.Start(t.Context()))
				t.Cleanup(func() { assert.NoError(t, shutdownWithin(t, store)) })
				blockUntil(t, clk, 1, "housekeeping never waited on the store's clock")

				clk.Advance(31 * time.Minute)

				require.ErrorIs(t, m.Touch(t.Context(), s), session.ErrExpired,
					"the manager did not judge the session expired at the shared instant")
				_, err = m.Load(t.Context(), s.ID)
				require.ErrorIs(t, err, session.ErrExpired,
					"the store did not judge the session expired at the shared instant")
				require.Equal(t, 1, store.Len(), "housekeeping swept before its interval")

				clk.Advance(29 * time.Minute)
				blockUntil(t, clk, 1, "housekeeping did not wait again after its sweep")

				assert.Zero(t, store.Len(), "the sweep did not remove the session the manager refuses")
			},
		},
		{
			// Pins time-source "A long jump runs once": the loop waits for one
			// interval and does not catch up on the intervals a jump skipped.
			// Each pass of the loop waits once, so the wait count, read once
			// the loop has parked again, is one more than the sweeps run.
			name: "a long jump sweeps once, and the next sweep is one interval after it",
			assert: func(t *testing.T) {
				clk := &countingClock{FakeClock: clockwork.NewFakeClockAt(createdAt)}
				store := must.Must(session.NewMemoryStore(
					session.WithMemoryStoreClock(clk),
					session.WithMemoryStoreHousekeepingInterval(10*time.Second),
				))
				require.NoError(t, store.Start(t.Context()))
				t.Cleanup(func() { assert.NoError(t, shutdownWithin(t, store)) })
				blockUntil(t, clk.FakeClock, 1, "housekeeping never waited on the store's clock")

				clk.Advance(50 * time.Second)
				blockUntil(t, clk.FakeClock, 1, "housekeeping did not wait again after the jump")
				require.Equal(t, int32(2), clk.waits.Load(), "a jump of five intervals did not sweep exactly once")

				clk.Advance(10*time.Second - time.Nanosecond)
				clk.Advance(time.Nanosecond)
				blockUntil(t, clk.FakeClock, 1, "housekeeping did not wait again after its second sweep")
				assert.Equal(t, int32(3), clk.waits.Load(),
					"the sweep after the jump did not come exactly one interval later")
			},
		},
		{
			// Pins time-source "Interval counted from the end of a run": a
			// sweep that takes 3s, starting at 10s, ends at 13s, so the next
			// one starts at 23s, not at 20s.
			name: "the next sweep is one interval after the previous one finished",
			assert: func(t *testing.T) {
				clk := &slowSweepClock{FakeClock: clockwork.NewFakeClockAt(createdAt), took: 3 * time.Second}
				store := must.Must(session.NewMemoryStore(
					session.WithMemoryStoreClock(clk),
					session.WithMemoryStoreHousekeepingInterval(10*time.Second),
				))
				require.NoError(t, store.Start(t.Context()))
				t.Cleanup(func() { assert.NoError(t, shutdownWithin(t, store)) })
				blockUntil(t, clk.FakeClock, 1, "housekeeping never waited on the store's clock")

				clk.Advance(10 * time.Second)
				blockUntil(t, clk.FakeClock, 1, "housekeeping did not wait again after its slow sweep")
				require.Equal(t, []time.Time{createdAt.Add(10 * time.Second)}, clk.sweepStarts())

				// Read once the loop has parked, the wait it parked on says when
				// the next sweep runs: 23s, not 20s, one interval after the
				// first sweep started.
				assert.Equal(t,
					[]time.Time{createdAt.Add(10 * time.Second), createdAt.Add(23 * time.Second)},
					clk.waitsDue(),
					"the next sweep was not due one interval after the first finished")

				clk.Advance(10*time.Second - time.Nanosecond)
				clk.Advance(time.Nanosecond)
				blockUntil(t, clk.FakeClock, 1, "housekeeping did not wait again after its second sweep")

				assert.Equal(t,
					[]time.Time{createdAt.Add(10 * time.Second), createdAt.Add(23 * time.Second)},
					clk.sweepStarts(),
					"the second sweep did not start one interval after the first finished")
			},
		},
		{
			// The only clock a consumer ships with.
			name: "the default system clock still sweeps",
			assert: func(t *testing.T) {
				store := must.Must(session.NewMemoryStore(session.WithMemoryStoreHousekeepingInterval(10 * time.Millisecond)))
				now := time.Now()
				require.NoError(t, store.Create(t.Context(), sessionExpiringAt("expired", now.Add(-time.Second))))
				require.NoError(t, store.Start(t.Context()))
				t.Cleanup(func() { assert.NoError(t, shutdownWithin(t, store)) })

				require.Eventually(t, func() bool { return store.Len() == 0 }, 2*time.Second, 5*time.Millisecond,
					"housekeeping on the system clock never swept")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t)
		})
	}
}

func TestMemoryStoreIsolatesRecords(t *testing.T) {
	t.Parallel()

	t.Run("a caller writing to what it created cannot change what was stored", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))

		s := storedSession("created")
		require.NoError(t, store.Create(t.Context(), s))

		// The caller keeps writing to the record it handed over, which is
		// ordinary: it is their struct and their map.
		s.Data["k"] = "mutated-after-store"
		s.MFA = session.MFASatisfied

		loaded, err := store.Load(t.Context(), s.ID)
		require.NoError(t, err)
		assert.Equal(t, "v", loaded.Data["k"], "the store aliased the caller's map on write")
		assert.Equal(t, session.MFANone, loaded.MFA, "the store aliased the caller's record on write")
	})

	t.Run("a caller writing to what it loaded cannot change what was stored", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
		require.NoError(t, store.Create(t.Context(), storedSession("loaded")))

		first, err := store.Load(t.Context(), "loaded")
		require.NoError(t, err)
		first.Data["k"] = "mutated-after-load"
		first.MFA = session.MFASatisfied
		first.UserID = "mallory"

		again, err := store.Load(t.Context(), "loaded")
		require.NoError(t, err)
		assert.Equal(t, "v", again.Data["k"], "the store aliased its own record on read")
		assert.Equal(t, session.MFANone, again.MFA, "the store aliased its own record on read")
		assert.Equal(t, testUser, again.UserID)
	})

	t.Run("a caller writing to what it saved cannot change what was stored", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
		require.NoError(t, store.Create(t.Context(), storedSession("saved")))

		s := storedSession("saved")
		s.Data = map[string]string{"k": "saved"}
		require.NoError(t, store.Save(t.Context(), s))

		s.Data["k"] = "mutated-after-save"

		loaded, err := store.Load(t.Context(), "saved")
		require.NoError(t, err)
		assert.Equal(t, "saved", loaded.Data["k"], "the store aliased the caller's map on save")
	})

	t.Run("a nil consumer map stays nil rather than becoming an empty one", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))

		s := storedSession("nil-data")
		s.Data = nil
		require.NoError(t, store.Create(t.Context(), s))

		loaded, err := store.Load(t.Context(), "nil-data")
		require.NoError(t, err)
		assert.Nil(t, loaded.Data, "the store invented a map the consumer never supplied")
	})

	t.Run("concurrent callers reading and writing do not race", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
		require.NoError(t, store.Create(t.Context(), storedSession("shared")))

		var wg sync.WaitGroup
		for range 8 {
			wg.Add(2)
			go func() {
				defer wg.Done()

				loaded, err := store.Load(t.Context(), "shared")
				if assert.NoError(t, err) {
					// A reader writing to what it read is what the copy on
					// read exists for; under -race this is where an alias
					// shows up.
					loaded.Data["k"] = "reader"
				}
			}()
			go func() {
				defer wg.Done()

				s := storedSession("shared")
				assert.NoError(t, store.Save(t.Context(), s))
				s.Data["k"] = "writer"
			}()
		}
		wg.Wait()

		loaded, err := store.Load(t.Context(), "shared")
		require.NoError(t, err)
		assert.Equal(t, "v", loaded.Data["k"])
	})
}

// Standalone: it reads, counts and sweeps one store that was never started.
func TestUnstartedMemoryStoreKeepsExpiredRecords(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
	require.NoError(t, store.Create(t.Context(), storedSession("expiring")))

	clk.Advance(createdAt.Add(time.Hour).Sub(clk.Now()))

	_, err := store.Load(t.Context(), "expiring")
	require.ErrorIs(t, err, session.ErrExpired, "an expired session was served by an unstarted store")

	// This is the documented limit of not calling Start, and the assertion
	// exists so that nobody later "fixes" it into a surprise purge: a caller
	// reading a session must not be the thing that deletes other people's.
	assert.Equal(t, 1, store.Len(),
		"the record is still held; that is the documented limit of not calling Start")

	// And it goes when something asks for it to go.
	removed, err := store.DeleteExpired(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, removed)
	assert.Zero(t, store.Len())
}

// nilTimed is a consumer's clock type that can also wait; (*nilTimed)(nil) is
// the typed nil an unchecked constructor error hands over.
type nilTimed struct{}

func (*nilTimed) Now() time.Time                       { return time.Time{} }
func (*nilTimed) After(time.Duration) <-chan time.Time { return nil }

// TestMemoryStoreConstruction covers what the constructor accepts and refuses:
// the system clock by default, and a configuration error, with no store, for a
// housekeeping interval of zero or less and for a nil clock, typed nil included.
func TestMemoryStoreConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.MemoryStoreOption
		assert func(t *testing.T, store *session.MemoryStore, err error)
	}

	// refused asserts a configuration error and no store.
	refused := func(t *testing.T, store *session.MemoryStore, err error) {
		t.Helper()

		require.ErrorIs(t, err, session.ErrConfig)
		assert.Nil(t, store)
	}

	// judgesBySystemTime asserts that the store read the system clock: a
	// session expired a second ago is refused, and one expiring in an hour is
	// served.
	judgesBySystemTime := func(t *testing.T, store *session.MemoryStore, err error) {
		t.Helper()

		require.NoError(t, err)

		now := time.Now()
		require.NoError(t, store.Create(t.Context(), &session.Session{
			ID: "expired", UserID: testUser, FamilyID: storedFamily, FamilyCreatedAt: now, CreatedAt: now.Add(-time.Hour),
			IdleExpiresAt: now.Add(-time.Second), AbsoluteExpiresAt: now.Add(time.Hour),
		}))
		require.NoError(t, store.Create(t.Context(), &session.Session{
			ID: "live", UserID: testUser, FamilyID: storedFamily, FamilyCreatedAt: now, CreatedAt: now,
			IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
		}))

		_, err = store.Load(t.Context(), "expired")
		require.ErrorIs(t, err, session.ErrExpired, "the store did not judge expiry by the system clock")
		_, err = store.Load(t.Context(), "live")
		require.NoError(t, err)
	}

	cases := []testCase{
		{name: "no clock option reads the system clock", assert: judgesBySystemTime},
		{
			name:   "an interval of zero is refused",
			opts:   []session.MemoryStoreOption{session.WithMemoryStoreHousekeepingInterval(0)},
			assert: refused,
		},
		{
			name:   "a negative interval is refused",
			opts:   []session.MemoryStoreOption{session.WithMemoryStoreHousekeepingInterval(-time.Second)},
			assert: refused,
		},
		{
			name:   "a nil clock is refused",
			opts:   []session.MemoryStoreOption{session.WithMemoryStoreClock(nil)},
			assert: refused,
		},
		{
			name:   "a typed-nil clock is refused",
			opts:   []session.MemoryStoreOption{session.WithMemoryStoreClock((*nilTimed)(nil))},
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, err := session.NewMemoryStore(tc.opts...)
			tc.assert(t, store, err)
		})
	}
}

// TestMemoryStoreSaveKeepsTheAuthenticationTime pins that Save cannot move
// when the user authenticated: a stale or edited copy saved back leaves the
// stored time as Create wrote it.
// Standalone: it saves through the store directly after creating through the manager.
func TestMemoryStoreSaveKeepsTheAuthenticationTime(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, store := managerOnClock(t, clk)
	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	s.AuthenticatedAt = createdAt.Add(time.Hour)
	require.NoError(t, store.Save(t.Context(), s))

	stored, err := store.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.True(t, stored.AuthenticatedAt.Equal(createdAt), "Save moved the authentication time to %s", stored.AuthenticatedAt)
}

func TestMemoryStoreSupersession(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, store *session.MemoryStore)
	}

	cases := []testCase{
		{
			// The durable stores key their rows by this digest, so a successor
			// digest the memory store records reads the same in any store.
			name: "the successor digest is the durable stores' session digest",
			assert: func(t *testing.T, ctx context.Context, store *session.MemoryStore) {
				require.NoError(t, store.Create(ctx, familyOf("old", id.MustParse("01926a4e-0000-7000-8000-000000000001"))))
				require.NoError(t, store.Supersede(ctx, firstRotation("old", storedSession("new"))))

				old, err := store.Load(ctx, "old")
				require.NoError(t, err)
				assert.Equal(t, storekit.SessionDigest("new"), old.SuccessorDigest)
			},
		},
		{
			name: "a loaded successor digest is the caller's own copy",
			assert: func(t *testing.T, ctx context.Context, store *session.MemoryStore) {
				require.NoError(t, store.Create(ctx, familyOf("old", id.MustParse("01926a4e-0000-7000-8000-000000000001"))))
				require.NoError(t, store.Supersede(ctx, firstRotation("old", storedSession("new"))))

				loaded, err := store.Load(ctx, "old")
				require.NoError(t, err)
				loaded.SuccessorDigest[0] ^= 0xff

				again, err := store.Load(ctx, "old")
				require.NoError(t, err)
				assert.Equal(t, storekit.SessionDigest("new"), again.SuccessorDigest)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, inner := sealingStore(t, 0x2a)
			tc.assert(t, t.Context(), inner)
		})
	}
}

// TestMemoryStoreReRotationIgnoresAnUnindexedSuccessor pins that a successor
// digest the store no longer indexes names no record, even one stored under
// the empty identifier: the successor is gone, so the re-rotation is refused
// as advanced and the unrelated record is left alone.
// Standalone: it deletes the first successor before superseding again.
func TestMemoryStoreReRotationIgnoresAnUnindexedSuccessor(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	s := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clockwork.NewFakeClockAt(createdAt))))
	require.NoError(t, s.Create(ctx, storedSession("")))
	require.NoError(t, s.Create(ctx, familyOf("old", id.MustParse("01926a4e-0000-7000-8000-000000000001"))))
	require.NoError(t, s.Supersede(ctx, firstRotation("old", storedSession("n1"))))
	require.NoError(t, s.Delete(ctx, "n1"))

	old, err := s.Load(ctx, "old")
	require.NoError(t, err)

	op := firstRotation("old", storedSession("n2"))
	op.ObservedSuccessor = old.SuccessorDigest
	require.ErrorIs(t, s.Supersede(ctx, op), session.ErrSuccessorAdvanced)

	unrelated, err := s.Load(ctx, "")
	require.NoError(t, err)
	assert.True(t, unrelated.SupersededAt.IsZero(), "an unrelated record was superseded")
}

// TestSupersedeRefusals pins the supersessions a store refuses with a plain
// error and writes nothing for, through the memory store and the sealing
// store over it: a successor with no family, and a retention deadline before
// the window's end.
func TestSupersedeRefusals(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		op     func() session.Supersession
		assert func(t *testing.T, err error, store *session.MemoryStore, old *session.Session)
	}

	refusedWithNothingWritten := func(t *testing.T, err error, store *session.MemoryStore, old *session.Session) {
		t.Helper()

		require.Error(t, err)
		require.NotErrorIs(t, err, session.ErrRenewalConflict)
		require.NotErrorIs(t, err, session.ErrNotFound)
		require.NotErrorIs(t, err, session.ErrSuccessorAdvanced)
		assert.Equal(t, 1, store.Len(), "a refused supersession inserted something")
		stored, err := store.Load(t.Context(), old.ID)
		require.NoError(t, err)
		assert.True(t, stored.SupersededAt.IsZero(), "a refused supersession marked the session")
		assert.Equal(t, old.AbsoluteExpiresAt, stored.AbsoluteExpiresAt)
	}

	cases := []testCase{
		{
			name: "a successor with no family",
			op: func() session.Supersession {
				successor := storedSession("new")
				successor.FamilyID = id.Nil

				return firstRotation("old", successor)
			},
			assert: refusedWithNothingWritten,
		},
		{
			name: "a retention deadline before the window's end",
			op: func() session.Supersession {
				op := firstRotation("old", storedSession("new"))
				op.RetainUntil = op.AcceptUntil.Add(-time.Second)

				return op
			},
			assert: refusedWithNothingWritten,
		},
	}

	for _, tc := range cases {
		for _, sealed := range []bool{false, true} {
			name := tc.name + " on the memory store"
			if sealed {
				name = tc.name + " on the sealing store"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				var store session.Store
				sealing, inner := sealingStore(t, 0x2a)
				store = inner
				if sealed {
					store = sealing
				}
				old := storedSession("old")
				require.NoError(t, store.Create(t.Context(), old))

				err := store.Supersede(t.Context(), tc.op())

				tc.assert(t, err, inner, old)
			})
		}
	}
}

// TestMemoryStoreSupersessionNeverLowersADeadline pins that a retention
// deadline below the absolute deadline a record already holds leaves it as it
// was, and the idle deadline becomes that same deadline, for Old and for Old's
// previous successor alike.
// Standalone: it supersedes one record twice in sequence.
func TestMemoryStoreSupersessionNeverLowersADeadline(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
	require.NoError(t, store.Create(t.Context(), storedSession("old")))

	// n1 is inserted already holding a retention deadline of 23:00, as a
	// store holds whatever it was given.
	n1 := storedSession("n1")
	n1.RetainUntil = createdAt.Add(14 * time.Hour)
	first := firstRotation("old", n1)
	first.RetainUntil = createdAt.Add(14 * time.Hour)
	require.NoError(t, store.Supersede(t.Context(), first))

	// The re-rotation gives a retention deadline of 11:00, earlier than both.
	second := firstRotation("old", storedSession("n2"))
	second.ObservedSuccessor = storekit.SessionDigest("n1")
	second.RetainUntil = createdAt.Add(2 * time.Hour)
	require.NoError(t, store.Supersede(t.Context(), second))

	for _, sessionID := range []string{"old", "n1"} {
		got, err := store.Load(t.Context(), sessionID)
		require.NoError(t, err)
		assert.Equal(t, createdAt.Add(14*time.Hour), got.RetainUntil, "%s: retention deadline lowered", sessionID)
		assert.Equal(t, createdAt.Add(12*time.Hour), got.AbsoluteExpiresAt, "%s: own absolute deadline changed", sessionID)
		assert.Equal(t, createdAt.Add(30*time.Minute), got.IdleExpiresAt, "%s: own idle deadline changed", sessionID)
	}
}
