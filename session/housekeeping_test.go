// The goroutine-exit test here is not parallel: goleak counts goroutines
// process-wide. It and the default-clock row of the controlled-clock table are
// the only tests that wait on real time, because they assert on the system
// clock a consumer actually ships with. The other tests drive housekeeping
// either through a synctest bubble or through a clockwork fake given to the
// store, never both in one test.
package session_test

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/kartaladev/scrty/session"
)

// seedForHousekeeping puts one already-expiring session and one long-lived one
// in store, both dated from the clock the store is reading.
func seedForHousekeeping(t *testing.T, store *session.MemoryStore) (expiredID, liveID string) {
	t.Helper()

	now := time.Now()
	expired := &session.Session{
		ID:                "expiring",
		UserID:            testUser,
		CreatedAt:         now,
		LastAccessedAt:    now,
		IdleExpiresAt:     now.Add(10 * time.Second),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}
	live := &session.Session{
		ID:                "live",
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
			store := session.NewMemoryStore(session.WithHousekeepingInterval(time.Minute))
			_, liveID := seedForHousekeeping(t, store)

			require.NoError(t, store.Start(t.Context()))
			require.Equal(t, 2, store.Len(), "housekeeping swept before its first interval")

			time.Sleep(90 * time.Second)
			synctest.Wait()

			assert.Equal(t, 1, store.Len(), "housekeeping did not run")
			_, err := store.Load(t.Context(), liveID)
			assert.NoError(t, err, "housekeeping swept a live session")

			require.NoError(t, store.Stop())
		})
	})

	t.Run("the interval defaults to one minute", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			store := session.NewMemoryStore()
			seedForHousekeeping(t, store)

			require.NoError(t, store.Start(t.Context()))

			time.Sleep(30 * time.Second)
			synctest.Wait()
			require.Equal(t, 2, store.Len(), "the default interval is shorter than a minute")

			time.Sleep(31 * time.Second)
			synctest.Wait()
			assert.Equal(t, 1, store.Len(), "the default interval is longer than a minute")

			require.NoError(t, store.Stop())
		})
	})

	t.Run("Start and Stop are idempotent", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			store := session.NewMemoryStore(session.WithHousekeepingInterval(time.Minute))
			seedForHousekeeping(t, store)

			require.NoError(t, store.Start(t.Context()))
			require.NoError(t, store.Start(t.Context()), "Start is idempotent")

			time.Sleep(90 * time.Second)
			synctest.Wait()
			assert.Equal(t, 1, store.Len())

			require.NoError(t, store.Stop())
			require.NoError(t, store.Stop(), "Stop is idempotent")

			// Nothing may keep running after Stop: put another expired record
			// in and let more than an interval pass.
			now := time.Now()
			require.NoError(t, store.Create(t.Context(), &session.Session{
				ID:                "after-stop",
				UserID:            testUser,
				CreatedAt:         now,
				IdleExpiresAt:     now.Add(-time.Second),
				AbsoluteExpiresAt: now.Add(time.Hour),
			}))

			time.Sleep(2 * time.Minute)
			synctest.Wait()
			assert.Equal(t, 2, store.Len(), "housekeeping kept running after Stop")
		})
	})

	t.Run("Stop without Start is not an error", func(t *testing.T) {
		t.Parallel()

		store := session.NewMemoryStore()
		assert.NoError(t, store.Stop())
	})
}

// TestHousekeepingExitsWithItsContext runs on the system clock, because a
// goroutine that outlives its context is exactly what a faked clock cannot
// show.
func TestHousekeepingExitsWithItsContext(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	ctx, cancel := context.WithCancel(t.Context())
	store := session.NewMemoryStore(session.WithHousekeepingInterval(5 * time.Millisecond))

	now := time.Now()
	require.NoError(t, store.Create(ctx, &session.Session{
		ID:                "expiring",
		UserID:            testUser,
		CreatedAt:         now,
		IdleExpiresAt:     now.Add(20 * time.Millisecond),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}))
	require.NoError(t, store.Start(ctx))

	require.Eventually(t, func() bool { return store.Len() == 0 },
		5*time.Second, time.Millisecond, "housekeeping on the system clock never swept")

	cancel()
	goleak.VerifyNone(t, ignore)

	// A record that expires after the context ended stays: the loop is gone,
	// not merely idle.
	stale := time.Now()
	require.NoError(t, store.Create(t.Context(), &session.Session{
		ID:                "after-cancel",
		UserID:            testUser,
		CreatedAt:         stale,
		IdleExpiresAt:     stale.Add(-time.Second),
		AbsoluteExpiresAt: stale.Add(time.Hour),
	}))
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 1, store.Len(), "housekeeping kept running after its context ended")

	require.NoError(t, store.Stop())
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

// sessionExpiringAt is a session whose idle deadline is at, and whose absolute
// deadline is well after it.
func sessionExpiringAt(id string, at time.Time) *session.Session {
	return &session.Session{
		ID:                id,
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
				store := session.NewMemoryStore(
					session.WithMemoryStoreClock(clk),
					session.WithHousekeepingInterval(10*time.Second),
				)
				require.NoError(t, store.Create(t.Context(), sessionExpiringAt("expiring", createdAt.Add(5*time.Second))))
				require.NoError(t, store.Create(t.Context(), sessionExpiringAt("live", createdAt.Add(time.Hour))))
				require.NoError(t, store.Start(t.Context()))
				t.Cleanup(func() { _ = store.Stop() })

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
				store := session.NewMemoryStore(
					session.WithMemoryStoreClock(clk),
					session.WithHousekeepingInterval(time.Hour),
				)
				m, err := session.NewManager(session.WithClock(clk), session.WithStore(store))
				require.NoError(t, err)

				s, err := m.Create(t.Context(), testUser)
				require.NoError(t, err)
				require.Equal(t, createdAt.Add(30*time.Minute), s.IdleExpiresAt, "the manager did not read the shared clock")

				require.NoError(t, store.Start(t.Context()))
				t.Cleanup(func() { _ = store.Stop() })
				blockUntil(t, clk, 1, "housekeeping never waited on the store's clock")

				clk.Advance(31 * time.Minute)

				require.ErrorIs(t, m.Touch(t.Context(), s), session.ErrSessionExpired,
					"the manager did not judge the session expired at the shared instant")
				_, err = m.Load(t.Context(), s.ID)
				require.ErrorIs(t, err, session.ErrSessionExpired,
					"the store did not judge the session expired at the shared instant")
				require.Equal(t, 1, store.Len(), "housekeeping swept before its interval")

				clk.Advance(29 * time.Minute)
				blockUntil(t, clk, 1, "housekeeping did not wait again after its sweep")

				assert.Zero(t, store.Len(), "the sweep did not remove the session the manager refuses")
			},
		},
		{
			name: "a restart counts the stopped loop's waiter and sweeps once",
			assert: func(t *testing.T) {
				clk := &countingClock{FakeClock: clockwork.NewFakeClockAt(createdAt)}
				store := session.NewMemoryStore(
					session.WithMemoryStoreClock(clk),
					session.WithHousekeepingInterval(10*time.Second),
				)
				require.NoError(t, store.Create(t.Context(), sessionExpiringAt("expiring", createdAt.Add(5*time.Second))))

				require.NoError(t, store.Start(t.Context()))
				blockUntil(t, clk.FakeClock, 1, "housekeeping never waited on the store's clock")
				require.NoError(t, store.Stop())
				require.NoError(t, store.Start(t.Context()))
				t.Cleanup(func() { _ = store.Stop() })

				// The stopped loop's After stays registered on the fake after
				// the loop has returned, so the restarted loop has parked only
				// once two waiters are held: the stale one and its own.
				blockUntil(t, clk.FakeClock, 2, "the restarted loop never waited on the store's clock")
				require.Equal(t, int32(2), clk.waits.Load())

				clk.Advance(10 * time.Second)
				blockUntil(t, clk.FakeClock, 1, "the restarted loop did not wait again after its sweep")

				assert.Zero(t, store.Len(), "the restarted loop did not sweep")
				assert.Equal(t, int32(3), clk.waits.Load(),
					"one sweep, by the restarted loop alone, is one wait more")
			},
		},
		{
			// The only clock a consumer ships with.
			name: "the default system clock still sweeps",
			assert: func(t *testing.T) {
				store := session.NewMemoryStore(session.WithHousekeepingInterval(10 * time.Millisecond))
				now := time.Now()
				require.NoError(t, store.Create(t.Context(), sessionExpiringAt("expired", now.Add(-time.Second))))
				require.NoError(t, store.Start(t.Context()))
				t.Cleanup(func() { _ = store.Stop() })

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
