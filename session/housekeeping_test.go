// The real-ticker test here is not parallel: goleak counts goroutines
// process-wide. It is the only test that waits on real time, because it is the
// only one asserting on the ticker a consumer actually ships with.
package session_test

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

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
			require.Equal(t, 2, store.Len(), "housekeeping swept before its first tick")

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

			// Nothing may keep ticking after Stop: put another expired record
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
			assert.Equal(t, 2, store.Len(), "a ticker kept running after Stop")
		})
	})

	t.Run("Stop without Start is not an error", func(t *testing.T) {
		t.Parallel()

		store := session.NewMemoryStore()
		assert.NoError(t, store.Stop())
	})
}

// TestHousekeepingTickerExitsWithItsContext runs on the real ticker, because a
// goroutine that outlives its context is exactly what a faked clock cannot
// show.
func TestHousekeepingTickerExitsWithItsContext(t *testing.T) {
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
		5*time.Second, time.Millisecond, "the real ticker never swept")

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
