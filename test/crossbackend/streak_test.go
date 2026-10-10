package crossbackend_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
)

// streakStore is a login-attempt store that keeps consecutive-failure streaks,
// as every durable backend's is.
type streakStore interface {
	policy.AttemptStore
	policy.FailureStreakStore
}

// streakStoreOf builds the named backend's login-attempt store, as a streak
// store.
func (b backends) streakStoreOf(t *testing.T, name string) streakStore {
	t.Helper()

	s, ok := b.attemptStore(t, name).(streakStore)
	require.True(t, ok, "the %s login-attempt store keeps no streaks", name)

	return s
}

// TestCrossBackendFailureStreak proves every ordered pair of backends agrees on
// the streak table: a hold set through the writer is read as held, with the
// same count and hold instant, through the reader; the reader's next add
// continues the streak without setting the hold again; and the reader's Reset
// lifts the hold for the writer.
func TestCrossBackendFailureStreak(t *testing.T) {
	t.Parallel()

	const limit = 5

	conn := migratedConn(t)
	b := backends{conn: conn, pool: openPgxPool(t, conn.DSN), gdb: openGormDB(t, conn.DSN), cipher: testCipher(t)}
	start := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	since := start.Add(-30 * 24 * time.Hour)

	for _, writer := range backendNames {
		for _, reader := range backendNames {
			if writer == reader {
				continue
			}

			t.Run(writer+"_holds_"+reader+"_reads", func(t *testing.T) {
				t.Parallel()

				ctx := t.Context()
				username := "ada-" + writer + "-" + reader
				w, rd := b.streakStoreOf(t, writer), b.streakStoreOf(t, reader)

				var setters int
				for i := range limit {
					_, setHold, err := w.AddStreakFailure(ctx, username, start.Add(time.Duration(i)*time.Second), since, limit)
					require.NoError(t, err)
					if setHold {
						setters++
					}
				}
				require.Equal(t, 1, setters, "the writer's add reaching the limit sets the hold")
				heldAt := start.Add((limit - 1) * time.Second)

				got, err := rd.FailureStreak(ctx, username, since)
				require.NoError(t, err)
				assert.Equal(t, limit, got.Failures)
				assert.True(t, got.Held(), "a hold set through %s is read as held through %s", writer, reader)
				assert.True(t, heldAt.Equal(got.HeldAt), "HeldAt is %v, want %v", got.HeldAt, heldAt)
				assert.True(t, heldAt.Equal(got.Newest), "Newest is %v, want %v", got.Newest, heldAt)

				next, setHold, err := rd.AddStreakFailure(ctx, username, start.Add(time.Hour), since, limit)
				require.NoError(t, err)
				assert.False(t, setHold, "a hold set through %s is not set again through %s", writer, reader)
				assert.Equal(t, limit+1, next.Failures)
				assert.True(t, heldAt.Equal(next.HeldAt), "HeldAt moved to %v", next.HeldAt)

				require.NoError(t, rd.Reset(ctx, username))
				cleared, err := w.FailureStreak(ctx, username, since)
				require.NoError(t, err)
				assert.Equal(t, policy.FailureStreak{}, cleared, "a Reset through %s lifts the hold for %s", reader, writer)
			})
		}
	}
}
