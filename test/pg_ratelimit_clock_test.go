package test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// runPGDatabaseClock pins the default time source, the database's
// clock_timestamp(), with no application clock configured: a failure stops
// counting one window after it was recorded, in real time, and each record
// reads the time once, so the newest stamp it writes and newest_at agree to
// the microsecond.
func runPGDatabaseClock(t *testing.T, b pgFaultBackend) {
	t.Helper()

	type testCase struct {
		name   string
		limit  int
		window time.Duration
		assert func(t *testing.T, conn PostgresConn, ns string, l ratelimit.Limiter)
	}

	cases := []testCase{
		{
			name:   "a failure stops counting one window later",
			limit:  1,
			window: 2 * time.Second,
			assert: func(t *testing.T, _ PostgresConn, _ string, l ratelimit.Limiter) {
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				exceeded, err := l.Exceeded(t.Context(), "k")
				require.NoError(t, err)
				assert.True(t, exceeded, "the failure just recorded does not count")

				time.Sleep(2100 * time.Millisecond)
				exceeded, err = l.Exceeded(t.Context(), "k")
				require.NoError(t, err)
				assert.False(t, exceeded, "the failure still counts a window after it was recorded")
			},
		},
		{
			name:   "each record leaves newest_at at its newest stamp",
			limit:  20,
			window: time.Minute,
			assert: func(t *testing.T, conn PostgresConn, ns string, l ratelimit.Limiter) {
				// More records than the limit: the reads of the broken
				// variant fall in one microsecond often enough that twenty
				// records could all agree by chance, and a full row keeps
				// its newest stamp last as well.
				for i := range 60 {
					require.NoError(t, l.RecordFailure(t.Context(), "k"))
					var equal bool
					require.NoError(t, conn.DB.QueryRowContext(t.Context(),
						`SELECT newest_at = stamps[array_upper(stamps, 1)] FROM rate_limit_buckets WHERE namespace = $1 AND key = $2`,
						ns, "k").Scan(&equal))
					assert.True(t, equal, "record %d: newest_at differs from the newest stamp", i)
				}
			},
		},
	}

	conn := migratedLimiterDB(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ns := pgScopedNamespace(t, "clock")
			l := b.limiter(t, conn, ns, tc.limit, tc.window, pgFaultOptions{})
			tc.assert(t, conn, ns, l)
		})
	}
}

func TestPGLimiter_DatabaseClock(t *testing.T) {
	t.Parallel()

	runPGFaultBackends(t, runPGDatabaseClock)
}

// pgRecordReadingTimeTwice is a record that reads clock_timestamp() once for
// the stamp and again for newest_at, so the two differ by however long lay
// between the reads.
const pgRecordReadingTimeTwice = `INSERT INTO rate_limit_buckets AS b (namespace, key, stamps, newest_at, longest_window_us)
SELECT $1, $2, ARRAY[coalesce($5::timestamptz, clock_timestamp())], coalesce($5::timestamptz, clock_timestamp()), $4::bigint
FROM (SELECT set_config('lock_timeout', $6::text, true)) AS lt
ON CONFLICT (namespace, key) DO UPDATE SET
  stamps = (SELECT array_agg(n.s ORDER BY n.s) FROM
            (SELECT s FROM unnest(b.stamps || EXCLUDED.stamps) AS u(s) ORDER BY s DESC LIMIT $3::int) AS n),
  newest_at = GREATEST(b.newest_at, EXCLUDED.newest_at),
  longest_window_us = GREATEST(b.longest_window_us, EXCLUDED.longest_window_us)`

var pgDatabaseClockBroken = pgFaultVariants(runPGDatabaseClock,
	pgFaultVariant{
		name: "clock-frozen-at-construction",
		backend: brokenLimiterBackend(func(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, o pgFaultOptions) ratelimit.Limiter {
			t.Helper()
			o.clock = clockwork.NewFakeClockAt(time.Now())
			return sqlstoreFaultLimiter(t, conn, ns, limit, window, o)
		}),
		failsCase: "a failure stops counting one window later",
		failsWith: "the failure still counts a window after it was recorded",
	},
	pgFaultVariant{
		name: "time-read-twice",
		backend: brokenLimiterBackend(func(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, o pgFaultOptions) ratelimit.Limiter {
			t.Helper()
			return newPGStatementLimiter(t, conn, ns, limit, window, o, nil, pgRecordReadingTimeTwice, "5000ms")
		}),
		failsCase: "each record leaves newest_at at its newest stamp",
		failsWith: "newest_at differs from the newest stamp",
	},
)

// TestPGLimiter_DatabaseClockBroken is the child half of
// TestPGLimiter_DatabaseClockCatchesBrokenVariants. Without a variant named it
// skips.
func TestPGLimiter_DatabaseClockBroken(t *testing.T) {
	storefix.RunBrokenChild(t, pgFaultBrokenVar, "TestPGLimiter_DatabaseClockCatchesBrokenVariants", pgDatabaseClockBroken)
}

func TestPGLimiter_DatabaseClockCatchesBrokenVariants(t *testing.T) {
	t.Parallel()

	catchPGFaultVariants(t, "TestPGLimiter_DatabaseClockBroken", pgDatabaseClockBroken)
}
