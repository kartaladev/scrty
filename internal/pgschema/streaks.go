package pgschema

// Consecutive-failure streak statements: one row per identifier in
// login_failure_streaks.
const (
	// StreakAdd adds one failure to username $2's streak: $1 id for a new
	// row, $2 username, $3 at, $4 since (the inactivity cutoff, inclusive),
	// $5 limit. It returns failures, newest_failure_at, held_at and set_hold,
	// one row, or no row when another writer created the streak after this
	// statement's snapshot was taken; the caller then runs it again.
	//
	// An existing streak is advanced by one UPDATE whose input is the row
	// locked FOR UPDATE in prev. The lock is taken before the UPDATE touches
	// the row and, under READ COMMITTED, on its newest committed version, so
	// prev.held_at is the hold exactly as it stood before this write, and
	// set_hold (the hold was NULL before and is set after) is true for exactly
	// one write, however many race. A plain RETURNING sees only the new row,
	// which cannot tell "this write set the hold" from "an earlier write did",
	// nor, when a cap was lowered, from the count alone.
	//
	// The UPDATE restarts a streak not held whose newest failure is at or
	// before $4 at {1, $3}; otherwise it adds one and keeps the later of the
	// stored newest failure and $3. It sets held_at to $3 when the streak was
	// not held and its new count is $5 or more, and never moves a set one.
	//
	// When prev found no row, the INSERT creates the streak at one. It does
	// nothing on a conflict with a row inserted since the snapshot, and the
	// statement then returns no row.
	StreakAdd = `WITH prev AS (
    SELECT id, held_at FROM login_failure_streaks WHERE username = $2::text FOR UPDATE
), advanced AS (
    UPDATE login_failure_streaks AS s SET
        failures = CASE WHEN s.held_at IS NULL AND s.newest_failure_at <= $4::timestamptz
                        THEN 1 ELSE s.failures + 1 END,
        newest_failure_at = CASE WHEN s.held_at IS NULL AND s.newest_failure_at <= $4::timestamptz
                                 THEN $3::timestamptz
                                 ELSE GREATEST(s.newest_failure_at, $3::timestamptz) END,
        held_at = CASE
            WHEN s.held_at IS NOT NULL THEN s.held_at
            WHEN (CASE WHEN s.newest_failure_at <= $4::timestamptz THEN 1 ELSE s.failures + 1 END) >= $5::integer
                THEN $3::timestamptz
            END
    FROM prev
    WHERE s.id = prev.id
    RETURNING s.failures, s.newest_failure_at, s.held_at,
              prev.held_at IS NULL AND s.held_at IS NOT NULL AS set_hold
), created AS (
    INSERT INTO login_failure_streaks (id, username, failures, newest_failure_at, held_at)
    SELECT $1::uuid, $2::text, 1, $3::timestamptz,
           CASE WHEN 1 >= $5::integer THEN $3::timestamptz END
    WHERE NOT EXISTS (SELECT 1 FROM prev)
    ON CONFLICT (username) DO NOTHING
    RETURNING failures, newest_failure_at, held_at, held_at IS NOT NULL AS set_hold
)
SELECT failures, newest_failure_at, held_at, set_hold FROM advanced
UNION ALL
SELECT failures, newest_failure_at, held_at, set_hold FROM created`

	// StreakRead reads username $1's streak as of cutoff $2: a streak not
	// held whose newest failure is at or before $2 is no row, as is no streak.
	StreakRead = `SELECT failures, newest_failure_at, held_at FROM login_failure_streaks
WHERE username = $1 AND (held_at IS NOT NULL OR newest_failure_at > $2)`

	// AttemptAndStreakDeleteByUsername clears username $1's failures and its
	// streak, hold included, in one statement, so no reader sees one cleared
	// without the other.
	AttemptAndStreakDeleteByUsername = `WITH attempts AS (DELETE FROM login_attempts WHERE username = $1)
DELETE FROM login_failure_streaks WHERE username = $1`

	// StreakDeleteBefore removes every streak not held whose newest failure is
	// strictly before $1.
	StreakDeleteBefore = `DELETE FROM login_failure_streaks WHERE held_at IS NULL AND newest_failure_at < $1`

	// StreakAddMaxRuns is the safety bound on how many times a store runs
	// StreakAdd for one failure. A run that returns no row means another writer
	// committed a create or a delete of the streak since this run's snapshot, so
	// the loop only continues while the system advances; the bound exists to end
	// a pathological storm, not to ration retries. The caller's context ends the
	// loop sooner.
	StreakAddMaxRuns = 64
)
