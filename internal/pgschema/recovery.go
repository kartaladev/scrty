package pgschema

// Saved recovery code statements. A spend is one conditional update: zero
// rows affected is the refusal, and the first spending time is kept. A
// replacement is RecoveryCodeLockUser, then RecoveryCodeDeleteUser, then
// RecoveryCodeInsert for each hash, run together in one transaction or under
// one savepoint.
const (
	// RecoveryCodeLockUser takes the transaction-scoped advisory lock of user
	// $1, and is a replacement's first statement. Without it, two overlapping
	// replacements at READ COMMITTED would both keep their sets: the second's
	// delete waits on the first's old rows, and once the first commits it
	// cannot see the rows the first inserted. The lock is held until the
	// enclosing transaction ends, so under a caller's transaction a
	// replacement of the same user elsewhere waits for the caller's commit or
	// rollback. Distinct users may share a lock when their hashes collide,
	// which only serialises them.
	RecoveryCodeLockUser = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`

	// RecoveryCodeInsert stores one code: $1 id, $2 user_id, $3 code_hash,
	// $4 created_at. A hash the user already holds is skipped, so a set
	// naming one hash twice stores it once.
	RecoveryCodeInsert = `INSERT INTO recovery_codes (id, user_id, code_hash, created_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id, code_hash) DO NOTHING`

	// RecoveryCodeDeleteUser removes every code of user $1, spent or not.
	RecoveryCodeDeleteUser = `DELETE FROM recovery_codes WHERE user_id = $1`

	// RecoveryCodeMatch selects whether user $1 holds an unspent code whose
	// hash is $2.
	RecoveryCodeMatch = `SELECT EXISTS (
  SELECT 1 FROM recovery_codes WHERE user_id = $1 AND code_hash = $2 AND spent_at IS NULL)`

	// RecoveryCodeSpend marks user $1's code with hash $2 spent at $3, only
	// while it is unspent.
	RecoveryCodeSpend = `UPDATE recovery_codes SET spent_at = $3
WHERE user_id = $1 AND code_hash = $2 AND spent_at IS NULL`

	// RecoveryCodeRemaining counts user $1's unspent codes.
	RecoveryCodeRemaining = `SELECT count(*) FROM recovery_codes WHERE user_id = $1 AND spent_at IS NULL`
)

// Recovery record statements. Completion and cancellation are each one
// conditional update on "neither completed nor cancelled": zero rows affected
// is the refusal, and a refused write changes nothing.
const (
	// RecoveryRecordInsert stores a record: $1 id, $2 user_id, $3 started_at,
	// $4 not_before, $5 completed_at (NULL while not completed),
	// $6 cancelled_at (NULL while not cancelled), $7 proven, $8 reported,
	// $9 saved_spent. Zero rows affected means the identifier is already
	// stored.
	RecoveryRecordInsert = `INSERT INTO account_recoveries (id, user_id, started_at, not_before,
  completed_at, cancelled_at, proven, reported, saved_spent)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (id) DO NOTHING`

	// RecoveryRecordSelect reads the record with identifier $1.
	RecoveryRecordSelect = `SELECT user_id, started_at, not_before, completed_at, cancelled_at,
  proven, reported, saved_spent
FROM account_recoveries WHERE id = $1`

	// RecoveryRecordComplete marks record $1 completed at $2, only while it
	// is neither completed nor cancelled and $2 is not before its
	// not_before.
	RecoveryRecordComplete = `UPDATE account_recoveries SET completed_at = $2
WHERE id = $1 AND completed_at IS NULL AND cancelled_at IS NULL AND not_before <= $2`

	// RecoveryRecordCancel marks record $1 cancelled at $2, only while it is
	// neither completed nor cancelled.
	RecoveryRecordCancel = `UPDATE account_recoveries SET cancelled_at = $2
WHERE id = $1 AND completed_at IS NULL AND cancelled_at IS NULL`

	// RecoveryRecordCancelPending marks every record of user $1 that is
	// neither completed nor cancelled as cancelled at $2.
	RecoveryRecordCancelPending = `UPDATE account_recoveries SET cancelled_at = $2
WHERE user_id = $1 AND completed_at IS NULL AND cancelled_at IS NULL`

	// RecoveryRecordLatestCompletion selects the latest completion time among
	// user $1's records: NULL when none is completed.
	RecoveryRecordLatestCompletion = `SELECT max(completed_at) FROM account_recoveries WHERE user_id = $1`
)
