package pgschema

// Login-attempt statements: one row per failure, keyed by a generated id.
const (
	// AttemptInsert records one failure: $1 id, $2 username, $3 attempted_at.
	AttemptInsert = `INSERT INTO login_attempts (id, username, attempted_at) VALUES ($1, $2, $3)`

	// AttemptDeleteByUsername clears username $1's failures.
	AttemptDeleteByUsername = `DELETE FROM login_attempts WHERE username = $1`

	// AttemptCountSince counts username $1's failures strictly after $2.
	AttemptCountSince = `SELECT count(*) FROM login_attempts WHERE username = $1 AND attempted_at > $2`

	// AttemptDeleteBefore removes every failure recorded strictly before $1.
	AttemptDeleteBefore = `DELETE FROM login_attempts WHERE attempted_at < $1`
)
