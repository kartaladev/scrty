package pgschema

// One-time token statements. Consumption is one conditional update: zero rows
// affected is the refusal, and the first consumption time is kept. A bounded
// insert is OneTimeLockSubject, then OneTimeCountRecent, then OneTimeInsert,
// run together in one READ COMMITTED transaction.
const (
	// OneTimeLockSubject takes the transaction-scoped advisory lock of
	// purpose $1 and subject $2, and is a bounded insert's first statement.
	// Without it, two bounded inserts for one subject would both count the
	// same records and both insert. The lock is held until the enclosing
	// transaction ends, so the next bounded insert for the subject counts
	// only once this one's record is committed or gone. The key is namespaced
	// and length-prefixed, so no two (purpose, subject) pairs spell the same
	// key; distinct pairs may still share a lock when their hashes collide,
	// which only serialises them.
	OneTimeLockSubject = `SELECT pg_advisory_xact_lock(hashtextextended(
  'onetime:' || length($1::text) || ':' || $1::text || ':' || $2::text, 0))`

	// OneTimeInsert stores a token: $1 id, $2 purpose, $3 subject,
	// $4 secret_hash, $5 binding_hash (NULL when unbound), $6 issued_at,
	// $7 expires_at, $8 consumed_at (NULL while unspent). Zero rows affected
	// means the identifier is already stored.
	OneTimeInsert = `INSERT INTO one_time_tokens (id, purpose, subject, secret_hash, binding_hash,
  issued_at, expires_at, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO NOTHING`

	// OneTimeSelect reads the token with identifier $1, spent or not.
	OneTimeSelect = `SELECT purpose, subject, secret_hash, binding_hash, issued_at, expires_at, consumed_at
FROM one_time_tokens WHERE id = $1`

	// OneTimeConsume marks token $1 consumed at $2 only while it is unspent.
	OneTimeConsume = `UPDATE one_time_tokens SET consumed_at = $2 WHERE id = $1 AND consumed_at IS NULL`

	// OneTimeCountRecent counts purpose $1's tokens for subject $2 issued at
	// or after $3, spent and expired ones included.
	OneTimeCountRecent = `SELECT count(*) FROM one_time_tokens
WHERE purpose = $1 AND subject = $2 AND issued_at >= $3`

	// OneTimeDeleteExpiredBefore removes purpose $1's tokens expired at $2
	// and issued strictly before $3.
	OneTimeDeleteExpiredBefore = `DELETE FROM one_time_tokens
WHERE purpose = $1 AND expires_at <= $2 AND issued_at < $3`
)
