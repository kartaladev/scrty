package pgschema

// One-time token statements. Consumption is one conditional update: zero rows
// affected is the refusal, and the first consumption time is kept.
const (
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
