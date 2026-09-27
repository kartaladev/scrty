package pgschema

// API key statements. A key arrives with its own id, which is the primary
// key; a revocation keeps the first revocation time.
//
//nolint:gosec // G101: SQL statements naming the digest column, not credentials
const (
	// APIKeyInsert stores a key: $1 id, $2 user_id, $3 name, $4 scopes (a
	// JSON array), $5 secret_digest, $6 expires_at, $7 revoked_at,
	// $8 last_used_at (each NULL when absent), $9 created_at.
	APIKeyInsert = `INSERT INTO api_keys (id, user_id, name, scopes, secret_digest, expires_at, revoked_at,
  last_used_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	// APIKeySelect reads key $1, revoked and expired ones included.
	APIKeySelect = `SELECT id, user_id, name, scopes, secret_digest, expires_at, revoked_at, last_used_at, created_at
FROM api_keys WHERE id = $1`

	// APIKeyRevoke marks key $1 revoked at $2, keeping a revocation already
	// recorded. Zero rows affected means there is no such key.
	APIKeyRevoke = `UPDATE api_keys SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1`

	// APIKeyTouch records a use of key $1 at $2. Zero rows affected means
	// there is no such key.
	APIKeyTouch = `UPDATE api_keys SET last_used_at = $2 WHERE id = $1`

	// APIKeyList reads every key of user $1, oldest first, the id breaking
	// ties so the order is stable.
	APIKeyList = `SELECT id, user_id, name, scopes, secret_digest, expires_at, revoked_at, last_used_at, created_at
FROM api_keys WHERE user_id = $1 ORDER BY created_at, id`
)
