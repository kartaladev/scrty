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

	// APIKeyRevoke marks key $1 revoked at $2 only while it is live, and
	// returns one row of two booleans: revoked, whether this statement revoked
	// it, and present, whether the key exists. A revocation already recorded is kept.
	//
	// The update is the conditional write that decides a race: under READ
	// COMMITTED a second concurrent statement waits on the row lock, then
	// re-checks revoked_at IS NULL against the committed row and updates
	// nothing. The existence check reads the statement's snapshot, so a key
	// revoked by someone else reads as present and not revoked, and only a key
	// that was never stored reads as absent.
	APIKeyRevoke = `WITH revoked AS (
  UPDATE api_keys SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL RETURNING id
)
SELECT EXISTS (SELECT 1 FROM revoked) AS revoked, EXISTS (SELECT 1 FROM api_keys WHERE id = $1) AS present`

	// APIKeyTouch records a use of key $1 at $2. Zero rows affected means
	// there is no such key.
	APIKeyTouch = `UPDATE api_keys SET last_used_at = $2 WHERE id = $1`

	// APIKeyList reads every key of user $1, oldest first, the id breaking
	// ties so the order is stable.
	APIKeyList = `SELECT id, user_id, name, scopes, secret_digest, expires_at, revoked_at, last_used_at, created_at
FROM api_keys WHERE user_id = $1 ORDER BY created_at, id`
)
