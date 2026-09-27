package pgschema

// Signing-key statements. Keys upsert by kid, as their contract defines, and
// a re-seal replaces the private material only while it still holds the value
// that was read.
const (
	// SigningKeyUpsert stores a key: $1 id, $2 kid, $3 alg, $4 private_key,
	// $5 public_jwk, $6 created_at, replacing the key already stored under
	// the same kid but keeping its id.
	SigningKeyUpsert = `INSERT INTO signing_keys (id, kid, alg, private_key, public_jwk, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (kid) DO UPDATE SET alg = EXCLUDED.alg, private_key = EXCLUDED.private_key,
  public_jwk = EXCLUDED.public_jwk, created_at = EXCLUDED.created_at`

	// SigningKeyLoadAll reads every key, oldest first, kid breaking ties so
	// the order is stable.
	SigningKeyLoadAll = `SELECT kid, alg, private_key, public_jwk, created_at FROM signing_keys
ORDER BY created_at, kid`

	// SigningKeyReseal replaces kid $1's private material with $3 only while
	// it still equals $2.
	SigningKeyReseal = `UPDATE signing_keys SET private_key = $3 WHERE kid = $1 AND private_key = $2`
)
