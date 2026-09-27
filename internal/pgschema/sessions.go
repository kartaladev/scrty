package pgschema

// Session statements. A session is found by id_digest, the SHA-256 of its
// identifier, which is never stored; every lookup takes that digest as $1.
// Save is an update only, so a save racing a logout never re-creates the
// session, and Create is an insert that does nothing when the digest is
// already stored.
const (
	// SessionInsert creates a session: $1 id, $2 id_digest, $3 user_id,
	// $4 created_at, $5 last_accessed_at, $6 idle_expires_at,
	// $7 absolute_expires_at, $8 first_factor, $9 mfa_state,
	// $10 mfa_satisfied_at, $11 password_change_pending, $12 external_provider,
	// $13 external_issuer, $14 external_session_id, $15 external_id_token,
	// $16 data, $17 enrolment_origin_deadline (NULL when not marked),
	// $18 enrolment_generation (NULL for none). Zero rows affected means the
	// digest is already stored.
	SessionInsert = `INSERT INTO sessions (id, id_digest, user_id, created_at, last_accessed_at,
  idle_expires_at, absolute_expires_at, first_factor, mfa_state, mfa_satisfied_at,
  password_change_pending, external_provider, external_issuer, external_session_id,
  external_id_token, data, enrolment_origin_deadline, enrolment_generation)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
ON CONFLICT (id_digest) DO NOTHING`

	// SessionUpdate replaces every field of the session with digest $1, in
	// SessionInsert's order from $2 user_id to $17 enrolment_generation. Zero
	// rows affected means there is no longer a session to update.
	SessionUpdate = `UPDATE sessions SET user_id = $2, created_at = $3, last_accessed_at = $4,
  idle_expires_at = $5, absolute_expires_at = $6, first_factor = $7, mfa_state = $8,
  mfa_satisfied_at = $9, password_change_pending = $10, external_provider = $11,
  external_issuer = $12, external_session_id = $13, external_id_token = $14, data = $15,
  enrolment_origin_deadline = $16, enrolment_generation = $17
WHERE id_digest = $1`

	// SessionSelect reads the session with digest $1. Expiry is judged by the
	// caller, with its clock.
	SessionSelect = `SELECT user_id, created_at, last_accessed_at, idle_expires_at,
  absolute_expires_at, first_factor, mfa_state, mfa_satisfied_at, password_change_pending,
  external_provider, external_issuer, external_session_id, external_id_token, data,
  enrolment_origin_deadline, enrolment_generation
FROM sessions WHERE id_digest = $1`

	// SessionDelete removes the session with digest $1.
	SessionDelete = `DELETE FROM sessions WHERE id_digest = $1`

	// SessionDeleteByUser removes every session of user $1, expired or not.
	SessionDeleteByUser = `DELETE FROM sessions WHERE user_id = $1`

	// SessionCountActive counts user $1's sessions unexpired at $2: both
	// deadlines strictly after it.
	SessionCountActive = `SELECT count(*) FROM sessions
WHERE user_id = $1 AND idle_expires_at > $2 AND absolute_expires_at > $2`

	// SessionDeleteExpired removes every session past either deadline at $1.
	SessionDeleteExpired = `DELETE FROM sessions WHERE idle_expires_at <= $1 OR absolute_expires_at <= $1`

	// SessionDeleteByExternal removes the sessions of issuer $1 and provider
	// session $2. The issuer always leads, and an empty argument matches
	// nothing.
	SessionDeleteByExternal = `DELETE FROM sessions
WHERE external_issuer = $1 AND external_session_id = $2 AND $1 <> '' AND $2 <> ''`

	// SessionDeleteByUserIssuer removes user $1's sessions from issuer $2. An
	// empty issuer matches nothing.
	SessionDeleteByUserIssuer = `DELETE FROM sessions WHERE user_id = $1 AND external_issuer = $2 AND $2 <> ''`
)
