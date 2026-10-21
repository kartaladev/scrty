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
	// $18 enrolment_generation (NULL for none), $19 recovered_at (NULL when
	// never recovered), $20 federated_amr (a JSON array of strings, '[]' for
	// none), $21 federated_acr ('' for none), $22 mfa_at_first_factor (a second
	// factor met at the first factor), $23 family_id (the all-zero UUID for
	// the nil family), $24 family_created_at, $25 superseded_at (NULL when not
	// superseded), $26 accept_until (NULL when not superseded),
	// $27 successor_digest (NULL for none), $28 first_presented_at (NULL when
	// never presented), $29 authenticated_at. Zero rows affected means the
	// digest is already stored.
	SessionInsert = `INSERT INTO sessions (id, id_digest, user_id, created_at, last_accessed_at,
  idle_expires_at, absolute_expires_at, first_factor, mfa_state, mfa_satisfied_at,
  password_change_pending, external_provider, external_issuer, external_session_id,
  external_id_token, data, enrolment_origin_deadline, enrolment_generation, recovered_at,
  federated_amr, federated_acr, mfa_at_first_factor, family_id, family_created_at,
  superseded_at, accept_until, successor_digest, first_presented_at, authenticated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22,
  $23, $24, $25, $26, $27, $28, $29)
ON CONFLICT (id_digest) DO NOTHING`

	// SessionUpdate replaces every field of the session with digest $1, in
	// SessionInsert's order from $2 user_id to $20 federated_acr. It leaves
	// mfa_at_first_factor, authenticated_at and the family, supersession and
	// presentation columns out: only the insert, the supersession and the first
	// presentation write them, so no later save can undo them. On a
	// superseded row (superseded_at set) it also leaves both deadlines as the
	// supersession set them, so a copy loaded before the supersession cannot
	// shorten them. Zero rows affected means there is no longer a session to
	// update.
	SessionUpdate = `UPDATE sessions SET user_id = $2, created_at = $3, last_accessed_at = $4,
  idle_expires_at = CASE WHEN superseded_at IS NULL THEN $5 ELSE idle_expires_at END,
  absolute_expires_at = CASE WHEN superseded_at IS NULL THEN $6 ELSE absolute_expires_at END,
  first_factor = $7, mfa_state = $8,
  mfa_satisfied_at = $9, password_change_pending = $10, external_provider = $11,
  external_issuer = $12, external_session_id = $13, external_id_token = $14, data = $15,
  enrolment_origin_deadline = $16, enrolment_generation = $17, recovered_at = $18,
  federated_amr = $19, federated_acr = $20
WHERE id_digest = $1`

	// SessionSelect reads the session with digest $1. Expiry is judged by the
	// caller, with its clock.
	SessionSelect = `SELECT user_id, created_at, last_accessed_at, idle_expires_at,
  absolute_expires_at, first_factor, mfa_state, mfa_satisfied_at, password_change_pending,
  external_provider, external_issuer, external_session_id, external_id_token, data,
  enrolment_origin_deadline, enrolment_generation, recovered_at,
  mfa_at_first_factor, federated_amr, federated_acr, family_id, family_created_at,
  superseded_at, accept_until, successor_digest, first_presented_at, authenticated_at
FROM sessions WHERE id_digest = $1`

	// SessionExists reports whether a session with digest $1 is stored,
	// expired or not. A conditional write that changed no row runs it to tell
	// a missing session from one whose condition did not hold.
	SessionExists = `SELECT EXISTS (SELECT 1 FROM sessions WHERE id_digest = $1)`

	// SessionRecordActivity writes $2 last_accessed_at and $3 idle_expires_at,
	// the latter capped at the stored absolute deadline, and nothing else, to
	// the session with digest $1, provided its stored last access is before $4
	// and it is not superseded. Zero rows affected means it is fresher,
	// superseded or missing; SessionExists tells which.
	SessionRecordActivity = `UPDATE sessions SET last_accessed_at = $2, idle_expires_at = LEAST($3, absolute_expires_at)
WHERE id_digest = $1 AND last_accessed_at <= $4 AND superseded_at IS NULL`

	// SessionSupersedeOld marks the session with digest $1 superseded at $3,
	// with its window ending at $4 and $5 as its successor's digest, and sets
	// its idle deadline to its absolute one, provided it is in a family, its
	// stored successor digest is still $2 (NULL for none), and, when $2 is
	// NULL, it is not superseded already: a superseded session is superseded
	// again only through its observed successor, and one with no successor was
	// knocked out of its chain, so renewing it as a fresh head would give the
	// family a second live head. Zero rows affected means it is missing, in no
	// family, or its successor is not the one observed; SessionSupersedeRefusal
	// tells which. This conditional update is what decides concurrent
	// supersessions: a second one waits on the family's row locks, in
	// SessionLockFamily, and then finds the successor changed.
	SessionSupersedeOld = `UPDATE sessions SET superseded_at = $3, accept_until = $4, successor_digest = $5,
  idle_expires_at = absolute_expires_at
WHERE id_digest = $1 AND successor_digest IS NOT DISTINCT FROM $2
  AND ($2::bytea IS NOT NULL OR superseded_at IS NULL)
  AND family_id <> '00000000-0000-0000-0000-000000000000'`

	// SessionSupersedeRefusal reads, for the session with digest $1, why a
	// SessionSupersedeOld that changed no row did: 0 when it is not stored, 2
	// when it is stored in no family (the all-zero family), and 1 otherwise,
	// when its successor or its supersession is the cause.
	SessionSupersedeRefusal = `SELECT COALESCE(MAX(CASE WHEN family_id = '00000000-0000-0000-0000-000000000000'
  THEN 2 ELSE 1 END), 0) FROM sessions WHERE id_digest = $1`

	// SessionSupersedePrevious marks the session with digest $1, the previous
	// successor of a session superseded again, superseded at $2 with a window
	// ending at $2, and sets its idle deadline to its absolute one, provided
	// it is not superseded already and, when $3 is true, has never been
	// presented. Zero rows affected means that successor has moved on: it is
	// superseded, presented when $3 requires it not to be, or no longer
	// stored; the supersession is refused and rolled back.
	//
	// It runs after SessionLockFamily and SessionSupersedeOld. Under READ
	// COMMITTED a supersession that waited on the successor's row lock, in
	// SessionLockFamily, runs this update on a snapshot taken after that lock
	// was released, so a presentation, a rotation or a removal of the
	// successor that held the lock first refuses the supersession, and one
	// that came after it waits for it.
	SessionSupersedePrevious = `UPDATE sessions SET superseded_at = $2, accept_until = $2,
  idle_expires_at = absolute_expires_at
WHERE id_digest = $1 AND superseded_at IS NULL AND (NOT $3::boolean OR first_presented_at IS NULL)`

	// SessionExtendSuperseded raises both deadlines of every superseded
	// session in the family of the session with digest $1 whose absolute
	// deadline is before $2 to $2, and touches no other row: live heads, and
	// superseded sessions already at or past $2, are left alone. A
	// supersession runs it after SessionSupersedeOld and
	// SessionSupersedePrevious, with $2 its successor's absolute deadline, so
	// a renewal that extends the family keeps every superseded member judged
	// as superseded, not expired, while the family is live. A superseded
	// session never authenticates past its window, so the raise grants
	// nothing. The rows it locks are already held, in id order, by the
	// SessionLockFamily the supersession began with.
	SessionExtendSuperseded = `UPDATE sessions SET idle_expires_at = $2, absolute_expires_at = $2
WHERE family_id = (SELECT family_id FROM sessions WHERE id_digest = $1)
  AND superseded_at IS NOT NULL AND absolute_expires_at < $2`

	// SessionMarkPresented records $2 as the first presentation of the
	// session with digest $1, only when none is recorded. Zero rows affected
	// means one is recorded already, or the session is missing; SessionExists
	// tells which.
	SessionMarkPresented = `UPDATE sessions SET first_presented_at = $2
WHERE id_digest = $1 AND first_presented_at IS NULL`

	// SessionLockFamily locks every session in the family of the session
	// with digest $1, in id order, and none when that family is the nil one,
	// and returns nothing the caller reads. A supersession runs it first, so it takes every family row it later
	// updates (the old session, its previous successor and the superseded
	// members SessionExtendSuperseded raises) in the one order
	// SessionDeleteFamily also takes them in. Two writers that each lock
	// several rows of one family then wait for each other instead of
	// deadlocking: without it, a supersession of the family's head locks the
	// head and then the older superseded members it raises, while a
	// re-rotation of an older member, or a family delete scanning the older
	// members first, takes them in the reverse order.
	SessionLockFamily = `SELECT id FROM sessions
WHERE family_id = (SELECT family_id FROM sessions WHERE id_digest = $1)
  AND family_id <> '00000000-0000-0000-0000-000000000000'
ORDER BY id FOR UPDATE`

	// SessionDeleteFamily removes every session of family $1, superseded or
	// not, expired or not, after locking them in id order, the order
	// SessionLockFamily takes them in. The caller refuses the nil family
	// before running it, and repeats it until it affects no row: under READ
	// COMMITTED a delete that waited on a row an uncommitted supersession
	// holds sees that row once the supersession commits, but not the
	// successor the supersession inserted, which only the next statement's
	// snapshot holds.
	SessionDeleteFamily = `WITH doomed AS MATERIALIZED (
  SELECT id FROM sessions WHERE family_id = $1 ORDER BY id FOR UPDATE
)
DELETE FROM sessions WHERE id IN (SELECT id FROM doomed)`

	// SessionDelete removes the session with digest $1.
	SessionDelete = `DELETE FROM sessions WHERE id_digest = $1`

	// SessionDeleteByUser removes every session of user $1, expired or not.
	SessionDeleteByUser = `DELETE FROM sessions WHERE user_id = $1`

	// SessionDeleteByUserExcept removes every session of user $1 except the
	// one with digest $2, expired or not.
	SessionDeleteByUserExcept = `DELETE FROM sessions WHERE user_id = $1 AND id_digest <> $2`

	// SessionCountActive counts user $1's sessions unexpired at $2: both
	// deadlines strictly after it, and not superseded.
	SessionCountActive = `SELECT count(*) FROM sessions
WHERE user_id = $1 AND idle_expires_at > $2 AND absolute_expires_at > $2
  AND superseded_at IS NULL`

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

// The values SessionSupersedeRefusal reads: the session is not stored, was
// refused for its successor or its supersession, or is stored in no family.
const (
	SupersedeRefusalMissing  = 0
	SupersedeRefusalOther    = 1
	SupersedeRefusalNoFamily = 2
)
