package pgschema

// MFA enrolment statements. Every refusal is a single conditional write: a
// begin over a confirmed enrolment, a second confirmation, a step at or below
// the recorded one, and a device proof, completion or charge whose conditions
// do not hold each affect no row. The secret and email_code columns hold the
// sealed values, base64url-encoded. A generation is bound as NULL when it is
// the nil identifier, so "generation = $n" never matches an enrolment stored
// without one.
const (
	// EnrolmentPutPending stores a pending enrolment: $1 id, $2 user_id,
	// $3 secret, $4 created_at, $5 generation (NULL for none). It replaces
	// the user's enrolment, keeping its id, only while that enrolment is
	// pending, starting a new generation: it clears the accepted step, the
	// device proof and the emailed code with its expiry and attempts. Zero
	// rows affected means the user's enrolment is confirmed.
	EnrolmentPutPending = `INSERT INTO mfa_enrolments (id, user_id, secret, confirmed_at, last_step, created_at, generation)
VALUES ($1, $2, $3, NULL, 0, $4, $5)
ON CONFLICT (user_id) DO UPDATE
   SET secret = EXCLUDED.secret, last_step = 0, created_at = EXCLUDED.created_at,
       generation = EXCLUDED.generation, device_proven_at = NULL,
       email_code = NULL, email_code_until = NULL, email_code_attempts = 0
 WHERE mfa_enrolments.confirmed_at IS NULL`

	// EnrolmentGet reads user $1's enrolment.
	EnrolmentGet = `SELECT secret, confirmed_at, last_step, created_at, generation, device_proven_at,
  email_code, email_code_until, email_code_attempts
FROM mfa_enrolments WHERE user_id = $1`

	// EnrolmentConfirm confirms user $1's enrolment at $3 and records step $2,
	// never moving the recorded step backwards, only while it is pending. It
	// clears the emailed code and keeps its expiry.
	EnrolmentConfirm = `UPDATE mfa_enrolments SET confirmed_at = $3, last_step = GREATEST(last_step, $2), email_code = NULL
WHERE user_id = $1 AND confirmed_at IS NULL`

	// EnrolmentProveDevice records the device proof of user $1's enrolment
	// on generation $2: step $3 as the last accepted step, emailed code $4
	// (NULL for none) good until $5, proven at $6, with no attempt charged.
	// It writes only where the enrolment is pending on $2, not yet proven,
	// and $3 is later than its recorded step. A NULL $2 matches no row.
	EnrolmentProveDevice = `UPDATE mfa_enrolments
   SET last_step = $3, device_proven_at = $6, email_code = $4, email_code_until = $5, email_code_attempts = 0
 WHERE user_id = $1 AND generation = $2 AND confirmed_at IS NULL
   AND device_proven_at IS NULL AND last_step < $3`

	// EnrolmentComplete confirms user $1's enrolment at $3 and clears its
	// emailed code, keeping the code's expiry, only where it is on
	// generation $2, proven and not yet confirmed. A NULL $2 matches no row.
	EnrolmentComplete = `UPDATE mfa_enrolments SET confirmed_at = $3, email_code = NULL
 WHERE user_id = $1 AND generation = $2 AND device_proven_at IS NOT NULL AND confirmed_at IS NULL`

	// EnrolmentChargeEmailCode charges one attempt against the emailed code
	// of user $1's enrolment on generation $2 at $3, and returns the count
	// after the write. It charges only where the enrolment is pending on $2,
	// proven, holds a code not expired at $3, and has fewer than $4 attempts
	// charged. No row returned means no charge. A NULL $2 matches no row.
	EnrolmentChargeEmailCode = `UPDATE mfa_enrolments SET email_code_attempts = email_code_attempts + 1
 WHERE user_id = $1 AND generation = $2 AND confirmed_at IS NULL
   AND device_proven_at IS NOT NULL AND email_code IS NOT NULL
   AND email_code_until > $3 AND email_code_attempts < $4
RETURNING email_code_attempts`

	// EnrolmentAcceptStep records step $2 for user $1 only where the
	// enrolment is confirmed and its recorded step is strictly lower.
	EnrolmentAcceptStep = `UPDATE mfa_enrolments SET last_step = $2
WHERE user_id = $1 AND confirmed_at IS NOT NULL AND last_step < $2`

	// EnrolmentDelete removes user $1's enrolment.
	EnrolmentDelete = `DELETE FROM mfa_enrolments WHERE user_id = $1`

	// EnrolmentReseal replaces user $1's secret with $3 only while it still
	// equals $2.
	EnrolmentReseal = `UPDATE mfa_enrolments SET secret = $3 WHERE user_id = $1 AND secret = $2`
)
