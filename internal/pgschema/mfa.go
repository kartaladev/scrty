package pgschema

// MFA enrolment statements. Every refusal is a single conditional write: a
// begin over a confirmed enrolment, a second confirmation, a step at or below
// the recorded one, a device proof, completion or charge whose conditions do
// not hold, and a TOTP verification charge or give-back that may not land each
// affect no row. The secret and email_code columns hold the
// sealed values, base64url-encoded. A generation is bound as NULL when it is
// the nil identifier, so "generation = $n" never matches an enrolment stored
// without one.
const (
	// EnrolmentPutPending stores a pending enrolment: $1 id, $2 user_id,
	// $3 secret, $4 created_at, $5 generation (NULL for none). It replaces
	// the user's enrolment, keeping its id, only while that enrolment is
	// pending, starting a new generation: it clears the accepted step, the
	// device proof, the emailed code with its expiry and attempts, and the
	// TOTP verification attempts with their window. Zero rows affected means
	// the user's enrolment is confirmed.
	EnrolmentPutPending = `INSERT INTO mfa_enrolments (id, user_id, secret, confirmed_at, last_step, created_at, generation)
VALUES ($1, $2, $3, NULL, 0, $4, $5)
ON CONFLICT (user_id) DO UPDATE
   SET secret = EXCLUDED.secret, last_step = 0, created_at = EXCLUDED.created_at,
       generation = EXCLUDED.generation, device_proven_at = NULL,
       email_code = NULL, email_code_until = NULL, email_code_attempts = 0,
       verify_attempts = 0, verify_window_until = NULL
 WHERE mfa_enrolments.confirmed_at IS NULL`

	// EnrolmentGet reads user $1's enrolment. verify_attempts and
	// verify_window_until are its last two columns, in that order.
	EnrolmentGet = `SELECT secret, confirmed_at, last_step, created_at, generation, device_proven_at,
  email_code, email_code_until, email_code_attempts, verify_attempts, verify_window_until
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

	// EnrolmentChargeVerifyAttempt charges one TOTP verification attempt
	// against user $1's confirmed enrolment at $2. When the window has ended
	// (none open, or its end at or before $2) it opens one ending at $3,
	// counting one; otherwise it counts one more while fewer than $4 are
	// charged. $3 is the caller's $2 plus the window, truncated to the
	// microsecond, so the database's clock is never used. It returns the
	// window's end. No row returned means no charge. Under read committed,
	// concurrent charges of one row serialise on its row lock and re-check
	// the WHERE clause against the committed row, so at most $4 succeed per
	// window.
	EnrolmentChargeVerifyAttempt = `UPDATE mfa_enrolments SET
  verify_attempts     = CASE WHEN verify_window_until IS NULL OR verify_window_until <= $2
                             THEN 1 ELSE verify_attempts + 1 END,
  verify_window_until = CASE WHEN verify_window_until IS NULL OR verify_window_until <= $2
                             THEN $3 ELSE verify_window_until END
 WHERE user_id = $1 AND confirmed_at IS NOT NULL
   AND (verify_window_until IS NULL OR verify_window_until <= $2 OR verify_attempts < $4)
RETURNING verify_window_until`

	// EnrolmentRefundVerifyAttempt gives back one attempt charged against
	// user $1's enrolment in the window ending at $2. Zero rows affected
	// means the window was replaced or nothing is charged.
	EnrolmentRefundVerifyAttempt = `UPDATE mfa_enrolments SET verify_attempts = verify_attempts - 1
 WHERE user_id = $1 AND verify_window_until = $2 AND verify_attempts > 0`

	// EnrolmentDelete removes user $1's enrolment.
	EnrolmentDelete = `DELETE FROM mfa_enrolments WHERE user_id = $1`

	// EnrolmentReseal replaces user $1's secret with $3 only while it still
	// equals $2.
	EnrolmentReseal = `UPDATE mfa_enrolments SET secret = $3 WHERE user_id = $1 AND secret = $2`
)
