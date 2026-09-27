package pgschema

// MFA enrolment statements. Every refusal is a single conditional write: a
// begin over a confirmed enrolment, a second confirmation and a step at or
// below the recorded one each affect no row. The secret column holds the
// sealed value, base64url-encoded.
const (
	// EnrolmentPutPending stores a pending enrolment: $1 id, $2 user_id,
	// $3 secret, $4 created_at. It replaces the user's enrolment, keeping its
	// id, only while that enrolment is pending, and clears its accepted step.
	// Zero rows affected means the user's enrolment is confirmed.
	EnrolmentPutPending = `INSERT INTO mfa_enrolments (id, user_id, secret, confirmed_at, last_step, created_at)
VALUES ($1, $2, $3, NULL, 0, $4)
ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, created_at = EXCLUDED.created_at, last_step = 0
WHERE mfa_enrolments.confirmed_at IS NULL`

	// EnrolmentGet reads user $1's enrolment.
	EnrolmentGet = `SELECT secret, confirmed_at, last_step, created_at FROM mfa_enrolments WHERE user_id = $1`

	// EnrolmentConfirm confirms user $1's enrolment at $3 and records step $2,
	// never moving the recorded step backwards, only while it is pending.
	EnrolmentConfirm = `UPDATE mfa_enrolments SET confirmed_at = $3, last_step = GREATEST(last_step, $2)
WHERE user_id = $1 AND confirmed_at IS NULL`

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
