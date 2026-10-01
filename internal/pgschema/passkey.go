package pgschema

import (
	"errors"
	"strings"
)

// Passkey credential statements. Every state change is one conditional
// write: zero rows affected, or no row returned, is the refusal, and a
// refused write changes nothing. The state and pending columns hold
// passkey.State and passkey.PendingReason as their numbers. The email_code
// column holds the sealed code, base64url-encoded.
const (
	// passkeyCredentialColumns is every column of a credential, in the order
	// the inserts bind and the selects return them.
	passkeyCredentialColumns = `id, user_id, credential_id, public_key, sign_count, backup_eligible, backup_state,
  transports, aaguid, attestation_format, attestation_statement, name, created_at, last_used_at,
  state, pending, email_code, email_code_expires_at, email_code_attempts`

	// PasskeyCredentialInsert stores a credential, binding the columns in
	// passkeyCredentialColumns' order as $1 to $19. Zero rows affected means
	// its credential ID, or its library identifier, is already stored: the
	// unique index decides, so of concurrent inserts of one credential ID
	// exactly one stores it, and the refusal fails no statement, so it never
	// aborts a caller's transaction.
	PasskeyCredentialInsert = `INSERT INTO passkey_credentials (` + passkeyCredentialColumns + `)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
ON CONFLICT DO NOTHING`

	// PasskeyCredentialByCredentialID reads the credential whose WebAuthn
	// credential ID is $1.
	PasskeyCredentialByCredentialID = `SELECT ` + passkeyCredentialColumns + `
FROM passkey_credentials WHERE credential_id = $1`

	// PasskeyCredentialFind reads credential $1 of user $2.
	PasskeyCredentialFind = `SELECT ` + passkeyCredentialColumns + `
FROM passkey_credentials WHERE id = $1 AND user_id = $2`

	// PasskeyCredentialList reads every credential of user $1, oldest first,
	// ties in library identifier order.
	PasskeyCredentialList = `SELECT ` + passkeyCredentialColumns + `
FROM passkey_credentials WHERE user_id = $1 ORDER BY created_at, id`

	// PasskeyCredentialCount counts user $1's credentials in every state.
	PasskeyCredentialCount = `SELECT count(*) FROM passkey_credentials WHERE user_id = $1`

	// PasskeyRecordAssertion sets credential $1's counter to $2, its backup
	// state to $3 and its last use to $4, only while it is active (state 1)
	// and its stored counter is lower than $2, or both are zero.
	PasskeyRecordAssertion = `UPDATE passkey_credentials SET sign_count = $2, backup_state = $3, last_used_at = $4
WHERE id = $1 AND state = 1 AND (sign_count < $2 OR (sign_count = 0 AND $2 = 0))`

	// PasskeyRecordUse sets credential $1's backup state to $2 and its last
	// use to $3, leaving its counter, only while it is active (state 1).
	PasskeyRecordUse = `UPDATE passkey_credentials SET backup_state = $2, last_used_at = $3 WHERE id = $1 AND state = 1`

	// PasskeySuspend moves credential $1 from active (1) to suspended (3).
	PasskeySuspend = `UPDATE passkey_credentials SET state = 3 WHERE id = $1 AND state = 1`

	// PasskeyClearReason clears reason $3 of user $2's credential $1, only
	// while it is pending (state 2) with $3 set, and returns the state that
	// results: active (1) when no reason remains. Clearing the emailed-code
	// reason (2) drops the code and its expiry. $3 must be exactly one reason,
	// 1 or 2; the adapters refuse any other value before running it.
	PasskeyClearReason = `UPDATE passkey_credentials
   SET pending = pending & ~$3::smallint,
       state = CASE WHEN pending & ~$3::smallint = 0 THEN 1 ELSE state END,
       email_code = CASE WHEN $3::smallint = 2 THEN NULL ELSE email_code END,
       email_code_expires_at = CASE WHEN $3::smallint = 2 THEN NULL ELSE email_code_expires_at END
 WHERE id = $1 AND user_id = $2 AND state = 2 AND pending & $3::smallint <> 0
RETURNING state`

	// PasskeyChargeEmailAttempt charges one attempt against the emailed code
	// of user $2's credential $1 at $3, and returns the code, its expiry and
	// the attempts after the write. It charges only while the credential is
	// pending (state 2) on its emailed code (reason 2), the code is
	// outstanding and not expired at $3, and fewer than $4 attempts are
	// charged. No row returned is the refusal.
	PasskeyChargeEmailAttempt = `UPDATE passkey_credentials SET email_code_attempts = email_code_attempts + 1
 WHERE id = $1 AND user_id = $2 AND state = 2 AND pending & 2 <> 0
   AND email_code IS NOT NULL AND email_code_expires_at > $3 AND email_code_attempts < $4
RETURNING email_code, email_code_expires_at, email_code_attempts`

	// PasskeyRename sets the name of user $2's credential $1 to $3.
	PasskeyRename = `UPDATE passkey_credentials SET name = $3 WHERE id = $1 AND user_id = $2`

	// PasskeyDelete removes user $2's credential $1.
	PasskeyDelete = `DELETE FROM passkey_credentials WHERE id = $1 AND user_id = $2`

	// PasskeyDeleteAwaitingSavedCodes removes every credential of user $1
	// whose saved-codes reason (1) is set.
	PasskeyDeleteAwaitingSavedCodes = `DELETE FROM passkey_credentials WHERE user_id = $1 AND pending & 1 <> 0`

	// PasskeyDeleteUser removes every credential of user $1.
	PasskeyDeleteUser = `DELETE FROM passkey_credentials WHERE user_id = $1`
)

// Passkey user-handle statements. An assignment is PasskeyHandleInsert, then
// PasskeyHandleOfUser: the insert stores the offer only when neither the user
// nor the handle is held, without failing a statement, and the select reads
// what the user holds afterwards, whichever insert stored it. No row from the
// select means the offered handle is another user's. Rows are never updated
// or deleted, so the two statements need no transaction between them.
const (
	// PasskeyHandleInsert stores handle $3 for user $2 under row id $1,
	// unless the user or the handle is already held.
	PasskeyHandleInsert = `INSERT INTO passkey_user_handles (id, user_id, handle) VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING`

	// PasskeyHandleOfUser reads the handle user $1 holds.
	PasskeyHandleOfUser = `SELECT handle FROM passkey_user_handles WHERE user_id = $1`

	// PasskeyHandleUser reads the user holding handle $1.
	PasskeyHandleUser = `SELECT user_id FROM passkey_user_handles WHERE handle = $1`
)

// The transports column holds a credential's transports one per line, in
// order, and the empty text for none. Every adapter writes and reads it
// through the two functions below, so a credential written by one reads back
// unchanged through another.

// ErrPasskeyTransportUnstorable is the refusal of a transport that would not
// read back as itself: an empty one, or one holding a newline. Its text
// carries no value.
var ErrPasskeyTransportUnstorable = errors.New("transports: a transport is empty or holds a newline")

// PasskeyTransportsText is transports as the transports column holds them.
func PasskeyTransportsText(transports []string) (string, error) {
	for _, tr := range transports {
		if tr == "" || strings.ContainsAny(tr, "\n\r") {
			return "", ErrPasskeyTransportUnstorable
		}
	}

	return strings.Join(transports, "\n"), nil
}

// ParsePasskeyTransports reads the transports column back: nil for the empty
// text.
func ParsePasskeyTransports(text string) []string {
	if text == "" {
		return nil
	}

	return strings.Split(text, "\n")
}
