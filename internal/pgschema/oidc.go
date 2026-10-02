package pgschema

// OIDC link, flow and handoff statements. A link insert never overwrites, a
// flow completion checks every binding and its expiry in the write that
// completes it, and a handoff consumption is one conditional update.
const (
	// LinkInsert stores a link: $1 id, $2 provider, $3 issuer, $4 subject,
	// $5 user_id, $6 username, $7 email, $8 created_at. Zero rows affected
	// means the external identity is already linked, and the stored link is
	// left as it was.
	LinkInsert = `INSERT INTO oidc_links (id, provider, issuer, subject, user_id, username, email, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (provider, issuer, subject) DO NOTHING`

	// LinkSelect reads the link of provider $1, issuer $2 and subject $3.
	LinkSelect = `SELECT id, user_id, username, email, created_at FROM oidc_links
WHERE provider = $1 AND issuer = $2 AND subject = $3`

	// LinkDeleteByUser removes every link of user $1; an empty reference
	// matches nothing.
	LinkDeleteByUser = `DELETE FROM oidc_links WHERE user_id = $1 AND $1 <> ''`

	// FlowInsert stores a flow: $1 id, $2 handle, $3 provider, $4 state,
	// $5 nonce, $6 verifier, $7 next, $8 expires_at.
	FlowInsert = `INSERT INTO oidc_flows (id, handle, provider, state, nonce, verifier, next, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	// FlowComplete completes flow $1 at $4 only where it was begun for
	// provider $2 with the non-empty state $3, is not completed and has not
	// expired by $4, and returns it. Zero rows means any of those failed, and
	// the flow is left as it was.
	FlowComplete = `UPDATE oidc_flows SET completed_at = $4
WHERE handle = $1 AND provider = $2 AND state = $3 AND $3 <> '' AND completed_at IS NULL AND expires_at > $4
RETURNING provider, state, nonce, verifier, next, expires_at`

	// FlowDeleteExpired removes every flow that expired strictly before $1.
	FlowDeleteExpired = `DELETE FROM oidc_flows WHERE expires_at < $1`

	// HandoffInsert stores a handoff record: $1 id, $2 token_id,
	// $3 secret_hash, $4 user_id, $5 provider, $6 issuer, $7 session_id,
	// $8 id_token, $9 next, $10 expires_at, $11 created_at, $12 consumed_at
	// (NULL while unconsumed), $13 amr (a JSON array of strings, '[]' for
	// none), $14 acr ('' for none).
	HandoffInsert = `INSERT INTO oidc_handoffs (id, token_id, secret_hash, user_id, provider, issuer, session_id,
  id_token, next, expires_at, created_at, consumed_at, amr, acr)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	// HandoffSelect reads the record of token id $1; an empty token id
	// matches nothing.
	HandoffSelect = `SELECT id, secret_hash, user_id, provider, issuer, session_id, id_token, next,
  expires_at, created_at, consumed_at, amr, acr
FROM oidc_handoffs WHERE token_id = $1 AND $1 <> ''`

	// HandoffConsume marks the record of token id $1 consumed at $2 only
	// while it is unconsumed; an empty token id matches nothing.
	HandoffConsume = `UPDATE oidc_handoffs SET consumed_at = $2
WHERE token_id = $1 AND $1 <> '' AND consumed_at IS NULL`

	// HandoffDeleteExpired removes every record that expired strictly
	// before $1.
	HandoffDeleteExpired = `DELETE FROM oidc_handoffs WHERE expires_at < $1`
)
