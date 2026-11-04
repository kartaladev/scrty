package pgschema

import "regexp"

// The provider's statements. Every write that decides something decides it in one
// statement, or, where a grant store must record revocations and write grants together,
// in the two steps GrantBulkWrite states, as one unit. A statement's arguments come from
// the matching function in oidcprovider_records.go, so the adapters bind the same values,
// and each adapter scans a row through the same Dest and Record.
const (
	// PendingRequestInsert stores a parked request, with the arguments
	// PendingRequestArgs returns. No row affected means its identifier or handle
	// digest is already held, and the stored record is left as it was.
	PendingRequestInsert = `INSERT INTO op_pending_requests (` + pendingRequestColumns + `)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
ON CONFLICT DO NOTHING`

	// PendingRequestSelect reads the record of handle digest $1.
	PendingRequestSelect = `SELECT ` + pendingRequestColumns + ` FROM op_pending_requests WHERE handle_digest = $1`

	// PendingRequestAdvance moves the record of handle digest $1 from stage $2 to
	// stage $3, storing sign-in $4 when it is not NULL. No row affected means no such
	// record at that stage. StageMoveAllowed judges the move before this runs.
	PendingRequestAdvance = `UPDATE op_pending_requests SET stage = $3, sign_in = COALESCE($4::jsonb, sign_in)
WHERE handle_digest = $1 AND stage = $2`

	// PendingRequestDeleteExpired removes the records that expired strictly before $1.
	PendingRequestDeleteExpired = `DELETE FROM op_pending_requests WHERE expires_at < $1`

	// CodeInsert stores a code record, with the arguments CodeArgs returns. No row
	// affected means its token identifier is already held.
	CodeInsert = `INSERT INTO op_authorization_codes (` + codeColumns + `)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
ON CONFLICT DO NOTHING`

	// CodeSelect reads the record of token identifier $1.
	CodeSelect = `SELECT ` + codeColumns + ` FROM op_authorization_codes WHERE token_id = $1`

	// CodeDeleteExpired removes the records that expired strictly before $1.
	CodeDeleteExpired = `DELETE FROM op_authorization_codes WHERE expires_at < $1`

	// CodeUnspentByClient lists the grant family of each record of user $1 and client $2.
	CodeUnspentByClient = `SELECT grant_family FROM op_authorization_codes WHERE user_ref = $1 AND client_id = $2`

	// ConsentGive adds scopes $4, which must hold no duplicate, to what user $2 has
	// allowed client $3, keeping their order. It is one statement, so concurrent gifts
	// accumulate. offline $5 can only turn on. $1 is the uuid of a row this creates.
	ConsentGive = `INSERT INTO op_consents (id, user_ref, client_id, scopes, offline, last_given_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (user_ref, client_id) DO UPDATE SET
  scopes = op_consents.scopes || COALESCE((
    SELECT jsonb_agg(given.scope ORDER BY given.position)
    FROM jsonb_array_elements(EXCLUDED.scopes) WITH ORDINALITY AS given(scope, position)
    WHERE NOT op_consents.scopes @> jsonb_build_array(given.scope)), '[]'::jsonb),
  offline = op_consents.offline OR EXCLUDED.offline,
  last_given_at = EXCLUDED.last_given_at`

	// ConsentSelect reads the consent of user $1 and client $2.
	ConsentSelect = `SELECT ` + consentColumns + ` FROM op_consents WHERE user_ref = $1 AND client_id = $2`

	// ConsentListByUser lists user $1's consents, by client.
	ConsentListByUser = `SELECT ` + consentColumns + ` FROM op_consents WHERE user_ref = $1 ORDER BY client_id`

	// ConsentDelete forgets the consent of user $1 and client $2.
	ConsentDelete = `DELETE FROM op_consents WHERE user_ref = $1 AND client_id = $2`

	// GrantInsert stores a grant, with the arguments GrantArgs returns. Over a
	// revocation recorded first, which alone has a NULL created_at, it fills in the
	// record, keeping the revocation and any sign-in-ended mark. Over a stored grant it
	// affects no row, and that is the refusal.
	GrantInsert = `INSERT INTO op_grants (` + grantColumns + `)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
ON CONFLICT (family) DO UPDATE SET
  user_ref = EXCLUDED.user_ref, client_id = EXCLUDED.client_id, scopes = EXCLUDED.scopes,
  resources = EXCLUDED.resources, auth_time = EXCLUDED.auth_time, amr = EXCLUDED.amr, acr = EXCLUDED.acr,
  key_binding = EXCLUDED.key_binding, code_id = EXCLUDED.code_id, sign_in_family = EXCLUDED.sign_in_family,
  external_issuer = EXCLUDED.external_issuer, external_session_id = EXCLUDED.external_session_id,
  offline = EXCLUDED.offline, ends_with_sign_in = EXCLUDED.ends_with_sign_in,
  holds_lineage = EXCLUDED.holds_lineage, created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at
WHERE op_grants.created_at IS NULL`

	// GrantSelect reads the record of family $1.
	GrantSelect = `SELECT ` + grantColumns + ` FROM op_grants WHERE family = $1`

	// GrantRevoke revokes family $1 at $2 with cause $3, recording the revocation first
	// when no record exists. A second revocation affects no row, and changes nothing.
	GrantRevoke = `INSERT INTO op_grants (family, revoked, revoked_at, revoke_cause) VALUES ($1, true, $2, $3)
ON CONFLICT (family) DO UPDATE SET
  revoked = true, revoked_at = EXCLUDED.revoked_at, revoke_cause = EXCLUDED.revoke_cause
WHERE NOT op_grants.revoked`

	// GrantDeleteExpired removes each unrevoked grant whose deadline is strictly before
	// $1, and each revoked one, recorded first or not, revoked strictly before $2. The
	// caller computes $2 as $1 less the retention. A revoked grant stored with no
	// revocation time has nothing to keep it, as the in-memory store has it. It locks its
	// rows in family order, the one order GrantBulkWrite states, and a plain DELETE would
	// take them in the order it scans them.
	GrantDeleteExpired = `WITH chosen AS (
  SELECT family AS chosen_family FROM op_grants
  WHERE (NOT revoked AND expires_at < $1) OR (revoked AND (revoked_at IS NULL OR revoked_at < $2))
  ORDER BY family FOR UPDATE)
DELETE FROM op_grants USING chosen WHERE family = chosen_family`

	// GrantOrphanCandidates lists up to $3 families created strictly before $1, holding
	// a lineage and unrevoked, after family $2 and in family order. A revocation
	// recorded first has a NULL created_at, so the comparison leaves it out.
	GrantOrphanCandidates = `SELECT family FROM op_grants
WHERE created_at < $1 AND holds_lineage AND NOT revoked AND family > $2 ORDER BY family LIMIT $3`

	// GrantOrphanDelete removes family $1 if it is still a candidate at cutoff $2, as a
	// revocation may have arrived while its lineage was being checked.
	GrantOrphanDelete = `DELETE FROM op_grants
WHERE family = $1 AND created_at < $2 AND holds_lineage AND NOT revoked`

	// AccessTokenInsert stores a token, with the arguments AccessTokenArgs returns. No
	// row affected means its identifier is already held.
	AccessTokenInsert = `INSERT INTO op_access_tokens (` + accessTokenColumns + `)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT DO NOTHING`

	// AccessTokenSelect reads token $1.
	AccessTokenSelect = `SELECT ` + accessTokenColumns + ` FROM op_access_tokens WHERE id = $1`

	// AccessTokenRevoke marks token $1 revoked. No row affected means it is not held.
	AccessTokenRevoke = `UPDATE op_access_tokens SET revoked = true WHERE id = $1`

	// AccessTokenDeleteExpired removes the tokens that expired strictly before $1.
	AccessTokenDeleteExpired = `DELETE FROM op_access_tokens WHERE expires_at < $1` //nolint:gosec // a statement, and no credential

	// AssertionIDRecord notes identifier $3 of client $2 until $4, with $1 the row's
	// uuid. One row affected means the pair is new, and none that it was held, whose
	// first until is left as it was.
	AssertionIDRecord = `INSERT INTO op_client_assertions (id, client_id, jti, held_until) VALUES ($1, $2, $3, $4)
ON CONFLICT (client_id, jti) DO NOTHING`

	// AssertionIDDeleteExpired removes the pairs held strictly before $1.
	AssertionIDDeleteExpired = `DELETE FROM op_client_assertions WHERE held_until < $1`

	// BrowserSessionInsert stores a session, with the arguments BrowserSessionArgs
	// returns. No row affected means its digest is already held.
	BrowserSessionInsert = `INSERT INTO op_browser_sessions (id, ` + browserSessionColumns + `)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (digest) DO NOTHING`

	// BrowserSessionSelect reads the session of digest $1 while $2 is before both of
	// its deadlines.
	BrowserSessionSelect = `SELECT ` + browserSessionColumns + ` FROM op_browser_sessions
WHERE digest = $1 AND $2 < idle_expires_at AND $2 < absolute_expires_at`

	// BrowserSessionTouch moves the idle deadline of digest $1 to $2, or to the absolute
	// deadline if that is sooner, and only ever later: one statement, so a slower touch
	// cannot shorten what a later one wrote. No row affected means it is not held.
	BrowserSessionTouch = `UPDATE op_browser_sessions
SET idle_expires_at = GREATEST(idle_expires_at, LEAST($2, absolute_expires_at))
WHERE digest = $1`

	// BrowserSessionDelete removes the session of digest $1.
	BrowserSessionDelete = `DELETE FROM op_browser_sessions WHERE digest = $1`

	// BrowserSessionDeleteExpired removes the sessions with either deadline strictly
	// before $1.
	BrowserSessionDeleteExpired = `DELETE FROM op_browser_sessions WHERE idle_expires_at < $1 OR absolute_expires_at < $1`

	// ClientUpsert adds or replaces a client, with the arguments ClientArgs returns. It
	// keeps the secrets held when $33 is true, in the one statement, so a settings change
	// cannot overwrite a secret generated beside it. $1, the row's uuid, stays as it was
	// on a replacement.
	ClientUpsert = `INSERT INTO op_clients (id, ` + clientColumns + `)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21,
  $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32)
ON CONFLICT (client_id) DO UPDATE SET
  name = EXCLUDED.name, client_type = EXCLUDED.client_type, application_type = EXCLUDED.application_type,
  auth_method = EXCLUDED.auth_method, pkce = EXCLUDED.pkce, jwks = EXCLUDED.jwks, jwks_uri = EXCLUDED.jwks_uri,
  redirect_uris = EXCLUDED.redirect_uris, post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
  back_channel_logout_uri = EXCLUDED.back_channel_logout_uri, scopes = EXCLUDED.scopes,
  resources = EXCLUDED.resources, default_audience = EXCLUDED.default_audience,
  resource_identifier = EXCLUDED.resource_identifier, grant_types = EXCLUDED.grant_types,
  first_party = EXCLUDED.first_party, offline_access = EXCLUDED.offline_access,
  id_token_alg = EXCLUDED.id_token_alg, id_token_lifetime_ns = EXCLUDED.id_token_lifetime_ns,
  access_token_lifetime_ns = EXCLUDED.access_token_lifetime_ns,
  opaque_access_tokens = EXCLUDED.opaque_access_tokens, require_binding = EXCLUDED.require_binding,
  refresh_grace_ns = EXCLUDED.refresh_grace_ns, grant_idle_timeout_ns = EXCLUDED.grant_idle_timeout_ns,
  grant_absolute_lifetime_ns = EXCLUDED.grant_absolute_lifetime_ns,
  disable_rotation = EXCLUDED.disable_rotation, end_grants_with_sign_in = EXCLUDED.end_grants_with_sign_in,
  keep_public_web_grants_past_sign_in = EXCLUDED.keep_public_web_grants_past_sign_in,
  metadata = EXCLUDED.metadata,
  secrets = CASE WHEN $33::boolean THEN op_clients.secrets ELSE EXCLUDED.secrets END`

	// ClientSelect reads client $1.
	ClientSelect = `SELECT ` + clientColumns + ` FROM op_clients WHERE client_id = $1`

	// ClientDelete removes client $1. No row affected means it is not held.
	ClientDelete = `DELETE FROM op_clients WHERE client_id = $1`

	// ClientSetSecrets replaces client $1's secrets with $3, only while it still has the
	// authentication method $2 they were generated for. No row affected means the client
	// is gone, or has moved to another method.
	ClientSetSecrets = `UPDATE op_clients SET secrets = $3 WHERE client_id = $1 AND auth_method = $2`
)

// The columns of each table, in the order its Args function binds and its Row scans.
const (
	pendingRequestColumns = `id, handle_digest, flow_digest, client_id, redirect_uri, scopes, resources, state, nonce,
  challenge, prompt, max_age, id_token_hint_subject, dpop_jkt, login_hint, ui_locales, claims_locales, acr_values,
  parked_at, expires_at, stage, sign_in`

	codeColumns = `token_id, client_id, redirect_uri, challenge, nonce, dpop_jkt, scopes, resources, user_ref,
  sign_in_family, authenticated_at, amr, acr, sign_in_absolute_expires_at, external_issuer, external_session_id,
  grant_family, offline, ends_with_sign_in, expires_at`

	consentColumns = `user_ref, client_id, scopes, offline, last_given_at`

	grantColumns = `family, user_ref, client_id, scopes, resources, auth_time, amr, acr, key_binding, code_id,
  sign_in_family, external_issuer, external_session_id, offline, ends_with_sign_in, holds_lineage, created_at,
  expires_at, revoked, revoked_at, revoke_cause, sign_in_ended_at`

	//nolint:gosec // a column list, and no credential
	accessTokenColumns = `id, digest, grant_family, client_id, user_ref, scopes, audience, confirmation, issued_at,
  expires_at, revoked`

	browserSessionColumns = `digest, user_ref, sign_in_family, authenticated_at, amr, acr, sign_in_absolute_expires_at,
  external_issuer, external_session_id, idle_expires_at, absolute_expires_at`

	clientColumns = `client_id, name, client_type, application_type, auth_method, pkce, jwks, jwks_uri, redirect_uris,
  post_logout_redirect_uris, back_channel_logout_uri, scopes, resources, default_audience, resource_identifier,
  grant_types, first_party, offline_access, id_token_alg, id_token_lifetime_ns, access_token_lifetime_ns,
  opaque_access_tokens, require_binding, refresh_grace_ns, grant_idle_timeout_ns, grant_absolute_lifetime_ns,
  disable_rotation, end_grants_with_sign_in, keep_public_web_grants_past_sign_in, metadata, secrets`
)

// heldFamilies is the set $1 of a statement writing the grants a hold returned.
const heldFamilies = `SELECT held.family::uuid FROM jsonb_array_elements_text($1::jsonb) AS held(family)`

// GrantOrphanPage is how many candidates the orphan pass lists at a time. The pass asks
// another store about each one, holding nothing, so it never needs them all at once.
const GrantOrphanPage = 500

// sessionsTable finds the sessions table's name in a session statement. No column of
// that table, and no alias in its statements, holds the word.
var sessionsTable = regexp.MustCompile(`\bsessions\b`)

// LineageStatement is a session statement run over the refresh-token lineage table,
// which has the sessions table's columns and indexes. It is how an adapter binds a
// session store to that table, and the table is fixed here, so a consumer can choose
// none other (T7).
func LineageStatement(sessionStatement string) string {
	return sessionsTable.ReplaceAllLiteralString(sessionStatement, RefreshTokenTable)
}
