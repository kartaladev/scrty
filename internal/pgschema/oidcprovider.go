package pgschema

// The tables of the OpenID Provider, which the security-state migration set creates.
// A credential is held only as a digest, in a column named for one.
const (
	// ClientTable holds the registered clients. A client's identifier is client_id,
	// consumer-chosen text, beside the row's own uuid.
	ClientTable = "scrty_op_clients"

	// PendingRequestTable holds the requests parked while a user signs in or answers
	// a page.
	PendingRequestTable = "scrty_op_pending_requests"

	// BrowserSessionTable holds the browser sessions.
	BrowserSessionTable = "scrty_op_browser_sessions"

	// CodeTable holds the request data of authorization codes. A code's secret and
	// its single spend live in token/onetime, so a row here says nothing about whether
	// its code was spent: every row is a held code.
	CodeTable = "scrty_op_authorization_codes"

	// ConsentTable holds one consent per user and client.
	ConsentTable = "scrty_op_consents"

	// GrantTable holds the grants, and the revocations recorded before their grant
	// was stored. A row with a NULL created_at is such a revocation: an exchange fills
	// it in once, and always writes created_at when it does.
	GrantTable = "scrty_op_grants"

	// RefreshTokenTable is the fixed table of refresh-token lineages. It has the
	// scrty_sessions table's columns and indexes, so a session store's statements run over it
	// unchanged but for the table's name, and it is never the table a sign-in is read
	// from.
	//nolint:gosec // G101: a table name, not a credential
	RefreshTokenTable = "scrty_op_refresh_tokens"

	// AccessTokenTable holds the opaque access tokens.
	//nolint:gosec // G101: a table name, not a credential
	AccessTokenTable = "scrty_op_access_tokens"

	// AssertionIDTable holds the client-assertion identifiers already accepted.
	AssertionIDTable = "scrty_op_client_assertions"

	// DeviceAuthorizationTable holds the device authorizations (RFC 8628), which the
	// device grant's migration adds.
	DeviceAuthorizationTable = "scrty_op_device_authorizations"
)

// OIDCProviderTables returns the tables the provider's migrations create.
func OIDCProviderTables() []string {
	return []string{
		ClientTable, PendingRequestTable, BrowserSessionTable, CodeTable, ConsentTable,
		GrantTable, RefreshTokenTable, AccessTokenTable, AssertionIDTable, DeviceAuthorizationTable,
	}
}
