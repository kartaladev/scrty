package test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"io/fs"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/gormstore"
	"github.com/kartaladev/scrty/store/migrate"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/store/seal"
	"github.com/kartaladev/scrty/store/sqlstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// provider builds a goose provider over db for the migration files in dir of
// fsys, recording applied versions in table. It mirrors exactly how
// WithTestPostgresMigrations builds one, so a test driving goose directly here
// exercises the same wiring a consumer would.
func provider(t *testing.T, db *sql.DB, fsys fs.FS, dir, table string) *goose.Provider {
	t.Helper()

	sub, err := fs.Sub(fsys, dir)
	require.NoError(t, err)

	p, err := goose.NewProvider(goose.DialectPostgres, db, sub, goose.WithTableName(table))
	require.NoError(t, err)

	return p
}

// migrated returns a database the security-state set has been applied to,
// with the leftover-table check turned on so this set's own test proves its
// rollback drops everything Up created.
func migrated(t *testing.T) *sql.DB {
	t.Helper()

	set := migrate.SecurityState()
	return RunTestPostgres(t,
		WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable),
		WithTestPostgresLeftoverTableCheck(),
	).DB
}

// queryStrings runs query against db and scans its single text column into a
// slice, in whatever order the query returned.
func queryStrings(t *testing.T, db *sql.DB, query string, args ...any) []string {
	t.Helper()

	rows, err := db.QueryContext(t.Context(), query, args...)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())

	return out
}

// providerTables lists the nine tables the provider's migration adds to the set.
var providerTables = []string{
	"op_clients", "op_pending_requests", "op_browser_sessions", "op_authorization_codes", "op_consents",
	"op_grants", "op_refresh_tokens", "op_access_tokens", "op_client_assertions",
}

// securityStateTables lists the twenty-four tables the security-state set creates.
var securityStateTables = append([]string{
	"sessions", "signing_keys", "login_attempts", "login_failure_streaks", "mfa_enrolments",
	"api_keys", "one_time_tokens", "oidc_links", "oidc_flows", "oidc_handoffs",
	"recovery_codes", "account_recoveries", "passkey_credentials", "passkey_user_handles",
	"rate_limit_buckets",
}, providerTables...)

// column is one column of the security-state set as the catalogue reports
// it: the type from format_type (which carries any precision modifier, so the
// default microsecond "timestamp with time zone" differs from
// "timestamp(0) with time zone"), whether NULL is allowed, and the default
// expression ("" for none).
type column struct {
	name     string
	typ      string
	nullable bool
	def      string
}

// String renders a column the way the catalogue query does, so a failing
// comparison names the table, the column and every pinned property.
func (c column) String() string {
	null := "NOT NULL"
	if c.nullable {
		null = "NULL"
	}
	return c.name + " " + c.typ + " " + null + " DEFAULT " + c.def
}

// Column types as format_type reports them.
const (
	colUUID        = "uuid"
	colText        = "text"
	colBytea       = "bytea"
	colJSONB       = "jsonb"
	colBigint      = "bigint"
	colInteger     = "integer"
	colSmallint    = "smallint"
	colBoolean     = "boolean"
	colTimestamptz = "timestamp with time zone" // microsecond precision: no modifier

	colTimestamptzArray = "timestamp with time zone[]"
)

// Default expressions as pg_get_expr reports them.
const (
	defEmptyText   = "''::text"
	defEmptyObject = "'{}'::jsonb"
	defEmptyArray  = "'[]'::jsonb"
)

// required is a NOT NULL column with no default.
func required(name, typ string) column { return column{name: name, typ: typ} }

// defaulted is a NOT NULL column with a default.
func defaulted(name, typ, def string) column { return column{name: name, typ: typ, def: def} }

// optional is a nullable column with no default: a nullable guard, or an
// absent value that must round-trip as absent.
func optional(name, typ string) column { return column{name: name, typ: typ, nullable: true} }

// sessionTableColumns pins the sessions table, and the refresh-token lineage table
// a session store runs over unchanged (T7).
var sessionTableColumns = []column{
	required("id", colUUID),
	required("id_digest", colBytea),
	required("user_id", colText),
	required("created_at", colTimestamptz),
	required("last_accessed_at", colTimestamptz),
	required("idle_expires_at", colTimestamptz),
	required("absolute_expires_at", colTimestamptz),
	defaulted("first_factor", colText, defEmptyText),
	defaulted("mfa_state", colSmallint, "0"),
	optional("mfa_satisfied_at", colTimestamptz),
	defaulted("password_change_pending", colBoolean, "false"),
	defaulted("external_provider", colText, defEmptyText),
	defaulted("external_issuer", colText, defEmptyText),
	defaulted("external_session_id", colText, defEmptyText),
	defaulted("external_id_token", colText, defEmptyText),
	defaulted("data", colJSONB, defEmptyObject),
	optional("enrolment_origin_deadline", colTimestamptz),
	optional("enrolment_generation", colUUID),
	optional("recovered_at", colTimestamptz),
	defaulted("mfa_at_first_factor", colBoolean, "false"),
	defaulted("federated_amr", colJSONB, defEmptyArray),
	defaulted("federated_acr", colText, defEmptyText),
	defaulted("family_id", colUUID, "gen_random_uuid()"),
	defaulted("family_created_at", colTimestamptz, "now()"),
	optional("superseded_at", colTimestamptz),
	optional("accept_until", colTimestamptz),
	optional("successor_digest", colBytea),
	optional("first_presented_at", colTimestamptz),
	optional("retain_until", colTimestamptz),
	defaulted("authenticated_at", colTimestamptz, "now()"),
	defaulted("rotated_strictly", colBoolean, "false"),
	optional("client_ip", colText),
	optional("user_agent", colText),
	optional("binding_kind", colText),
	optional("binding_thumbprint", colText),
	optional("csrf_token", colText),
}

// securityStateColumns pins each table's exact columns, with their types,
// nullability and defaults, against design.md's table model (decision 2) and
// the column encodings of decision 9 (bytea for the signing key envelope and
// the digests, base64url text for the MFA secret and the session ID token).
// It also pins the enrolment-path columns mfa-enrolment-path adds:
// sessions.enrolment_origin_deadline and sessions.enrolment_generation, and
// mfa_enrolments.generation, device_proven_at, email_code, email_code_until
// and email_code_attempts. sessions.mfa_state stays a smallint: the row below
// pins its type unchanged even though it gains a new ordinal value. It also
// pins the account-recovery columns: sessions.recovered_at, and the two new
// tables recovery_codes and account_recoveries. It also pins the TOTP
// verification charge: mfa_enrolments.verify_attempts and
// verify_window_until.
var securityStateColumns = map[string][]column{
	"op_clients": {
		required("id", colUUID),
		required("client_id", colText),
		defaulted("name", colText, defEmptyText),
		required("client_type", colSmallint),
		defaulted("application_type", colSmallint, "0"),
		required("auth_method", colText),
		defaulted("pkce", colSmallint, "0"),
		optional("jwks", colBytea),
		defaulted("jwks_uri", colText, defEmptyText),
		defaulted("redirect_uris", colJSONB, defEmptyArray),
		defaulted("post_logout_redirect_uris", colJSONB, defEmptyArray),
		defaulted("back_channel_logout_uri", colText, defEmptyText),
		defaulted("scopes", colJSONB, defEmptyArray),
		defaulted("resources", colJSONB, defEmptyArray),
		defaulted("default_audience", colJSONB, defEmptyArray),
		defaulted("resource_identifier", colText, defEmptyText),
		defaulted("grant_types", colJSONB, defEmptyArray),
		defaulted("first_party", colBoolean, "false"),
		defaulted("offline_access", colSmallint, "0"),
		defaulted("id_token_alg", colText, defEmptyText),
		defaulted("id_token_lifetime_ns", colBigint, "0"),
		defaulted("access_token_lifetime_ns", colBigint, "0"),
		defaulted("opaque_access_tokens", colBoolean, "false"),
		defaulted("require_binding", colSmallint, "0"),
		defaulted("refresh_grace_ns", colBigint, "0"),
		defaulted("grant_idle_timeout_ns", colBigint, "0"),
		defaulted("grant_absolute_lifetime_ns", colBigint, "0"),
		defaulted("disable_rotation", colBoolean, "false"),
		defaulted("end_grants_with_sign_in", colBoolean, "false"),
		defaulted("keep_public_web_grants_past_sign_in", colBoolean, "false"),
		defaulted("metadata", colJSONB, defEmptyObject),
		defaulted("secrets", colJSONB, defEmptyArray),
	},
	"op_pending_requests": {
		required("id", colUUID),
		required("handle_digest", colBytea),
		required("flow_digest", colBytea),
		required("client_id", colText),
		defaulted("redirect_uri", colText, defEmptyText),
		defaulted("scopes", colJSONB, defEmptyArray),
		defaulted("resources", colJSONB, defEmptyArray),
		defaulted("state", colText, defEmptyText),
		defaulted("nonce", colText, defEmptyText),
		defaulted("challenge", colText, defEmptyText),
		defaulted("prompt", colJSONB, defEmptyArray),
		optional("max_age", colBigint),
		defaulted("id_token_hint_subject", colText, defEmptyText),
		defaulted("dpop_jkt", colText, defEmptyText),
		defaulted("login_hint", colText, defEmptyText),
		defaulted("ui_locales", colJSONB, defEmptyArray),
		defaulted("claims_locales", colJSONB, defEmptyArray),
		defaulted("acr_values", colJSONB, defEmptyArray),
		required("parked_at", colTimestamptz),
		required("expires_at", colTimestamptz),
		required("stage", colSmallint),
		optional("sign_in", colJSONB),
	},
	"op_browser_sessions": {
		required("id", colUUID),
		required("digest", colBytea),
		required("user_ref", colText),
		required("sign_in_family", colUUID),
		required("authenticated_at", colTimestamptz),
		defaulted("amr", colJSONB, defEmptyArray),
		defaulted("acr", colText, defEmptyText),
		required("sign_in_absolute_expires_at", colTimestamptz),
		defaulted("external_issuer", colText, defEmptyText),
		defaulted("external_session_id", colText, defEmptyText),
		required("idle_expires_at", colTimestamptz),
		required("absolute_expires_at", colTimestamptz),
	},
	"op_authorization_codes": {
		required("token_id", colUUID),
		required("client_id", colText),
		defaulted("redirect_uri", colText, defEmptyText),
		defaulted("challenge", colText, defEmptyText),
		defaulted("nonce", colText, defEmptyText),
		defaulted("dpop_jkt", colText, defEmptyText),
		defaulted("scopes", colJSONB, defEmptyArray),
		defaulted("resources", colJSONB, defEmptyArray),
		required("user_ref", colText),
		required("sign_in_family", colUUID),
		required("authenticated_at", colTimestamptz),
		defaulted("amr", colJSONB, defEmptyArray),
		defaulted("acr", colText, defEmptyText),
		required("sign_in_absolute_expires_at", colTimestamptz),
		defaulted("external_issuer", colText, defEmptyText),
		defaulted("external_session_id", colText, defEmptyText),
		required("grant_family", colUUID),
		defaulted("offline", colBoolean, "false"),
		defaulted("ends_with_sign_in", colBoolean, "false"),
		required("expires_at", colTimestamptz),
	},
	"op_consents": {
		required("id", colUUID),
		required("user_ref", colText),
		required("client_id", colText),
		defaulted("scopes", colJSONB, defEmptyArray),
		defaulted("offline", colBoolean, "false"),
		required("last_given_at", colTimestamptz),
	},
	"op_grants": {
		required("family", colUUID),
		defaulted("user_ref", colText, defEmptyText),
		defaulted("client_id", colText, defEmptyText),
		defaulted("scopes", colJSONB, defEmptyArray),
		defaulted("resources", colJSONB, defEmptyArray),
		optional("auth_time", colTimestamptz),
		defaulted("amr", colJSONB, defEmptyArray),
		defaulted("acr", colText, defEmptyText),
		defaulted("key_binding", colText, defEmptyText),
		defaulted("cert_binding", colText, defEmptyText),
		optional("code_id", colUUID),
		optional("sign_in_family", colUUID),
		defaulted("external_issuer", colText, defEmptyText),
		defaulted("external_session_id", colText, defEmptyText),
		defaulted("offline", colBoolean, "false"),
		defaulted("ends_with_sign_in", colBoolean, "false"),
		defaulted("holds_lineage", colBoolean, "false"),
		optional("created_at", colTimestamptz),
		optional("expires_at", colTimestamptz),
		defaulted("revoked", colBoolean, "false"),
		optional("revoked_at", colTimestamptz),
		defaulted("revoke_cause", colText, defEmptyText),
		optional("sign_in_ended_at", colTimestamptz),
	},
	"op_access_tokens": {
		required("id", colUUID),
		required("digest", colBytea),
		required("grant_family", colUUID),
		required("client_id", colText),
		required("user_ref", colText),
		defaulted("scopes", colJSONB, defEmptyArray),
		defaulted("audience", colJSONB, defEmptyArray),
		defaulted("confirmation", colJSONB, defEmptyObject),
		required("issued_at", colTimestamptz),
		required("expires_at", colTimestamptz),
		defaulted("revoked", colBoolean, "false"),
	},
	"op_client_assertions": {
		required("id", colUUID),
		required("client_id", colText),
		required("jti", colText),
		required("held_until", colTimestamptz),
	},
	"sessions":          sessionTableColumns,
	"op_refresh_tokens": sessionTableColumns,
	"signing_keys": {
		required("id", colUUID),
		required("kid", colText),
		required("alg", colText),
		required("private_key", colBytea),
		required("public_jwk", colBytea),
		required("created_at", colTimestamptz),
	},
	"login_attempts": {
		required("id", colUUID),
		required("username", colText),
		required("attempted_at", colTimestamptz),
	},
	"login_failure_streaks": {
		required("id", colUUID),
		required("username", colText),
		required("failures", colInteger),
		required("newest_failure_at", colTimestamptz),
		optional("held_at", colTimestamptz),
	},
	"mfa_enrolments": {
		required("id", colUUID),
		required("user_id", colText),
		required("secret", colText),
		optional("confirmed_at", colTimestamptz),
		defaulted("last_step", colBigint, "0"),
		required("created_at", colTimestamptz),
		optional("generation", colUUID),
		optional("device_proven_at", colTimestamptz),
		optional("email_code", colText),
		optional("email_code_until", colTimestamptz),
		defaulted("email_code_attempts", colInteger, "0"),
		defaulted("verify_attempts", colInteger, "0"),
		optional("verify_window_until", colTimestamptz),
	},
	"api_keys": {
		required("id", colUUID),
		required("user_id", colText),
		required("name", colText),
		defaulted("scopes", colJSONB, defEmptyArray),
		required("secret_digest", colBytea),
		optional("expires_at", colTimestamptz),
		optional("revoked_at", colTimestamptz),
		optional("last_used_at", colTimestamptz),
		required("created_at", colTimestamptz),
	},
	"one_time_tokens": {
		required("id", colUUID),
		required("purpose", colText),
		required("subject", colText),
		required("secret_hash", colBytea),
		optional("binding_hash", colBytea),
		required("issued_at", colTimestamptz),
		required("expires_at", colTimestamptz),
		optional("consumed_at", colTimestamptz),
	},
	"oidc_links": {
		required("id", colUUID),
		required("provider", colText),
		required("issuer", colText),
		required("subject", colText),
		required("user_id", colText),
		defaulted("username", colText, defEmptyText),
		defaulted("email", colText, defEmptyText),
		required("created_at", colTimestamptz),
	},
	"oidc_flows": {
		required("id", colUUID),
		required("handle", colText),
		required("provider", colText),
		required("state", colText),
		required("nonce", colText),
		required("verifier", colText),
		defaulted("next", colText, defEmptyText),
		required("expires_at", colTimestamptz),
		optional("completed_at", colTimestamptz),
	},
	"oidc_handoffs": {
		required("id", colUUID),
		required("token_id", colText),
		required("secret_hash", colBytea),
		required("user_id", colText),
		defaulted("provider", colText, defEmptyText),
		defaulted("issuer", colText, defEmptyText),
		defaulted("session_id", colText, defEmptyText),
		defaulted("id_token", colText, defEmptyText),
		defaulted("next", colText, defEmptyText),
		defaulted("amr", colJSONB, defEmptyArray),
		defaulted("acr", colText, defEmptyText),
		required("expires_at", colTimestamptz),
		required("created_at", colTimestamptz),
		optional("consumed_at", colTimestamptz),
	},
	"recovery_codes": {
		required("id", colUUID),
		required("user_id", colText),
		required("code_hash", colBytea),
		required("created_at", colTimestamptz),
		optional("spent_at", colTimestamptz),
	},
	"account_recoveries": {
		required("id", colUUID),
		required("user_id", colText),
		required("started_at", colTimestamptz),
		required("not_before", colTimestamptz),
		optional("completed_at", colTimestamptz),
		optional("cancelled_at", colTimestamptz),
		required("proven", colText),
		required("reported", colText),
		defaulted("saved_spent", colBoolean, "false"),
	},
	"passkey_credentials": {
		required("id", colUUID),
		required("user_id", colText),
		required("credential_id", colBytea),
		required("public_key", colBytea),
		required("sign_count", colBigint),
		required("backup_eligible", colBoolean),
		required("backup_state", colBoolean),
		required("transports", colText),
		optional("aaguid", colBytea),
		optional("attestation_format", colText),
		optional("attestation_statement", colBytea),
		required("name", colText),
		required("created_at", colTimestamptz),
		optional("last_used_at", colTimestamptz),
		required("state", colSmallint),
		required("pending", colSmallint),
		optional("email_code", colText),
		optional("email_code_expires_at", colTimestamptz),
		defaulted("email_code_attempts", colSmallint, "0"),
	},
	"passkey_user_handles": {
		required("id", colUUID),
		required("user_id", colText),
		required("handle", colBytea),
	},
	"rate_limit_buckets": {
		required("namespace", colText),
		required("key", colText),
		required("stamps", colTimestamptzArray),
		required("newest_at", colTimestamptz),
		required("longest_window_us", colBigint),
	},
}

// securityStateIndexes pins every index of every security-state table, keyed
// by table, as pg_indexes defines it with the schema qualifier removed: the
// primary keys, the natural-key unique indexes, the issuer-leading partial
// session indexes with their exact column order and predicate, both
// login_attempts indexes, and every lookup and expiry index the stores' queries
// seek on. An index that is added, dropped, moved to another table, made
// unique or not, or whose columns are reordered fails the comparison.
var securityStateIndexes = map[string][]string{
	"op_clients": {
		"CREATE UNIQUE INDEX op_clients_pkey ON op_clients USING btree (id)",
		"CREATE UNIQUE INDEX op_clients_client_id_key ON op_clients USING btree (client_id)",
	},
	"op_pending_requests": {
		"CREATE UNIQUE INDEX op_pending_requests_pkey ON op_pending_requests USING btree (id)",
		"CREATE UNIQUE INDEX op_pending_requests_handle_digest_key ON op_pending_requests USING btree (handle_digest)",
		"CREATE INDEX op_pending_requests_expiry ON op_pending_requests USING btree (expires_at)",
	},
	"op_browser_sessions": {
		"CREATE UNIQUE INDEX op_browser_sessions_pkey ON op_browser_sessions USING btree (id)",
		"CREATE UNIQUE INDEX op_browser_sessions_digest_key ON op_browser_sessions USING btree (digest)",
		"CREATE INDEX op_browser_sessions_user_issuer ON op_browser_sessions USING btree (user_ref, external_issuer)",
		"CREATE INDEX op_browser_sessions_sign_in ON op_browser_sessions USING btree (sign_in_family)",
		"CREATE INDEX op_browser_sessions_external_session ON op_browser_sessions USING btree (external_issuer, external_session_id)",
		"CREATE INDEX op_browser_sessions_idle_expiry ON op_browser_sessions USING btree (idle_expires_at)",
		"CREATE INDEX op_browser_sessions_absolute_expiry ON op_browser_sessions USING btree (absolute_expires_at)",
	},
	"op_authorization_codes": {
		"CREATE UNIQUE INDEX op_authorization_codes_pkey ON op_authorization_codes USING btree (token_id)",
		"CREATE INDEX op_authorization_codes_user_client ON op_authorization_codes USING btree (user_ref, client_id)",
		"CREATE INDEX op_authorization_codes_user_issuer ON op_authorization_codes USING btree (user_ref, external_issuer)",
		"CREATE INDEX op_authorization_codes_sign_in ON op_authorization_codes USING btree (sign_in_family)",
		"CREATE INDEX op_authorization_codes_external_session ON op_authorization_codes USING btree (external_issuer, external_session_id)",
		"CREATE INDEX op_authorization_codes_expiry ON op_authorization_codes USING btree (expires_at)",
	},
	"op_consents": {
		"CREATE UNIQUE INDEX op_consents_pkey ON op_consents USING btree (id)",
		"CREATE UNIQUE INDEX op_consents_user_ref_client_id_key ON op_consents USING btree (user_ref, client_id)",
	},
	"op_grants": {
		"CREATE UNIQUE INDEX op_grants_pkey ON op_grants USING btree (family)",
		"CREATE INDEX op_grants_user ON op_grants USING btree (user_ref)",
		"CREATE INDEX op_grants_user_client ON op_grants USING btree (user_ref, client_id)",
		"CREATE INDEX op_grants_user_issuer ON op_grants USING btree (user_ref, external_issuer)",
		"CREATE INDEX op_grants_sign_in ON op_grants USING btree (sign_in_family)",
		"CREATE INDEX op_grants_external_session ON op_grants USING btree (external_issuer, external_session_id)",
		"CREATE INDEX op_grants_expiry ON op_grants USING btree (expires_at)",
		"CREATE INDEX op_grants_revoked ON op_grants USING btree (revoked_at)",
	},
	"op_refresh_tokens": {
		"CREATE UNIQUE INDEX op_refresh_tokens_pkey ON op_refresh_tokens USING btree (id)",
		"CREATE UNIQUE INDEX op_refresh_tokens_id_digest_key ON op_refresh_tokens USING btree (id_digest)",
		"CREATE INDEX op_refresh_tokens_external_session ON op_refresh_tokens USING btree (external_issuer, external_session_id) WHERE (external_session_id <> ''::text)",
		"CREATE INDEX op_refresh_tokens_user_issuer ON op_refresh_tokens USING btree (user_id, external_issuer) WHERE (external_issuer <> ''::text)",
		"CREATE INDEX op_refresh_tokens_user ON op_refresh_tokens USING btree (user_id)",
		"CREATE INDEX op_refresh_tokens_idle_expiry ON op_refresh_tokens USING btree (idle_expires_at)",
		"CREATE INDEX op_refresh_tokens_absolute_expiry ON op_refresh_tokens USING btree (absolute_expires_at)",
		"CREATE INDEX op_refresh_tokens_family ON op_refresh_tokens USING btree (family_id)",
	},
	"op_access_tokens": {
		"CREATE UNIQUE INDEX op_access_tokens_pkey ON op_access_tokens USING btree (id)",
		"CREATE INDEX op_access_tokens_expiry ON op_access_tokens USING btree (expires_at)",
	},
	"op_client_assertions": {
		"CREATE UNIQUE INDEX op_client_assertions_pkey ON op_client_assertions USING btree (id)",
		"CREATE UNIQUE INDEX op_client_assertions_client_id_jti_key ON op_client_assertions USING btree (client_id, jti)",
		"CREATE INDEX op_client_assertions_expiry ON op_client_assertions USING btree (held_until)",
	},
	"sessions": {
		"CREATE UNIQUE INDEX sessions_pkey ON sessions USING btree (id)",
		"CREATE UNIQUE INDEX sessions_id_digest_key ON sessions USING btree (id_digest)",
		"CREATE INDEX sessions_external_session ON sessions USING btree (external_issuer, external_session_id) WHERE (external_session_id <> ''::text)",
		"CREATE INDEX sessions_user_issuer ON sessions USING btree (user_id, external_issuer) WHERE (external_issuer <> ''::text)",
		"CREATE INDEX sessions_user ON sessions USING btree (user_id)",
		"CREATE INDEX sessions_idle_expiry ON sessions USING btree (idle_expires_at)",
		"CREATE INDEX sessions_absolute_expiry ON sessions USING btree (absolute_expires_at)",
		"CREATE INDEX sessions_family ON sessions USING btree (family_id)",
	},
	"signing_keys": {
		"CREATE UNIQUE INDEX signing_keys_pkey ON signing_keys USING btree (id)",
		"CREATE UNIQUE INDEX signing_keys_kid_key ON signing_keys USING btree (kid)",
	},
	"login_attempts": {
		"CREATE UNIQUE INDEX login_attempts_pkey ON login_attempts USING btree (id)",
		"CREATE INDEX login_attempts_username ON login_attempts USING btree (username, attempted_at)",
		"CREATE INDEX login_attempts_time ON login_attempts USING btree (attempted_at)",
	},
	"login_failure_streaks": {
		"CREATE UNIQUE INDEX login_failure_streaks_pkey ON login_failure_streaks USING btree (id)",
		"CREATE UNIQUE INDEX login_failure_streaks_username_key ON login_failure_streaks USING btree (username)",
		"CREATE INDEX login_failure_streaks_inactive ON login_failure_streaks USING btree (newest_failure_at) WHERE (held_at IS NULL)",
	},
	"mfa_enrolments": {
		"CREATE UNIQUE INDEX mfa_enrolments_pkey ON mfa_enrolments USING btree (id)",
		"CREATE UNIQUE INDEX mfa_enrolments_user_id_key ON mfa_enrolments USING btree (user_id)",
	},
	"api_keys": {
		"CREATE UNIQUE INDEX api_keys_pkey ON api_keys USING btree (id)",
		"CREATE INDEX api_keys_user ON api_keys USING btree (user_id)",
	},
	"one_time_tokens": {
		"CREATE UNIQUE INDEX one_time_tokens_pkey ON one_time_tokens USING btree (id)",
		"CREATE INDEX one_time_tokens_subject ON one_time_tokens USING btree (purpose, subject)",
		"CREATE INDEX one_time_tokens_expiry ON one_time_tokens USING btree (purpose, expires_at)",
	},
	"oidc_links": {
		"CREATE UNIQUE INDEX oidc_links_pkey ON oidc_links USING btree (id)",
		"CREATE UNIQUE INDEX oidc_links_provider_issuer_subject_key ON oidc_links USING btree (provider, issuer, subject)",
		"CREATE INDEX oidc_links_user ON oidc_links USING btree (user_id)",
	},
	"oidc_flows": {
		"CREATE UNIQUE INDEX oidc_flows_pkey ON oidc_flows USING btree (id)",
		"CREATE UNIQUE INDEX oidc_flows_handle_key ON oidc_flows USING btree (handle)",
		"CREATE INDEX oidc_flows_expiry ON oidc_flows USING btree (expires_at)",
	},
	"oidc_handoffs": {
		"CREATE UNIQUE INDEX oidc_handoffs_pkey ON oidc_handoffs USING btree (id)",
		"CREATE UNIQUE INDEX oidc_handoffs_token_id_key ON oidc_handoffs USING btree (token_id)",
		"CREATE INDEX oidc_handoffs_expiry ON oidc_handoffs USING btree (expires_at)",
	},
	"recovery_codes": {
		"CREATE UNIQUE INDEX recovery_codes_pkey ON recovery_codes USING btree (id)",
		"CREATE UNIQUE INDEX recovery_codes_user_id_code_hash_key ON recovery_codes USING btree (user_id, code_hash)",
	},
	"account_recoveries": {
		"CREATE UNIQUE INDEX account_recoveries_pkey ON account_recoveries USING btree (id)",
		"CREATE INDEX account_recoveries_user ON account_recoveries USING btree (user_id)",
	},
	"passkey_credentials": {
		"CREATE UNIQUE INDEX passkey_credentials_pkey ON passkey_credentials USING btree (id)",
		"CREATE UNIQUE INDEX passkey_credentials_credential_id_key ON passkey_credentials USING btree (credential_id)",
		"CREATE INDEX passkey_credentials_user_id_idx ON passkey_credentials USING btree (user_id)",
	},
	"passkey_user_handles": {
		"CREATE UNIQUE INDEX passkey_user_handles_pkey ON passkey_user_handles USING btree (id)",
		"CREATE UNIQUE INDEX passkey_user_handles_user_id_key ON passkey_user_handles USING btree (user_id)",
		"CREATE UNIQUE INDEX passkey_user_handles_handle_key ON passkey_user_handles USING btree (handle)",
	},
	"rate_limit_buckets": {
		"CREATE UNIQUE INDEX rate_limit_buckets_pkey ON rate_limit_buckets USING btree (namespace, key)",
	},
}

// groupByTable splits rows of "table|value" into a map from table to its
// values, sorted, so two schemas compare independently of catalogue order and
// a difference is reported under the table it belongs to.
func groupByTable(t *testing.T, rows []string) map[string][]string {
	t.Helper()

	out := make(map[string][]string)
	for _, r := range rows {
		table, value, ok := strings.Cut(r, "|")
		require.True(t, ok, r)
		out[table] = append(out[table], value)
	}
	for _, values := range out {
		slices.Sort(values)
	}
	return out
}

// sortedByTable returns a copy of want with every table's values sorted, in
// the shape groupByTable produces.
func sortedByTable[V any](want map[string][]V, render func(V) string) map[string][]string {
	out := make(map[string][]string, len(want))
	for table, values := range want {
		rendered := make([]string, 0, len(values))
		for _, v := range values {
			rendered = append(rendered, render(v))
		}
		slices.Sort(rendered)
		out[table] = rendered
	}
	return out
}

// schemaCheck is one assertion over the security-state schema: run query
// against a migrated database and hand the scanned rows to assert.
type schemaCheck struct {
	name   string
	query  string
	args   []any
	assert func(t *testing.T, rows []string)
}

// securityStateSchemaChecks is every pinned schema assertion for the
// security-state migration set (tables, column types, nullable guards and
// indexes), parameterised by the version table name so the same checks run
// whichever table a
// provider was built with (TestSecurityStateMigrations_Schema uses the
// default; TestGooseDirect uses its own).
func securityStateSchemaChecks(versionTable string) []schemaCheck {
	return []schemaCheck{
		{
			name:  "fresh database has the twenty-four tables and the version table",
			query: `SELECT tablename FROM pg_tables WHERE schemaname = current_schema() ORDER BY 1`,
			assert: func(t *testing.T, rows []string) {
				want := append(slices.Clone(securityStateTables), versionTable)
				assert.ElementsMatch(t, want, rows)
			},
		},
		{
			name: "no identity tables",
			query: `SELECT tablename FROM pg_tables
			         WHERE tablename IN ('users','roles','organizations','groups','privileges')`,
			assert: func(t *testing.T, rows []string) { assert.Empty(t, rows) },
		},
		{
			name: "every primary key is uuid",
			query: `SELECT c.table_name || '.' || c.column_name || ':' || c.data_type
			           FROM information_schema.table_constraints tc
			           JOIN information_schema.key_column_usage k
			             ON k.constraint_name = tc.constraint_name AND k.table_name = tc.table_name
			             AND k.table_schema = tc.table_schema
			           JOIN information_schema.columns c
			             ON c.table_name = k.table_name AND c.column_name = k.column_name
			             AND c.table_schema = k.table_schema
			          WHERE tc.constraint_type = 'PRIMARY KEY'
			            AND tc.table_schema = current_schema()
			            AND c.table_name <> $1
			            AND c.table_name <> 'rate_limit_buckets'`,
			args: []any{versionTable},
			assert: func(t *testing.T, rows []string) {
				// rate_limit_buckets is keyed by (namespace, key), not a uuid.
				require.Len(t, rows, len(securityStateTables)-1)
				for _, r := range rows {
					assert.True(t, strings.HasSuffix(r, ":uuid"), r)
				}
			},
		},
		{
			name: "every user reference is text",
			query: `SELECT table_name || ':' || data_type FROM information_schema.columns
			         WHERE column_name IN ('user_id', 'user_ref') AND table_schema = current_schema()`,
			assert: func(t *testing.T, rows []string) {
				// user_id: sessions, mfa_enrolments, api_keys, oidc_links,
				// oidc_handoffs, recovery_codes, account_recoveries,
				// passkey_credentials, passkey_user_handles, op_refresh_tokens.
				// user_ref: op_browser_sessions, op_authorization_codes, op_consents,
				// op_grants, op_access_tokens.
				require.Len(t, rows, 15)
				for _, r := range rows {
					assert.True(t, strings.HasSuffix(r, ":text"), r)
				}
			},
		},
		{
			name:  "no foreign keys",
			query: `SELECT constraint_name FROM information_schema.table_constraints WHERE constraint_type = 'FOREIGN KEY'`,
			assert: func(t *testing.T, rows []string) {
				assert.Empty(t, rows)
			},
		},
		{
			name: "nullable guards with no default",
			query: `SELECT table_name||'.'||column_name||':'||is_nullable||':'||coalesce(column_default,'')
			           FROM information_schema.columns
			          WHERE table_schema = current_schema()
			            AND column_name IN ('consumed_at','completed_at','confirmed_at','revoked_at',
			                                'spent_at','cancelled_at')`,
			assert: func(t *testing.T, rows []string) {
				assert.ElementsMatch(t, []string{
					"one_time_tokens.consumed_at:YES:",
					"oidc_handoffs.consumed_at:YES:",
					"oidc_flows.completed_at:YES:",
					"mfa_enrolments.confirmed_at:YES:",
					"api_keys.revoked_at:YES:",
					"recovery_codes.spent_at:YES:",
					"account_recoveries.completed_at:YES:",
					"account_recoveries.cancelled_at:YES:",
					"op_grants.revoked_at:YES:",
				}, rows)
			},
		},
		{
			// Spec scenario "Consecutive failure counts": one streak per
			// login name, and the hold instant is a nullable guard with no
			// default, so a streak is not held until a write sets it.
			name: "consecutive failure counts are unique per login name, with a nullable hold and no default",
			query: `SELECT 'unique:' || i.indexname
			          FROM pg_indexes i
			         WHERE i.schemaname = current_schema()
			           AND i.tablename = 'login_failure_streaks'
			           AND i.indexdef LIKE 'CREATE UNIQUE INDEX % USING btree (username)'
			        UNION ALL
			        SELECT 'held_at:' || is_nullable || ':' || coalesce(column_default, '')
			          FROM information_schema.columns
			         WHERE table_schema = current_schema()
			           AND table_name = 'login_failure_streaks' AND column_name = 'held_at'`,
			assert: func(t *testing.T, rows []string) {
				assert.ElementsMatch(t, []string{
					"unique:login_failure_streaks_username_key",
					"held_at:YES:",
				}, rows)
			},
		},
		{
			name: "exact indexes per table",
			query: `SELECT tablename || '|' || replace(indexdef, ' ON ' || quote_ident(schemaname) || '.', ' ON ')
			          FROM pg_indexes
			         WHERE schemaname = current_schema()
			           AND tablename = ANY(string_to_array($1, ','))`,
			args: []any{strings.Join(securityStateTables, ",")},
			assert: func(t *testing.T, rows []string) {
				want := sortedByTable(securityStateIndexes, func(s string) string { return s })
				assert.Equal(t, want, groupByTable(t, rows))
			},
		},
		{
			name: "exact columns per table, with type, nullability and default",
			query: `SELECT c.relname || '|' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod)
			               || CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE ' NULL' END
			               || ' DEFAULT ' || coalesce(pg_get_expr(d.adbin, d.adrelid), '')
			          FROM pg_attribute a
			          JOIN pg_class c ON c.oid = a.attrelid
			          JOIN pg_namespace n ON n.oid = c.relnamespace
			          LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
			         WHERE n.nspname = current_schema()
			           AND c.relkind = 'r'
			           AND a.attnum > 0 AND NOT a.attisdropped
			           AND c.relname = ANY(string_to_array($1, ','))`,
			args: []any{strings.Join(securityStateTables, ",")},
			assert: func(t *testing.T, rows []string) {
				want := sortedByTable(securityStateColumns, column.String)
				assert.Equal(t, want, groupByTable(t, rows))
			},
		},
		{
			name: "rate_limit_buckets is a logged table",
			query: `SELECT c.relpersistence::text FROM pg_class c
			          JOIN pg_namespace n ON n.oid = c.relnamespace
			         WHERE n.nspname = current_schema() AND c.relname = 'rate_limit_buckets'`,
			assert: func(t *testing.T, rows []string) {
				assert.Equal(t, []string{"p"}, rows, "unlogged would lose every limit on a crash or failover")
			},
		},
		{
			name: "rate_limit_buckets has its primary key as its only index",
			query: `SELECT i.indexrelid::regclass::text || '|' || i.indisprimary::text
			          FROM pg_index i
			          JOIN pg_class c ON c.oid = i.indrelid
			          JOIN pg_namespace n ON n.oid = c.relnamespace
			         WHERE n.nspname = current_schema() AND c.relname = 'rate_limit_buckets'`,
			assert: func(t *testing.T, rows []string) {
				assert.Equal(t, []string{"rate_limit_buckets_pkey|true"}, rows,
					"an index on a column that changes would stop updates being HOT")
			},
		},
		{
			// The values the limiter benchmark settled: room on each page for
			// HOT updates, a TOAST threshold high enough that a row holding
			// the widest stamp array stays in the heap, and autovacuum that
			// keeps up with a small table whose rows are updated and pruned
			// constantly.
			name: "rate_limit_buckets declares its own fill factor, TOAST threshold and autovacuum storage parameters",
			query: `SELECT unnest(c.reloptions) FROM pg_class c
			          JOIN pg_namespace n ON n.oid = c.relnamespace
			         WHERE n.nspname = current_schema() AND c.relname = 'rate_limit_buckets'`,
			assert: func(t *testing.T, rows []string) {
				assert.ElementsMatch(t, []string{
					"fillfactor=70",
					"toast_tuple_target=8160",
					"autovacuum_vacuum_scale_factor=0.01",
					"autovacuum_vacuum_insert_scale_factor=0.01",
				}, rows)
			},
		},
		{
			// The one-time token contract tells an absent binding from an
			// empty one, so NULL must be storable and must stay distinct
			// from an empty bytea.
			name: "one-time token binding stores NULL as unbound, apart from empty",
			query: `INSERT INTO one_time_tokens (id, purpose, subject, secret_hash, binding_hash, issued_at, expires_at)
			        VALUES (gen_random_uuid(), 'probe', 'unbound', '\x01', NULL, now(), now()),
			               (gen_random_uuid(), 'probe', 'empty', '\x01', '\x'::bytea, now(), now())
			        RETURNING subject || ':' || coalesce(encode(binding_hash, 'hex'), 'NULL')`,
			assert: func(t *testing.T, rows []string) {
				assert.ElementsMatch(t, []string{"unbound:NULL", "empty:"}, rows)
			},
		},
	}
}

// runSchemaChecks runs every check in checks against db, each as its own
// subtest.
func runSchemaChecks(t *testing.T, db *sql.DB, checks []schemaCheck) {
	t.Helper()

	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, queryStrings(t, db, tc.query, tc.args...))
		})
	}
}

func TestSecurityStateMigrations_Schema(t *testing.T) {
	t.Parallel()

	db := migrated(t)
	runSchemaChecks(t, db, securityStateSchemaChecks(migrate.SecurityStateVersionTable))
}

// securityStateMigrationCount is how many migration files the security-state
// set holds.
const securityStateMigrationCount = 5

// Versions of the security-state migrations the family tests address.
const (
	versionSecurityState   int64 = 20260926000000
	versionSessionFamilies int64 = 20261021000000
	versionStrictRotation  int64 = 20261101000000
	versionSessionSignIns  int64 = 20261102000000
)

// sessionColumnsAndIndexes describes the sessions table as sorted column and
// index lines, for comparing its shape before and after a migration.
func sessionColumnsAndIndexes(t *testing.T, db *sql.DB) []string {
	t.Helper()

	lines := queryStrings(t, db, `SELECT 'col ' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod)
	        || CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE ' NULL' END
	        || coalesce(' DEFAULT ' || pg_get_expr(d.adbin, d.adrelid), '')
	   FROM pg_attribute a
	   LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
	  WHERE a.attrelid = 'sessions'::regclass AND a.attnum > 0 AND NOT a.attisdropped
	 UNION ALL
	 SELECT 'idx ' || replace(indexdef, current_schema() || '.', '') FROM pg_indexes
	  WHERE tablename = 'sessions' AND schemaname = current_schema()`)
	slices.Sort(lines)
	return lines
}

// TestSecurityStateMigrations_SessionFamilies pins the session-family
// migration: the columns and index it adds, the backfill of rows that already
// exist, and a rollback that restores the previous shape. The backfill and
// rollback are asserted with SQL against the table, not through a store.
func TestSecurityStateMigrations_SessionFamilies(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()

	type testCase struct {
		name string
		run  func(t *testing.T, db *sql.DB, p *goose.Provider)
	}

	cases := []testCase{
		{
			name: "adds the family columns and index",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				_, err := p.UpTo(t.Context(), versionSessionFamilies)
				require.NoError(t, err)

				got := sessionColumnsAndIndexes(t, db)
				for _, want := range []string{
					"col family_id uuid NOT NULL DEFAULT gen_random_uuid()",
					"col family_created_at timestamp with time zone NOT NULL DEFAULT now()",
					"col authenticated_at timestamp with time zone NOT NULL DEFAULT now()",
					"col superseded_at timestamp with time zone NULL",
					"col accept_until timestamp with time zone NULL",
					"col successor_digest bytea NULL",
					"col first_presented_at timestamp with time zone NULL",
					"idx CREATE INDEX sessions_family ON sessions USING btree (family_id)",
				} {
					assert.Contains(t, got, want)
				}
			},
		},
		{
			name: "backfills existing sessions as their own family",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				_, err := p.UpTo(t.Context(), versionSecurityState)
				require.NoError(t, err)

				ids := []string{"0192f000-0000-7000-8000-0000000000c1", "0192f000-0000-7000-8000-0000000000c2"}
				created := []time.Time{
					time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
					time.Date(2026, 9, 2, 11, 30, 0, 0, time.UTC),
				}
				for i, sid := range ids {
					_, err := db.ExecContext(t.Context(), `INSERT INTO sessions
						(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at)
						VALUES ($1, $2, 'u', $3, $3, $4, $4)`,
						sid, []byte{byte(i + 1)}, created[i], created[i].Add(time.Hour))
					require.NoError(t, err)
				}

				_, err = p.UpTo(t.Context(), versionSessionFamilies)
				require.NoError(t, err)

				rows, err := db.QueryContext(t.Context(),
					`SELECT id::text, family_id::text, created_at, family_created_at,
					        superseded_at IS NULL, accept_until IS NULL,
					        successor_digest IS NULL, first_presented_at IS NULL
					   FROM sessions ORDER BY id`)
				require.NoError(t, err)
				defer func() { _ = rows.Close() }()

				n := 0
				for rows.Next() {
					var sid, fid string
					var createdAt, familyCreatedAt time.Time
					var supersededNull, acceptNull, successorNull, presentedNull bool
					require.NoError(t, rows.Scan(&sid, &fid, &createdAt, &familyCreatedAt,
						&supersededNull, &acceptNull, &successorNull, &presentedNull))
					assert.Equal(t, sid, fid, "family_id is the row's own id")
					assert.True(t, createdAt.Equal(familyCreatedAt), "family_created_at is created_at")
					assert.True(t, supersededNull && acceptNull && successorNull && presentedNull,
						"the supersession columns stay NULL")
					n++
				}
				require.NoError(t, rows.Err())
				assert.Equal(t, len(ids), n)
			},
		},
		{
			name: "an older writer's insert succeeds",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				_, err := p.UpTo(t.Context(), versionSessionFamilies)
				require.NoError(t, err)

				// Names neither family column nor authenticated_at.
				_, err = db.ExecContext(t.Context(), `INSERT INTO sessions
					(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at)
					VALUES ('0192f000-0000-7000-8000-0000000000d1', '\x07', 'u', now(), now(), now(), now())`)
				require.NoError(t, err)

				var ok bool
				require.NoError(t, db.QueryRowContext(t.Context(),
					`SELECT family_id IS NOT NULL AND family_created_at IS NOT NULL AND authenticated_at IS NOT NULL
					   FROM sessions`).Scan(&ok))
				assert.True(t, ok, "the three columns take their defaults")
			},
		},
		{
			name: "existing rows get their authentication time",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				_, err := p.UpTo(t.Context(), versionSecurityState)
				require.NoError(t, err)

				signedIn := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
				second := signedIn.Add(20 * time.Minute)
				_, err = db.ExecContext(t.Context(), `INSERT INTO sessions
					(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at, mfa_satisfied_at)
					VALUES ('0192f000-0000-7000-8000-0000000000e1', '\x01', 'u', $1, $1, $2, $2, $3),
					       ('0192f000-0000-7000-8000-0000000000e2', '\x02', 'u', $1, $1, $2, $2, NULL)`,
					signedIn, signedIn.Add(time.Hour), second)
				require.NoError(t, err)

				_, err = p.UpTo(t.Context(), versionSessionFamilies)
				require.NoError(t, err)

				for id, want := range map[string]time.Time{
					"0192f000-0000-7000-8000-0000000000e1": second,
					"0192f000-0000-7000-8000-0000000000e2": signedIn,
				} {
					var got time.Time
					require.NoError(t, db.QueryRowContext(t.Context(),
						`SELECT authenticated_at FROM sessions WHERE id = $1`, id).Scan(&got))
					assert.True(t, want.Equal(got), "session %s: authenticated_at %s, want %s", id, got, want)
				}
			},
		},
		{
			// A row written before the column existed reads back with no
			// retention deadline, which a store judges by the row's own
			// deadlines; the down step removes the column again.
			name: "adds the retention deadline, nullable with no default, unset on existing rows, removed on rollback",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				_, err := p.UpTo(t.Context(), versionSecurityState)
				require.NoError(t, err)

				_, err = db.ExecContext(t.Context(), `INSERT INTO sessions
					(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at)
					VALUES ('0192f000-0000-7000-8000-0000000000f1', '\x01', 'u', now(), now(), now(), now())`)
				require.NoError(t, err)

				_, err = p.UpTo(t.Context(), versionSessionFamilies)
				require.NoError(t, err)

				assert.Contains(t, sessionColumnsAndIndexes(t, db), "col retain_until timestamp with time zone NULL",
					"retain_until is a nullable timestamptz with no default")
				var unset bool
				require.NoError(t, db.QueryRowContext(t.Context(),
					`SELECT retain_until IS NULL FROM sessions WHERE id = '0192f000-0000-7000-8000-0000000000f1'`).
					Scan(&unset))
				assert.True(t, unset, "a row that existed before the column has no retention deadline")

				_, err = p.Down(t.Context())
				require.NoError(t, err)

				for _, line := range sessionColumnsAndIndexes(t, db) {
					assert.NotContains(t, line, "retain_until", "the down step removes the column")
				}
			},
		},
		{
			name: "rollback restores the previous columns and indexes",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				_, err := p.UpTo(t.Context(), versionSecurityState)
				require.NoError(t, err)
				before := sessionColumnsAndIndexes(t, db)

				_, err = p.UpTo(t.Context(), versionSessionFamilies)
				require.NoError(t, err)
				require.NotEqual(t, before, sessionColumnsAndIndexes(t, db),
					"the family migration changed the sessions table")

				_, err = p.Down(t.Context())
				require.NoError(t, err)

				assert.Equal(t, before, sessionColumnsAndIndexes(t, db))
				assert.Equal(t, 1, appliedVersionCount(t, db, migrate.SecurityStateVersionTable))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db, p := freshSecurityState(t, set)
			tc.run(t, db, p)
		})
	}
}

// TestSecurityStateMigrations_SessionStrictRotation pins the strict-rotation
// migration: a boolean mark that defaults to false, rows from before it read
// back unmarked, a writer from before it still inserts, and a rollback
// restores the previous columns and indexes.
func TestSecurityStateMigrations_SessionStrictRotation(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()

	type testCase struct {
		name string
		run  func(t *testing.T, db *sql.DB, p *goose.Provider)
	}

	const oldInsert = `INSERT INTO sessions
		(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at)
		VALUES ($1, $2, 'u', now(), now(), now(), now())`

	cases := []testCase{
		{
			name: "adds the mark as a not-null boolean defaulting to false",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				_, err := p.Up(t.Context())
				require.NoError(t, err)

				assert.Contains(t, sessionColumnsAndIndexes(t, db), "col rotated_strictly boolean NOT NULL DEFAULT false")
			},
		},
		{
			name: "a superseded row from before the migration reads unmarked",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				_, err := p.UpTo(t.Context(), versionSessionFamilies)
				require.NoError(t, err)

				_, err = db.ExecContext(t.Context(), `INSERT INTO sessions
					(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at,
					 superseded_at, accept_until, retain_until)
					VALUES ('0192f000-0000-7000-8000-0000000000b1', '\x01', 'u', now(), now(), now(), now(),
					        now(), now(), now())`)
				require.NoError(t, err)

				_, err = p.Up(t.Context())
				require.NoError(t, err)

				var marked bool
				require.NoError(t, db.QueryRowContext(t.Context(),
					`SELECT rotated_strictly FROM sessions WHERE id = '0192f000-0000-7000-8000-0000000000b1'`).Scan(&marked))
				assert.False(t, marked, "a rotation from before the mark was not strict")
			},
		},
		{
			name: "an older writer's insert succeeds and is unmarked",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				_, err := p.Up(t.Context())
				require.NoError(t, err)

				_, err = db.ExecContext(t.Context(), oldInsert, "0192f000-0000-7000-8000-0000000000b2", []byte{0x02})
				require.NoError(t, err)

				var marked bool
				require.NoError(t, db.QueryRowContext(t.Context(),
					`SELECT rotated_strictly FROM sessions WHERE id = '0192f000-0000-7000-8000-0000000000b2'`).Scan(&marked))
				assert.False(t, marked)
			},
		},
		{
			name: "rollback restores the previous columns and indexes",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				_, err := p.UpTo(t.Context(), versionSessionFamilies)
				require.NoError(t, err)
				before := sessionColumnsAndIndexes(t, db)

				_, err = p.UpTo(t.Context(), versionStrictRotation)
				require.NoError(t, err)
				require.NotEqual(t, before, sessionColumnsAndIndexes(t, db), "the migration changed the sessions table")

				_, err = p.Down(t.Context())
				require.NoError(t, err)

				assert.Equal(t, before, sessionColumnsAndIndexes(t, db))
				assert.Equal(t, 2, appliedVersionCount(t, db, migrate.SecurityStateVersionTable))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db, p := freshSecurityState(t, set)
			tc.run(t, db, p)
		})
	}
}

// rollBackAtCleanup registers a cleanup that rolls p back to version zero,
// failing the test if that errors, and then fails naming every table left in
// the current schema other than exempt: the leftover-table check the helper
// runs for a set it applied, for a test that applies goose itself.
func rollBackAtCleanup(t *testing.T, db *sql.DB, p *goose.Provider, exempt ...string) {
	t.Helper()

	t.Cleanup(func() {
		// t.Context() is already cancelled when cleanup runs: rolling back
		// under it fails before goose touches the database.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), postgresTeardownBudget)
		defer cancel()

		if _, err := p.DownTo(ctx, 0); err != nil {
			t.Errorf("roll back to version zero: %v", err)
		}
		assertNoLeftoverTables(ctx, t, db, exempt...)
	})
}

// assertNoLeftoverTables fails naming every table left in the current schema
// other than exempt, using the same query as the helper's leftover-table
// check.
func assertNoLeftoverTables(ctx context.Context, t *testing.T, db *sql.DB, exempt ...string) {
	t.Helper()

	leftover, err := postgresLeftoverTables(ctx, db, exempt)
	if err != nil {
		t.Errorf("leftover table check: %v", err)
		return
	}
	assert.Empty(t, leftover, "tables left behind")
}

// regclassExists reports whether name resolves to an existing relation.
func regclassExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()

	var regclass sql.NullString
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT to_regclass($1)::text`, name).Scan(&regclass))
	return regclass.Valid
}

// appliedVersionCount reports how many versions above zero are recorded
// applied in table.
func appliedVersionCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()

	var n int
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT count(*) FROM `+table+` WHERE is_applied AND version_id > 0`).Scan(&n))
	return n
}

func TestSecurityStateMigrations_VersionTable(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()

	type testCase struct {
		name   string
		apply  func(t *testing.T, db *sql.DB)
		assert func(t *testing.T, db *sql.DB)
	}

	cases := []testCase{
		{
			name: "default version table",
			apply: func(t *testing.T, db *sql.DB) {
				p := provider(t, db, set.FS(), set.Dir, migrate.SecurityStateVersionTable)
				rollBackAtCleanup(t, db, p, migrate.SecurityStateVersionTable)
				_, err := p.Up(t.Context())
				require.NoError(t, err)
			},
			assert: func(t *testing.T, db *sql.DB) {
				assert.Equal(t, securityStateMigrationCount, appliedVersionCount(t, db, migrate.SecurityStateVersionTable))
			},
		},
		{
			name: "consumer version table",
			apply: func(t *testing.T, db *sql.DB) {
				p := provider(t, db, set.FS(), set.Dir, "auth_schema_versions")
				rollBackAtCleanup(t, db, p, "auth_schema_versions")
				_, err := p.Up(t.Context())
				require.NoError(t, err)
			},
			assert: func(t *testing.T, db *sql.DB) {
				assert.Equal(t, securityStateMigrationCount, appliedVersionCount(t, db, "auth_schema_versions"))
				assert.False(t, regclassExists(t, db, migrate.SecurityStateVersionTable),
					"no goose_security_state table is created")
			},
		},
		{
			name: "independent from the identity set",
			apply: func(t *testing.T, db *sql.DB) {
				sp := provider(t, db, set.FS(), set.Dir, migrate.SecurityStateVersionTable)
				rollBackAtCleanup(t, db, sp, migrate.SecurityStateVersionTable, "goose_identity_probe")
				_, err := sp.Up(t.Context())
				require.NoError(t, err)

				ip := provider(t, db, os.DirFS("."), "testdata/migrations/identity_probe", "goose_identity_probe")
				_, err = ip.Up(t.Context())
				require.NoError(t, err)
				_, err = ip.DownTo(t.Context(), 0)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, db *sql.DB) {
				for _, tbl := range securityStateTables {
					assert.True(t, regclassExists(t, db, tbl), "table %s should still exist", tbl)
				}
				assert.Equal(t, securityStateMigrationCount, appliedVersionCount(t, db, migrate.SecurityStateVersionTable))
				assert.False(t, regclassExists(t, db, "identity_probe_users"),
					"the probe set's own table is gone after its own rollback")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := RunTestPostgres(t).DB
			tc.apply(t, db)
			tc.assert(t, db)
		})
	}
}

// runDownSection executes just the Down section of the migration file named
// name in fsys against db, without goose or a version table: it strips
// goose's annotation and comment lines and executes what is left one
// statement per line.
//
// goose's own SQL parser lives in an internal package
// (github.com/pressly/goose/v3/internal/sqlparser) and cannot be imported
// from outside the goose module, so this is a minimal parser for exactly the
// shape the security-state set's Down sections use: one statement per line,
// no StatementBegin/StatementEnd, and no semicolon inside a string literal.
// It is not a general goose parser and must not be used as one.
func runDownSection(t *testing.T, db *sql.DB, fsys fs.FS, name string) {
	t.Helper()

	data, err := fs.ReadFile(fsys, name)
	require.NoError(t, err)

	const marker = "-- +goose Down"
	idx := strings.Index(string(data), marker)
	require.GreaterOrEqual(t, idx, 0, "no %q section in %s", marker, name)
	section := string(data)[idx+len(marker):]

	for line := range strings.SplitSeq(section, "\n") {
		stmt := strings.TrimSpace(line)
		if stmt == "" || strings.HasPrefix(stmt, "--") {
			continue
		}
		stmt = strings.TrimSuffix(stmt, ";")
		_, err := db.ExecContext(t.Context(), stmt)
		require.NoError(t, err, stmt)
	}
}

// freshSecurityState starts a fresh database and a provider for set's default
// version table, for lifecycle cases that begin from an unmigrated database.
// At cleanup it rolls the set back to zero and checks no table other than the
// version table is left.
func freshSecurityState(t *testing.T, set migrate.Set) (*sql.DB, *goose.Provider) {
	t.Helper()

	db := RunTestPostgres(t).DB
	p := provider(t, db, set.FS(), set.Dir, migrate.SecurityStateVersionTable)
	rollBackAtCleanup(t, db, p, migrate.SecurityStateVersionTable)
	return db, p
}

// TestSecurityStateMigrations_Lifecycle pins application and rollback:
// re-applying an up-to-date database is a no-op, a migration that fails
// partway leaves nothing behind, rollback to zero leaves no security-state
// table, rollback still succeeds when a table was already dropped out of
// band, and the set can be re-applied after a full rollback. It also proves
// each migration's own Down section, run in isolation against a migrated
// database, removes exactly what its Up section created.
//
// Cases share the theme (apply/rollback behaviour of this set) but not a
// setup shape: several drive goose's Up/DownTo, one drives a raw fixture
// through the same provider to observe a mid-set failure, and the last
// executes a Down section directly without goose. Each case is therefore a
// self-contained run rather than a shared apply/assert pair.
func TestSecurityStateMigrations_Lifecycle(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()

	type testCase struct {
		name string
		run  func(t *testing.T)
	}

	cases := []testCase{
		{
			name: "re-applying is a no-op",
			run: func(t *testing.T) {
				db, p := freshSecurityState(t, set)

				_, err := p.Up(t.Context())
				require.NoError(t, err)

				beforeCount := appliedVersionCount(t, db, migrate.SecurityStateVersionTable)
				var relfilenodeBefore string
				require.NoError(t, db.QueryRowContext(t.Context(),
					`SELECT pg_relation_filenode('sessions')::text`).Scan(&relfilenodeBefore))

				results, err := p.Up(t.Context())
				require.NoError(t, err)
				assert.Empty(t, results, "no pending migrations to apply")
				assert.Equal(t, beforeCount, appliedVersionCount(t, db, migrate.SecurityStateVersionTable))

				var relfilenodeAfter string
				require.NoError(t, db.QueryRowContext(t.Context(),
					`SELECT pg_relation_filenode('sessions')::text`).Scan(&relfilenodeAfter))
				assert.Equal(t, relfilenodeBefore, relfilenodeAfter, "sessions was not rewritten")
			},
		},
		{
			name: "failing migration leaves nothing",
			run: func(t *testing.T) {
				db := RunTestPostgres(t).DB
				p := provider(t, db, os.DirFS("."), "testdata/migrations/fails_partway", "goose_fails_partway")
				rollBackAtCleanup(t, db, p, "goose_fails_partway")

				_, err := p.Up(t.Context())
				require.Error(t, err)

				assert.True(t, regclassExists(t, db, "ok_table"), "the first migration still applied")
				assert.False(t, regclassExists(t, db, "half_a"), "the failing migration's own table did not survive")
				assert.Equal(t, 1, appliedVersionCount(t, db, "goose_fails_partway"),
					"only the first migration's version is recorded")
			},
		},
		{
			name: "full rollback",
			run: func(t *testing.T) {
				db, p := freshSecurityState(t, set)

				_, err := p.Up(t.Context())
				require.NoError(t, err)
				_, err = p.DownTo(t.Context(), 0)
				require.NoError(t, err)

				for _, tbl := range securityStateTables {
					assert.False(t, regclassExists(t, db, tbl), "table %s should be gone", tbl)
				}
				assert.Equal(t, 0, appliedVersionCount(t, db, migrate.SecurityStateVersionTable))
			},
		},
		{
			name: "table already dropped",
			run: func(t *testing.T) {
				db, p := freshSecurityState(t, set)

				_, err := p.Up(t.Context())
				require.NoError(t, err)

				_, err = db.ExecContext(t.Context(), `DROP TABLE oidc_links`)
				require.NoError(t, err)

				_, err = p.DownTo(t.Context(), 0)
				require.NoError(t, err, "rollback succeeds even though a table was already dropped")
			},
		},
		{
			name: "re-apply after rollback",
			run: func(t *testing.T) {
				db, p := freshSecurityState(t, set)

				_, err := p.Up(t.Context())
				require.NoError(t, err)
				_, err = p.DownTo(t.Context(), 0)
				require.NoError(t, err)

				_, err = p.Up(t.Context())
				require.NoError(t, err)

				for _, tbl := range securityStateTables {
					assert.True(t, regclassExists(t, db, tbl), "table %s should exist", tbl)
				}
			},
		},
		{
			name: "each migration's Down executed on its own",
			run: func(t *testing.T) {
				db, p := freshSecurityState(t, set)

				_, err := p.Up(t.Context())
				require.NoError(t, err)

				sub, err := fs.Sub(set.FS(), set.Dir)
				require.NoError(t, err)
				entries, err := fs.ReadDir(sub, ".")
				require.NoError(t, err)
				require.Len(t, entries, securityStateMigrationCount,
					"extend this case if the set gains another migration file")

				// Newest first, the order a rollback runs them in.
				for _, e := range slices.Backward(entries) {
					runDownSection(t, db, sub, e.Name())
				}

				for _, tbl := range securityStateTables {
					assert.False(t, regclassExists(t, db, tbl), "table %s should be gone after its own Down", tbl)
				}
				assert.Equal(t, securityStateMigrationCount, appliedVersionCount(t, db, migrate.SecurityStateVersionTable),
					"the version table itself is untouched by executing the Down section directly")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.run(t)
		})
	}
}

// TestGooseDirect applies the embedded security-state set with exactly the
// goose recipe ExampleSet documents — a database.Store for the PostgreSQL
// dialect named after the consumer's version table, handed to a provider
// opened with DialectCustom — so the recipe a consumer copies is the one
// tested. It proves every table, column and index exists as the set defines
// it by reusing the schema checks, then that DownTo(0) leaves no table but the
// version table behind.
func TestGooseDirect(t *testing.T) {
	t.Parallel()

	const versionTable = "app_security_versions"

	db := RunTestPostgres(t).DB
	set := migrate.SecurityState()

	// The recipe, as ExampleSet spells it.
	fsys, err := fs.Sub(set.FS(), set.Dir)
	require.NoError(t, err)
	store, err := database.NewStore(database.DialectPostgres, versionTable)
	require.NoError(t, err)
	p, err := goose.NewProvider(goose.DialectCustom, db, fsys, goose.WithStore(store))
	require.NoError(t, err)
	rollBackAtCleanup(t, db, p, versionTable)

	_, err = p.Up(t.Context())
	require.NoError(t, err)

	// A non-parallel wrapper: runSchemaChecks's own subtests call
	// t.Parallel(), which only pauses them until this function returns, so
	// checking the schema and rolling back must not be two steps of the same
	// parent test — the rollback would run while the parallel checks are
	// still paused, before they ever query the database. Wrapping them in a
	// subtest that is not itself parallel forces this t.Run call to block
	// until every check underneath it has actually run.
	t.Run("schema", func(t *testing.T) {
		runSchemaChecks(t, db, securityStateSchemaChecks(versionTable))
	})

	_, err = p.DownTo(t.Context(), 0)
	require.NoError(t, err)

	assertNoLeftoverTables(t.Context(), t, db, versionTable)
	assert.Equal(t, 0, appliedVersionCount(t, db, versionTable))
}

// sessionStoreOpener is one durable session store, opened over the
// connection a test migrated; sessionStoreOpeners lists them.
type sessionStoreOpener struct {
	name string
	open func(t *testing.T, conn PostgresConn, c seal.Cipher) session.Store
}

func sessionStoreOpeners() []sessionStoreOpener {
	return []sessionStoreOpener{
		{
			name: "sqlstore",
			open: func(t *testing.T, conn PostgresConn, c seal.Cipher) session.Store {
				s, err := sqlstore.NewSessionStore(conn.DB, c)
				require.NoError(t, err)
				return s
			},
		},
		{
			name: "pgx",
			open: func(t *testing.T, conn PostgresConn, c seal.Cipher) session.Store {
				pool, err := pgxpool.New(t.Context(), conn.DSN)
				require.NoError(t, err)
				t.Cleanup(pool.Close)

				s, err := pgxstore.NewSessionStore(pool, c)
				require.NoError(t, err)
				return s
			},
		},
		{
			name: "gorm",
			open: func(t *testing.T, conn PostgresConn, c seal.Cipher) session.Store {
				db, err := gormdb.Open(postgres.Open(conn.DSN), &gormdb.Config{DisableAutomaticPing: true})
				require.NoError(t, err)
				sqlDB, err := db.DB()
				require.NoError(t, err)
				t.Cleanup(func() { _ = sqlDB.Close() })

				s, err := gormstore.NewSessionStore(db, c)
				require.NoError(t, err)
				return s
			},
		},
	}
}

// A row written before the strict-rotation mark existed, superseded or not,
// reads back through each store as not marked: a rotation from before the
// mark was not strict.
func TestSecurityStateMigrations_StrictMarkReadsBackUnmarked(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()

	for _, tc := range sessionStoreOpeners() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conn := RunTestPostgres(t)
			p := provider(t, conn.DB, set.FS(), set.Dir, migrate.SecurityStateVersionTable)
			rollBackAtCleanup(t, conn.DB, p, migrate.SecurityStateVersionTable)

			_, err := p.UpTo(t.Context(), versionSessionFamilies)
			require.NoError(t, err)

			const (
				supersededID   = "a-superseded-session-from-before-the-mark"
				unsupersededID = "a-live-session-from-before-the-mark"
			)
			supersededDigest := sha256.Sum256([]byte(supersededID))
			unsupersededDigest := sha256.Sum256([]byte(unsupersededID))
			_, err = conn.DB.ExecContext(t.Context(), `INSERT INTO sessions
				(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at,
				 superseded_at, accept_until, retain_until)
				VALUES ('0192f000-0000-7000-8000-0000000000c1', $1, 'u', '2026-09-01', '2026-09-01',
				        '2099-01-01', '2099-01-01', '2026-09-01', '2026-09-01', '2099-01-01')`,
				supersededDigest[:])
			require.NoError(t, err)
			_, err = conn.DB.ExecContext(t.Context(), `INSERT INTO sessions
				(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at)
				VALUES ('0192f000-0000-7000-8000-0000000000c2', $1, 'u', '2026-09-01', '2026-09-01',
				        '2099-01-01', '2099-01-01')`, unsupersededDigest[:])
			require.NoError(t, err)

			_, err = p.Up(t.Context())
			require.NoError(t, err)

			store := tc.open(t, conn, storefix.TestCipher(t))

			superseded, err := store.Load(t.Context(), supersededID)
			require.NoError(t, err)
			assert.False(t, superseded.SupersededAt.IsZero(), "the row is superseded")
			assert.False(t, superseded.RotatedStrictly, "a rotation from before the mark was not strict")

			live, err := store.Load(t.Context(), unsupersededID)
			require.NoError(t, err)
			assert.False(t, live.RotatedStrictly)
		})
	}
}

// TestSecurityStateMigrations_ExistingSessionsReadBack pins what a session
// written before the session-families migration looks like through each
// durable store once the migration has run: a family of its own, created when
// it was, and no retention deadline. The schema cases above read the columns;
// this one reads the rows as a consumer's code does, through the stores.
func TestSecurityStateMigrations_ExistingSessionsReadBack(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()

	cases := sessionStoreOpeners()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conn := RunTestPostgres(t)
			p := provider(t, conn.DB, set.FS(), set.Dir, migrate.SecurityStateVersionTable)
			rollBackAtCleanup(t, conn.DB, p, migrate.SecurityStateVersionTable)

			_, err := p.UpTo(t.Context(), versionSecurityState)
			require.NoError(t, err)

			const (
				sessionID = "a-session-written-by-older-code"
				rowID     = "0192f000-0000-7000-8000-0000000000a1"
			)
			created := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
			digest := sha256.Sum256([]byte(sessionID))
			_, err = conn.DB.ExecContext(t.Context(), `INSERT INTO sessions
				(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at)
				VALUES ($1, $2, 'u', $3, $3, '2099-01-01', '2099-01-01')`,
				rowID, digest[:], created)
			require.NoError(t, err)

			_, err = p.Up(t.Context())
			require.NoError(t, err)

			got, err := tc.open(t, conn, storefix.TestCipher(t)).Load(t.Context(), sessionID)
			require.NoError(t, err)

			assert.Equal(t, rowID, got.FamilyID.String(), "the row is a family of its own")
			assert.True(t, got.CreatedAt.Equal(created), "created_at is kept, got %s", got.CreatedAt)
			assert.True(t, got.FamilyCreatedAt.Equal(got.CreatedAt),
				"the family was created when the row was: %s, want %s", got.FamilyCreatedAt, got.CreatedAt)
			assert.True(t, got.RetainUntil.IsZero(), "a row from before the column has no retention deadline")
		})
	}
}

// TestSecurityStateMigrations_SessionSignIns pins the sign-in state
// migration: five nullable text columns (the sign-in metadata, the key
// binding's kind and thumbprint, and the sealed CSRF token) and no index, a
// row from before it that reads back with all five null, an insert by a
// writer from before it that still succeeds, and a rollback that restores the
// previous shape.
func TestSecurityStateMigrations_SessionSignIns(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()
	columns := []string{"client_ip", "user_agent", "binding_kind", "binding_thumbprint", "csrf_token"}

	type testCase struct {
		name string
		run  func(t *testing.T, db *sql.DB, p *goose.Provider)
	}

	cases := []testCase{
		{
			name: "adds five nullable text columns and no index",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				_, err := p.UpTo(t.Context(), versionStrictRotation)
				require.NoError(t, err)
				before := sessionColumnsAndIndexes(t, db)

				_, err = p.Up(t.Context())
				require.NoError(t, err)
				after := sessionColumnsAndIndexes(t, db)

				for _, c := range columns {
					assert.Contains(t, after, "col "+c+" text NULL")
				}
				var added []string
				for _, line := range after {
					if !slices.Contains(before, line) {
						added = append(added, line)
					}
				}
				assert.Len(t, added, len(columns), "only the five columns are added, no index: %v", added)
			},
		},
		{
			name: "a populated row from before the migration reads back with every new column null",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				_, err := p.UpTo(t.Context(), versionStrictRotation)
				require.NoError(t, err)

				_, err = db.ExecContext(t.Context(), `INSERT INTO sessions
					(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at,
					 external_id_token, data)
					VALUES ('0192f000-0000-7000-8000-0000000000d1', '\x01', 'u', now(), now(), now(), now(),
					        'sealed', '{"k":"v"}')`)
				require.NoError(t, err)

				_, err = p.Up(t.Context())
				require.NoError(t, err)

				var nulls int
				require.NoError(t, db.QueryRowContext(t.Context(), `SELECT
					(client_ip IS NULL)::int + (user_agent IS NULL)::int + (binding_kind IS NULL)::int
					+ (binding_thumbprint IS NULL)::int + (csrf_token IS NULL)::int
					FROM sessions WHERE id = '0192f000-0000-7000-8000-0000000000d1'`).Scan(&nulls))
				assert.Equal(t, len(columns), nulls, "an existing row has no metadata, no binding and no token")
			},
		},
		{
			name: "an older writer's insert still succeeds",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				_, err := p.Up(t.Context())
				require.NoError(t, err)

				_, err = db.ExecContext(t.Context(), `INSERT INTO sessions
					(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at)
					VALUES ('0192f000-0000-7000-8000-0000000000d2', '\x02', 'u', now(), now(), now(), now())`)
				require.NoError(t, err)
			},
		},
		{
			name: "rollback restores the previous columns and indexes",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				_, err := p.UpTo(t.Context(), versionStrictRotation)
				require.NoError(t, err)
				before := sessionColumnsAndIndexes(t, db)

				_, err = p.UpTo(t.Context(), versionSessionSignIns)
				require.NoError(t, err)
				require.NotEqual(t, before, sessionColumnsAndIndexes(t, db), "the migration changed the sessions table")

				_, err = p.Down(t.Context())
				require.NoError(t, err)

				assert.Equal(t, before, sessionColumnsAndIndexes(t, db))
				assert.Equal(t, 3, appliedVersionCount(t, db, migrate.SecurityStateVersionTable))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db, p := freshSecurityState(t, set)
			tc.run(t, db, p)
		})
	}
}

// A session written before the sign-in state migration reads back through
// each durable store unbound, with no sign-in metadata and no CSRF token, and
// its sealed ID token still opens.
func TestSecurityStateMigrations_SignInStateReadsBackEmpty(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()

	for _, tc := range sessionStoreOpeners() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conn := RunTestPostgres(t)
			p := provider(t, conn.DB, set.FS(), set.Dir, migrate.SecurityStateVersionTable)
			rollBackAtCleanup(t, conn.DB, p, migrate.SecurityStateVersionTable)

			_, err := p.UpTo(t.Context(), versionStrictRotation)
			require.NoError(t, err)

			const sessionID = "a-session-from-before-the-sign-in-state"
			digest := sha256.Sum256([]byte(sessionID))
			_, err = conn.DB.ExecContext(t.Context(), `INSERT INTO sessions
				(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at)
				VALUES ('0192f000-0000-7000-8000-0000000000d3', $1, 'u', '2026-09-01', '2026-09-01',
				        '2099-01-01', '2099-01-01')`, digest[:])
			require.NoError(t, err)

			_, err = p.Up(t.Context())
			require.NoError(t, err)

			store := tc.open(t, conn, storefix.TestCipher(t))
			got, err := store.Load(t.Context(), sessionID)
			require.NoError(t, err)
			assert.True(t, got.KeyBinding.IsZero(), "an existing row is unbound")
			assert.Empty(t, got.ClientIP)
			assert.Empty(t, got.UserAgent)
			assert.Empty(t, got.CSRFToken, "an existing row has no token")

			listed, err := store.ListByUser(t.Context(), "u", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
			require.NoError(t, err)
			require.Len(t, listed, 1, "an existing row is listed")
			assert.Empty(t, listed[0].CSRFToken)
		})
	}
}

// providerOutsideSchema describes every table of the set outside the provider's migration,
// as sorted column and index lines: what the migration must leave as it found it.
func providerOutsideSchema(t *testing.T, db *sql.DB) []string {
	t.Helper()

	lines := queryStrings(t, db, `SELECT c.relname || ' col ' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod)
	        || CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE ' NULL' END
	        || coalesce(' DEFAULT ' || pg_get_expr(d.adbin, d.adrelid), '')
	   FROM pg_attribute a
	   JOIN pg_class c ON c.oid = a.attrelid
	   JOIN pg_namespace n ON n.oid = c.relnamespace
	   LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
	  WHERE n.nspname = current_schema() AND c.relkind = 'r'
	    AND a.attnum > 0 AND NOT a.attisdropped AND c.relname NOT LIKE 'op\_%'
	  UNION ALL
	  SELECT tablename || ' idx ' || indexdef FROM pg_indexes
	   WHERE schemaname = current_schema() AND tablename NOT LIKE 'op\_%'`)
	slices.Sort(lines)

	return lines
}

// sessionRows returns the stored sessions, each as every column's value.
func sessionRows(t *testing.T, db *sql.DB) []string {
	t.Helper()

	return queryStrings(t, db, `SELECT to_jsonb(s)::text FROM sessions s ORDER BY id`)
}

// holdSessions stores one plain and one superseded session.
func holdSessions(t *testing.T, db *sql.DB) {
	t.Helper()

	_, err := db.ExecContext(t.Context(), `INSERT INTO sessions
		(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at,
		 superseded_at, accept_until, retain_until, client_ip, data)
		VALUES ('0192f000-0000-7000-8000-0000000000c1', '\x01', 'u-1', now(), now(), now(), now(),
		        NULL, NULL, NULL, '203.0.113.7', '{"k":"v"}'),
		       ('0192f000-0000-7000-8000-0000000000c2', '\x02', 'u-2', now(), now(), now(), now(),
		        now(), now(), now(), NULL, '{}')`)
	require.NoError(t, err)
}

// orderedShape describes table's columns in their order, then its indexes with the
// table's own name replaced by "T", so two tables of one shape compare equal.
func orderedShape(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()

	columns := queryStrings(t, db, `SELECT a.attname || ' ' || format_type(a.atttypid, a.atttypmod)
	        || CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE ' NULL' END
	        || coalesce(' DEFAULT ' || pg_get_expr(d.adbin, d.adrelid), '')
	   FROM pg_attribute a
	   JOIN pg_class c ON c.oid = a.attrelid
	   JOIN pg_namespace n ON n.oid = c.relnamespace
	   LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
	  WHERE n.nspname = current_schema() AND c.relname = $1 AND a.attnum > 0 AND NOT a.attisdropped
	  ORDER BY a.attnum`, table)

	indexes := queryStrings(t, db, `SELECT indexdef FROM pg_indexes
	   WHERE schemaname = current_schema() AND tablename = $1`, table)
	for i, def := range indexes {
		indexes[i] = strings.ReplaceAll(def, table, "T")
	}
	slices.Sort(indexes)

	return append(columns, indexes...)
}

// recordColumns names the column holding each field of one port record. A field mapped
// to "" is deliberately not a column of table, and the entry's comment says why.
type recordColumns struct {
	record  any
	table   string
	columns map[string]string
}

// flatSignIn maps a SignIn's fields to the columns of a table that can be selected by
// its sign-in.
var flatSignIn = map[string]string{
	"User":              "user_ref",
	"Family":            "sign_in_family",
	"AuthenticatedAt":   "authenticated_at",
	"AMR":               "amr",
	"ACR":               "acr",
	"AbsoluteExpiresAt": "sign_in_absolute_expires_at",
	"ExternalIssuer":    "external_issuer",
	"ExternalSessionID": "external_session_id",
}

// providerRecordColumns covers every record the provider's ports hold.
var providerRecordColumns = []recordColumns{
	{
		// Secret is nil once registered: only the digests in RegisteredClient.Secrets are kept.
		record: oidcprovider.Client{},
		table:  "op_clients",
		columns: map[string]string{ //nolint:gosec // field-to-column names, no credential
			"ID": "client_id", "Name": "name", "Type": "client_type", "ApplicationType": "application_type",
			"AuthMethod": "auth_method", "PKCE": "pkce", "Secret": "", "JWKS": "jwks", "JWKSURI": "jwks_uri",
			"RedirectURIs": "redirect_uris", "PostLogoutRedirectURIs": "post_logout_redirect_uris",
			"BackChannelLogoutURI": "back_channel_logout_uri", "Scopes": "scopes", "Resources": "resources",
			"DefaultAudience": "default_audience", "ResourceIdentifier": "resource_identifier",
			"GrantTypes": "grant_types", "FirstParty": "first_party", "OfflineAccess": "offline_access",
			"IDTokenAlg": "id_token_alg", "IDTokenLifetime": "id_token_lifetime_ns",
			"AccessTokenLifetime": "access_token_lifetime_ns", "OpaqueAccessTokens": "opaque_access_tokens",
			"RequireBinding": "require_binding", "RefreshGrace": "refresh_grace_ns",
			"GrantIdleTimeout": "grant_idle_timeout_ns", "GrantAbsoluteLifetime": "grant_absolute_lifetime_ns",
			"DisableRotation": "disable_rotation", "EndGrantsWithSignIn": "end_grants_with_sign_in",
			"KeepPublicWebGrantsPastSignIn": "keep_public_web_grants_past_sign_in", "Metadata": "metadata",
		},
	},
	{
		// The embedded Client is the entry above.
		record:  oidcprovider.RegisteredClient{},
		table:   "op_clients",
		columns: map[string]string{"Client": "", "Secrets": "secrets"},
	},
	{
		record: oidcprovider.PendingRequest{},
		table:  "op_pending_requests",
		columns: map[string]string{ //nolint:gosec // field-to-column names, no credential
			"ID": "id", "HandleDigest": "handle_digest", "FlowDigest": "flow_digest", "ClientID": "client_id",
			"RedirectURI": "redirect_uri", "Scopes": "scopes", "Resources": "resources", "State": "state",
			"Nonce": "nonce", "Challenge": "challenge", "Prompt": "prompt", "MaxAge": "max_age",
			"IDTokenHintSubject": "id_token_hint_subject", "DPoPJKT": "dpop_jkt", "LoginHint": "login_hint",
			"UILocales": "ui_locales", "ClaimsLocales": "claims_locales", "ACRValues": "acr_values",
			"ParkedAt": "parked_at", "ExpiresAt": "expires_at", "Stage": "stage", "SignIn": "sign_in",
		},
	},
	{
		// SignIn is flattened, in the entry after this one, as a selector reads its fields.
		record: oidcprovider.BrowserSession{},
		table:  "op_browser_sessions",
		columns: map[string]string{
			"Digest": "digest", "SignIn": "", "IdleExpiresAt": "idle_expires_at",
			"AbsoluteExpiresAt": "absolute_expires_at",
		},
	},
	{record: oidcprovider.SignIn{}, table: "op_browser_sessions", columns: flatSignIn},
	{
		// SignIn is flattened, in the entry after this one, as a selector reads its fields.
		record: oidcprovider.CodeRecord{},
		table:  "op_authorization_codes",
		columns: map[string]string{
			"TokenID": "token_id", "ClientID": "client_id", "RedirectURI": "redirect_uri",
			"Challenge": "challenge", "Nonce": "nonce", "DPoPJKT": "dpop_jkt", "Scopes": "scopes",
			"Resources": "resources", "SignIn": "", "GrantFamily": "grant_family", "Offline": "offline",
			"EndsWithSignIn": "ends_with_sign_in", "ExpiresAt": "expires_at",
		},
	},
	{record: oidcprovider.SignIn{}, table: "op_authorization_codes", columns: flatSignIn},
	{
		record: oidcprovider.Consent{},
		table:  "op_consents",
		columns: map[string]string{
			"User": "user_ref", "ClientID": "client_id", "Scopes": "scopes", "Offline": "offline",
			"LastGivenAt": "last_given_at",
		},
	},
	{
		record: oidcprovider.Grant{},
		table:  "op_grants",
		columns: map[string]string{
			"Family": "family", "User": "user_ref", "ClientID": "client_id", "Scopes": "scopes",
			"Resources": "resources", "AuthTime": "auth_time", "AMR": "amr", "ACR": "acr",
			"KeyBinding": "key_binding", "CertBinding": "cert_binding", "CodeID": "code_id", "SignInFamily": "sign_in_family",
			"ExternalIssuer": "external_issuer", "ExternalSessionID": "external_session_id",
			"Offline": "offline", "EndsWithSignIn": "ends_with_sign_in", "HoldsLineage": "holds_lineage",
			"CreatedAt": "created_at", "ExpiresAt": "expires_at", "Revoked": "revoked",
			"RevokedAt": "revoked_at", "RevokeCause": "revoke_cause", "SignInEndedAt": "sign_in_ended_at",
		},
	},
	{
		record: oidcprovider.AccessTokenRecord{},
		table:  "op_access_tokens",
		columns: map[string]string{
			"ID": "id", "Digest": "digest", "GrantFamily": "grant_family", "ClientID": "client_id",
			"User": "user_ref", "Scopes": "scopes", "Audience": "audience", "Confirmation": "confirmation",
			"IssuedAt": "issued_at", "ExpiresAt": "expires_at", "Revoked": "revoked",
		},
	},
}

// credentialNamedColumns is every provider column whose name could suggest a credential,
// with why it holds none. A new one must be added here, by someone who has checked.
var credentialNamedColumns = []string{
	"op_authorization_codes.token_id",           // the code token's identifier, not its secret
	"op_clients.access_token_lifetime_ns",       // a duration
	"op_clients.id_token_alg",                   // an algorithm's name
	"op_clients.id_token_lifetime_ns",           // a duration
	"op_clients.opaque_access_tokens",           // a setting
	"op_clients.secrets",                        // digests and deadlines only
	"op_grants.code_id",                         // the code's identifier, not its secret
	"op_pending_requests.flow_digest",           // a digest
	"op_pending_requests.handle_digest",         // a digest
	"op_pending_requests.id_token_hint_subject", // a subject
	"op_refresh_tokens.password_change_pending", // a flag
	"op_refresh_tokens.csrf_token",              // sealed, as on sessions
	"op_refresh_tokens.external_id_token",       // sealed, as on sessions
}

// opLookup is one lookup a provider store makes, and the index that must serve it.
type opLookup struct {
	name    string
	table   string
	index   string
	where   string
	args    string
	columns []string
}

// signInLookups returns the five shapes SignInSelector.Validate accepts, on table,
// whose index for the user alone is byUser.
func signInLookups(table, byUser string) []opLookup {
	const (
		user   = `'u-1'`
		family = `'0192f000-0000-7000-8000-0000000000d1'`
		issuer = `'https://idp.example.com'`
		stream = `'x-9'`
	)

	return []opLookup{
		{
			name: table + " by family", table: table, index: table + "_sign_in",
			where: `sign_in_family = $1`, args: family,
			columns: []string{"sign_in_family"},
		},
		{
			name: table + " by user", table: table, index: byUser,
			where: `user_ref = $1`, args: user,
			columns: []string{"user_ref"},
		},
		{
			name: table + " by user except a family", table: table, index: byUser,
			where: `user_ref = $1 AND sign_in_family IS DISTINCT FROM $2`, args: user + `, ` + family,
			columns: []string{"user_ref"},
		},
		{
			name: table + " by upstream session", table: table, index: table + "_external_session",
			where: `external_issuer = $1 AND external_session_id = $2`, args: issuer + `, ` + stream,
			columns: []string{"external_issuer", "external_session_id"},
		},
		{
			name: table + " by user and upstream issuer", table: table, index: table + "_user_issuer",
			where: `user_ref = $1 AND external_issuer = $2`, args: user + `, ` + issuer,
			columns: []string{"user_ref", "external_issuer"},
		},
	}
}

// providerLookups is every lookup the provider's stores make other than by primary key.
func providerLookups() []opLookup {
	const (
		digest = `'\x01'::bytea`
		user   = `'u-1'`
		client = `'billing-web'`
		when   = `'2026-11-04T00:00:00Z'::timestamptz`
	)

	expired := func(name, table, index, column string) opLookup {
		return opLookup{
			name: name, table: table, index: index,
			where: column + ` < $1`, args: when, columns: []string{column},
		}
	}
	userAndClient := func(name, table, index string) opLookup {
		return opLookup{
			name: name, table: table, index: index,
			where: `user_ref = $1 AND client_id = $2`, args: user + `, ` + client,
			columns: []string{"user_ref", "client_id"},
		}
	}

	lookups := []opLookup{
		{
			name: "client by its identifier", table: "op_clients", index: "op_clients_client_id_key",
			where: `client_id = $1`, args: client, columns: []string{"client_id"},
		},
		{
			name: "pending request by handle", table: "op_pending_requests", index: "op_pending_requests_handle_digest_key",
			where: `handle_digest = $1`, args: digest, columns: []string{"handle_digest"},
		},
		{
			name: "browser session by digest", table: "op_browser_sessions", index: "op_browser_sessions_digest_key",
			where: `digest = $1`, args: digest, columns: []string{"digest"},
		},
		{
			name: "consents of a user", table: "op_consents", index: "op_consents_user_ref_client_id_key",
			where: `user_ref = $1`, args: user, columns: []string{"user_ref"},
		},
		{
			name: "assertion identifier of a client", table: "op_client_assertions", index: "op_client_assertions_client_id_jti_key",
			where: `client_id = $1 AND jti = $2`, args: client + `, 'j-1'`, columns: []string{"client_id", "jti"},
		},
		userAndClient("held codes of a user and client", "op_authorization_codes", "op_authorization_codes_user_client"),
		userAndClient("consent of a user and client", "op_consents", "op_consents_user_ref_client_id_key"),
		userAndClient("grants of a user and client", "op_grants", "op_grants_user_client"),
		expired("expired pending requests", "op_pending_requests", "op_pending_requests_expiry", "expires_at"),
		expired("browser sessions past idle", "op_browser_sessions", "op_browser_sessions_idle_expiry", "idle_expires_at"),
		expired("browser sessions past absolute", "op_browser_sessions", "op_browser_sessions_absolute_expiry", "absolute_expires_at"),
		expired("expired codes", "op_authorization_codes", "op_authorization_codes_expiry", "expires_at"),
		expired("expired grants", "op_grants", "op_grants_expiry", "expires_at"),
		expired("long revoked grants", "op_grants", "op_grants_revoked", "revoked_at"),
		expired("expired access tokens", "op_access_tokens", "op_access_tokens_expiry", "expires_at"),
		expired("expired assertion identifiers", "op_client_assertions", "op_client_assertions_expiry", "held_until"),
	}
	lookups = append(lookups, signInLookups("op_grants", "op_grants_user")...)
	lookups = append(lookups, signInLookups("op_authorization_codes", "op_authorization_codes_user_client")...)
	lookups = append(lookups, signInLookups("op_browser_sessions", "op_browser_sessions_user_issuer")...)

	return lookups
}

// genericPlan returns the plan of lookup with its index as the table's only choice: in
// a transaction it rolls back, every other plain index of the table is dropped and
// sequential scans are priced out, so what an empty table's statistics would pick cannot
// decide the answer. The plan is the generic one a prepared statement can reach, in which
// a parameter proves no partial index's predicate, so an index only a literal value can
// use does not count.
func genericPlan(t *testing.T, db *sql.DB, lookup opLookup) string {
	t.Helper()

	conn, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer func() { assert.NoError(t, conn.Close()) }()

	tx, err := conn.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { assert.NoError(t, tx.Rollback()) }()

	exec := func(stmt string) {
		t.Helper()

		_, err := tx.ExecContext(t.Context(), stmt)
		require.NoError(t, err, stmt)
	}

	others := queryStrings(t, db, `SELECT indexname FROM pg_indexes
		WHERE schemaname = current_schema() AND tablename = $1 AND indexname <> $2
		  AND indexdef NOT LIKE 'CREATE UNIQUE %'`, lookup.table, lookup.index)
	for _, index := range others {
		exec(`DROP INDEX ` + index)
	}
	exec(`SET LOCAL enable_seqscan = off`)
	exec(`SET LOCAL plan_cache_mode = force_generic_plan`)
	exec(`PREPARE op_lookup AS SELECT 1 FROM ` + lookup.table + ` WHERE ` + lookup.where)
	defer exec(`DEALLOCATE op_lookup`)

	rows, err := tx.QueryContext(t.Context(), `EXPLAIN EXECUTE op_lookup(`+lookup.args+`)`)
	require.NoError(t, err)
	defer func() { assert.NoError(t, rows.Close()) }()

	var plan strings.Builder
	for rows.Next() {
		var line string
		require.NoError(t, rows.Scan(&line))
		plan.WriteString(line + "\n")
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())

	return plan.String()
}

// indexLeadingColumn returns the first column of the named index in the applied schema.
func indexLeadingColumn(t *testing.T, db *sql.DB, index string) string {
	t.Helper()

	got := queryStrings(t, db, `SELECT a.attname FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
		WHERE c.relname = $1 AND c.relnamespace = current_schema()::regnamespace`, index)
	require.Len(t, got, 1, "index %s", index)

	return got[0]
}

// indexCondition returns the plan's index condition, and "" when it has none.
func indexCondition(plan string) string {
	for line := range strings.SplitSeq(plan, "\n") {
		if strings.Contains(line, "Index Cond") {
			return line
		}
	}

	return ""
}

// TestMigrations pins the migrations this set adds on top of its own earlier tests.
//
// The cases share the theme, not a setup shape: some compare a database before and
// after the migration, and the rest read the applied schema.
func TestMigrations(t *testing.T) {
	t.Parallel()

	t.Run("oidc_provider", func(t *testing.T) {
		t.Parallel()

		set := migrate.SecurityState()

		type testCase struct {
			name string
			run  func(t *testing.T, db *sql.DB, p *goose.Provider)
		}

		cases := []testCase{
			{
				name: "the tables pgschema names are the provider's nine",
				run: func(t *testing.T, _ *sql.DB, _ *goose.Provider) {
					assert.ElementsMatch(t, providerTables, pgschema.OIDCProviderTables())
					assert.Contains(t, providerTables, pgschema.RefreshTokenTable)
				},
			},
			{
				name: "applied over a database holding sessions, the tables exist and the sessions are unchanged",
				run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
					_, err := p.UpTo(t.Context(), versionSessionSignIns)
					require.NoError(t, err)
					holdSessions(t, db)
					rows, schema := sessionRows(t, db), providerOutsideSchema(t, db)
					require.Len(t, rows, 2)

					_, err = p.Up(t.Context())
					require.NoError(t, err)

					for _, tbl := range providerTables {
						assert.True(t, regclassExists(t, db, tbl), "table %s should exist", tbl)
					}
					assert.Equal(t, rows, sessionRows(t, db))
					assert.Equal(t, schema, providerOutsideSchema(t, db))
				},
			},
			{
				name: "rolled back, exactly the nine are gone",
				run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
					_, err := p.UpTo(t.Context(), versionSessionSignIns)
					require.NoError(t, err)
					holdSessions(t, db)
					rows, schema := sessionRows(t, db), providerOutsideSchema(t, db)

					_, err = p.Up(t.Context())
					require.NoError(t, err)
					for _, tbl := range providerTables {
						require.True(t, regclassExists(t, db, tbl), "table %s should exist before the rollback", tbl)
					}

					_, err = p.DownTo(t.Context(), versionSessionSignIns)
					require.NoError(t, err)

					for _, tbl := range providerTables {
						assert.False(t, regclassExists(t, db, tbl), "table %s should be gone", tbl)
					}
					assert.Equal(t, rows, sessionRows(t, db))
					assert.Equal(t, schema, providerOutsideSchema(t, db))
				},
			},
			{
				name: "the lineage table is the sessions table, column by column and index by index",
				run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
					_, err := p.Up(t.Context())
					require.NoError(t, err)

					sessions := orderedShape(t, db, "sessions")
					require.NotEmpty(t, sessions)
					assert.Equal(t, sessions, orderedShape(t, db, pgschema.RefreshTokenTable))
				},
			},
			{
				name: "a session statement names no column the lineage table lacks",
				run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
					_, err := p.Up(t.Context())
					require.NoError(t, err)

					// A row written by the session store's own insert, over the fixed name.
					insert := strings.ReplaceAll(pgschema.SessionInsert, "sessions", pgschema.RefreshTokenTable)
					result, err := db.ExecContext(t.Context(), insert,
						"0192f000-0000-7000-8000-0000000000e1", []byte{1}, "u-1", time.Now(), time.Now(), time.Now(), time.Now(),
						"", 0, nil, false, "", "", "", "", "{}", nil, nil, nil, "[]", "", false,
						"0192f000-0000-7000-8000-0000000000e2", time.Now(), nil, nil, nil, nil, time.Now(), nil,
						nil, nil, nil, nil, nil)
					require.NoError(t, err)
					n, err := result.RowsAffected()
					require.NoError(t, err)
					assert.Equal(t, int64(1), n)

					assert.Empty(t, sessionRows(t, db), "the lineage row is not a session")
				},
			},
			{
				name: "a grant can be a revocation recorded first, with everything else unset",
				run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
					_, err := p.Up(t.Context())
					require.NoError(t, err)

					_, err = db.ExecContext(t.Context(), `INSERT INTO op_grants (family, revoked, revoked_at, revoke_cause, sign_in_ended_at)
						VALUES ('0192f000-0000-7000-8000-0000000000f1', true, now(), 'sign_in_ended', now())`)
					require.NoError(t, err)

					got := queryStrings(t, db, `SELECT concat_ws('|', user_ref = '', client_id = '', scopes = '[]', resources = '[]',
							amr = '[]', acr = '', key_binding = '', cert_binding = '', external_issuer = '', external_session_id = '',
							NOT offline, NOT ends_with_sign_in, NOT holds_lineage,
							auth_time IS NULL, code_id IS NULL, sign_in_family IS NULL, created_at IS NULL, expires_at IS NULL)
						FROM op_grants`)
					assert.Equal(t, []string{"t|t|t|t|t|t|t|t|t|t|t|t|t|t|t|t|t|t"}, got,
						"no value is invented, and a NULL created_at is what tells it from a stored grant")
				},
			},
			{
				name: "a handle digest is one request's, and an assertion identifier one client's",
				run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
					_, err := p.Up(t.Context())
					require.NoError(t, err)

					affected := func(query string) int64 {
						t.Helper()

						result, err := db.ExecContext(t.Context(), query)
						require.NoError(t, err, query)
						n, err := result.RowsAffected()
						require.NoError(t, err)

						return n
					}

					pending := func(id string) string {
						return `INSERT INTO op_pending_requests (id, handle_digest, flow_digest, client_id, parked_at, expires_at, stage)
							VALUES ('` + id + `', '\x01', '\x02', 'billing-web', now(), now(), 0) ON CONFLICT (handle_digest) DO NOTHING`
					}
					assert.Equal(t, int64(1), affected(pending("0192f000-0000-7000-8000-000000000101")))
					assert.Equal(t, int64(0), affected(pending("0192f000-0000-7000-8000-000000000102")))

					assertion := func(id, client string) string {
						return `INSERT INTO op_client_assertions (id, client_id, jti, held_until)
							VALUES ('` + id + `', '` + client + `', 'j-1', now()) ON CONFLICT (client_id, jti) DO NOTHING`
					}
					assert.Equal(t, int64(1), affected(assertion("0192f000-0000-7000-8000-000000000103", "billing-web")))
					assert.Equal(t, int64(0), affected(assertion("0192f000-0000-7000-8000-000000000104", "billing-web")))
					assert.Equal(t, int64(1), affected(assertion("0192f000-0000-7000-8000-000000000105", "billing-ios")))
				},
			},
			{
				name: "no column is named for a credential it would hold in clear",
				run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
					_, err := p.Up(t.Context())
					require.NoError(t, err)

					got := queryStrings(t, db, `SELECT table_name || '.' || column_name FROM information_schema.columns
						WHERE table_schema = current_schema() AND table_name LIKE 'op\_%'
						  AND column_name ~ '(secret|token|code|handle|flow|credential|password|assertion)'`)
					assert.ElementsMatch(t, credentialNamedColumns, got)

					bytes := queryStrings(t, db, `SELECT table_name || '.' || column_name FROM information_schema.columns
						WHERE table_schema = current_schema() AND table_name LIKE 'op\_%' AND table_name <> 'op_clients'
						  AND table_name <> $1 AND data_type = 'bytea'`, pgschema.RefreshTokenTable)
					assert.ElementsMatch(t, []string{
						"op_pending_requests.handle_digest", "op_pending_requests.flow_digest",
						"op_browser_sessions.digest", "op_access_tokens.digest",
					}, bytes, "the only binary values the records hold are digests")
				},
			},
			{
				name: "every field of every provider record has its column",
				run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
					_, err := p.Up(t.Context())
					require.NoError(t, err)

					for _, rc := range providerRecordColumns {
						typ := reflect.TypeOf(rc.record)
						held := queryStrings(t, db, `SELECT column_name FROM information_schema.columns
							WHERE table_schema = current_schema() AND table_name = $1`, rc.table)
						for field := range typ.Fields() {
							column, named := rc.columns[field.Name]
							if !assert.True(t, named, "%s.%s is mapped to no column of %s", typ.Name(), field.Name, rc.table) || column == "" {
								continue
							}
							assert.Contains(t, held, column, "%s.%s", typ.Name(), field.Name)
						}
					}
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				db, p := freshSecurityState(t, set)
				tc.run(t, db, p)
			})
		}

		t.Run("lookups", func(t *testing.T) {
			t.Parallel()

			db, p := freshSecurityState(t, set)
			_, err := p.Up(t.Context())
			require.NoError(t, err)

			for _, lookup := range providerLookups() {
				t.Run(lookup.name, func(t *testing.T) {
					plan := genericPlan(t, db, lookup)

					assert.NotContains(t, plan, "Seq Scan", "no index serves this lookup")
					assert.Contains(t, plan, lookup.index)
					condition := indexCondition(plan)
					for _, column := range lookup.columns {
						assert.Contains(t, condition, column, "the plan does not seek on this column:\n%s", plan)
					}

					// An index seeks on a column only when it leads it, or follows columns the lookup
					// also names, so the kept index's leading column must be one the lookup names.
					assert.Contains(t, lookup.columns, indexLeadingColumn(t, db, lookup.index),
						"the index is not led by a looked-up column:\n%s", plan)
				})
			}
		})
	})
}
