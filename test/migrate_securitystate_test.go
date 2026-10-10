package test

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/migrate"
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

// securityStateTables lists the fifteen tables the security-state set creates.
var securityStateTables = []string{
	"sessions", "signing_keys", "login_attempts", "login_failure_streaks", "mfa_enrolments",
	"api_keys", "one_time_tokens", "oidc_links", "oidc_flows", "oidc_handoffs",
	"recovery_codes", "account_recoveries", "passkey_credentials", "passkey_user_handles",
	"rate_limit_buckets",
}

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
	"sessions": {
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
	},
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
	"sessions": {
		"CREATE UNIQUE INDEX sessions_pkey ON sessions USING btree (id)",
		"CREATE UNIQUE INDEX sessions_id_digest_key ON sessions USING btree (id_digest)",
		"CREATE INDEX sessions_external_session ON sessions USING btree (external_issuer, external_session_id) WHERE (external_session_id <> ''::text)",
		"CREATE INDEX sessions_user_issuer ON sessions USING btree (user_id, external_issuer) WHERE (external_issuer <> ''::text)",
		"CREATE INDEX sessions_user ON sessions USING btree (user_id)",
		"CREATE INDEX sessions_idle_expiry ON sessions USING btree (idle_expires_at)",
		"CREATE INDEX sessions_absolute_expiry ON sessions USING btree (absolute_expires_at)",
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
			name:  "fresh database has the fifteen tables and the version table",
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
			         WHERE column_name = 'user_id' AND table_schema = current_schema()`,
			assert: func(t *testing.T, rows []string) {
				// sessions, mfa_enrolments, api_keys, oidc_links, oidc_handoffs,
				// recovery_codes, account_recoveries, passkey_credentials,
				// passkey_user_handles
				require.Len(t, rows, 9)
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
			// HOT updates, and autovacuum that keeps up with a small table
			// whose rows are updated and pruned constantly.
			name: "rate_limit_buckets declares its own fill factor and autovacuum storage parameters",
			query: `SELECT unnest(c.reloptions) FROM pg_class c
			          JOIN pg_namespace n ON n.oid = c.relnamespace
			         WHERE n.nspname = current_schema() AND c.relname = 'rate_limit_buckets'`,
			assert: func(t *testing.T, rows []string) {
				assert.ElementsMatch(t, []string{
					"fillfactor=70",
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
				assert.Equal(t, 1, appliedVersionCount(t, db, migrate.SecurityStateVersionTable))
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
				assert.Equal(t, 1, appliedVersionCount(t, db, "auth_schema_versions"))
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
				assert.Equal(t, 1, appliedVersionCount(t, db, migrate.SecurityStateVersionTable))
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
				require.Len(t, entries, 1,
					"the set has exactly one migration file today; extend this case if it gains a second")

				runDownSection(t, db, sub, entries[0].Name())

				for _, tbl := range securityStateTables {
					assert.False(t, regclassExists(t, db, tbl), "table %s should be gone after its own Down", tbl)
				}
				assert.Equal(t, 1, appliedVersionCount(t, db, migrate.SecurityStateVersionTable),
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
