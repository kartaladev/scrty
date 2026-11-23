package test

import (
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/store/migrate"
)

// identityTables lists the eight tables the identity set holds once it is
// fully applied: every one under its scrty_ name.
var identityTables = prefixNames([]string{
	"groups", "organizations", "roles", "users", "assigned_roles", "resource_privileges", "password_history",
	"user_attributes",
})

// migratedIdentity returns a database the identity set alone has been applied
// to, with the leftover-table check turned on so this set's own test proves
// its rollback drops everything Up created.
func migratedIdentity(t *testing.T) *sql.DB {
	t.Helper()

	set := migrate.Identity()
	return RunTestPostgres(t,
		WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable),
		WithTestPostgresLeftoverTableCheck(),
	).DB
}

// TestIdentityMigrations_Independent pins the schema-migrations requirement
// that the identity set is independent of security state: each set applies
// alone without the other, rolling back the identity set never touches
// security state, and a consumer's own version table name is honoured.
func TestIdentityMigrations_Independent(t *testing.T) {
	t.Parallel()

	t.Run("identity set alone creates exactly the eight tables", func(t *testing.T) {
		t.Parallel()

		db := migratedIdentity(t)

		rows := queryStrings(t, db, `SELECT tablename FROM pg_tables WHERE schemaname = current_schema()`)
		want := append(slices.Clone(identityTables), migrate.IdentityVersionTable)
		assert.ElementsMatch(t, want, rows)
		assert.NotContains(t, rows, "scrty_sessions")
	})

	t.Run("security-state set alone creates no identity table", func(t *testing.T) {
		t.Parallel()

		set := migrate.SecurityState()
		db := RunTestPostgres(t,
			WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable),
			WithTestPostgresLeftoverTableCheck(),
		).DB

		rows := queryStrings(t, db, `SELECT tablename FROM pg_tables WHERE schemaname = current_schema()`)
		for _, tbl := range append(slices.Clone(identityTables), migrate.IdentityVersionTable) {
			assert.NotContains(t, rows, tbl, "the security-state set created identity table %s", tbl)
		}
	})

	t.Run("rolling back the identity set leaves security state intact", func(t *testing.T) {
		t.Parallel()

		ss := migrate.SecurityState()
		id := migrate.Identity()
		db := RunTestPostgres(t,
			WithTestPostgresMigrations(ss.FS(), ss.Dir, ss.VersionTable),
			WithTestPostgresMigrations(id.FS(), id.Dir, id.VersionTable),
		).DB

		p := provider(t, db, id.FS(), id.Dir, id.VersionTable)
		_, err := p.DownTo(t.Context(), 0)
		require.NoError(t, err)

		for _, tbl := range identityTables {
			assert.False(t, regclassExists(t, db, tbl), "table %s should be gone", tbl)
		}
		for _, tbl := range securityStateTables {
			assert.True(t, regclassExists(t, db, tbl), "table %s should still exist", tbl)
		}
		assert.Equal(t, securityStateMigrationCount, appliedVersionCount(t, db, ss.VersionTable))
		// The identity version records are gone: goose keeps only the
		// version-zero row it bootstraps its version table with.
		assert.Equal(t, []string{"0"},
			queryStrings(t, db, `SELECT version_id::text FROM `+id.VersionTable+` ORDER BY 1`))
	})

	t.Run("consumer version table records the version there", func(t *testing.T) {
		t.Parallel()

		set := migrate.Identity()
		db := RunTestPostgres(t,
			WithTestPostgresMigrations(set.FS(), set.Dir, "app_identity_versions"),
		).DB

		assert.Equal(t, 3, appliedVersionCount(t, db, "app_identity_versions"))
		assert.False(t, regclassExists(t, db, migrate.IdentityVersionTable))
	})
}

// identityStatements is every exported pgschema identity constant, by name,
// so a failure names which statement broke rather than which table.
var identityStatements = []struct {
	name string
	sql  string
}{
	{"UserByUsername", pgschema.UserByUsername},
	{"UserByID", pgschema.UserByID},
	{"GrantsByUser", pgschema.GrantsByUser},
	{"OrganizationByID", pgschema.OrganizationByID},
	{"GroupByID", pgschema.GroupByID},
	{"PrivilegesByRole", pgschema.PrivilegesByRole},
	{"InsertUser", pgschema.InsertUser},
	{"LockUserByUsername", pgschema.LockUserByUsername},
	{"DeleteGrantsByUser", pgschema.DeleteGrantsByUser},
	{"InsertGrant", pgschema.InsertGrant},
	{"MFARequiredByID", pgschema.MFARequiredByID},
	{"NewestHistory", pgschema.NewestHistory},
	{"InsertHistory", pgschema.InsertHistory},
	{"PruneHistory", pgschema.PruneHistory},
	{"RecentHistory", pgschema.RecentHistory},
	{"ForgetHistory", pgschema.ForgetHistory},
}

// TestIdentityQueriesMatchSchema PREPAREs every pgschema identity statement
// against the migrated identity schema, so a typo'd column or table name in
// internal/pgschema fails here rather than in a later dispatch's adapter.
// PREPARE never executes the statement, so this is safe for the writes too.
func TestIdentityQueriesMatchSchema(t *testing.T) {
	t.Parallel()

	db := migratedIdentity(t)

	for _, tc := range identityStatements {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stmt, err := db.PrepareContext(t.Context(), tc.sql)
			require.NoError(t, err, tc.sql)
			require.NoError(t, stmt.Close())
		})
	}
}

// identityColumns pins each identity table's exact columns, with their types,
// nullability and defaults. created_at, updated_at and the password hashes
// carry no default: every writer supplies them. password_changed_at is
// nullable, NULL meaning never recorded. mfa_required is NOT NULL DEFAULT
// false, so a NULL can never scan as "not required". scrty_password_history.seq
// is an identity column the table assigns (see identitySeqAlways).
var identityColumns = map[string][]column{
	"scrty_groups": {
		required("id", colUUID),
		required("name", colText),
		defaulted("internal", colBoolean, "false"),
		required("created_at", colTimestamptz),
		required("updated_at", colTimestamptz),
	},
	"scrty_organizations": {
		required("id", colUUID),
		required("name", colText),
		optional("group_id", colUUID),
		required("created_at", colTimestamptz),
		required("updated_at", colTimestamptz),
	},
	"scrty_roles": {
		required("id", colUUID),
		required("name", colText),
		defaulted("super_role", colBoolean, "false"),
		required("created_at", colTimestamptz),
		required("updated_at", colTimestamptz),
		defaulted("display_name", colText, defEmptyText),
		defaulted("description", colText, defEmptyText),
		defaulted("labels", colTextArray, defEmptyTextArray),
		defaulted("version", colBigint, "1"),
	},
	"scrty_users": {
		required("id", colUUID),
		defaulted("name", colText, defEmptyText),
		required("username", colText),
		required("password", colBytea),
		defaulted("active", colBoolean, "true"),
		defaulted("role", colText, defEmptyText),
		optional("organization_id", colUUID),
		optional("password_changed_at", colTimestamptz),
		defaulted("mfa_required", colBoolean, "false"),
		required("created_at", colTimestamptz),
		required("updated_at", colTimestamptz),
		optional("email", colText),
		optional("email_verified_at", colTimestamptz),
		optional("deleted_at", colTimestamptz),
		defaulted("version", colBigint, "1"),
	},
	"scrty_assigned_roles": {
		required("id", colUUID),
		required("user_id", colUUID),
		required("role_name", colText),
		required("position", colInteger),
		defaulted("is_primary", colBoolean, "false"),
		defaulted("super_role", colBoolean, "false"),
		optional("start_date", colTimestamptz),
		optional("valid_until", colTimestamptz),
		required("created_at", colTimestamptz),
		required("updated_at", colTimestamptz),
	},
	"scrty_resource_privileges": {
		required("id", colUUID),
		required("role_name", colText),
		required("resource_group", colText),
		required("resource", colText),
		required("privilege", colText),
		defaulted("granted", colBoolean, "false"),
		required("created_at", colTimestamptz),
		required("updated_at", colTimestamptz),
		defaulted("scope", colText, "'all'::text"),
	},
	"scrty_user_attributes": {
		required("user_id", colUUID),
		required("name", colText),
		required("value", colText),
	},
	"scrty_password_history": {
		required("id", colUUID),
		required("user_id", colUUID),
		required("password", colBytea),
		defaulted("seq", colBigint, identitySeqAlways),
		required("retired_at", colTimestamptz),
	},
}

// identitySeqAlways is how the identity column query renders a GENERATED
// ALWAYS AS IDENTITY column in the default slot: PostgreSQL keeps no default
// expression for an identity column, so the query reports attidentity there
// instead.
const identitySeqAlways = "GENERATED ALWAYS AS IDENTITY"

// identityIndexes pins every index of every identity table, keyed by table,
// as pg_indexes defines it with the schema qualifier removed: the primary
// keys, the natural-key unique constraints on users.username and roles.name,
// and the three lookup indexes, password_history_user_seq with its exact
// (user_id, seq DESC) order.
var identityIndexes = map[string][]string{
	"scrty_groups": {
		"CREATE UNIQUE INDEX scrty_groups_pkey ON scrty_groups USING btree (id)",
	},
	"scrty_organizations": {
		"CREATE UNIQUE INDEX scrty_organizations_pkey ON scrty_organizations USING btree (id)",
	},
	"scrty_roles": {
		"CREATE UNIQUE INDEX scrty_roles_pkey ON scrty_roles USING btree (id)",
		"CREATE UNIQUE INDEX scrty_roles_name_key ON scrty_roles USING btree (name)",
	},
	"scrty_users": {
		"CREATE UNIQUE INDEX scrty_users_pkey ON scrty_users USING btree (id)",
		"CREATE UNIQUE INDEX scrty_users_username_key ON scrty_users USING btree (username)",
		"CREATE UNIQUE INDEX scrty_users_email_live ON scrty_users USING btree (lower(email)) WHERE ((deleted_at IS NULL) AND (email IS NOT NULL))",
		"CREATE INDEX scrty_users_username_lower ON scrty_users USING btree (lower(username), id)",
	},
	"scrty_user_attributes": {
		"CREATE UNIQUE INDEX scrty_user_attributes_pkey ON scrty_user_attributes USING btree (user_id, name)",
		"CREATE INDEX scrty_user_attributes_name_value ON scrty_user_attributes USING btree (name, value)",
	},
	"scrty_assigned_roles": {
		"CREATE UNIQUE INDEX scrty_assigned_roles_pkey ON scrty_assigned_roles USING btree (id)",
		"CREATE INDEX scrty_assigned_roles_user_id ON scrty_assigned_roles USING btree (user_id)",
		"CREATE INDEX scrty_assigned_roles_role_name ON scrty_assigned_roles USING btree (role_name)",
	},
	"scrty_resource_privileges": {
		"CREATE UNIQUE INDEX scrty_resource_privileges_pkey ON scrty_resource_privileges USING btree (id)",
		"CREATE INDEX scrty_resource_privileges_role_name ON scrty_resource_privileges USING btree (role_name)",
	},
	"scrty_password_history": {
		"CREATE UNIQUE INDEX scrty_password_history_pkey ON scrty_password_history USING btree (id)",
		"CREATE INDEX scrty_password_history_user_seq ON scrty_password_history USING btree (user_id, seq DESC)",
	},
}

// identitySchemaChecks is every pinned schema assertion for the identity
// migration set: exact columns, exact indexes and unique constraints, and no
// foreign key to or from any identity table.
func identitySchemaChecks() []schemaCheck {
	tables := strings.Join(identityTables, ",")

	return []schemaCheck{
		{
			name: "exact columns per table, with type, nullability and default",
			query: `SELECT c.relname || '|' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod)
			               || CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE ' NULL' END
			               || ' DEFAULT ' || CASE a.attidentity
			                    WHEN 'a' THEN 'GENERATED ALWAYS AS IDENTITY'
			                    WHEN 'd' THEN 'GENERATED BY DEFAULT AS IDENTITY'
			                    ELSE coalesce(pg_get_expr(d.adbin, d.adrelid), '') END
			          FROM pg_attribute a
			          JOIN pg_class c ON c.oid = a.attrelid
			          JOIN pg_namespace n ON n.oid = c.relnamespace
			          LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
			         WHERE n.nspname = current_schema()
			           AND c.relkind = 'r'
			           AND a.attnum > 0 AND NOT a.attisdropped
			           AND c.relname = ANY(string_to_array($1, ','))`,
			args: []any{tables},
			assert: func(t *testing.T, rows []string) {
				want := sortedByTable(identityColumns, func(c column) string { return c.String() })
				assert.Equal(t, want, groupByTable(t, rows))
			},
		},
		{
			name: "exact indexes per table",
			query: `SELECT tablename || '|' || replace(indexdef, ' ON ' || quote_ident(schemaname) || '.', ' ON ')
			          FROM pg_indexes
			         WHERE schemaname = current_schema()
			           AND tablename = ANY(string_to_array($1, ','))`,
			args: []any{tables},
			assert: func(t *testing.T, rows []string) {
				want := sortedByTable(identityIndexes, func(s string) string { return s })
				assert.Equal(t, want, groupByTable(t, rows))
			},
		},
		{
			name: "unique constraints on username and role name",
			query: `SELECT conrelid::regclass::text || '|' || pg_get_constraintdef(oid)
			          FROM pg_constraint
			         WHERE contype = 'u'
			           AND conrelid::regclass::text = ANY(string_to_array($1, ','))`,
			args: []any{tables},
			assert: func(t *testing.T, rows []string) {
				assert.ElementsMatch(t, []string{"scrty_users|UNIQUE (username)", "scrty_roles|UNIQUE (name)"}, rows)
			},
		},
		{
			name: "no foreign key to or from an identity table",
			query: `SELECT count(*)::text
			          FROM pg_constraint
			         WHERE contype = 'f'
			           AND (conrelid::regclass::text = ANY(string_to_array($1, ','))
			                OR confrelid::regclass::text = ANY(string_to_array($1, ',')))`,
			args: []any{tables},
			assert: func(t *testing.T, rows []string) {
				assert.Equal(t, []string{"0"}, rows)
			},
		},
	}
}

// TestIdentityMigrations_Schema pins the identity set's exact catalogue, so a
// column that changes type, nullability or default, a dropped unique
// constraint or index, or an added foreign key fails here.
func TestIdentityMigrations_Schema(t *testing.T) {
	t.Parallel()

	runSchemaChecks(t, migratedIdentity(t), identitySchemaChecks())
}

// versionIdentityPrefix and versionIdentityAdministration address the two
// latest identity migrations: the scrty_ rename, and the administration
// columns that follow it.
const (
	versionIdentityPrefix         int64 = 20261124000000
	versionIdentityAdministration int64 = 20261125000000
)

// identityAt returns an empty database with a goose provider over the identity
// set, rolled back at cleanup so the leftover-table check proves the set's
// rollback drops everything it created, including a failed upgrade's remains.
func identityAt(t *testing.T) (*sql.DB, *goose.Provider) {
	t.Helper()

	set := migrate.Identity()
	db := RunTestPostgres(t).DB
	p := provider(t, db, set.FS(), set.Dir, set.VersionTable)
	rollBackAtCleanup(t, db, p, set.VersionTable)

	return db, p
}

// administrationColumns are the columns the administration migration adds,
// keyed by table, as the catalogue renders them.
var administrationColumns = map[string][]column{
	"scrty_users": {
		optional("email", colText),
		optional("email_verified_at", colTimestamptz),
		optional("deleted_at", colTimestamptz),
		defaulted("version", colBigint, "1"),
	},
	"scrty_roles": {
		defaulted("display_name", colText, defEmptyText),
		defaulted("description", colText, defEmptyText),
		defaulted("labels", colTextArray, defEmptyTextArray),
		defaulted("version", colBigint, "1"),
	},
	"scrty_resource_privileges": {
		defaulted("scope", colText, "'all'::text"),
	},
	"scrty_user_attributes": {
		required("user_id", colUUID),
		required("name", colText),
		required("value", colText),
	},
}

// administrationIndexes are the indexes the administration migration adds, as
// pg_indexes defines them with the schema qualifier removed.
var administrationIndexes = []string{
	"CREATE UNIQUE INDEX scrty_users_email_live ON scrty_users USING btree (lower(email)) WHERE ((deleted_at IS NULL) AND (email IS NOT NULL))",
	"CREATE INDEX scrty_users_username_lower ON scrty_users USING btree (lower(username), id)",
	"CREATE INDEX scrty_assigned_roles_role_name ON scrty_assigned_roles USING btree (role_name)",
	"CREATE UNIQUE INDEX scrty_user_attributes_pkey ON scrty_user_attributes USING btree (user_id, name)",
	"CREATE INDEX scrty_user_attributes_name_value ON scrty_user_attributes USING btree (name, value)",
}

// administrationIndexNames are the names of administrationIndexes.
var administrationIndexNames = []string{
	"scrty_users_email_live", "scrty_users_username_lower", "scrty_assigned_roles_role_name",
	"scrty_user_attributes_pkey", "scrty_user_attributes_name_value",
}

// tableColumns renders the named columns of table the way column.String does,
// in the order given, skipping any the table does not have.
func tableColumns(t *testing.T, db *sql.DB, table string, names []string) []string {
	t.Helper()

	got := queryStrings(t, db, `SELECT a.attname || ' ' || format_type(a.atttypid, a.atttypmod)
	               || CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE ' NULL' END
	               || ' DEFAULT ' || coalesce(pg_get_expr(d.adbin, d.adrelid), '')
	          FROM pg_attribute a
	          JOIN pg_class c ON c.oid = a.attrelid
	          JOIN pg_namespace n ON n.oid = c.relnamespace
	          LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
	         WHERE n.nspname = current_schema() AND c.relname = $1
	           AND a.attnum > 0 AND NOT a.attisdropped
	           AND a.attname = ANY(string_to_array($2, ','))
	         ORDER BY array_position(string_to_array($2, ','), a.attname::text)`,
		table, strings.Join(names, ","))

	return got
}

// columnNames returns the names of cols, in order.
func columnNames(cols []column) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = c.name
	}
	return out
}

// columnStrings renders cols the way tableColumns does.
func columnStrings(cols []column) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = c.String()
	}
	return out
}

// indexDefs returns the definitions of the named indexes of the current
// schema, schema qualifier removed, in name order.
func indexDefs(t *testing.T, db *sql.DB, names []string) []string {
	t.Helper()

	return queryStrings(t, db, `SELECT replace(indexdef, ' ON ' || quote_ident(schemaname) || '.', ' ON ')
	          FROM pg_indexes
	         WHERE schemaname = current_schema() AND indexname = ANY(string_to_array($1, ','))
	         ORDER BY indexname`, strings.Join(names, ","))
}

// identityCatalog snapshots every column and index of every table in the
// current schema except the version table, sorted, so a rollback can be
// compared with the catalog it started from.
func identityCatalog(t *testing.T, db *sql.DB) []string {
	t.Helper()

	cols := queryStrings(t, db, `SELECT 'column|' || c.relname || '|' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod)
	               || CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE ' NULL' END
	               || ' DEFAULT ' || coalesce(pg_get_expr(d.adbin, d.adrelid), '')
	          FROM pg_attribute a
	          JOIN pg_class c ON c.oid = a.attrelid
	          JOIN pg_namespace n ON n.oid = c.relnamespace
	          LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
	         WHERE n.nspname = current_schema() AND c.relkind = 'r' AND c.relname <> $1
	           AND a.attnum > 0 AND NOT a.attisdropped`, migrate.IdentityVersionTable)
	idx := queryStrings(t, db, `SELECT 'index|' || indexdef FROM pg_indexes
	         WHERE schemaname = current_schema() AND tablename <> $1`, migrate.IdentityVersionTable)

	out := append(cols, idx...)
	slices.Sort(out)

	return out
}

// TestIdentityMigration_Administration pins the catalogue the administration
// migration leaves: every added column with its type, nullability and
// default, the attribute table, every index, and the scrty_ prefix on each
// relation it created.
func TestIdentityMigration_Administration(t *testing.T) {
	t.Parallel()

	db, p := identityAt(t)
	_, err := p.Up(t.Context())
	require.NoError(t, err)

	for table, cols := range administrationColumns {
		assert.Equal(t, columnStrings(cols), tableColumns(t, db, table, columnNames(cols)), "table %s", table)
	}

	assert.Equal(t, []string{
		"scrty_assigned_roles_role_name", "scrty_user_attributes_name_value", "scrty_user_attributes_pkey",
		"scrty_users_email_live", "scrty_users_username_lower",
	}, indexNamesOf(t, db, administrationIndexNames))

	want := slices.Clone(administrationIndexes)
	slices.Sort(want)
	got := indexDefs(t, db, administrationIndexNames)
	slices.Sort(got)
	assert.Equal(t, want, got)

	assert.Equal(t, 1, queryCount(t, db, `SELECT count(*) FROM `+migrate.IdentityVersionTable+
		` WHERE is_applied AND version_id = $1`, versionIdentityAdministration))

	unprefixed := queryStrings(t, db, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
	         WHERE n.nspname = current_schema() AND c.relkind IN ('r','i','S')
	           AND c.relname NOT LIKE 'scrty\_%' AND c.relname NOT LIKE $1`, migrate.IdentityVersionTable+"%")
	assert.Empty(t, unprefixed, "every relation carries the scrty_ prefix")
}

// indexNamesOf returns which of names exist as indexes in the current schema.
func indexNamesOf(t *testing.T, db *sql.DB, names []string) []string {
	t.Helper()

	got := queryStrings(t, db, `SELECT indexname FROM pg_indexes
	         WHERE schemaname = current_schema() AND indexname = ANY(string_to_array($1, ','))
	         ORDER BY indexname`, strings.Join(names, ","))

	return got
}

// TestIdentityMigration_AdministrationDown pins that rolling the
// administration migration back drops exactly what it added, leaving the
// catalogue as it was at the prefix migration and each user's other columns
// unchanged, including a user that held an email and attributes.
func TestIdentityMigration_AdministrationDown(t *testing.T) {
	t.Parallel()

	db, p := identityAt(t)
	ctx := t.Context()

	_, err := p.UpTo(ctx, versionIdentityPrefix)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO scrty_users (id, name, username, password, role, created_at, updated_at)
	     VALUES ('00000000-0000-0000-0000-0000000000a1', 'Ada', 'ada', '\x01', 'admin', now(), now())`)
	require.NoError(t, err)
	before := identityCatalog(t, db)
	rowBefore := queryStrings(t, db, userRowQuery)

	_, err = p.UpTo(ctx, versionIdentityAdministration)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `UPDATE scrty_users SET email = 'ada@example.com', version = 4`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO scrty_user_attributes (user_id, name, value)
	     VALUES ('00000000-0000-0000-0000-0000000000a1', 'team', 'core')`)
	require.NoError(t, err)
	require.NotEqual(t, before, identityCatalog(t, db), "the migration changed the catalogue")

	res, err := p.Down(ctx)
	require.NoError(t, err)
	assert.Equal(t, versionIdentityAdministration, res.Source.Version)

	assert.Equal(t, before, identityCatalog(t, db), "the catalogue is as it was at the prefix migration")
	assert.False(t, regclassExists(t, db, "scrty_user_attributes"))
	assert.Empty(t, indexNamesOf(t, db, administrationIndexNames))
	assert.Equal(t, rowBefore, queryStrings(t, db, userRowQuery))
}

// userRowQuery renders every column of scrty_users that exists before the
// administration migration, one text row per user.
const userRowQuery = `SELECT concat_ws('|', id::text, name, username, encode(password, 'hex'), active::text, role,
	mfa_required::text) FROM scrty_users ORDER BY id`

// TestIdentityMigration_FailsAtomically pins that the administration
// migration applies in one transaction: on a database where a consumer already
// added an email column to the users table it fails, and nothing it would add
// exists afterwards.
func TestIdentityMigration_FailsAtomically(t *testing.T) {
	t.Parallel()

	db, p := identityAt(t)
	ctx := t.Context()

	_, err := p.UpTo(ctx, versionIdentityPrefix)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `ALTER TABLE scrty_users ADD COLUMN email text`)
	require.NoError(t, err)
	before := identityCatalog(t, db)

	_, err = p.UpTo(ctx, versionIdentityAdministration)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr, "the upgrade fails with the server's error: %v", err)
	assert.Equal(t, "42701", pgErr.Code, "duplicate_column")

	assert.Equal(t, before, identityCatalog(t, db), "a failed migration leaves the catalogue as the consumer had it")
	assert.False(t, regclassExists(t, db, "scrty_user_attributes"))
	assert.Empty(t, indexNamesOf(t, db, administrationIndexNames))
	for _, tc := range []struct {
		table string
		names []string
	}{
		{"scrty_users", []string{"email_verified_at", "deleted_at", "version"}},
		{"scrty_roles", []string{"display_name", "description", "labels", "version"}},
		{"scrty_resource_privileges", []string{"scope"}},
	} {
		assert.Empty(t, tableColumns(t, db, tc.table, tc.names), "table %s", tc.table)
	}
	assert.Equal(t, 0, queryCount(t, db, `SELECT count(*) FROM `+migrate.IdentityVersionTable+
		` WHERE is_applied AND version_id = $1`, versionIdentityAdministration), "the failed migration is not recorded")
}

// TestIdentityMigration_AdministrationPopulated pins that rows written before
// the migration read back with no email, not deleted, version 1, an empty role
// display name, description and labels, and scope all.
func TestIdentityMigration_AdministrationPopulated(t *testing.T) {
	t.Parallel()

	db, p := identityAt(t)
	ctx := t.Context()

	_, err := p.UpTo(ctx, versionIdentityPrefix)
	require.NoError(t, err)
	for _, stmt := range []string{
		`INSERT INTO scrty_users (id, username, password, created_at, updated_at)
		   VALUES ('00000000-0000-0000-0000-0000000000a1', 'ada', '\x01', now(), now())`,
		`INSERT INTO scrty_roles (id, name, created_at, updated_at)
		   VALUES ('00000000-0000-0000-0000-0000000000b1', 'admin', now(), now())`,
		`INSERT INTO scrty_resource_privileges (id, role_name, resource_group, resource, privilege, granted, created_at, updated_at)
		   VALUES ('00000000-0000-0000-0000-0000000000c1', 'admin', 'docs', 'doc', 'read', true, now(), now())`,
	} {
		_, err = db.ExecContext(ctx, stmt)
		require.NoError(t, err)
	}

	_, err = p.UpTo(ctx, versionIdentityAdministration)
	require.NoError(t, err)

	assert.Equal(t, []string{"true|true|true|1"}, queryStrings(t, db, `SELECT concat_ws('|', (email IS NULL)::text, (email_verified_at IS NULL)::text,
	     (deleted_at IS NULL)::text, version) FROM scrty_users`))
	assert.Equal(t, []string{"true|true|true|1"}, queryStrings(t, db, `SELECT concat_ws('|', (display_name = '')::text,
	     (description = '')::text, (labels = '{}')::text, version) FROM scrty_roles`))
	assert.Equal(t, []string{"all"}, queryStrings(t, db, `SELECT scope FROM scrty_resource_privileges`))
}
