package test

import (
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/migrate"
)

// identityTables lists the seven tables the identity set creates.
var identityTables = []string{
	"groups", "organizations", "roles", "users", "assigned_roles", "resource_privileges", "password_history",
}

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

	t.Run("identity set alone creates exactly the seven tables", func(t *testing.T) {
		t.Parallel()

		db := migratedIdentity(t)

		rows := queryStrings(t, db, `SELECT tablename FROM pg_tables WHERE schemaname = current_schema()`)
		want := append(slices.Clone(identityTables), migrate.IdentityVersionTable)
		assert.ElementsMatch(t, want, rows)
		assert.NotContains(t, rows, "sessions")
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
		assert.Equal(t, 1, appliedVersionCount(t, db, ss.VersionTable))
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

		assert.Equal(t, 1, appliedVersionCount(t, db, "app_identity_versions"))
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
// false, so a NULL can never scan as "not required". password_history.seq is
// an identity column the table assigns (see identitySeqAlways).
var identityColumns = map[string][]column{
	"groups": {
		required("id", colUUID),
		required("name", colText),
		defaulted("internal", colBoolean, "false"),
		required("created_at", colTimestamptz),
		required("updated_at", colTimestamptz),
	},
	"organizations": {
		required("id", colUUID),
		required("name", colText),
		optional("group_id", colUUID),
		required("created_at", colTimestamptz),
		required("updated_at", colTimestamptz),
	},
	"roles": {
		required("id", colUUID),
		required("name", colText),
		defaulted("super_role", colBoolean, "false"),
		required("created_at", colTimestamptz),
		required("updated_at", colTimestamptz),
	},
	"users": {
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
	},
	"assigned_roles": {
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
	"resource_privileges": {
		required("id", colUUID),
		required("role_name", colText),
		required("resource_group", colText),
		required("resource", colText),
		required("privilege", colText),
		defaulted("granted", colBoolean, "false"),
		required("created_at", colTimestamptz),
		required("updated_at", colTimestamptz),
	},
	"password_history": {
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
	"groups": {
		"CREATE UNIQUE INDEX groups_pkey ON groups USING btree (id)",
	},
	"organizations": {
		"CREATE UNIQUE INDEX organizations_pkey ON organizations USING btree (id)",
	},
	"roles": {
		"CREATE UNIQUE INDEX roles_pkey ON roles USING btree (id)",
		"CREATE UNIQUE INDEX roles_name_key ON roles USING btree (name)",
	},
	"users": {
		"CREATE UNIQUE INDEX users_pkey ON users USING btree (id)",
		"CREATE UNIQUE INDEX users_username_key ON users USING btree (username)",
	},
	"assigned_roles": {
		"CREATE UNIQUE INDEX assigned_roles_pkey ON assigned_roles USING btree (id)",
		"CREATE INDEX assigned_roles_user_id ON assigned_roles USING btree (user_id)",
	},
	"resource_privileges": {
		"CREATE UNIQUE INDEX resource_privileges_pkey ON resource_privileges USING btree (id)",
		"CREATE INDEX resource_privileges_role_name ON resource_privileges USING btree (role_name)",
	},
	"password_history": {
		"CREATE UNIQUE INDEX password_history_pkey ON password_history USING btree (id)",
		"CREATE INDEX password_history_user_seq ON password_history USING btree (user_id, seq DESC)",
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
				assert.ElementsMatch(t, []string{"users|UNIQUE (username)", "roles|UNIQUE (name)"}, rows)
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
