package test

import (
	"cmp"
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/store/migrate"
	"github.com/kartaladev/scrty/store/sqlstore"
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
	{"UserRecordByUsername", pgschema.UserRecordByUsername},
	{"UserRecordByID", pgschema.UserRecordByID},
	{"UserRecordByVerifiedEmail", pgschema.UserRecordByVerifiedEmail},
	{"ScopedPrivilegesByRole", pgschema.ScopedPrivilegesByRole},
	{"BumpUserVersion", pgschema.BumpUserVersion},
	{"IdentifierLockKeys", pgschema.IdentifierLockKeys},
	{"LockIdentifierKey", pgschema.LockIdentifierKey},
	{"EmailHeldByLiveUser", pgschema.EmailHeldByLiveUser},
	{"UsernameHeldByLiveUser", pgschema.UsernameHeldByLiveUser},
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

// TestIdentifierLockKeys pins how a write that sets usernames or emails takes
// their advisory locks: the keys are computed by the server from the values
// themselves, as hashtextextended(lower(value), 0), one per distinct key, in
// ascending key order, so every writer takes overlapping locks in the same
// order whatever order or spelling it named them in.
func TestIdentifierLockKeys(t *testing.T) {
	t.Parallel()

	db := migratedIdentity(t)

	// keysOf is what the server computes for values, independently of the
	// statement under test.
	keysOf := func(t *testing.T, values ...string) []int64 {
		t.Helper()

		var out []int64
		for _, v := range values {
			var k int64
			require.NoError(t, db.QueryRowContext(t.Context(),
				`SELECT hashtextextended(lower($1), 0)`, v).Scan(&k))
			out = append(out, k)
		}

		return out
	}

	type testCase struct {
		name   string
		values []string
		// order, when set, rearranges values before the call.
		order  func(t *testing.T, values []string) []string
		assert func(t *testing.T, keys []int64)
	}

	descending := func(t *testing.T, values []string) []string {
		t.Helper()

		keys := keysOf(t, values...)
		out := slices.Clone(values)
		slices.SortFunc(out, func(a, b string) int {
			return cmp.Compare(keys[slices.Index(values, b)], keys[slices.Index(values, a)])
		})

		return out
	}

	cases := []testCase{
		{
			name:   "values named in descending key order come back as keys in ascending order",
			values: []string{"zeta@example.com", "alpha", "mid-user", "bob@example.com"},
			order:  descending,
			assert: func(t *testing.T, keys []int64) {
				want := keysOf(t, "zeta@example.com", "alpha", "mid-user", "bob@example.com")
				slices.Sort(want)
				assert.Equal(t, want, keys)
			},
		},
		{
			name:   "keys come back in ascending order whatever order the values were named in",
			values: []string{"zeta@example.com", "alpha", "mid-user", "bob@example.com"},
			assert: func(t *testing.T, keys []int64) {
				want := keysOf(t, "zeta@example.com", "alpha", "mid-user", "bob@example.com")
				slices.Sort(want)
				assert.Equal(t, want, keys)
			},
		},
		{
			name:   "spellings of one value and repeats collapse to one key",
			values: []string{"Ada@Example.com", "ada@example.com", "ADA@EXAMPLE.COM", "ada@example.com"},
			assert: func(t *testing.T, keys []int64) {
				assert.Equal(t, keysOf(t, "ada@example.com"), keys)
			},
		},
		{
			name:   "an empty value guards nothing",
			values: []string{"", "ada"},
			assert: func(t *testing.T, keys []int64) {
				assert.Equal(t, keysOf(t, "ada"), keys)
			},
		},
		{
			name: "nothing to lock",
			assert: func(t *testing.T, keys []int64) {
				assert.Empty(t, keys)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			values := tc.values
			if tc.order != nil {
				values = tc.order(t, values)
			}

			// The array is sent as its text form, as the database/sql store
			// sends it.
			rows, err := db.QueryContext(ctx, pgschema.IdentifierLockKeys, pgschema.TextArray(values))
			require.NoError(t, err)
			var keys []int64
			for rows.Next() {
				var k int64
				require.NoError(t, rows.Scan(&k))
				keys = append(keys, k)
			}
			require.NoError(t, rows.Err())
			require.NoError(t, rows.Close())

			tc.assert(t, keys)
		})
	}

	t.Run("locking a key holds that advisory lock until the transaction ends", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		key := keysOf(t, "held@example.com")[0]

		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback() }()

		_, err = tx.ExecContext(ctx, pgschema.LockIdentifierKey, key)
		require.NoError(t, err)

		var free bool
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT pg_try_advisory_xact_lock($1)`, key).Scan(&free))
		assert.False(t, free, "another session must not be able to take the key while it is held")

		require.NoError(t, tx.Rollback())
		// A session-level lock is taken and released on one connection, never
		// on the pool, so the unlock reaches the session that holds it.
		conn, err := db.Conn(ctx)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		require.NoError(t, conn.QueryRowContext(ctx,
			`SELECT pg_try_advisory_lock($1)`, key).Scan(&free))
		assert.True(t, free, "the lock is released with the transaction")
		_, err = conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, key)
		require.NoError(t, err)
	})
}

// versionIdentityBaseline is the version of the identity set's single
// baseline migration.
const versionIdentityBaseline int64 = 20261126000000

// identityBaselineVersionTable is the version table the baseline records into
// by default; it is spelled out so a changed default is caught here.
const identityBaselineVersionTable = "scrty_identity_migrate"

// TestIdentityBaseline pins how the identity set applies to a database: one
// recorded migration, beside a consumer's own users table, atomically when its
// last relation already exists, and with the email and privilege-scope rules
// the identity store depends on.
func TestIdentityBaseline(t *testing.T) {
	t.Parallel()

	const (
		firstUser  = "00000000-0000-0000-0000-0000000000a1"
		secondUser = "00000000-0000-0000-0000-0000000000a2"
	)
	insertUser := func(t *testing.T, db *sql.DB, id, username, email string) error {
		t.Helper()

		_, err := db.ExecContext(t.Context(), `INSERT INTO scrty_users (id, username, password, email, created_at, updated_at)
		     VALUES ($1, $2, '\x01', $3, now(), now())`, id, username, email)

		return err
	}

	type testCase struct {
		name         string
		prepare      string
		versionTable string
		assert       func(t *testing.T, db *sql.DB, err error)
	}

	cases := []testCase{
		{
			name:         "one migration recorded",
			versionTable: identityBaselineVersionTable,
			assert: func(t *testing.T, db *sql.DB, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"20261126000000"}, queryStrings(t, db,
					`SELECT version_id::text FROM scrty_identity_migrate WHERE version_id > 0`))
			},
		},
		{
			name:         "beside consumer users",
			prepare:      `CREATE TABLE users(id int); INSERT INTO users VALUES (1); INSERT INTO users VALUES (2)`,
			versionTable: identityBaselineVersionTable,
			assert: func(t *testing.T, db *sql.DB, err error) {
				require.NoError(t, err)
				for _, tbl := range identityTables {
					assert.True(t, regclassExists(t, db, tbl), "table %s should exist", tbl)
				}
				assert.Len(t, identityTables, 8)
				assert.Equal(t, 2, queryCount(t, db, `SELECT count(*) FROM users`), "the consumer's rows are kept")
			},
		},
		{
			name:         "last relation present",
			prepare:      `CREATE TABLE scrty_password_history(id int)`,
			versionTable: identityBaselineVersionTable,
			assert: func(t *testing.T, db *sql.DB, err error) {
				require.Error(t, err)
				assert.Empty(t, queryStrings(t, db, `SELECT relname::text FROM pg_class
					WHERE relnamespace = current_schema()::regnamespace
					  AND relname <> 'scrty_password_history'
					  AND relname NOT LIKE 'scrty\_identity\_migrate%'`),
					"no relation of the set, under any name, survives the failed apply")
				assert.Equal(t, 0, appliedVersionCount(t, db, identityBaselineVersionTable), "no version is recorded")
			},
		},
		{
			name:         "consumer version table",
			versionTable: "auth_identity_versions",
			assert: func(t *testing.T, db *sql.DB, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"20261126000000"}, queryStrings(t, db,
					`SELECT version_id::text FROM auth_identity_versions WHERE version_id > 0`))
				assert.False(t, regclassExists(t, db, identityBaselineVersionTable),
					"the default version table is not created")
			},
		},
		{
			name:         "live email unique ignoring case",
			versionTable: identityBaselineVersionTable,
			assert: func(t *testing.T, db *sql.DB, err error) {
				require.NoError(t, err)
				require.NoError(t, insertUser(t, db, firstUser, "ana", "Ana@example.com"))

				var pgErr *pgconn.PgError
				require.ErrorAs(t, insertUser(t, db, secondUser, "ana2", "ana@example.com"), &pgErr)
				assert.Equal(t, "23505", pgErr.Code, "unique_violation")
			},
		},
		{
			name:         "deleted user's email is free",
			versionTable: identityBaselineVersionTable,
			assert: func(t *testing.T, db *sql.DB, err error) {
				require.NoError(t, err)
				require.NoError(t, insertUser(t, db, firstUser, "ana", "Ana@example.com"))
				_, err = db.ExecContext(t.Context(), `UPDATE scrty_users SET deleted_at = now() WHERE id = $1`, firstUser)
				require.NoError(t, err)

				assert.NoError(t, insertUser(t, db, secondUser, "ana2", "ana@example.com"))
			},
		},
		{
			name:         "privilege without scope loads as all",
			versionTable: identityBaselineVersionTable,
			assert: func(t *testing.T, db *sql.DB, err error) {
				require.NoError(t, err)
				_, err = db.ExecContext(t.Context(), `INSERT INTO scrty_resource_privileges
				     (id, role_name, resource_group, resource, privilege, granted, created_at, updated_at)
				     VALUES ('00000000-0000-0000-0000-0000000000c1', 'admin', 'docs', 'doc', 'read', true, now(), now())`)
				require.NoError(t, err)

				store, err := sqlstore.NewIdentityStore(db)
				require.NoError(t, err)
				got, err := store.LoadPrivileges(t.Context(), "admin")
				require.NoError(t, err)
				require.Len(t, got, 1)
				require.Len(t, got[0].Privileges, 1)
				assert.Equal(t, identity.ScopeAll, got[0].Privileges[0].EffectiveScope())
				assert.Equal(t, []string{"all"}, queryStrings(t, db, `SELECT scope FROM scrty_resource_privileges`))
			},
		},
	}

	set := migrate.Identity()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := RunTestPostgres(t).DB
			if tc.prepare != "" {
				_, err := db.ExecContext(t.Context(), tc.prepare)
				require.NoError(t, err)
			}
			p := provider(t, db, set.FS(), set.Dir, tc.versionTable)

			_, err := p.Up(t.Context())
			tc.assert(t, db, err)
		})
	}
}
