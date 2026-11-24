package test

import (
	"database/sql"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/store/migrate"
)

// frozenChainDir is the test-data directory holding a byte-identical copy of
// the migration chains v0.5.0 shipped, one sub-directory per set. The copy is
// never embedded in the library: it exists only so the baselines can be
// proven to build the same schema.
const frozenChainDir = "testdata/migrate/v0.5.0"

// frozenChainVersionTable records the frozen chain's versions. It is named
// apart from every set's default so a mix-up between the two databases shows.
const frozenChainVersionTable = "frozen_chain_migrate"

// schemaCatalog is one database's schema as sorted catalogue lines, grouped by
// what they describe. Two catalogs are equal exactly when the schemas are the
// same in everything a store or a consumer's SQL can observe: column order,
// types, collations, nullability, defaults, identity generation, persistence,
// storage parameters, index names and definitions, sequences, constraints,
// triggers, and the comments on relations, columns and constraints.
type schemaCatalog struct {
	Columns     []string
	Relations   []string
	Indexes     []string
	Sequences   []string
	Constraints []string
	Triggers    []string
	Comments    []string
}

// catalogOf reads db's current schema into a schemaCatalog, leaving out every
// relation owned by a version table: the table itself, and anything whose name
// starts with the table's name and an underscore (its primary key and
// sequence). exclude names the version tables; the frozen chain's and every
// set's default are always excluded.
func catalogOf(t *testing.T, db *sql.DB, exclude ...string) schemaCatalog {
	t.Helper()

	exclude = append([]string{
		frozenChainVersionTable, migrate.SecurityStateVersionTable, migrate.IdentityVersionTable,
	}, exclude...)
	// One array parameter: the names are bound, never concatenated.
	excluded := "{" + strings.Join(exclude, ",") + "}"
	const owned = `NOT (%[1]s = ANY($1::text[]) OR EXISTS (
		SELECT 1 FROM unnest($1::text[]) v WHERE starts_with(%[1]s, v || '_')))`
	keep := func(col string) string { return strings.ReplaceAll(owned, "%[1]s", col) }

	read := func(query string) []string {
		rows := queryStrings(t, db, query, excluded)
		slices.Sort(rows)
		return rows
	}

	return schemaCatalog{
		// attnum is zero-padded so the lines of one table sort in column
		// order: a reordered column is a difference, not a permutation.
		Columns: read(`SELECT concat_ws(' | ', c.relname, lpad(a.attnum::text, 4, '0'), a.attname,
				format_type(a.atttypid, a.atttypmod),
				'collation=' || coalesce(col.collname, ''),
				CASE WHEN a.attnotnull THEN 'NOT NULL' ELSE 'NULL' END,
				'identity=' || a.attidentity::text,
				'default=' || coalesce(pg_get_expr(d.adbin, d.adrelid), ''))
			FROM pg_attribute a
			JOIN pg_class c ON c.oid = a.attrelid
			LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
			LEFT JOIN pg_collation col ON col.oid = a.attcollation AND a.attcollation <> 0
			WHERE c.relnamespace = current_schema()::regnamespace
			  AND c.relkind IN ('r', 'p')
			  AND a.attnum > 0 AND NOT a.attisdropped
			  AND ` + keep("c.relname")),
		Relations: read(`SELECT concat_ws(' | ', c.relname, c.relkind::text,
				'persistence=' || c.relpersistence::text,
				'options=' || coalesce(array_to_string(c.reloptions, ','), ''))
			FROM pg_class c
			WHERE c.relnamespace = current_schema()::regnamespace
			  AND ` + keep("c.relname")),
		Indexes: read(`SELECT indexname || ' | ' || replace(indexdef, current_schema() || '.', '')
			FROM pg_indexes
			WHERE schemaname = current_schema()
			  AND ` + keep("tablename")),
		Sequences: read(`SELECT concat_ws(' | ', c.relname, s.seqtypid::regtype::text, s.seqstart::text,
				s.seqincrement::text, s.seqmin::text, s.seqmax::text, s.seqcache::text,
				s.seqcycle::text)
			FROM pg_sequence s
			JOIN pg_class c ON c.oid = s.seqrelid
			WHERE c.relnamespace = current_schema()::regnamespace
			  AND ` + keep("c.relname")),
		// A check constraint's name is left out: the chain kept the names it
		// had before the scrty_ rename, and the baseline takes PostgreSQL's
		// natural prefixed ones. An index-backed constraint's name is kept,
		// since its index carries it.
		Constraints: read(`SELECT concat_ws(' | ', c.relname, k.contype::text,
				CASE WHEN k.contype IN ('p', 'u', 'x') THEN k.conname END,
				pg_get_constraintdef(k.oid))
			FROM pg_constraint k
			JOIN pg_class c ON c.oid = k.conrelid
			WHERE k.connamespace = current_schema()::regnamespace
			  AND ` + keep("c.relname")),
		// Triggers the schema defines, not the internal ones PostgreSQL keeps
		// behind a foreign key. A trigger's name is part of what a consumer
		// sees in an error, so it is kept.
		Triggers: read(`SELECT concat_ws(' | ', c.relname, t.tgname,
				replace(pg_get_triggerdef(t.oid), current_schema() || '.', ''))
			FROM pg_trigger t
			JOIN pg_class c ON c.oid = t.tgrelid
			WHERE NOT t.tgisinternal
			  AND c.relnamespace = current_schema()::regnamespace
			  AND ` + keep("c.relname")),
		// Comments on relations (tables, indexes, sequences), on columns, and
		// on constraints. An unnamed comment is no line, so a comment the
		// baseline adds or drops is a difference.
		Comments: read(`SELECT 'relation | ' || c.relname || ' | ' || obj_description(c.oid, 'pg_class')
				FROM pg_class c
				WHERE c.relnamespace = current_schema()::regnamespace
				  AND obj_description(c.oid, 'pg_class') IS NOT NULL
				  AND ` + keep("c.relname") + `
			UNION ALL
			SELECT 'column | ' || c.relname || ' | ' || a.attname || ' | ' || col_description(c.oid, a.attnum)
				FROM pg_attribute a
				JOIN pg_class c ON c.oid = a.attrelid
				WHERE c.relnamespace = current_schema()::regnamespace
				  AND a.attnum > 0 AND NOT a.attisdropped
				  AND col_description(c.oid, a.attnum) IS NOT NULL
				  AND ` + keep("c.relname") + `
			UNION ALL
			SELECT 'constraint | ' || c.relname || ' | ' || k.conname || ' | ' || obj_description(k.oid, 'pg_constraint')
				FROM pg_constraint k
				JOIN pg_class c ON c.oid = k.conrelid
				WHERE k.connamespace = current_schema()::regnamespace
				  AND obj_description(k.oid, 'pg_constraint') IS NOT NULL
				  AND ` + keep("c.relname")),
	}
}

// assertCatalogsEqual compares two catalogs part by part, so a difference is
// reported under the part it is in, with testify's line diff.
func assertCatalogsEqual(t *testing.T, want, got schemaCatalog) {
	t.Helper()

	assert.NotEmpty(t, want.Columns, "the reference catalog is empty: nothing was applied")
	assert.Equal(t, want.Columns, got.Columns, "columns (attnum order, type, collation, nullability, identity, default)")
	assert.Equal(t, want.Relations, got.Relations, "relations (kind, persistence, storage parameters)")
	assert.Equal(t, want.Indexes, got.Indexes, "index names and definitions")
	assert.Equal(t, want.Sequences, got.Sequences, "sequences")
	assert.Equal(t, want.Constraints, got.Constraints, "constraints")
	assert.Equal(t, want.Triggers, got.Triggers, "triggers")
	assert.Equal(t, want.Comments, got.Comments, "comments on relations, columns and constraints")
}

// TestBaselineMatchesV050Chain proves each embedded set builds exactly the
// schema the v0.5.0 chain built, on both PostgreSQL majors CI runs.
func TestBaselineMatchesV050Chain(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		set    migrate.Set
		image  string
		assert func(t *testing.T, chain, baseline schemaCatalog)
	}

	var cases []testCase
	for _, image := range []string{postgres15Image, postgres18Image} {
		cases = append(cases,
			testCase{
				name:  "security-state on " + image,
				set:   migrate.SecurityState(),
				image: image,
				assert: func(t *testing.T, chain, baseline schemaCatalog) {
					assertCatalogsEqual(t, chain, baseline)
				},
			},
			testCase{
				name:  "identity on " + image,
				set:   migrate.Identity(),
				image: image,
				assert: func(t *testing.T, chain, baseline schemaCatalog) {
					assertCatalogsEqual(t, chain, baseline)
					// A BY DEFAULT identity would pass a type-only comparison and
					// let a caller write the history order: pin ALWAYS directly.
					assert.Contains(t, baseline.Columns,
						"scrty_password_history | 0004 | seq | bigint | collation= | NOT NULL | identity=a | default=",
						"password history's seq is GENERATED ALWAYS AS IDENTITY")
				},
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain := RunTestPostgres(t,
				WithTestPostgresImage(tc.image),
				WithTestPostgresMigrations(os.DirFS(frozenChainDir), tc.set.Dir, frozenChainVersionTable),
			).DB
			baseline := RunTestPostgres(t,
				WithTestPostgresImage(tc.image),
				WithTestPostgresMigrations(baselineOnly(t, tc.set), tc.set.Dir, tc.set.VersionTable),
			).DB

			tc.assert(t, catalogOf(t, chain), catalogOf(t, baseline))
		})
	}
}

// baselineOnly is set's files with only its first migration, the baseline, under
// set.Dir. A migration added after the baseline changes the schema on purpose, and is
// no part of what the v0.5.0 chain is compared with.
func baselineOnly(t *testing.T, set migrate.Set) fs.FS {
	t.Helper()

	names, err := fs.Glob(set.FS(), set.Dir+"/*.sql")
	require.NoError(t, err)
	require.NotEmpty(t, names, "the set has no migration")
	slices.Sort(names)
	data, err := fs.ReadFile(set.FS(), names[0])
	require.NoError(t, err)

	return fstest.MapFS{names[0]: &fstest.MapFile{Data: data}}
}

// TestBaselineRefusesV050Chain pins that a database already at the end of the
// v0.5.0 chain cannot take the baseline: applying it fails, changes nothing in
// the schema, and records no version. The baseline never detects an earlier
// history; it fails because the relations it creates already exist, and the
// transaction it runs in undoes whatever it did before that statement.
func TestBaselineRefusesV050Chain(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		set  migrate.Set
		// seed inserts one row into a table of the frozen chain.
		seed string
		// table is the table seed fills.
		table string
	}

	cases := []testCase{
		{
			name: "security-state", set: migrate.SecurityState(), table: "scrty_login_attempts",
			seed: `INSERT INTO scrty_login_attempts (id, username, attempted_at)
				VALUES ('00000000-0000-0000-0000-000000000001', 'seeded', now())`,
		},
		{
			name: "identity", set: migrate.Identity(), table: "scrty_groups",
			seed: `INSERT INTO scrty_groups (id, name, created_at, updated_at)
				VALUES ('00000000-0000-0000-0000-000000000001', 'seeded', now(), now())`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := RunTestPostgres(t,
				WithTestPostgresMigrations(os.DirFS(frozenChainDir), tc.set.Dir, frozenChainVersionTable),
			).DB
			before := catalogOf(t, db)
			require.NotEmpty(t, before.Columns, "the chain was applied")

			_, err := db.ExecContext(t.Context(), tc.seed)
			require.NoError(t, err, "seed a row into the frozen chain's data")
			versionsBefore := queryStrings(t, db,
				`SELECT version_id || ' | ' || is_applied FROM `+frozenChainVersionTable+` ORDER BY id`)
			require.NotEmpty(t, versionsBefore, "the frozen chain recorded its versions")

			p := provider(t, db, tc.set.FS(), tc.set.Dir, tc.set.VersionTable)
			_, err = p.Up(t.Context())

			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr, "the baseline fails with the server's error: %v", err)
			assert.Equal(t, "42P07", pgErr.Code, "duplicate_table")

			assertCatalogsEqual(t, before, catalogOf(t, db))
			assert.Equal(t, 0, appliedVersionCount(t, db, tc.set.VersionTable),
				"no version is recorded in the baseline's version table")

			// The refused apply must not cost the consumer data or history.
			assert.Equal(t, 1, rowCount(t, db, tc.table), "the seeded row survives the refused apply")
			assert.Equal(t, versionsBefore, queryStrings(t, db,
				`SELECT version_id || ' | ' || is_applied FROM `+frozenChainVersionTable+` ORDER BY id`),
				"the frozen chain's version rows are unchanged")
		})
	}
}

// rowCount reports how many rows table holds. table is a literal from the
// calling test, never input.
func rowCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()

	var n int
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT count(*) FROM `+table).Scan(&n))
	return n
}
