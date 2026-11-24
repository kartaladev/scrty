package test

import (
	"database/sql"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

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
// types, nullability, defaults, identity generation, persistence, storage
// parameters, index names and definitions, sequences, and constraints.
type schemaCatalog struct {
	Columns     []string
	Relations   []string
	Indexes     []string
	Sequences   []string
	Constraints []string
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
				CASE WHEN a.attnotnull THEN 'NOT NULL' ELSE 'NULL' END,
				'identity=' || a.attidentity::text,
				'default=' || coalesce(pg_get_expr(d.adbin, d.adrelid), ''))
			FROM pg_attribute a
			JOIN pg_class c ON c.oid = a.attrelid
			LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
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
				s.seqincrement::text, s.seqmin::text, s.seqmax::text, s.seqcycle::text)
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
	}
}

// assertCatalogsEqual compares two catalogs part by part, so a difference is
// reported under the part it is in, with testify's line diff.
func assertCatalogsEqual(t *testing.T, want, got schemaCatalog) {
	t.Helper()

	assert.NotEmpty(t, want.Columns, "the reference catalog is empty: nothing was applied")
	assert.Equal(t, want.Columns, got.Columns, "columns (attnum order, type, nullability, identity, default)")
	assert.Equal(t, want.Relations, got.Relations, "relations (kind, persistence, storage parameters)")
	assert.Equal(t, want.Indexes, got.Indexes, "index names and definitions")
	assert.Equal(t, want.Sequences, got.Sequences, "sequences")
	assert.Equal(t, want.Constraints, got.Constraints, "constraints")
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
		cases = append(cases, testCase{
			name:  "security-state on " + image,
			set:   migrate.SecurityState(),
			image: image,
			assert: func(t *testing.T, chain, baseline schemaCatalog) {
				assertCatalogsEqual(t, chain, baseline)
			},
		})
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
				WithTestPostgresMigrations(tc.set.FS(), tc.set.Dir, tc.set.VersionTable),
			).DB

			tc.assert(t, catalogOf(t, chain), catalogOf(t, baseline))
		})
	}
}
