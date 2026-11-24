package test

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/store/migrate"
)

// ownedBy keeps only the relations of got that inv names, so one set's
// relations can be compared while the other set's sit in the same schema.
func ownedBy(got, inv relationInventory) relationInventory {
	keep := func(names, owned []string) []string {
		var out []string
		for _, n := range names {
			if slices.Contains(owned, n) {
				out = append(out, n)
			}
		}
		return out
	}
	return relationInventory{
		Tables:    keep(got.Tables, inv.Tables),
		Indexes:   keep(got.Indexes, inv.Indexes),
		Sequences: keep(got.Sequences, inv.Sequences),
	}
}

// versionRows lists a version table's rows, ids and timestamps included, so a
// change to any of them shows.
func versionRows(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()

	return queryStrings(t, db, `SELECT id::text || ' ' || version_id::text || ' ' || is_applied::text || ' '
		|| tstamp::text FROM `+table+` ORDER BY id`)
}

// TestPrefix_SetsIndependent pins that the two sets are independent: the
// identity baseline, applied or rolled back beside the applied security-state
// baseline, changes no relation or version row of it.
func TestPrefix_SetsIndependent(t *testing.T) {
	t.Parallel()

	ss := migrate.SecurityState()
	id := migrate.Identity()

	type testCase struct {
		name   string
		assert func(t *testing.T, db *sql.DB, ssP, idP *goose.Provider)
	}

	cases := []testCase{
		{
			name: "identity applied beside security-state",
			assert: func(t *testing.T, db *sql.DB, ssP, idP *goose.Provider) {
				ctx := t.Context()

				_, err := ssP.Up(ctx)
				require.NoError(t, err)
				ssBefore := catalogRelations(t, db)
				ssVersions := versionRows(t, db, ss.VersionTable)
				require.Equal(t, prefixed(securityStateInventory), ssBefore)

				_, err = idP.Up(ctx)
				require.NoError(t, err)

				got := catalogRelations(t, db)
				assert.Equal(t, prefixed(securityStateInventory), ownedBy(got, prefixed(securityStateInventory)),
					"security-state keeps its relations")
				assert.Equal(t, prefixed(identityInventory), ownedBy(got, prefixed(identityInventory)),
					"identity has its own")
				assert.Len(t, got.Tables, len(securityStateInventory.Tables)+len(identityInventory.Tables),
					"nothing else is in the schema")
				assert.Equal(t, ssVersions, versionRows(t, db, ss.VersionTable), "security-state versions are untouched")
				assert.Equal(t, 1, appliedVersionCount(t, db, id.VersionTable))
			},
		},
		{
			name: "identity rolled back, security-state untouched",
			assert: func(t *testing.T, db *sql.DB, ssP, idP *goose.Provider) {
				ctx := t.Context()

				_, err := ssP.Up(ctx)
				require.NoError(t, err)
				_, err = idP.Up(ctx)
				require.NoError(t, err)

				ssVersions := versionRows(t, db, ss.VersionTable)

				_, err = idP.Down(ctx)
				require.NoError(t, err)

				got := catalogRelations(t, db)
				assert.Equal(t, prefixed(securityStateInventory), got, "only identity is gone")
				assert.Equal(t, ssVersions, versionRows(t, db, ss.VersionTable), "security-state versions are untouched")
				assert.Equal(t, 0, appliedVersionCount(t, db, id.VersionTable))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := RunTestPostgres(t).DB
			ssP := provider(t, db, ss.FS(), ss.Dir, ss.VersionTable)
			idP := provider(t, db, id.FS(), id.Dir, id.VersionTable)

			// One cleanup for both sets: either set's own leftover check would
			// see the other's tables.
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), postgresTeardownBudget)
				defer cancel()

				if _, err := idP.DownTo(ctx, 0); err != nil {
					t.Errorf("roll back identity: %v", err)
				}
				if _, err := ssP.DownTo(ctx, 0); err != nil {
					t.Errorf("roll back security-state: %v", err)
				}
				assertNoLeftoverTables(ctx, t, db, ss.VersionTable, id.VersionTable)
			})

			tc.assert(t, db, ssP, idP)
		})
	}
}
