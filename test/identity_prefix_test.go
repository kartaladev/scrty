package test

import (
	"context"
	"database/sql"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/store/migrate"
	"github.com/kartaladev/scrty/store/sqlstore"
)

// freshIdentity starts a fresh database and a provider for the identity set's
// default version table. At cleanup it rolls the set back to zero and checks
// no table other than the version table is left.
func freshIdentity(t *testing.T) (*sql.DB, *goose.Provider) {
	t.Helper()

	set := migrate.Identity()
	db := RunTestPostgres(t).DB
	p := provider(t, db, set.FS(), set.Dir, set.VersionTable)
	rollBackAtCleanup(t, db, p, set.VersionTable)
	return db, p
}

// flatRelations returns every table, index and sequence name in inv.
func flatRelations(inv relationInventory) []string {
	return slices.Concat(inv.Tables, inv.Indexes, inv.Sequences)
}

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

// mergeInventories joins two inventories into one, each list sorted.
func mergeInventories(a, b relationInventory) relationInventory {
	join := func(x, y []string) []string {
		out := slices.Concat(x, y)
		slices.Sort(out)
		if len(out) == 0 {
			return nil
		}
		return out
	}
	return relationInventory{
		Tables:    join(a.Tables, b.Tables),
		Indexes:   join(a.Indexes, b.Indexes),
		Sequences: join(a.Sequences, b.Sequences),
	}
}

// identityAdministrationInventory is what the administration migration adds on
// top of the renamed identity relations. A table's primary-key index is in
// Indexes, as in the other inventories.
var identityAdministrationInventory = relationInventory{
	Tables: []string{"scrty_user_attributes"},
	Indexes: []string{
		"scrty_assigned_roles_role_name",
		"scrty_user_attributes_name_value",
		"scrty_user_attributes_pkey",
		"scrty_users_email_live",
		"scrty_users_username_lower",
	},
}

// TestIdentityPrefix_Catalog pins the catalog the rename migration leaves:
// exactly the scrty_ names, the sequence behind password_history.seq renamed
// and still linked to its column, none above the identifier limit, and the
// rename recorded in the version table. It stops at the rename's own version,
// so a later migration cannot change what it pins; a last step applies the rest
// of the set and pins the final inventory. It runs on both PostgreSQL images,
// because index, constraint and sequence names must not depend on the server
// version.
func TestIdentityPrefix_Catalog(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		image string
	}

	cases := []testCase{
		{name: "postgres 15", image: postgres15Image},
		{name: "postgres 18", image: postgres18Image},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := migrate.Identity()
			db := RunTestPostgres(t, WithTestPostgresImage(tc.image)).DB
			p := provider(t, db, set.FS(), set.Dir, set.VersionTable)
			rollBackAtCleanup(t, db, p, set.VersionTable)

			_, err := p.UpTo(t.Context(), versionScrtyPrefix)
			require.NoError(t, err)

			got := catalogRelations(t, db)
			assert.Equal(t, prefixed(identityInventory), got, "the catalog is exactly the prefixed inventory")

			for _, n := range flatRelations(got) {
				assert.LessOrEqual(t, len(n), postgresNameLimit, "%s must fit PostgreSQL's identifier limit", n)
			}

			assert.Equal(t, []string{"scrty_password_history_seq_seq"}, got.Sequences, "the sequence is renamed with its table")
			assert.Equal(t, []string{"scrty_password_history_seq_seq"}, queryStrings(t, db,
				`SELECT pg_get_serial_sequence('scrty_password_history', 'seq')::regclass::text`),
				"the sequence is still owned by the column it fills")

			assert.Equal(t, 1, queryCount(t, db, `SELECT count(*) FROM `+set.VersionTable+
				` WHERE is_applied AND version_id = 20261124000000`), "the rename is recorded as applied")
			assert.Equal(t, 2, appliedVersionCount(t, db, set.VersionTable))

			_, err = p.Up(t.Context())
			require.NoError(t, err)
			assert.Equal(t, mergeInventories(prefixed(identityInventory), identityAdministrationInventory),
				catalogRelations(t, db), "the whole set adds the administration relations to the prefixed inventory")
		})
	}
}

// Fixed identifiers for the rows TestIdentityPrefix_Populated seeds.
const (
	populatedUserID  = "11111111-1111-4111-8111-111111111111"
	populatedGrantID = "22222222-2222-4222-8222-222222222222"
)

// TestIdentityPrefix_Populated pins that the rename carries rows and the
// history order across: a user, a role grant and three password-history entries
// seeded before the rename are all present after it, a fourth entry recorded
// after it orders after the three, and the identity store reads the same data
// back.
//
// The raw-row case stops at the rename. The store-backed case then migrates
// to the latest identity version, as a deployment does before running the
// current store, which reads columns later migrations add; the rows seeded
// before the rename must survive those migrations too.
func TestIdentityPrefix_Populated(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// latest migrates past the rename to the newest identity version
		// before the assertion.
		latest bool
		assert func(t *testing.T, db *sql.DB)
	}

	cases := []testCase{
		{
			name: "raw rows are present under the new names and the sequence carries on",
			assert: func(t *testing.T, db *sql.DB) {
				assert.Equal(t, []string{"alice"}, queryStrings(t, db, `SELECT username FROM scrty_users`))
				assert.Equal(t, []string{"admin"}, queryStrings(t, db,
					`SELECT role_name FROM scrty_assigned_roles WHERE user_id = $1`, populatedUserID))
				assert.Equal(t, []string{"h1", "h2", "h3"}, queryStrings(t, db,
					`SELECT convert_from(password, 'UTF8') FROM scrty_password_history
					  WHERE user_id = $1 ORDER BY seq`, populatedUserID))

				var maxBefore int64
				require.NoError(t, db.QueryRowContext(t.Context(),
					`SELECT max(seq) FROM scrty_password_history`).Scan(&maxBefore))

				_, err := db.ExecContext(t.Context(),
					`INSERT INTO scrty_password_history (id, user_id, password, retired_at)
					 VALUES ($1, $2, 'h4', now())`, "33333333-3333-4333-8333-333333333334", populatedUserID)
				require.NoError(t, err)

				assert.Equal(t, []string{"h4", "h3", "h2", "h1"}, queryStrings(t, db,
					`SELECT convert_from(password, 'UTF8') FROM scrty_password_history
					  WHERE user_id = $1 ORDER BY seq DESC`, populatedUserID), "the new entry is the newest")
				assert.Equal(t, 1, queryCount(t, db,
					`SELECT count(*) FROM scrty_password_history WHERE seq > $1`, maxBefore))
			},
		},
		{
			name:   "the identity store reads the seeded rows and orders a new entry newest",
			latest: true,
			assert: func(t *testing.T, db *sql.DB) {
				ctx := t.Context()

				s, err := sqlstore.NewIdentityStore(db)
				require.NoError(t, err)

				d, err := s.LoadByUsername(ctx, "alice")
				require.NoError(t, err)
				require.NotNil(t, d)
				assert.Equal(t, identity.UserID(populatedUserID), d.ID)
				require.Len(t, d.Roles, 1)
				assert.Equal(t, "admin", d.Roles[0].Name)

				require.NoError(t, s.RetirePassword(ctx, identity.UserID(populatedUserID), []byte("h4"), 10))

				got, err := s.RecentPasswords(ctx, identity.UserID(populatedUserID), 10)
				require.NoError(t, err)
				assert.Equal(t, [][]byte{[]byte("h4"), []byte("h3"), []byte("h2"), []byte("h1")}, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db, p := freshIdentity(t)
			ctx := t.Context()

			_, err := p.UpTo(ctx, versionIdentityBeforeName)
			require.NoError(t, err)
			seedIdentityBeforeRename(t, db)

			_, err = p.UpTo(ctx, versionScrtyPrefix)
			require.NoError(t, err)

			if tc.latest {
				_, err = p.Up(ctx)
				require.NoError(t, err)
			}

			tc.assert(t, db)
		})
	}
}

// TestIdentityPrefix_Failures pins how the rename fails and how it rolls back:
// the upgrade is strict (a missing relation or a held lock fails it and
// renames nothing, records nothing) and the rollback is tolerant (a relation
// dropped since still lets it complete).
func TestIdentityPrefix_Failures(t *testing.T) {
	t.Parallel()

	set := migrate.Identity()

	// oldNames checks every identity table still has its original name and
	// none has its prefixed one.
	oldNames := func(t *testing.T, db *sql.DB, missing ...string) {
		t.Helper()

		for _, table := range identityInventory.Tables {
			if slices.Contains(missing, table) {
				continue
			}
			assert.True(t, regclassExists(t, db, table), "table %s keeps its name", table)
			assert.False(t, regclassExists(t, db, scrtyPrefix+table), "table %s was renamed", table)
		}
	}
	noVersion := func(t *testing.T, db *sql.DB, before int) {
		t.Helper()

		assert.Equal(t, 0, queryCount(t, db, `SELECT count(*) FROM `+set.VersionTable+
			` WHERE is_applied AND version_id = $1`, versionScrtyPrefix), "no version is recorded")
		assert.Equal(t, before, appliedVersionCount(t, db, set.VersionTable))
	}

	type testCase struct {
		name string
		run  func(t *testing.T, db *sql.DB, p *goose.Provider)
	}

	cases := []testCase{
		{
			name: "a missing table fails the upgrade and renames nothing",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				ctx := t.Context()
				before := appliedVersionCount(t, db, set.VersionTable)

				_, err := db.ExecContext(ctx, `DROP TABLE roles CASCADE`)
				require.NoError(t, err)

				_, err = p.UpTo(ctx, versionScrtyPrefix)
				var pgErr *pgconn.PgError
				require.ErrorAs(t, err, &pgErr, "the upgrade fails with the server's error: %v", err)
				assert.Equal(t, "42P01", pgErr.Code, "undefined_table")

				oldNames(t, db, "roles")
				assert.False(t, regclassExists(t, db, "scrty_roles"))
				noVersion(t, db, before)
			},
		},
		{
			name: "a lock held on a table fails the upgrade within the bound, and a retry succeeds",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				ctx := t.Context()
				before := appliedVersionCount(t, db, set.VersionTable)

				// A reader mid-transaction holds ACCESS SHARE, which the rename's
				// ACCESS EXCLUSIVE lock waits behind.
				holder, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				released := false
				release := func() {
					if !released {
						released = true
						_ = holder.Rollback()
					}
				}
				t.Cleanup(release)
				_, err = holder.ExecContext(ctx, `LOCK TABLE users IN ACCESS SHARE MODE`)
				require.NoError(t, err)

				const deadline = 10 * time.Second
				upCtx, cancel := context.WithTimeout(ctx, deadline)
				defer cancel()
				started := time.Now()
				_, err = p.UpTo(upCtx, versionScrtyPrefix)
				elapsed := time.Since(started)

				var pgErr *pgconn.PgError
				require.ErrorAs(t, err, &pgErr, "the upgrade fails with the server's error, not a client timeout: %v", err)
				assert.Equal(t, "55P03", pgErr.Code, "lock_not_available")
				assert.Less(t, elapsed, deadline, "the bound, not the caller's deadline, ended the wait")

				oldNames(t, db)
				noVersion(t, db, before)

				release()
				_, err = p.UpTo(ctx, versionScrtyPrefix)
				require.NoError(t, err, "the same upgrade succeeds once the lock is gone")
				assert.True(t, regclassExists(t, db, "scrty_users"))
			},
		},
		{
			name: "rolling the rename back completes after a table was dropped",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				ctx := t.Context()

				_, err := p.UpTo(ctx, versionScrtyPrefix)
				require.NoError(t, err)
				_, err = db.ExecContext(ctx, `DROP TABLE scrty_roles CASCADE`)
				require.NoError(t, err)

				_, err = p.Down(ctx)
				require.NoError(t, err, "the rollback succeeds even though a table was already dropped")

				oldNames(t, db, "roles")
				assert.False(t, regclassExists(t, db, "scrty_roles"))
				assert.Equal(t, 0, queryCount(t, db, `SELECT count(*) FROM `+set.VersionTable+
					` WHERE is_applied AND version_id = $1`, versionScrtyPrefix), "the rename is no longer recorded")
			},
		},
		{
			name: "rolling the rename back fails atomically while the consumer owns an old name",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				ctx := t.Context()

				_, err := p.UpTo(ctx, versionScrtyPrefix)
				require.NoError(t, err)
				const consumerTable = "users"
				_, err = db.ExecContext(ctx, `CREATE TABLE `+consumerTable+` (id int PRIMARY KEY)`)
				require.NoError(t, err)
				// The fixture's own cleanup rolls the set back, which needs the name free.
				t.Cleanup(func() { _, _ = db.ExecContext(context.WithoutCancel(ctx), `DROP TABLE IF EXISTS `+consumerTable) })
				_, err = db.ExecContext(ctx, `INSERT INTO `+consumerTable+` (id) VALUES (7)`)
				require.NoError(t, err)

				_, err = p.Down(ctx)
				require.Error(t, err, "the rollback refuses to take over the consumer's name")

				for _, table := range identityInventory.Tables {
					assert.True(t, regclassExists(t, db, scrtyPrefix+table), "table %s%s keeps its prefixed name", scrtyPrefix, table)
				}
				assert.Equal(t, 1, queryCount(t, db, `SELECT count(*) FROM users WHERE id = 7`), "the consumer's table is unchanged")
				assert.Equal(t, 1, queryCount(t, db, `SELECT count(*) FROM `+set.VersionTable+
					` WHERE is_applied AND version_id = $1`, versionScrtyPrefix), "the rename is still recorded")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db, p := freshIdentity(t)
			_, err := p.UpTo(t.Context(), versionIdentityBeforeName)
			require.NoError(t, err)

			tc.run(t, db, p)
		})
	}
}

// seedIdentityBeforeRename writes one user, one role grant and three password
// history entries under the names the identity set had before the rename.
func seedIdentityBeforeRename(t *testing.T, db *sql.DB) {
	t.Helper()

	ctx := t.Context()
	for _, stmt := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users (id, username, password, created_at, updated_at)
		  VALUES ($1, 'alice', 'hash', now(), now())`, []any{populatedUserID}},
		{`INSERT INTO assigned_roles (id, user_id, role_name, position, created_at, updated_at)
		  VALUES ($1, $2, 'admin', 0, now(), now())`, []any{populatedGrantID, populatedUserID}},
		{`INSERT INTO password_history (id, user_id, password, retired_at) VALUES
		  ('33333333-3333-4333-8333-333333333331', $1, 'h1', now()),
		  ('33333333-3333-4333-8333-333333333332', $1, 'h2', now()),
		  ('33333333-3333-4333-8333-333333333333', $1, 'h3', now())`, []any{populatedUserID}},
	} {
		_, err := db.ExecContext(ctx, stmt.query, stmt.args...)
		require.NoError(t, err, stmt.query)
	}
}

// versionRows lists a version table's rows, ids and timestamps included, so a
// change to any of them shows.
func versionRows(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()

	return queryStrings(t, db, `SELECT id::text || ' ' || version_id::text || ' ' || is_applied::text || ' '
		|| tstamp::text FROM `+table+` ORDER BY id`)
}

// TestPrefix_SetsIndependent pins that the two sets rename on their own:
// renaming one set's relations changes no relation or version row of the
// other, and rolling the identity rename back reverts only identity.
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
			name: "security-state renamed, identity not, then identity renamed",
			assert: func(t *testing.T, db *sql.DB, ssP, idP *goose.Provider) {
				ctx := t.Context()

				_, err := ssP.UpTo(ctx, versionScrtyPrefix)
				require.NoError(t, err)
				_, err = idP.UpTo(ctx, versionIdentityBeforeName)
				require.NoError(t, err)

				got := catalogRelations(t, db)
				assert.Equal(t, prefixed(securityStateInventory), ownedBy(got, prefixed(securityStateInventory)),
					"security-state is prefixed")
				assert.Equal(t, identityInventory, ownedBy(got, identityInventory), "identity is not")
				assert.Equal(t, mergeInventories(prefixed(securityStateInventory), identityInventory), got,
					"nothing else is in the schema")

				ssVersions := versionRows(t, db, ss.VersionTable)
				idVersions := versionRows(t, db, id.VersionTable)

				_, err = idP.UpTo(ctx, versionScrtyPrefix)
				require.NoError(t, err)

				got = catalogRelations(t, db)
				assert.Equal(t, mergeInventories(prefixed(securityStateInventory), prefixed(identityInventory)), got)
				assert.Equal(t, ssVersions, versionRows(t, db, ss.VersionTable), "security-state versions are untouched")
				rows := versionRows(t, db, id.VersionTable)
				require.GreaterOrEqual(t, len(rows), len(idVersions), "no identity version row went missing")
				assert.Equal(t, idVersions, rows[:len(idVersions)],
					"the identity rows already there are untouched")
			},
		},
		{
			name: "identity rename rolled back, security-state untouched",
			assert: func(t *testing.T, db *sql.DB, ssP, idP *goose.Provider) {
				ctx := t.Context()

				_, err := ssP.UpTo(ctx, versionScrtyPrefix)
				require.NoError(t, err)
				_, err = idP.UpTo(ctx, versionScrtyPrefix)
				require.NoError(t, err)

				ssVersions := versionRows(t, db, ss.VersionTable)
				ssBefore := ownedBy(catalogRelations(t, db), prefixed(securityStateInventory))
				require.Equal(t, prefixed(securityStateInventory), ssBefore)

				_, err = idP.Down(ctx)
				require.NoError(t, err)

				got := catalogRelations(t, db)
				assert.Equal(t, identityInventory, ownedBy(got, identityInventory), "only identity reverts")
				assert.Equal(t, ssBefore, ownedBy(got, prefixed(securityStateInventory)), "security-state keeps its names")
				assert.Equal(t, mergeInventories(prefixed(securityStateInventory), identityInventory), got)
				assert.Equal(t, ssVersions, versionRows(t, db, ss.VersionTable), "security-state versions are untouched")
				assert.Equal(t, 1, appliedVersionCount(t, db, id.VersionTable))
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
