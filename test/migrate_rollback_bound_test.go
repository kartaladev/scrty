package test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/store/migrate"
)

// TestMigrationRollback_LockBound pins that rolling back the administration
// and selected-role migrations waits a bounded time for the ACCESS EXCLUSIVE
// lock its DROP statements take, as their upgrades do: a long transaction
// holding a table fails the rollback with lock_not_available within the bound,
// instead of queueing every query on the table behind it, and leaves the
// migration applied; the same rollback succeeds once the lock is gone.
func TestMigrationRollback_LockBound(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// open returns a database at the migration under test, its provider
		// and version table.
		open    func(t *testing.T) (*sql.DB, *goose.Provider, string)
		version int64
		// locked is the table a reader holds; column is one the migration
		// added to it, which a refused rollback keeps.
		locked, column string
	}

	cases := []testCase{
		{
			name: "identity administration",
			open: func(t *testing.T) (*sql.DB, *goose.Provider, string) {
				db, p := identityAt(t)

				return db, p, migrate.IdentityVersionTable
			},
			version: versionIdentityAdministration,
			locked:  "scrty_users", column: "deleted_at",
		},
		{
			name: "security-state selected role",
			open: func(t *testing.T) (*sql.DB, *goose.Provider, string) {
				set := migrate.SecurityState()
				db := RunTestPostgres(t).DB
				p := provider(t, db, set.FS(), set.Dir, set.VersionTable)
				rollBackAtCleanup(t, db, p, set.VersionTable)

				return db, p, set.VersionTable
			},
			version: versionSelectedRole,
			locked:  "scrty_sessions", column: "selected_role",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db, p, versions := tc.open(t)
			ctx := t.Context()

			_, err := p.UpTo(ctx, tc.version)
			require.NoError(t, err)

			// A reader mid-transaction holds ACCESS SHARE, which the DROP's
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
			_, err = holder.ExecContext(ctx, `LOCK TABLE `+tc.locked+` IN ACCESS SHARE MODE`)
			require.NoError(t, err)

			const deadline = 10 * time.Second
			downCtx, cancel := context.WithTimeout(ctx, deadline)
			defer cancel()
			started := time.Now()
			_, err = p.Down(downCtx)
			elapsed := time.Since(started)

			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr, "the rollback fails with the server's error, not a client timeout: %v", err)
			assert.Equal(t, "55P03", pgErr.Code, "lock_not_available")
			assert.Less(t, elapsed, deadline, "the bound, not the caller's deadline, ended the wait")

			assert.Equal(t, 1, queryCount(t, db, `SELECT count(*) FROM `+versions+
				` WHERE is_applied AND version_id = $1`, tc.version), "the migration stays applied")
			assert.NotEmpty(t, tableColumns(t, db, tc.locked, []string{tc.column}),
				"a refused rollback drops nothing")

			release()
			res, err := p.Down(ctx)
			require.NoError(t, err, "the same rollback succeeds once the lock is gone")
			assert.Equal(t, tc.version, res.Source.Version)
			assert.Empty(t, tableColumns(t, db, tc.locked, []string{tc.column}))
		})
	}
}
