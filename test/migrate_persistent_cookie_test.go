package test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/gormstore"
	"github.com/kartaladev/scrty/store/migrate"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/store/sqlstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// TestPersistentCookieMigration_PopulatedUpgrade pins the migration that adds the
// persistent-cookie mark: it rewrites no table, adds the column nullable with no
// default to the sessions table and the lineage table that mirrors it, leaves a session
// row written at the previous version with no value, loads that row through every
// backend with the mark unset, and rolls back to exactly the previous schema.
func TestPersistentCookieMigration_PopulatedUpgrade(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()
	conn := RunTestPostgres(t)
	db := conn.DB
	p := provider(t, db, set.FS(), set.Dir, set.VersionTable)
	rollBackAtCleanup(t, db, p, set.VersionTable)
	ctx := t.Context()

	_, err := p.UpTo(ctx, versionSignInProof)
	require.NoError(t, err)

	const sessionID = "a-session-written-before-the-migration"
	deadline := time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err = db.ExecContext(ctx, `INSERT INTO scrty_sessions (id, id_digest, user_id, created_at, last_accessed_at,
		idle_expires_at, absolute_expires_at) VALUES ('0192f000-0000-7000-8000-0000000004a1', $1, 'u-1', $2, $2, $3, $3)`,
		storekit.SessionDigest(sessionID), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), deadline)
	require.NoError(t, err)

	tables := []string{"scrty_sessions", "scrty_op_refresh_tokens"}
	previous := catalogOf(t, db)
	var files []string
	for _, table := range tables {
		files = append(files, queryStrings(t, db, `SELECT pg_relation_filenode($1::regclass)::text`, table)...)
	}

	results, err := p.Up(ctx)
	require.NoError(t, err)
	require.Len(t, results, 1, "only the persistent-cookie migration is pending")
	assert.Equal(t, versionPersistentCookie, results[0].Source.Version)

	var after []string
	for _, table := range tables {
		after = append(after, queryStrings(t, db, `SELECT pg_relation_filenode($1::regclass)::text`, table)...)
		assert.Equal(t, []string{"persistent_cookie boolean NULL DEFAULT "},
			tableColumns(t, db, table, []string{"persistent_cookie"}), "%s: nullable, with no default", table)
	}
	assert.Equal(t, files, after, "adding the column rewrote a table")
	assert.Equal(t, 0, queryCount(t, db, `SELECT count(*) FROM scrty_sessions WHERE persistent_cookie IS NOT NULL`),
		"an existing row was given a value")

	pool, err := pgxpool.New(ctx, conn.DSN)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	gdb, err := gormdb.Open(postgres.Open(conn.DSN), &gormdb.Config{DisableAutomaticPing: true})
	require.NoError(t, err)
	gsql, err := gdb.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = gsql.Close() })

	cipher := storefix.TestCipher(t)
	stores := map[string]func() (session.Store, error){
		"sqlstore":  func() (session.Store, error) { return sqlstore.NewSessionStore(db, cipher) },
		"pgxstore":  func() (session.Store, error) { return pgxstore.NewSessionStore(pool, cipher) },
		"gormstore": func() (session.Store, error) { return gormstore.NewSessionStore(gdb, cipher) },
	}
	for name, open := range stores {
		t.Run(name, func(t *testing.T) {
			store, err := open()
			require.NoError(t, err)

			loaded, err := store.Load(ctx, sessionID)
			require.NoError(t, err)
			assert.False(t, loaded.PersistentCookie, "a row written before the migration reads as unset")
			assert.Equal(t, "u-1", string(loaded.UserID), "the row's other fields are kept")
		})
	}

	_, err = p.Down(ctx)
	require.NoError(t, err)
	assertCatalogsEqual(t, previous, catalogOf(t, db))
	assert.Equal(t, 1, rowCount(t, db, "scrty_sessions"), "the row is kept through the rollback")
}
