// Package gormstore_test runs the gorm stores against PostgreSQL: the portable
// conformance suites, the durable suites, and the cases only a real database
// can show.
//
// Every test starts one container through test.RunTestPostgres and shares it
// among its cases, reaching it through a *gorm.DB opened from the helper's DSN.
// The portable suites run their cases one after another and require an empty
// store for each, so their factories empty the store's table before handing it
// over; the durable suites and tables use records of their own and never empty
// anything.
package gormstore_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/migrate"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// poolSize is how many connections every gorm handle here may open at once.
// The race suites race 8 callers per record, so this leaves room; it is set on
// each handle's *sql.DB with SetMaxOpenConns, so the width the harness declares
// is the width the store has.
const poolSize = 32

// database is the one PostgreSQL a test runs against: conn, the helper's
// connection (its *sql.DB reaches the tables out of band), and db, a *gorm.DB
// of its own opened from conn.DSN, which the stores are built on.
type database struct {
	conn test.PostgresConn
	db   *gormdb.DB
}

// migratedDB starts PostgreSQL with the security-state set applied. The set is
// rolled back at cleanup.
func migratedDB(t *testing.T) database {
	t.Helper()

	set := migrate.SecurityState()
	conn := test.RunTestPostgres(t, test.WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))

	return database{conn: conn, db: openGorm(t, conn.DSN)}
}

// openGorm opens a *gorm.DB on the database at dsn, with its own connection
// pool of poolSize, as a replica of an application would. It keeps gorm's
// default logger, so a statement a store failed to silence would show in the
// test output. The pool is closed at cleanup.
func openGorm(t *testing.T, dsn string) *gormdb.DB {
	t.Helper()

	db, err := gormdb.Open(postgres.Open(dsn), &gormdb.Config{DisableAutomaticPing: true})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(poolSize)
	t.Cleanup(func() { _ = sqlDB.Close() })

	return db
}

// emptied truncates table through the raw handle and returns db, so a
// portable suite's factory hands each case an empty store over the test's one
// database. The suites run their cases one after another, so no case sees
// another's truncation.
func emptied(t *testing.T, d database, table string) *gormdb.DB {
	t.Helper()

	// table is always one of this package's constants, never input.
	_, err := d.conn.DB.ExecContext(t.Context(), "TRUNCATE "+table)
	require.NoError(t, err)

	return d.db
}

// beginGorm begins a transaction on db under ctx, rolled back at cleanup
// unless the case commits or rolls it back first.
func beginGorm(ctx context.Context, t *testing.T, db *gormdb.DB) *gormdb.DB {
	t.Helper()

	tx := db.WithContext(ctx).Begin()
	require.NoError(t, tx.Error)
	t.Cleanup(func() { tx.Rollback() })

	return tx
}

// resolving is a resolver that always reports tx.
func resolving(tx *gormdb.DB) gormstore.TxResolver {
	return func(context.Context) (*gormdb.DB, bool) { return tx, true }
}

// unreachableDB is a handle on a server that is not there. Constructors never
// touch the database, so it builds any store; an operation on it fails.
func unreachableDB(t *testing.T) *gormdb.DB {
	t.Helper()

	return openGorm(t, "postgres://nobody@127.0.0.1:1/none?connect_timeout=5")
}

// refusedConfig asserts a constructor refused its configuration with exactly
// text, and returned no store.
func refusedConfig[S any](text string) func(t *testing.T, s S, err error) {
	return storefix.RefusedConfig[S](gormstore.ErrConfig, "gorm", text)
}

// storeFactory builds a store of type S over db with opts, failing t when the
// constructor refuses.
type storeFactory[S any] func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) S

// durableHarness is the harness the durable suites take, over d:
//   - New builds the store on d.db, and NewReplica on a *gorm.DB of its own
//     opened from the DSN, so racers split across two pools;
//   - Raw is the helper's *sql.DB;
//   - Begin attaches a transaction of d.db with gormstore.WithTx;
//   - BeginResolved builds a store whose resolver reports the transaction;
//   - BeginForeign attaches, with sqlstore.WithTx, a database/sql transaction
//     on the same database: another backend's attachment, which these stores
//     must not see;
//   - PoolSize is the width every gorm handle here is set to.
func durableHarness[S any](d database, newWith storeFactory[S]) storetest.DurableHarness[S] {
	begin := func(t *testing.T) *gormdb.DB {
		t.Helper()
		return beginGorm(t.Context(), t, d.db)
	}
	commit := func(tx *gormdb.DB) func() error { return func() error { return tx.Commit().Error } }
	rollback := func(tx *gormdb.DB) func() error { return func() error { return tx.Rollback().Error } }

	return storetest.DurableHarness[S]{
		Harness: storetest.Harness[S]{
			New: func(t *testing.T) S { return newWith(t, d.db) },
		},
		NewReplica: func(t *testing.T) S { return newWith(t, openGorm(t, d.conn.DSN)) },
		Raw:        d.conn.DB,
		Begin: func(t *testing.T) (context.Context, func() error, func() error) {
			tx := begin(t)
			return gormstore.WithTx(t.Context(), tx), commit(tx), rollback(tx)
		},
		BeginResolved: func(t *testing.T) (S, context.Context, func() error, func() error) {
			tx := begin(t)
			s := newWith(t, d.db, gormstore.WithTxResolver(resolving(tx)))
			return s, t.Context(), commit(tx), rollback(tx)
		},
		BeginForeign: func(t *testing.T) (context.Context, func() error) {
			t.Helper()
			return storefix.BeginSQLStoreTx(t, d.conn.DB)
		},
		PoolSize: poolSize,
	}
}
