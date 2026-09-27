// Package sqlstore_test runs the database/sql stores of package sqlstore
// against PostgreSQL: the portable conformance suites, the durable suites, and
// the cases only a real database can show.
//
// Every test starts one container through test.RunTestPostgres and shares it
// among its cases. The portable suites run their cases one after another and
// require an empty store for each, so their factories empty the store's table
// before handing it over; the durable suites and tables use records of their
// own and never empty anything.
package sqlstore_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver the replicas open
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/migrate"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// poolSize is how many connections every handle here may open at once. The
// race suites race 8 callers per record, so this leaves room; it is set on
// each handle with SetMaxOpenConns, so the width the harness declares is the
// width the store has.
const poolSize = 32

// migratedDB starts PostgreSQL with the security-state set applied, and
// returns the connection. The set is rolled back at cleanup.
func migratedDB(t *testing.T) test.PostgresConn {
	t.Helper()

	set := migrate.SecurityState()
	conn := test.RunTestPostgres(t, test.WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))
	conn.DB.SetMaxOpenConns(poolSize)

	return conn
}

// emptied truncates table and returns db, so a portable suite's factory hands
// each case an empty store over the test's one database. The suites run their
// cases one after another, so no case sees another's truncation.
func emptied(t *testing.T, db *sql.DB, table string) *sql.DB {
	t.Helper()

	// table is always one of this package's constants, never input.
	_, err := db.ExecContext(t.Context(), "TRUNCATE "+table)
	require.NoError(t, err)

	return db
}

// openReplica opens a second handle on the database at dsn, with its own
// connection pool, as a second replica of an application would.
func openReplica(t *testing.T, dsn string) *sql.DB {
	t.Helper()

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	db.SetMaxOpenConns(poolSize)
	t.Cleanup(func() { _ = db.Close() })

	return db
}

// unreachableDB is a handle on a server that is not there. Constructors never
// touch the database, so it builds any store; an operation on it fails.
func unreachableDB(t *testing.T) *sql.DB {
	t.Helper()

	return openReplica(t, "postgres://nobody@127.0.0.1:1/none?connect_timeout=5")
}

// refusedConfig asserts a constructor refused its configuration with exactly
// text, and returned no store.
func refusedConfig[S any](text string) func(t *testing.T, s S, err error) {
	return storefix.RefusedConfig[S](sqlstore.ErrConfig, "sqlstore", text)
}

// storeFactory builds a store of type S over db with opts, failing t when the
// constructor refuses.
type storeFactory[S any] func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) S

// durableHarness is the harness the durable suites take, over the database of
// conn:
//   - New builds the store on conn.DB, and NewReplica on a handle of its own
//     opened from conn.DSN, so racers split across two pools;
//   - Raw is conn.DB;
//   - Begin attaches a transaction of conn.DB with sqlstore.WithTx;
//   - BeginResolved builds a store whose resolver reports the transaction;
//   - BeginForeign attaches a transaction of another backend: see
//     beginForeign;
//   - PoolSize is the width every handle here is set to.
func durableHarness[S any](conn test.PostgresConn, newWith storeFactory[S]) storetest.DurableHarness[S] {
	db := conn.DB

	begin := func(t *testing.T) *sql.Tx {
		t.Helper()
		tx, err := db.BeginTx(t.Context(), nil)
		require.NoError(t, err)
		return tx
	}

	return storetest.DurableHarness[S]{
		Harness: storetest.Harness[S]{
			New: func(t *testing.T) S { return newWith(t, db) },
		},
		NewReplica: func(t *testing.T) S { return newWith(t, openReplica(t, conn.DSN)) },
		Raw:        db,
		Begin: func(t *testing.T) (context.Context, func() error, func() error) {
			tx := begin(t)
			return sqlstore.WithTx(t.Context(), tx), tx.Commit, tx.Rollback
		},
		BeginResolved: func(t *testing.T) (S, context.Context, func() error, func() error) {
			tx := begin(t)
			s := newWith(t, db, sqlstore.WithTxResolver(func(context.Context) (sqlstore.DBTX, bool) {
				return tx, true
			}))
			return s, t.Context(), tx.Commit, tx.Rollback
		},
		BeginForeign: func(t *testing.T) (context.Context, func() error) {
			t.Helper()
			return beginForeign(t, conn.DSN)
		},
		PoolSize: poolSize,
	}
}

// foreignTxKey is the context key beginForeign attaches its transaction
// under. It belongs to this test package, not to sqlstore.
type foreignTxKey struct{}

// beginForeign begins a transaction on the database at dsn through a pgx
// connection pool, a backend other than database/sql, and attaches it to the
// context under a key of its own, as another backend's adapter attaches its
// transactions under a key private to that adapter. To sqlstore that is
// exactly what another backend's attachment is: a live transaction on the
// same database, in a context value it cannot see. A store that wrote in it
// would lose its write to the rollback.
//
// The pool is closed at cleanup, after the suite's own cleanup rolls the
// transaction back and returns its connection.
func beginForeign(t *testing.T, dsn string) (context.Context, func() error) {
	t.Helper()

	pool, err := pgxpool.New(t.Context(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	tx, err := pool.Begin(t.Context())
	require.NoError(t, err)

	// The rollback may run at cleanup, when t.Context() is already done.
	rollbackCtx := context.WithoutCancel(t.Context())

	return context.WithValue(t.Context(), foreignTxKey{}, tx), func() error { return tx.Rollback(rollbackCtx) }
}
