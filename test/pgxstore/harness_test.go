// Package pgxstore_test runs the native pgx stores of the scrty pgx module
// against PostgreSQL: the portable conformance suites, the durable suites, and
// the cases only a real database can show.
//
// Every test starts one container through test.RunTestPostgres and shares it
// among its cases, reaching it through a pgxpool.Pool opened from the
// helper's DSN. The portable suites run their cases one after another and
// require an empty store for each, so their factories empty the store's table
// before handing it over; the durable suites and tables use records of their
// own and never empty anything.
package pgxstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/migrate"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// poolSize is the most connections every pool here may open at once. The race
// suites race 8 callers per record, so this leaves room; it is each pool's
// MaxConns, and the harness declares the width it reads back from the pool.
const poolSize = 32

// poolCloseWait bounds how long a pool's cleanup waits for its connections to
// come back. pgxpool.Pool.Close waits for every acquired connection, and a
// racer that ignored its context would otherwise hang the test in cleanup.
const poolCloseWait = 10 * time.Second

// database is one migrated PostgreSQL database: the helper's handles, and a
// pool the stores run on.
type database struct {
	test.PostgresConn

	Pool *pgxpool.Pool
}

// migrated starts PostgreSQL with the security-state set applied, and opens a
// pool on it. The set is rolled back at cleanup.
func migrated(t *testing.T) database {
	t.Helper()

	set := migrate.SecurityState()
	conn := test.RunTestPostgres(t, test.WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))

	return database{PostgresConn: conn, Pool: openPool(t, conn.DSN)}
}

// openPool opens a pool of at most poolSize connections on the database at
// dsn, as a replica of an application would, and closes it at cleanup
// without waiting longer than poolCloseWait. It never connects eagerly.
func openPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.MaxConns = poolSize

	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { closeBounded(t, pool) })

	return pool
}

// closeBounded closes pool, and fails t instead of hanging when a connection
// is not returned within poolCloseWait. The close goes on in the background:
// the connection it waits for belongs to a call the test already abandoned.
func closeBounded(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		defer close(done)
		pool.Close()
	}()

	select {
	case <-done:
	case <-time.After(poolCloseWait):
		t.Errorf("the pool did not close within %v: a connection was never returned", poolCloseWait)
	}
}

// emptied truncates table, so a portable suite's factory hands each case an
// empty store over the test's one database. The suites run their cases one
// after another, so no case sees another's truncation.
func emptied(t *testing.T, db database, table string) *pgxpool.Pool {
	t.Helper()

	// table is always one of this package's constants, never input.
	_, err := db.DB.ExecContext(t.Context(), "TRUNCATE "+table)
	require.NoError(t, err)

	return db.Pool
}

// unreachablePool is a pool on a server that is not there. Constructors never
// touch the database, and the pool does not connect until used, so it builds
// any store; an operation on it fails.
func unreachablePool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	return openPool(t, "postgres://nobody@127.0.0.1:1/none?connect_timeout=5")
}

// refusedConfig asserts a constructor refused its configuration with exactly
// text, and returned no store.
func refusedConfig[S any](text string) func(t *testing.T, s S, err error) {
	return storefix.RefusedConfig[S](pgxstore.ErrConfig, "pgx", text)
}

// beginTx begins a transaction of pool for a table case, and rolls it back at
// cleanup unless the case ended it. The rollback may run when t.Context() is
// already done.
func beginTx(ctx context.Context, t *testing.T, pool *pgxpool.Pool) pgx.Tx {
	t.Helper()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(context.WithoutCancel(ctx)) })

	return tx
}

// storeFactory builds a store of type S over pool with opts, failing t when
// the constructor refuses.
type storeFactory[S any] func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) S

// durableHarness is the harness the durable suites take, over db:
//   - New builds the store on db.Pool, and NewReplica on a pool of its own
//     opened from db.DSN, so racers split across two pools;
//   - Raw is db.DB, the helper's database/sql handle;
//   - Begin attaches a transaction of db.Pool with pgxstore.WithTx;
//   - BeginResolved builds a store whose resolver reports the transaction;
//   - BeginForeign attaches a database/sql transaction with sqlstore.WithTx,
//     the other backend's own attachment;
//   - PoolSize is db.Pool's MaxConns.
func durableHarness[S any](db database, newWith storeFactory[S]) storetest.DurableHarness[S] {
	pool := db.Pool

	// begin starts a transaction of pool. Its commit and rollback may run at
	// cleanup, when t.Context() is already done.
	begin := func(t *testing.T) (pgx.Tx, func() error, func() error) {
		t.Helper()
		tx, err := pool.Begin(t.Context())
		require.NoError(t, err)
		ctx := context.WithoutCancel(t.Context())
		return tx, func() error { return tx.Commit(ctx) }, func() error { return tx.Rollback(ctx) }
	}

	return storetest.DurableHarness[S]{
		Harness: storetest.Harness[S]{
			New: func(t *testing.T) S { return newWith(t, pool) },
		},
		NewReplica: func(t *testing.T) S { return newWith(t, openPool(t, db.DSN)) },
		Raw:        db.DB,
		Begin: func(t *testing.T) (context.Context, func() error, func() error) {
			tx, commit, rollback := begin(t)
			return pgxstore.WithTx(t.Context(), tx), commit, rollback
		},
		BeginResolved: func(t *testing.T) (S, context.Context, func() error, func() error) {
			tx, commit, rollback := begin(t)
			s := newWith(t, pool, pgxstore.WithTxResolver(func(context.Context) (pgx.Tx, bool) {
				return tx, true
			}))
			return s, t.Context(), commit, rollback
		},
		BeginForeign: func(t *testing.T) (context.Context, func() error) {
			t.Helper()
			return storefix.BeginSQLStoreTx(t, db.DB)
		},
		PoolSize: int(pool.Config().MaxConns),
	}
}
