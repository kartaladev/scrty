package pgxstore

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/store"
)

// DBTX is the subset of *pgxpool.Pool and pgx.Tx a store runs its statements
// on. Both satisfy it.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// TxResolver reports the transaction a store should run an operation on, given
// the operation's context. It reports false when there is none, and the store
// then uses the *pgxpool.Pool it was constructed with.
//
// A resolver that reports true must return a non-nil transaction. When it
// reports true with a nil one, including an interface holding a nil pointer,
// the store runs no statement and returns an error wrapping
// ErrNilTransaction, rather than panicking or falling back to its pool: the
// resolver said the operation belongs to a transaction, and running it outside
// one would detach it from the caller's commit or rollback.
//
// A consumer whose transaction manager already carries the current
// transaction in the context supplies one with WithTxResolver, so the
// transaction needs no second attachment through WithTx.
type TxResolver func(ctx context.Context) (pgx.Tx, bool)

// txKey is the context key WithTx attaches under. It is unexported and belongs
// to this package alone, so a transaction another backend attaches (the
// database/sql stores' or the gorm adapter's) is never seen by these stores,
// and theirs never sees this one.
type txKey struct{}

// WithTx returns a copy of ctx carrying tx, so that every store in this package
// runs operations made with that context inside tx. The stores never commit or
// roll back tx: its outcome belongs to the caller, and so does the outcome of
// every store write made inside it.
//
// A nil tx, including an interface holding a nil pointer, attaches nothing:
// ctx is returned unchanged, so a transaction an outer WithTx attached still
// applies. A store configured with WithTxResolver ignores what WithTx attached
// and asks its resolver instead.
//
// A transaction attached for another backend (the database/sql stores or the
// gorm adapter) is invisible to these stores, and this one is invisible to
// theirs.
//
// Limit: a refusal (an already-consumed token, a duplicate link, a stale save)
// is reported without a failed statement, so it never aborts tx. Any statement
// a store runs inside tx that fails for an unexpected reason does abort it, as
// PostgreSQL defines: a read (for example one cancelled by a statement timeout)
// as much as a write. Every later statement in tx then fails, and tx can only
// be rolled back.
func WithTx(ctx context.Context, tx pgx.Tx) context.Context {
	if nilcheck.IsNil(tx) {
		return ctx
	}

	return context.WithValue(ctx, txKey{}, tx)
}

// conn resolves the handle an operation on ctx runs on: the resolver's
// transaction when a resolver is configured and reports one, otherwise the
// transaction WithTx attached, when no resolver is configured, otherwise the
// pool. A configured resolver replaces the context lookup entirely, so its
// false means the pool even with a transaction attached.
//
// ambient reports that the handle is a caller's transaction, whichever way it
// was supplied.
//
// A resolver reporting a transaction with a nil handle yields
// ErrNilTransaction and no handle; the calling store wraps it with its
// operation name and runs no statement.
func (c *config) conn(ctx context.Context) (q DBTX, ambient bool, err error) {
	if c.resolver != nil {
		tx, ok := c.resolver(ctx)
		if !ok {
			return c.base, false, nil
		}
		if nilcheck.IsNil(tx) {
			return nil, false, ErrNilTransaction
		}

		return tx, true, nil
	}

	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return tx, true, nil
	}

	return c.base, false, nil
}

// ErrIsolationTooStrong is wrapped by the error an operation returns when it
// is run inside a caller's transaction whose isolation is stronger than READ
// COMMITTED, and its guarantee depends on READ COMMITTED. It is
// store.ErrIsolationTooStrong under this package's name, so errors.Is
// matches either, and the error names the isolation it found. The operation
// writes nothing, and the caller's transaction stays usable. The operations
// that refuse are RecoveryCodeStore.ReplaceSet, AttemptStore.AddStreakFailure,
// OneTimeStore.InsertWithin and PasskeyCredentialStore.InsertWithin;
// every other operation joins a caller's transaction at any isolation. There
// is no option to relax it: a store cannot change a transaction's isolation
// once it has begun, so a consumer whose own work needs a stronger isolation
// runs these operations outside that transaction.
var ErrIsolationTooStrong = store.ErrIsolationTooStrong

// beginReadCommitted begins a transaction of the store's own on its pool at
// READ COMMITTED, whatever the database's or the role's default isolation is.
// The isolation travels in the BEGIN itself (BEGIN ISOLATION LEVEL READ
// COMMITTED), so setting it costs no round trip of its own. A failure to
// begin is returned as the driver gave it.
func (c *config) beginReadCommitted(ctx context.Context) (pgx.Tx, error) {
	return beginReadCommitted(ctx, c.base)
}

// beginReadCommitted is config.beginReadCommitted on pool, for the limiter,
// which has no store config.
func beginReadCommitted(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {
	return pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
}

// readCommitted runs fn in a READ COMMITTED transaction of the store's own,
// begun by beginReadCommitted, and commits it when fn succeeds. It is rolled
// back on every other way out, a panic in fn included, even when ctx is done,
// so the transaction and its locks never outlive the call. fn's error is
// returned as it is; a failure to begin or commit as the driver gave it.
func (c *config) readCommitted(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := c.beginReadCommitted(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// requireReadCommitted reads the isolation of q, a caller's transaction, and
// refuses one stronger than READ COMMITTED with an error wrapping
// ErrIsolationTooStrong and naming the isolation found. The read is a plain
// SELECT, so a refusal leaves the transaction usable. A failure to read is
// returned as the driver gave it.
func (c *config) requireReadCommitted(ctx context.Context, q DBTX) error {
	var level string
	if err := q.QueryRow(ctx, pgschema.CurrentIsolation).Scan(&level); err != nil {
		return err
	}
	if !pgschema.ReadCommittedOrWeaker(level) {
		return fmt.Errorf("%w: it runs at %s", ErrIsolationTooStrong, level)
	}

	return nil
}
