package sqlstore

import (
	"context"
	"database/sql"

	"github.com/kartaladev/scrty/internal/nilcheck"
)

// DBTX is the subset of *sql.DB and *sql.Tx a store runs its statements on.
// Both satisfy it, as does any consumer handle offering the same three methods,
// which is what a TxResolver returns.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// TxResolver reports the transaction a store should run an operation on, given
// the operation's context. It reports false when there is none, and the store
// then uses the *sql.DB it was constructed with.
//
// A resolver that reports true must return a non-nil handle. When it reports
// true with a nil handle, including an interface holding a nil pointer, the
// store runs no statement and returns an error wrapping ErrNilTransaction,
// rather than panicking or falling back to its *sql.DB: the resolver said the
// operation belongs to a transaction, and running it outside one would detach
// it from the caller's commit or rollback.
//
// A consumer whose transaction manager already carries the current transaction
// in the context supplies one with WithTxResolver, so the transaction needs no
// second attachment through WithTx.
type TxResolver func(ctx context.Context) (DBTX, bool)

// txKey is the context key WithTx attaches under. It is unexported and belongs
// to this package alone, so a transaction another backend attaches is never
// seen by these stores, and theirs never sees this one.
type txKey struct{}

// WithTx returns a copy of ctx carrying tx, so that every store in this package
// runs operations made with that context inside tx. The stores never commit or
// roll back tx: its outcome belongs to the caller, and so does the outcome of
// every store write made inside it.
//
// A nil tx attaches nothing: ctx is returned unchanged, so a transaction an
// outer WithTx attached still applies. A store configured with WithTxResolver
// ignores what WithTx attached and asks its resolver instead.
//
// A transaction attached for another backend (the pgx or gorm adapters) is
// invisible to these stores, and this one is invisible to theirs.
//
// Limit: a refusal (an already-consumed token, a duplicate link, a stale save)
// is reported without a failed statement, so it never aborts tx. Any statement
// a store runs inside tx that fails for an unexpected reason does abort it, as
// PostgreSQL defines: a read (for example one cancelled by a statement timeout)
// as much as a write. Every later statement in tx then fails, and tx can only
// be rolled back.
func WithTx(ctx context.Context, tx *sql.Tx) context.Context {
	if tx == nil {
		return ctx
	}

	return context.WithValue(ctx, txKey{}, tx)
}

// conn resolves the handle an operation on ctx runs on: the resolver's
// transaction when a resolver is configured and reports one, otherwise the
// transaction WithTx attached, when no resolver is configured, otherwise the
// base handle. A configured resolver replaces the context lookup entirely, so
// its false means the base handle even with a transaction attached.
//
// ambient reports that the handle is a caller's transaction, whichever way it
// was supplied. tx is that transaction when it is a *sql.Tx, and nil otherwise:
// a resolver may hand back a handle of its own type.
//
// A resolver reporting a transaction with a nil handle yields ErrNilTransaction
// and no handle; the calling store wraps it with its operation name and runs no
// statement.
func (c *config) conn(ctx context.Context) (q DBTX, tx *sql.Tx, ambient bool, err error) {
	if c.resolver != nil {
		h, ok := c.resolver(ctx)
		if !ok {
			return c.base, nil, false, nil
		}
		if nilcheck.IsNil(h) {
			return nil, nil, false, ErrNilTransaction
		}

		t, _ := h.(*sql.Tx)

		return h, t, true, nil
	}

	if t, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return t, t, true, nil
	}

	return c.base, nil, false, nil
}
