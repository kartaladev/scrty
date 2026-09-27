package gorm

import (
	"context"

	gormdb "gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TxResolver reports the transaction a store should run an operation on, given
// the operation's context. It reports false when there is none, and the store
// then uses the *gorm.DB it was constructed with.
//
// A resolver that reports true must return a non-nil handle. When it reports
// true with a nil handle, the store runs no statement and returns an error
// wrapping ErrNilTransaction, rather than panicking or falling back to its
// *gorm.DB: the resolver said the operation belongs to a transaction, and
// running it outside one would detach it from the caller's commit or rollback.
//
// A consumer whose transaction manager already carries the current transaction
// in the context supplies one with WithTxResolver, so the transaction needs no
// second attachment through WithTx.
type TxResolver func(ctx context.Context) (*gormdb.DB, bool)

// txKey is the context key WithTx attaches under. It is unexported and belongs
// to this package alone, so a transaction another backend attaches is never
// seen by these stores, and theirs never sees this one.
type txKey struct{}

// WithTx returns a copy of ctx carrying tx, a transaction begun on a *gorm.DB
// (db.Begin(), or the handle db.Transaction hands its function), so that every
// store in this package runs operations made with that context inside tx. The
// stores never commit or roll back tx: its outcome belongs to the caller, and
// so does the outcome of every store write made inside it.
//
// The stores run on tx's connection only. Conditions, a logger or any other
// session state chained on tx do not carry into their statements.
//
// A nil tx attaches nothing: ctx is returned unchanged, so a transaction an
// outer WithTx attached still applies. A store configured with WithTxResolver
// ignores what WithTx attached and asks its resolver instead.
//
// A transaction attached for another backend (package sqlstore, or the pgx
// adapter) is invisible to these stores, and this one is invisible to theirs.
//
// Limit: a refusal (an already-consumed token, a duplicate identifier, a stale
// save) is reported without a failed statement, so it never aborts tx. Any
// statement a store runs inside tx that fails for an unexpected reason does
// abort it, as PostgreSQL defines: a read (for example one cancelled by a
// statement timeout) as much as a write. Every later statement in tx then
// fails, and tx can only be rolled back.
func WithTx(ctx context.Context, tx *gormdb.DB) context.Context {
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
// was supplied. A resolver reporting a transaction with a nil handle yields
// ErrNilTransaction and no handle; the calling store wraps it with its
// operation name and runs no statement.
//
// The handle returned is a fresh session on the resolved one's connection
// (see opSession), never the resolved handle itself.
func (c *config) conn(ctx context.Context) (q *gormdb.DB, ambient bool, err error) {
	if c.resolver != nil {
		h, ok := c.resolver(ctx)
		if !ok {
			return opSession(ctx, c.base), false, nil
		}
		if h == nil {
			return nil, false, ErrNilTransaction
		}

		return opSession(ctx, h), true, nil
	}

	if t, ok := ctx.Value(txKey{}).(*gormdb.DB); ok {
		return opSession(ctx, t), true, nil
	}

	return opSession(ctx, c.base), false, nil
}

// opSession returns a new session on h's connection for one operation on ctx:
//   - with no conditions or other statement state h may carry, so a caller's
//     chained WHERE never narrows a store's statement;
//   - with gorm's logger discarded, because gorm's loggers print statements
//     with their bound values, which here are secrets, digests and user
//     references;
//   - without gorm's default transaction, which would wrap each write in a
//     BEGIN and COMMIT of its own: every operation is one statement, run on
//     the caller's transaction when there is one;
//   - without model hooks, which the store's models do not have and which
//     would otherwise be free to run statements of their own.
func opSession(ctx context.Context, h *gormdb.DB) *gormdb.DB {
	return h.Session(&gormdb.Session{
		NewDB:                  true,
		Context:                ctx,
		Logger:                 logger.Discard,
		SkipDefaultTransaction: true,
		SkipHooks:              true,
	})
}
