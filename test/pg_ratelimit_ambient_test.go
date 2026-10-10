package test

import (
	"context"
	"testing"
	"time"

	pgxv5 "github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// pgAmbient is a caller's open transaction on one backend: a session store
// that writes in it, the context to call through, a limiter of the same
// backend, and the rollback.
type pgAmbient struct {
	sessions session.Store
	ctx      context.Context
	limiter  ratelimit.Limiter
	rollback func() error
}

// sqlstoreAmbient begins a transaction on a handle of its own. Attached, the
// transaction rides on the context through sqlstore.WithTx; resolved, the
// session store's WithTxResolver returns it and the context carries none.
func sqlstoreAmbient(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, resolved bool) pgAmbient {
	t.Helper()

	db := pgFaultDB(t, conn, nil)
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })

	ctx := sqlstore.WithTx(t.Context(), tx)
	var opts []sqlstore.Option
	if resolved {
		ctx = t.Context()
		opts = append(opts, sqlstore.WithTxResolver(func(context.Context) (sqlstore.DBTX, bool) { return tx, true }))
	}
	sessions, err := sqlstore.NewSessionStore(db, storefix.TestCipher(t), opts...)
	require.NoError(t, err)

	return pgAmbient{
		sessions: sessions,
		ctx:      ctx,
		limiter:  sqlstoreFaultLimiter(t, conn, ns, limit, window, pgFaultOptions{}),
		rollback: tx.Rollback,
	}
}

// pgxAmbient is sqlstoreAmbient for the pgx backend, over a pool of its own.
func pgxAmbient(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, resolved bool) pgAmbient {
	t.Helper()

	pool := pgFaultPool(t, conn, nil)
	tx, err := pool.Begin(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	ctx := pgxstore.WithTx(t.Context(), tx)
	var opts []pgxstore.Option
	if resolved {
		ctx = t.Context()
		opts = append(opts, pgxstore.WithTxResolver(func(context.Context) (pgxv5.Tx, bool) { return tx, true }))
	}
	sessions, err := pgxstore.NewSessionStore(pool, storefix.TestCipher(t), opts...)
	require.NoError(t, err)

	return pgAmbient{
		sessions: sessions,
		ctx:      ctx,
		limiter:  pgxFaultLimiter(t, conn, ns, limit, window, pgFaultOptions{}),
		rollback: func() error { return tx.Rollback(context.Background()) },
	}
}

// runPGIgnoresAmbientTx pins that the limiter ignores its caller's
// transaction: a failure recorded while the caller's transaction is attached,
// or resolved by the session store, still counts after that transaction rolls
// back, while a session saved in it does not survive.
func runPGIgnoresAmbientTx(t *testing.T, b pgFaultBackend) {
	t.Helper()

	type testCase struct {
		name     string
		resolved bool
		assert   func(t *testing.T, sessionKept, exceeded bool, err error)
	}

	rolledBack := func(t *testing.T, sessionKept, exceeded bool, err error) {
		t.Helper()
		assert.False(t, sessionKept, "the session saved in the rolled back transaction survived")
		require.NoError(t, err)
		assert.True(t, exceeded, "the failure recorded during the rolled back transaction was lost")
	}

	cases := []testCase{
		{name: "transaction attached to the context", assert: rolledBack},
		{name: "transaction from the session store's resolver", resolved: true, assert: rolledBack},
	}

	conn := migratedLimiterDB(t)
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sid := storefix.AmbientSID(1000 + i)
			a := b.ambient(t, conn, pgScopedNamespace(t, "ambient"), 1, time.Minute, tc.resolved)
			require.NoError(t, a.sessions.Create(a.ctx, storefix.DurableSession(sid, time.Now())))
			require.NoError(t, a.limiter.RecordFailure(a.ctx, "k"))
			require.NoError(t, a.rollback())

			kept := storefix.Exists(t, conn.DB, `SELECT EXISTS (SELECT 1 FROM sessions WHERE id_digest = $1)`, storefix.Digest(sid))
			exceeded, err := a.limiter.Exceeded(t.Context(), "k")
			tc.assert(t, kept, exceeded, err)
		})
	}
}

func TestPGLimiter_IgnoresAmbientTx(t *testing.T) {
	t.Parallel()

	runPGFaultBackends(t, runPGIgnoresAmbientTx)
}

// pgJoiningBackend is the sqlstore backend whose limiter records on the
// caller's transaction, as a limiter honouring WithTx or a resolver would.
var pgJoiningBackend = func() pgFaultBackend {
	b := sqlstoreFaultBackend
	b.name = pgFaultBrokenBackend
	b.ambient = func(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, resolved bool) pgAmbient {
		t.Helper()

		db := pgFaultDB(t, conn, nil)
		tx, err := db.BeginTx(t.Context(), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = tx.Rollback() })

		ctx := sqlstore.WithTx(t.Context(), tx)
		var opts []sqlstore.Option
		if resolved {
			ctx = t.Context()
			opts = append(opts, sqlstore.WithTxResolver(func(context.Context) (sqlstore.DBTX, bool) { return tx, true }))
		}
		sessions, err := sqlstore.NewSessionStore(db, storefix.TestCipher(t), opts...)
		require.NoError(t, err)

		return pgAmbient{
			sessions: sessions,
			ctx:      ctx,
			limiter: newPGStatementLimiter(t, conn, ns, limit, window, pgFaultOptions{},
				dbExecer(tx), pgRecordStatement, "5000ms"),
			rollback: tx.Rollback,
		}
	}
	return b
}()

var pgIgnoresAmbientTxBroken = pgFaultVariants(runPGIgnoresAmbientTx,
	pgFaultVariant{
		name:      "joins-the-transaction",
		backend:   pgJoiningBackend,
		failsCase: "transaction attached to the context",
		failsWith: "the failure recorded during the rolled back transaction was lost",
	},
	pgFaultVariant{
		name:      "joins-the-resolved-transaction",
		backend:   pgJoiningBackend,
		failsCase: "transaction from the session store's resolver",
		failsWith: "the failure recorded during the rolled back transaction was lost",
	},
)

// TestPGLimiter_IgnoresAmbientTxBroken is the child half of
// TestPGLimiter_IgnoresAmbientTxCatchesBrokenVariants. Without a variant named
// it skips.
func TestPGLimiter_IgnoresAmbientTxBroken(t *testing.T) {
	storefix.RunBrokenChild(t, pgFaultBrokenVar, "TestPGLimiter_IgnoresAmbientTxCatchesBrokenVariants", pgIgnoresAmbientTxBroken)
}

func TestPGLimiter_IgnoresAmbientTxCatchesBrokenVariants(t *testing.T) {
	t.Parallel()

	catchPGFaultVariants(t, "TestPGLimiter_IgnoresAmbientTxBroken", pgIgnoresAmbientTxBroken)
}
