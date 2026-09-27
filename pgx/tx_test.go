package pgx

import (
	"context"
	"database/sql"
	"testing"

	pgxv5 "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/sqlstore"
)

// fakeTx stands in for a caller's pgx transaction. It is only ever compared
// by identity: resolution never runs a statement.
type fakeTx struct{ pgxv5.Tx }

// foreignTxKey is the kind of key another backend attaches its transaction
// under; these stores must never see a transaction attached that way.
type foreignTxKey struct{}

func TestConfigConn(t *testing.T) {
	t.Parallel()

	// Zero values, never used to run a statement: resolution only picks one,
	// and the assertions compare them by pointer.
	base := new(pgxpool.Pool)
	attached := &fakeTx{}
	inner := &fakeTx{}
	resolved := &fakeTx{}

	type testCase struct {
		name   string
		opts   []Option
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, q DBTX, ambient bool, err error)
	}

	isBase := func(t *testing.T, q DBTX, ambient bool, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.Same(t, base, q)
		assert.False(t, ambient)
	}
	isTx := func(want *fakeTx) func(t *testing.T, q DBTX, ambient bool, err error) {
		return func(t *testing.T, q DBTX, ambient bool, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Same(t, want, q)
			assert.True(t, ambient)
		}
	}
	isNilHandle := func(t *testing.T, q DBTX, ambient bool, err error) {
		t.Helper()
		require.ErrorIs(t, err, ErrNilTransaction)
		assert.Nil(t, q, "no handle is resolved when the resolver's is nil")
		assert.False(t, ambient)
	}
	resolver := func(tx pgxv5.Tx, ok bool) []Option {
		return []Option{WithTxResolver(func(context.Context) (pgxv5.Tx, bool) { return tx, ok })}
	}

	cases := []testCase{
		{
			name:   "no resolver and nothing attached uses the pool",
			assert: isBase,
		},
		{
			name:   "a transaction attached with WithTx is used and is ambient",
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, attached) },
			assert: isTx(attached),
		},
		{
			name: "the innermost WithTx wins",
			ctx: func(ctx context.Context) context.Context {
				return WithTx(WithTx(ctx, attached), inner)
			},
			assert: isTx(inner),
		},
		{
			name: "an attached transaction is still resolved on a cancelled context",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(WithTx(ctx, attached))
				cancel()
				return cctx
			},
			assert: isTx(attached),
		},
		{
			name: "a transaction attached under another backend's key is invisible",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, foreignTxKey{}, attached)
			},
			assert: isBase,
		},
		{
			name: "a transaction attached for the database/sql stores is invisible",
			ctx: func(ctx context.Context) context.Context {
				return sqlstore.WithTx(ctx, new(sql.Tx))
			},
			assert: isBase,
		},
		{
			name:   "WithTx with a nil transaction attaches nothing",
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, nil) },
			assert: isBase,
		},
		{
			name:   "WithTx with a typed nil transaction attaches nothing",
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, (*fakeTx)(nil)) },
			assert: isBase,
		},
		{
			name: "WithTx with a nil transaction leaves an outer attachment in place",
			ctx: func(ctx context.Context) context.Context {
				return WithTx(WithTx(ctx, attached), nil)
			},
			assert: isTx(attached),
		},
		{
			name:   "a resolver's transaction wins over one attached to the context",
			opts:   resolver(resolved, true),
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, attached) },
			assert: isTx(resolved),
		},
		{
			name:   "a resolver reporting none uses the pool even with a transaction attached",
			opts:   resolver(nil, false),
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, attached) },
			assert: isBase,
		},
		{
			name: "the resolver is asked with the operation's context",
			opts: []Option{WithTxResolver(func(ctx context.Context) (pgxv5.Tx, bool) {
				v, ok := ctx.Value(foreignTxKey{}).(*fakeTx)
				return v, ok
			})},
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, foreignTxKey{}, resolved)
			},
			assert: isTx(resolved),
		},
		{
			name:   "a resolver reporting a transaction with an untyped nil handle is refused",
			opts:   resolver(nil, true),
			assert: isNilHandle,
		},
		{
			name:   "a resolver reporting a transaction with a typed nil handle is refused",
			opts:   resolver((*fakeTx)(nil), true),
			assert: isNilHandle,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			c, err := newConfig(base, tc.opts)
			require.NoError(t, err)

			q, ambient, err := c.conn(ctx)
			tc.assert(t, q, ambient, err)
		})
	}
}
