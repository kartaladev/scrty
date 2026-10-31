package sqlstore

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDBTX stands in for a consumer transaction manager's handle. It is only
// ever compared by identity: resolution never runs a statement.
type fakeDBTX struct{ DBTX }

// foreignTxKey is the kind of key another backend attaches its transaction
// under; sqlstore must never see a transaction attached that way.
type foreignTxKey struct{}

func TestConfigConn(t *testing.T) {
	t.Parallel()

	// Zero values, never used to run a statement: resolution only picks one,
	// and the assertions compare them by pointer.
	base := new(sql.DB)
	attached := new(sql.Tx)
	inner := new(sql.Tx)
	resolvedTx := new(sql.Tx)
	managed := &fakeDBTX{}

	type testCase struct {
		name   string
		opts   []Option
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, q DBTX, tx *sql.Tx, ambient bool, err error)
	}

	isBase := func(t *testing.T, q DBTX, tx *sql.Tx, ambient bool, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.Same(t, base, q)
		assert.Nil(t, tx)
		assert.False(t, ambient)
	}
	isAttached := func(want *sql.Tx) func(t *testing.T, q DBTX, tx *sql.Tx, ambient bool, err error) {
		return func(t *testing.T, q DBTX, tx *sql.Tx, ambient bool, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Same(t, want, q)
			assert.Same(t, want, tx)
			assert.True(t, ambient)
		}
	}
	isNilHandle := func(t *testing.T, q DBTX, tx *sql.Tx, ambient bool, err error) {
		t.Helper()
		require.ErrorIs(t, err, ErrNilTransaction)
		assert.Nil(t, q, "no handle is resolved when the resolver's is nil")
		assert.Nil(t, tx)
		assert.False(t, ambient)
	}

	cases := []testCase{
		{
			name:   "no resolver and nothing attached uses the base handle",
			assert: isBase,
		},
		{
			name:   "a transaction attached with WithTx is used and is ambient",
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, attached) },
			assert: isAttached(attached),
		},
		{
			name: "the innermost WithTx wins",
			ctx: func(ctx context.Context) context.Context {
				return WithTx(WithTx(ctx, attached), inner)
			},
			assert: isAttached(inner),
		},
		{
			name: "an attached transaction is still resolved on a cancelled context",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(WithTx(ctx, attached))
				cancel()
				return cctx
			},
			assert: isAttached(attached),
		},
		{
			name: "a transaction attached under another backend's key is invisible",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, foreignTxKey{}, attached)
			},
			assert: isBase,
		},
		{
			name:   "WithTx with a nil transaction attaches nothing",
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, nil) },
			assert: isBase,
		},
		{
			name: "WithTx with a nil transaction leaves an outer attachment in place",
			ctx: func(ctx context.Context) context.Context {
				return WithTx(WithTx(ctx, attached), nil)
			},
			assert: isAttached(attached),
		},
		{
			name: "a resolver's transaction wins over one attached to the context",
			opts: []Option{WithTxResolver(func(context.Context) (DBTX, bool) { return managed, true })},
			ctx:  func(ctx context.Context) context.Context { return WithTx(ctx, attached) },
			assert: func(t *testing.T, q DBTX, tx *sql.Tx, ambient bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Same(t, managed, q)
				assert.Nil(t, tx, "a resolved handle that is not a *sql.Tx has no *sql.Tx to report")
				assert.True(t, ambient)
			},
		},
		{
			name:   "a resolver reporting a *sql.Tx reports it as the transaction",
			opts:   []Option{WithTxResolver(func(context.Context) (DBTX, bool) { return resolvedTx, true })},
			assert: isAttached(resolvedTx),
		},
		{
			name:   "a resolver reporting none uses the base handle even with a transaction attached",
			opts:   []Option{WithTxResolver(func(context.Context) (DBTX, bool) { return nil, false })},
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, attached) },
			assert: isBase,
		},
		{
			name: "the resolver is asked with the operation's context",
			opts: []Option{WithTxResolver(func(ctx context.Context) (DBTX, bool) {
				v, ok := ctx.Value(foreignTxKey{}).(*sql.Tx)
				return v, ok
			})},
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, foreignTxKey{}, resolvedTx)
			},
			assert: isAttached(resolvedTx),
		},
		{
			name:   "a resolver reporting a transaction with an untyped nil handle is refused",
			opts:   []Option{WithTxResolver(func(context.Context) (DBTX, bool) { return nil, true })},
			assert: isNilHandle,
		},
		{
			name: "a resolver reporting a transaction with a typed nil *sql.Tx is refused",
			opts: []Option{WithTxResolver(func(context.Context) (DBTX, bool) {
				return (*sql.Tx)(nil), true
			})},
			assert: isNilHandle,
		},
		{
			name: "a resolver reporting a transaction with a typed nil handle of its own type is refused",
			opts: []Option{WithTxResolver(func(context.Context) (DBTX, bool) {
				return (*fakeDBTX)(nil), true
			})},
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

			q, tx, ambient, err := c.conn(ctx)
			tc.assert(t, q, tx, ambient, err)
		})
	}
}
