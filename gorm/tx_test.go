package gorm

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/utils/tests"
)

// fakePool stands in for a connection pool or a transaction. It is only ever
// compared by identity: resolution never runs a statement, and a fakePool
// would panic if asked to.
type fakePool struct {
	gormdb.ConnPool

	name string
}

// fakeDB returns a *gorm.DB over a pool of its own, named name, that never
// reaches a database.
func fakeDB(t *testing.T, name string) (*gormdb.DB, *fakePool) {
	t.Helper()

	pool := &fakePool{name: name}
	db, err := gormdb.Open(tests.DummyDialector{}, &gormdb.Config{ConnPool: pool})
	require.NoError(t, err)

	return db, pool
}

// foreignTxKey is the kind of key another backend attaches its transaction
// under; these stores must never see a transaction attached that way.
type foreignTxKey struct{}

// resolvedPool is the pool a resolved handle runs its statements on.
func resolvedPool(t *testing.T, q *gormdb.DB) *fakePool {
	t.Helper()

	require.NotNil(t, q)
	pool, ok := q.Statement.ConnPool.(*fakePool)
	require.True(t, ok, "the resolved handle runs on %T", q.Statement.ConnPool)

	return pool
}

func TestConfigConn(t *testing.T) {
	t.Parallel()

	base, basePool := fakeDB(t, "base")
	attached, attachedPool := fakeDB(t, "attached")
	inner, innerPool := fakeDB(t, "inner")
	managed, managedPool := fakeDB(t, "managed")
	failed, _ := fakeDB(t, "failed")
	errHandle := errors.New("handle already failed")
	_ = failed.AddError(errHandle)

	type testCase struct {
		name   string
		base   *gormdb.DB // nil means the shared base handle
		opts   []Option
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, ctx context.Context, q *gormdb.DB, ambient bool, err error)
	}

	runsOn := func(want *fakePool, wantAmbient bool) func(t *testing.T, ctx context.Context, q *gormdb.DB, ambient bool, err error) {
		return func(t *testing.T, _ context.Context, q *gormdb.DB, ambient bool, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Same(t, want, resolvedPool(t, q), "resolved to the %s handle", resolvedPool(t, q).name)
			assert.Equal(t, wantAmbient, ambient)
		}
	}

	refusesWith := func(want error) func(t *testing.T, ctx context.Context, q *gormdb.DB, ambient bool, err error) {
		return func(t *testing.T, _ context.Context, q *gormdb.DB, ambient bool, err error) {
			t.Helper()
			require.ErrorIs(t, err, want)
			assert.Nil(t, q, "no session is opened on a handle that already failed")
			assert.False(t, ambient)
		}
	}

	cases := []testCase{
		{
			name:   "a WithTx handle that already carries an error is refused with it",
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, failed) },
			assert: refusesWith(errHandle),
		},
		{
			name:   "a base handle that already carries an error is refused with it",
			base:   failed,
			assert: refusesWith(errHandle),
		},
		{
			name:   "no resolver and nothing attached uses the base handle",
			assert: runsOn(basePool, false),
		},
		{
			name:   "a transaction attached with WithTx is used and is ambient",
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, attached) },
			assert: runsOn(attachedPool, true),
		},
		{
			name:   "the innermost WithTx wins",
			ctx:    func(ctx context.Context) context.Context { return WithTx(WithTx(ctx, attached), inner) },
			assert: runsOn(innerPool, true),
		},
		{
			name: "a transaction attached under another backend's key is invisible",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, foreignTxKey{}, attached)
			},
			assert: runsOn(basePool, false),
		},
		{
			name:   "WithTx with a nil transaction attaches nothing",
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, nil) },
			assert: runsOn(basePool, false),
		},
		{
			name:   "WithTx with a nil transaction leaves an outer attachment in place",
			ctx:    func(ctx context.Context) context.Context { return WithTx(WithTx(ctx, attached), nil) },
			assert: runsOn(attachedPool, true),
		},
		{
			name:   "a resolver's transaction wins over one attached to the context",
			opts:   []Option{WithTxResolver(func(context.Context) (*gormdb.DB, bool) { return managed, true })},
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, attached) },
			assert: runsOn(managedPool, true),
		},
		{
			name:   "a resolver reporting none means the base handle, even with a transaction attached",
			opts:   []Option{WithTxResolver(func(context.Context) (*gormdb.DB, bool) { return managed, false })},
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, attached) },
			assert: runsOn(basePool, false),
		},
		{
			name: "a resolver reporting a transaction with a nil handle is refused, not a fallback",
			opts: []Option{WithTxResolver(func(context.Context) (*gormdb.DB, bool) { return nil, true })},
			assert: func(t *testing.T, _ context.Context, q *gormdb.DB, ambient bool, err error) {
				t.Helper()
				require.ErrorIs(t, err, ErrNilTransaction)
				assert.Nil(t, q, "no handle is resolved when the resolver's is nil")
				assert.False(t, ambient)
			},
		},
		{
			name: "the resolved handle discards its log, skips gorm's own transaction and carries the operation's context",
			ctx:  func(ctx context.Context) context.Context { return WithTx(ctx, attached) },
			assert: func(t *testing.T, ctx context.Context, q *gormdb.DB, _ bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, logger.Discard, q.Logger, "gorm's logger prints statements with their bound values")
				assert.True(t, q.SkipDefaultTransaction, "gorm would wrap every write in a transaction of its own")
				assert.Equal(t, ctx, q.Where("id = ?", 1).Statement.Context)
				assert.NotEqual(t, logger.Discard, attached.Logger, "the caller's handle is left as it was")
			},
		},
		{
			name: "conditions chained on an attached handle do not carry into the store's statements",
			ctx: func(ctx context.Context) context.Context {
				return WithTx(ctx, attached.Where("user_id = ?", "someone"))
			},
			assert: func(t *testing.T, _ context.Context, q *gormdb.DB, ambient bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Same(t, attachedPool, resolvedPool(t, q))
				assert.True(t, ambient)
				where, ok := q.Where("id = ?", 1).Statement.Clauses["WHERE"].Expression.(clause.Where)
				require.True(t, ok)
				assert.Len(t, where.Exprs, 1, "the caller's WHERE would narrow the store's statement")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			b := base
			if tc.base != nil {
				b = tc.base
			}
			c, err := newConfig(b, tc.opts)
			require.NoError(t, err)
			q, ambient, err := c.conn(ctx)
			tc.assert(t, ctx, q, ambient, err)
		})
	}
}
