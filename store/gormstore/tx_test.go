package gormstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/utils/tests"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/pkg/id"
)

// fakePool stands in for a connection pool or a transaction. It is only ever
// compared by identity: resolution never runs a statement, and a fakePool
// would panic if asked to.
type fakePool struct {
	gorm.ConnPool

	name string
}

// fakeDB returns a *gorm.DB over a pool of its own, named name, that never
// reaches a database.
func fakeDB(t *testing.T, name string) (*gorm.DB, *fakePool) {
	t.Helper()

	pool := &fakePool{name: name}
	db, err := gorm.Open(tests.DummyDialector{}, &gorm.Config{ConnPool: pool})
	require.NoError(t, err)

	return db, pool
}

// foreignTxKey is the kind of key another backend attaches its transaction
// under; these stores must never see a transaction attached that way.
type foreignTxKey struct{}

// resolvedPool is the pool a resolved handle runs its statements on.
func resolvedPool(t *testing.T, q *gorm.DB) *fakePool {
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
		name string
		base *gorm.DB // nil means the shared base handle
		// failBase gives the case a base handle of its own and sets an error on
		// it after construction, which newConfig refuses to accept at
		// construction: the case the conn guard still covers.
		failBase bool
		opts     []Option
		ctx      func(ctx context.Context) context.Context // nil means identity
		assert   func(t *testing.T, ctx context.Context, q *gorm.DB, ambient bool, err error)
	}

	runsOn := func(want *fakePool, wantAmbient bool) func(t *testing.T, ctx context.Context, q *gorm.DB, ambient bool, err error) {
		return func(t *testing.T, _ context.Context, q *gorm.DB, ambient bool, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Same(t, want, resolvedPool(t, q), "resolved to the %s handle", resolvedPool(t, q).name)
			assert.Equal(t, wantAmbient, ambient)
		}
	}

	refusesWith := func(want error) func(t *testing.T, ctx context.Context, q *gorm.DB, ambient bool, err error) {
		return func(t *testing.T, _ context.Context, q *gorm.DB, ambient bool, err error) {
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
			name:     "a base handle that gains an error after construction is refused with it",
			failBase: true,
			assert:   refusesWith(errHandle),
		},
		{
			name:     "a resolver reporting none, over a base handle that gains an error, is refused with it",
			failBase: true,
			opts: []Option{WithTxResolver(func(context.Context) (*gorm.DB, bool) {
				return managed, false
			})},
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
			opts:   []Option{WithTxResolver(func(context.Context) (*gorm.DB, bool) { return managed, true })},
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, attached) },
			assert: runsOn(managedPool, true),
		},
		{
			name:   "a resolver reporting none means the base handle, even with a transaction attached",
			opts:   []Option{WithTxResolver(func(context.Context) (*gorm.DB, bool) { return managed, false })},
			ctx:    func(ctx context.Context) context.Context { return WithTx(ctx, attached) },
			assert: runsOn(basePool, false),
		},
		{
			name: "a resolver reporting a transaction with a nil handle is refused, not a fallback",
			opts: []Option{WithTxResolver(func(context.Context) (*gorm.DB, bool) { return nil, true })},
			assert: func(t *testing.T, _ context.Context, q *gorm.DB, ambient bool, err error) {
				t.Helper()
				require.ErrorIs(t, err, ErrNilTransaction)
				assert.Nil(t, q, "no handle is resolved when the resolver's is nil")
				assert.False(t, ambient)
			},
		},
		{
			name: "the resolved handle discards its log, skips gorm's own transaction and carries the operation's context",
			ctx:  func(ctx context.Context) context.Context { return WithTx(ctx, attached) },
			assert: func(t *testing.T, ctx context.Context, q *gorm.DB, _ bool, err error) {
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
			assert: func(t *testing.T, _ context.Context, q *gorm.DB, ambient bool, err error) {
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
			if tc.failBase {
				b, _ = fakeDB(t, "late")
			}
			c, err := newConfig(b, tc.opts)
			require.NoError(t, err)
			if tc.failBase {
				_ = b.AddError(errHandle)
			}
			q, ambient, err := c.conn(ctx)
			tc.assert(t, ctx, q, ambient, err)
		})
	}
}

// errBeginFailed is the failure a caller's handle carries, as a Begin that
// failed leaves it.
var errBeginFailed = errors.New("begin failed")

// TestStores_FailedHandleIsAnError pins that every gorm store operation run on
// a caller's handle that already carries an error returns an error wrapping
// it, runs no statement, and does not panic.
//
// It stands apart from TestConfigConn: it runs each store's operations on
// the errored handle, not the resolution alone.
func TestStores_FailedHandleIsAnError(t *testing.T) {
	t.Parallel()

	// handleSource says where the errored handle rides.
	type handleSource int
	const (
		viaWithTx   handleSource = iota // a transaction attached with WithTx
		viaResolver                     // a transaction from a TxResolver
		viaBase                         // the base handle, with no transaction attached
	)

	type testCase struct {
		name   string
		source handleSource
		call   func(ctx context.Context, cfg *config) error
		assert func(t *testing.T, err error)
	}

	wrapsFailure := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err)
		assert.ErrorIs(t, err, errBeginFailed)
	}

	cases := []testCase{
		{
			name: "enrolment charge",
			call: func(ctx context.Context, cfg *config) error {
				_, _, err := (&enrolmentStore{c: cfg}).ChargeVerifyAttempt(ctx, "u", time.Now(), 5, time.Minute)
				return err
			},
			assert: wrapsFailure,
		},
		{
			name: "enrolment give-back",
			call: func(ctx context.Context, cfg *config) error {
				_, err := (&enrolmentStore{c: cfg}).RefundVerifyAttempt(ctx, "u", time.Now())
				return err
			},
			assert: wrapsFailure,
		},
		{
			name: "recovery record latest completion",
			call: func(ctx context.Context, cfg *config) error {
				_, _, err := (&RecoveryRecordStore{c: cfg}).LatestCompletion(ctx, "u")
				return err
			},
			assert: wrapsFailure,
		},
		{
			name: "recovery code match",
			call: func(ctx context.Context, cfg *config) error {
				_, err := (&RecoveryCodeStore{c: cfg}).Match(ctx, "u", []byte("digest"))
				return err
			},
			assert: wrapsFailure,
		},
		{
			name: "passkey handle assign",
			call: func(ctx context.Context, cfg *config) error {
				_, err := (&PasskeyHandleStore{c: cfg}).Assign(ctx, "u", make([]byte, passkey.HandleSize))
				return err
			},
			assert: wrapsFailure,
		},
		{
			name: "passkey user for handle",
			call: func(ctx context.Context, cfg *config) error {
				_, _, err := (&PasskeyHandleStore{c: cfg}).UserFor(ctx, make([]byte, passkey.HandleSize))
				return err
			},
			assert: wrapsFailure,
		},
		{
			name: "passkey credential charge, through returning",
			call: func(ctx context.Context, cfg *config) error {
				_, _, err := (&PasskeyCredentialStore{c: cfg}).ChargeEmailAttempt(ctx, "u", id.ID{1}, time.Now())
				return err
			},
			assert: wrapsFailure,
		},
		{
			name: "a builder-chain operation",
			call: func(ctx context.Context, cfg *config) error {
				_, err := (&RecoveryCodeStore{c: cfg}).Remaining(ctx, "u")
				return err
			},
			assert: wrapsFailure,
		},
		{
			name:   "a resolver's handle carrying an error",
			source: viaResolver,
			call: func(ctx context.Context, cfg *config) error {
				_, err := (&RecoveryCodeStore{c: cfg}).Match(ctx, "u", []byte("digest"))
				return err
			},
			assert: wrapsFailure,
		},
		{
			name:   "the base handle carrying an error, with no transaction attached",
			source: viaBase,
			call: func(ctx context.Context, cfg *config) error {
				_, err := (&RecoveryCodeStore{c: cfg}).Match(ctx, "u", []byte("digest"))
				return err
			},
			assert: wrapsFailure,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base, _ := fakeDB(t, "base")
			tx, _ := fakeDB(t, "tx")
			_ = tx.AddError(errBeginFailed) // the returned error is the one just added

			ctx := t.Context()
			var opts []Option
			switch tc.source {
			case viaWithTx:
				ctx = WithTx(ctx, tx)
			case viaResolver:
				opts = []Option{WithTxResolver(func(context.Context) (*gorm.DB, bool) { return tx, true })}
			case viaBase:
				// Construction refuses an errored base, so the error is set after it:
				// a base that fails later, with nothing attached.
				_, err := newConfig(tx, nil)
				require.ErrorIs(t, err, ErrConfig)
				require.ErrorIs(t, err, errBeginFailed)
			}
			cfg, err := newConfig(base, opts, optIDGenerator, optClock, optResealOnRead)
			require.NoError(t, err)
			if tc.source == viaBase {
				_ = base.AddError(errBeginFailed)
			}

			var got error
			require.NotPanics(t, func() { got = tc.call(ctx, cfg) })
			tc.assert(t, got)
		})
	}
}
