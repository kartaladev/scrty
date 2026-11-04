package gormstore_test

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/store/gormstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// handleBound is the gorm.Config.DefaultContextTimeout the cases below configure.
const handleBound = 300 * time.Millisecond

// TestGormStore_HandleTimeoutBoundsProviderStores holds a lock on a provider table and calls,
// on a handle whose DefaultContextTimeout is short, each store call that reaches the server
// through the handle's connection pool rather than through gorm's own finishers. Every one
// must end at the handle's bound, as a gorm-built statement does, when its context carries no
// deadline of its own.
func TestGormStore_HandleTimeoutBoundsProviderStores(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// lock is the table lock the blocker takes: ACCESS EXCLUSIVE stops every statement,
		// SHARE only the writes.
		table, mode string
		// ctx is the call's context; nil means one with no deadline.
		ctx func(ctx context.Context) context.Context
		// call runs the store call on g, the handle with the bound, and base, one without.
		call   func(ctx context.Context, t *testing.T, g, base *gormdb.DB) error
		assert func(t *testing.T, elapsed time.Duration, err error)
	}

	bounded := func(t *testing.T, elapsed time.Duration, err error) {
		t.Helper()
		require.Error(t, err)
		assert.ErrorIs(t, err, context.DeadlineExceeded, "ended by the handle's bound, not by something else")
		assert.Less(t, elapsed, 3*time.Second, "bounded by the handle's DefaultContextTimeout, took %s", elapsed)
	}
	usingCodes := func(t *testing.T, g *gormdb.DB) oidcprovider.GrantStore {
		t.Helper()
		s := newGrantStore(t, g)
		require.NoError(t, s.UseCodes(must.Must(oidcprovider.NewMemoryCodeStore())))

		return s
	}

	cases := []testCase{
		{
			name: "a write through the pool", table: pgschema.GrantTable, mode: "ACCESS EXCLUSIVE",
			call: func(ctx context.Context, t *testing.T, g, _ *gormdb.DB) error {
				return newGrantStore(t, g).Revoke(ctx, opID(901), oidcprovider.CauseReuse, opTime)
			},
			assert: bounded,
		},
		{
			name: "a one-row read through the pool", table: pgschema.PendingRequestTable, mode: "ACCESS EXCLUSIVE",
			call: func(ctx context.Context, t *testing.T, g, _ *gormdb.DB) error {
				_, err := newPendingStore(t, g).Load(ctx, []byte{1})

				return err
			},
			assert: bounded,
		},
		{
			name: "a many-row read of identifiers", table: pgschema.CodeTable, mode: "ACCESS EXCLUSIVE",
			call: func(ctx context.Context, t *testing.T, g, _ *gormdb.DB) error {
				_, err := newCodeStore(t, g).UnspentByClient(ctx, identity.UserID("u-1"), "c-1")

				return err
			},
			assert: bounded,
		},
		{
			name: "a many-row read of records", table: pgschema.ConsentTable, mode: "ACCESS EXCLUSIVE",
			call: func(ctx context.Context, t *testing.T, g, _ *gormdb.DB) error {
				_, err := newConsentStore(t, g).ListByUser(ctx, identity.UserID("u-1"))

				return err
			},
			assert: bounded,
		},
		{
			name: "a many-grant call, its hold read", table: pgschema.GrantTable, mode: "ACCESS EXCLUSIVE",
			call: func(ctx context.Context, t *testing.T, g, _ *gormdb.DB) error {
				_, err := usingCodes(t, g).EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1"}, opTime)

				return err
			},
			assert: bounded,
		},
		{
			name: "a raw single-row read gorm runs", table: "sessions", mode: "ACCESS EXCLUSIVE",
			call: func(ctx context.Context, t *testing.T, g, _ *gormdb.DB) error {
				_, err := newSessionStore(t, g, storefix.TestCipher(t)).SuccessorPresented(ctx, "x")

				return err
			},
			assert: bounded,
		},
		{
			name: "the handle a caller's transaction resolves to, not the store's own", table: pgschema.GrantTable, mode: "ACCESS EXCLUSIVE",
			call: func(ctx context.Context, t *testing.T, g, base *gormdb.DB) error {
				tx := beginGorm(ctx, t, g)
				s := newGrantStore(t, base, gormstore.WithTxResolver(resolving(tx)))

				return s.Revoke(ctx, opID(901), oidcprovider.CauseReuse, opTime)
			},
			assert: bounded,
		},
		{
			name: "a context with a deadline of its own keeps it", table: pgschema.GrantTable, mode: "ACCESS EXCLUSIVE",
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
				context.AfterFunc(ctx, cancel)

				return c
			},
			call: func(ctx context.Context, t *testing.T, g, _ *gormdb.DB) error {
				return newGrantStore(t, g).Revoke(ctx, opID(901), oidcprovider.CauseReuse, opTime)
			},
			assert: func(t *testing.T, elapsed time.Duration, err error) {
				require.Error(t, err)
				assert.GreaterOrEqual(t, elapsed, time.Second, "the caller's longer deadline wins over the handle's bound")
				assert.Less(t, elapsed, 4*time.Second)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// A backstop only: a call the handle's bound does not reach waits on the lock until
			// this fires, and the case reports how long it took.
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			time.AfterFunc(6*time.Second, cancel)
			d := migratedDB(t)
			g := openGormWith(t, d.conn.DSN, &gormdb.Config{DefaultContextTimeout: handleBound})
			base := openGormWith(t, d.conn.DSN, &gormdb.Config{})

			blocker, err := d.conn.DB.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer func() { _ = blocker.Rollback() }()
			// tc.table is a constant of this package, never input.
			_, err = blocker.ExecContext(t.Context(), "LOCK TABLE "+tc.table+" IN "+tc.mode+" MODE")
			require.NoError(t, err)

			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			start := time.Now()
			err = tc.call(ctx, t, g, base)
			tc.assert(t, time.Since(start), err)
		})
	}
}

// TestGormStore_HandleTimeoutLeavesReadsWhole runs the many-row reads on a handle with a bound
// far longer than they take: the bound's cancel must not fire before the rows are read.
func TestGormStore_HandleTimeoutLeavesReadsWhole(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	d := migratedDB(t)
	g := openGormWith(t, d.conn.DSN, &gormdb.Config{DefaultContextTimeout: time.Minute})

	consents := newConsentStore(t, g)
	for _, client := range []string{"c-1", "c-2", "c-3"} {
		require.NoError(t, consents.Give(ctx, "u-1", client, []string{"openid"}, false, opTime))
	}
	got, err := consents.ListByUser(ctx, "u-1")
	require.NoError(t, err)
	assert.Len(t, got, 3)

	_, err = newCodeStore(t, g).UnspentByClient(ctx, "u-1", "c-1")
	require.NoError(t, err)
}

// deadlineLog records, for each statement that reached it, whether the context it ran under
// carried a deadline.
type deadlineLog struct {
	mu       sync.Mutex
	deadline []bool
}

func (l *deadlineLog) note(ctx context.Context) {
	_, ok := ctx.Deadline()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.deadline = append(l.deadline, ok)
}

func (l *deadlineLog) all() []bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]bool(nil), l.deadline...)
}

// deadlinePool is a connection pool that records the context of every statement run on it
// directly, and begins transactions that record the same way. Both are used by pointer, which
// gorm needs to commit through them.
type deadlinePool struct {
	*sql.DB
	seen *deadlineLog
}

func (p *deadlinePool) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	p.seen.note(ctx)

	return p.DB.ExecContext(ctx, query, args...)
}

func (p *deadlinePool) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	p.seen.note(ctx)

	return p.DB.QueryContext(ctx, query, args...)
}

func (p *deadlinePool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gormdb.ConnPool, error) {
	tx, err := p.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &deadlineTx{Tx: tx, seen: p.seen}, nil
}

type deadlineTx struct {
	*sql.Tx
	seen *deadlineLog
}

func (x *deadlineTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	x.seen.note(ctx)

	return x.Tx.ExecContext(ctx, query, args...)
}

func (x *deadlineTx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	x.seen.note(ctx)

	return x.Tx.QueryContext(ctx, query, args...)
}

// TestGormStore_HandleTimeoutReachesEachStatementOfAUnit runs a many-grant call, which sends
// two statements to the pool in a transaction of its own, on a handle with a bound and
// a pool that records the context each statement ran under: both must have run bounded, the
// second as much as the first.
func TestGormStore_HandleTimeoutReachesEachStatementOfAUnit(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	sqlDB, err := d.db.DB()
	require.NoError(t, err)
	seen := &deadlineLog{}
	g, err := gormdb.Open(postgres.New(postgres.Config{Conn: &deadlinePool{DB: sqlDB, seen: seen}}),
		&gormdb.Config{DefaultContextTimeout: time.Minute, DisableAutomaticPing: true})
	require.NoError(t, err)

	s := newGrantStore(t, g)
	require.NoError(t, s.UseCodes(must.Must(oidcprovider.NewMemoryCodeStore())))
	_, err = s.EndSignIns(t.Context(), oidcprovider.SignInSelector{User: "u-1"}, opTime)
	require.NoError(t, err)

	assert.Equal(t, []bool{true, true}, seen.all(), "the hold read and the write each ran under the handle's bound")
}

// TestGormStore_RawRowReadsStayOnGormsPath reads a login streak, one of the stores' raw
// single-row reads, on a handle carrying a callback of the consumer's on gorm's row
// processor: the read must run through that processor, as it always has, so what the consumer
// hangs on it (a trace, a metric, a bound) still sees the store's statements.
func TestGormStore_RawRowReadsStayOnGormsPath(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	g := openGormWith(t, d.conn.DSN, &gormdb.Config{})
	var rows atomic.Int32
	require.NoError(t, g.Callback().Row().After("gorm:row").Register("test:count", func(*gormdb.DB) { rows.Add(1) }))

	_, err := newAttemptStore(t, g).FailureStreak(t.Context(), "alice", opTime)
	require.NoError(t, err)

	assert.EqualValues(t, 1, rows.Load())
}
