package sqlstore_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/store/sqlstore"
)

// typedNilClock is a consumer's clock type; (*typedNilClock)(nil) is the typed
// nil a plain `== nil` check misses.
type typedNilClock struct{}

func (*typedNilClock) Now() time.Time { return time.Time{} }

func TestNewLimiter(t *testing.T) {
	t.Parallel()

	// A zero *sql.DB is never used: construction performs no I/O, and would
	// panic here if it tried.
	db := new(sql.DB)

	accepted := func(t *testing.T, l *sqlstore.Limiter, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, l)
	}
	refused := func(want ...string) func(t *testing.T, l *sqlstore.Limiter, err error) {
		return func(t *testing.T, l *sqlstore.Limiter, err error) {
			t.Helper()
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			for _, w := range want {
				assert.Contains(t, err.Error(), w)
			}
			assert.Nil(t, l)
		}
	}

	type testCase struct {
		name      string
		db        *sql.DB
		namespace string
		limit     int
		window    time.Duration
		opts      []sqlstore.LimiterOption
		assert    func(t *testing.T, l *sqlstore.Limiter, err error)
	}

	cases := []testCase{
		{name: "defaults accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute, assert: accepted},
		{name: "nil handle", db: nil, namespace: "api-key", limit: 20, window: time.Minute, assert: refused("nil")},
		{name: "empty namespace", db: db, namespace: "", limit: 20, window: time.Minute, assert: refused("namespace")},
		{name: "colon in namespace", db: db, namespace: "a:b", limit: 20, window: time.Minute, assert: refused("colon")},
		{name: "NUL in namespace", db: db, namespace: "a\x00b", limit: 20, window: time.Minute, assert: refused("UTF-8", "NUL")},
		{name: "invalid UTF-8 in namespace", db: db, namespace: "a\xffb", limit: 20, window: time.Minute, assert: refused("UTF-8", "NUL")},
		{name: "64-byte namespace accepted", db: db, namespace: strings.Repeat("n", 64), limit: 20, window: time.Minute, assert: accepted},
		{name: "65-byte namespace", db: db, namespace: strings.Repeat("n", 65), limit: 20, window: time.Minute, assert: refused("64")},
		{
			name: "64 bytes of multi-byte UTF-8 accepted", db: db, namespace: strings.Repeat("é", 32), limit: 20, window: time.Minute,
			assert: accepted,
		},
		{
			name: "65 bytes of multi-byte UTF-8 refused", db: db, namespace: strings.Repeat("é", 32) + "x", limit: 20, window: time.Minute,
			assert: refused("64"),
		},
		{name: "zero limit", db: db, namespace: "api-key", limit: 0, window: time.Minute, assert: refused("limit")},
		{name: "negative limit", db: db, namespace: "api-key", limit: -1, window: time.Minute, assert: refused("limit")},
		{name: "limit 401", db: db, namespace: "api-key", limit: 401, window: time.Minute, assert: refused("400")},
		{name: "limit 400 accepted", db: db, namespace: "api-key", limit: 400, window: time.Minute, assert: accepted},
		{name: "sub-microsecond window", db: db, namespace: "api-key", limit: 20, window: 999 * time.Nanosecond, assert: refused("microsecond")},
		{name: "one-microsecond window accepted", db: db, namespace: "api-key", limit: 20, window: time.Microsecond, assert: accepted},
		{
			name: "clock accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterClock(clockwork.NewFakeClock())}, assert: accepted,
		},
		{
			name: "nil clock", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterClock(nil)}, assert: refused("clock"),
		},
		{
			name: "typed nil clock", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterClock((*typedNilClock)(nil))}, assert: refused("clock"),
		},
		{
			name: "nil logger", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterLogger(nil)}, assert: refused("logger"),
		},
		{
			name: "unknown mode", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterOnUnavailable(99)}, assert: refused("mode"),
		},
		{
			name: "fall-back mode accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts:   []sqlstore.LimiterOption{sqlstore.WithLimiterOnUnavailable(ratelimit.UnavailableFallbackToLocal)},
			assert: accepted,
		},
		{
			name: "zero timeout", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterOperationTimeout(0)}, assert: refused("timeout"),
		},
		{
			name: "negative timeout", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterOperationTimeout(-time.Second)}, assert: refused("timeout"),
		},
		{
			name: "timeout at the lock_timeout maximum accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts:   []sqlstore.LimiterOption{sqlstore.WithLimiterOperationTimeout(2147483647 * time.Millisecond)},
			assert: accepted,
		},
		{
			name: "timeout above the lock_timeout maximum", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts:   []sqlstore.LimiterOption{sqlstore.WithLimiterOperationTimeout(2147483648 * time.Millisecond)},
			assert: refused("timeout", "at most 2147483647ms"),
		},
		{
			name: "zero probe interval", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterProbeInterval(0)}, assert: refused("probe"),
		},
		{
			name: "zero log interval accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterUnavailableLogInterval(0)}, assert: accepted,
		},
		{
			name: "nil option skipped", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{nil}, assert: accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, err := sqlstore.NewLimiter(tc.db, tc.namespace, tc.limit, tc.window, tc.opts...)
			tc.assert(t, l, err)
		})
	}
}

func TestLimiter_Policy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		window time.Duration
		assert func(t *testing.T, limit int, window time.Duration)
	}

	cases := []testCase{
		{
			name: "whole window reported as given", window: time.Minute,
			assert: func(t *testing.T, limit int, window time.Duration) {
				assert.Equal(t, 7, limit)
				assert.Equal(t, time.Minute, window)
			},
		},
		{
			name: "sub-microsecond part dropped", window: time.Minute + 999*time.Nanosecond,
			assert: func(t *testing.T, limit int, window time.Duration) {
				assert.Equal(t, 7, limit)
				assert.Equal(t, time.Minute, window)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, err := sqlstore.NewLimiter(new(sql.DB), "api-key", 7, tc.window)
			require.NoError(t, err)
			limit, window := l.Policy()
			tc.assert(t, limit, window)
		})
	}
}

// stubDriver is a database/sql driver that reaches no database: every Exec
// succeeds with driver.ResultNoRows, which reports no row count, every query
// fails with errStubQuery, and every transaction begins and ends. Each
// connection it opens is a stubConn.
type stubDriver struct{}

var errStubQuery = errors.New("stub driver: no rows to query")

func (stubDriver) Open(string) (driver.Conn, error) { return stubConn{}, nil }

type stubConn struct{}

func (stubConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("stub driver: no prepare")
}

func (stubConn) Close() error { return nil }

func (stubConn) Begin() (driver.Tx, error) { return stubTx{}, nil }

// BeginTx begins a stubTx at any isolation, as a PostgreSQL driver does: the
// stores begin their own transactions at READ COMMITTED.
func (stubConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return stubTx{}, nil
}

// stubTx is a transaction of stubConn: its statements run as stubConn's do,
// and committing or rolling it back always succeeds.
type stubTx struct{}

func (stubTx) Commit() error { return nil }

func (stubTx) Rollback() error { return nil }

func (stubConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.ResultNoRows, nil
}

func (stubConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return nil, errStubQuery
}

var (
	_ driver.ExecerContext  = stubConn{}
	_ driver.QueryerContext = stubConn{}
	_ driver.ConnBeginTx    = stubConn{}
)

// stubDB opens a *sql.DB over stubDriver, through a connector so no driver
// name is registered.
func stubDB(t *testing.T) *sql.DB {
	t.Helper()

	db := sql.OpenDB(stubConnector{})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type stubConnector struct{}

func (stubConnector) Connect(context.Context) (driver.Conn, error) { return stubConn{}, nil }

func (stubConnector) Driver() driver.Driver { return stubDriver{} }

// It stands apart from the tables above: the limiter runs over a stub driver
// rather than a database handle.
func TestLimiter_RecordSucceedsWhenDriverReportsNoRowCount(t *testing.T) {
	t.Parallel()

	l, err := sqlstore.NewLimiter(stubDB(t), "api-key", 3, time.Minute)
	require.NoError(t, err)

	assert.NoError(t, l.RecordFailure(t.Context(), "k"))
}

// TestLimiter_VerifyErrorsStartWithThePrefix pins the adapter's prefix on the
// shared core's errors.
//
// It stands apart from the tables above: the limiter runs over a stub driver
// rather than a database handle.
func TestLimiter_VerifyErrorsStartWithThePrefix(t *testing.T) {
	t.Parallel()

	l, err := sqlstore.NewLimiter(stubDB(t), "api-key", 3, time.Minute)
	require.NoError(t, err)

	err = l.Verify(t.Context())
	require.ErrorIs(t, err, errStubQuery)
	assert.True(t, strings.HasPrefix(err.Error(), "sqlstore: "), "got %q", err)
}
