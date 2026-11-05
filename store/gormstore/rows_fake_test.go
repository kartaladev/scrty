package gormstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/utils/tests"
)

// errAtClose and errAtNext are the failures a scripted statement reports, at the close of its
// rows and when asked for a row.
var (
	errAtClose = errors.New("server error at the end of the statement")
	errAtNext  = errors.New("server error while sending rows")
)

// script is what a statement run on the fake driver returns: rows integer rows, then io.EOF,
// or nextErr in place of the row numbered failAt (counting from one, zero for never), and
// closeErr from closing them.
type script struct {
	rows     int
	failAt   int
	nextErr  error
	closeErr error
}

// scriptedConnector is a driver whose every query returns the same script, and whose
// transactions do nothing.
type scriptedConnector struct{ s script }

func (c scriptedConnector) Connect(context.Context) (driver.Conn, error) {
	return scriptedConn(c), nil
}

func (scriptedConnector) Driver() driver.Driver { return nil }

type scriptedConn struct{ s script }

func (scriptedConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (scriptedConn) Close() error                        { return nil }
func (c scriptedConn) Begin() (driver.Tx, error)         { return scriptedTx{}, nil }
func (c scriptedConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &scriptedRows{s: c.s}, nil
}

type scriptedTx struct{}

func (scriptedTx) Commit() error   { return nil }
func (scriptedTx) Rollback() error { return nil }

type scriptedRows struct {
	s    script
	sent int
}

func (*scriptedRows) Columns() []string { return []string{"a"} }
func (r *scriptedRows) Close() error    { return r.s.closeErr }
func (r *scriptedRows) Next(dest []driver.Value) error {
	r.sent++
	if r.s.failAt == r.sent {
		return r.s.nextErr
	}
	if r.sent > r.s.rows {
		return io.EOF
	}
	dest[0] = int64(r.sent)

	return nil
}

// scriptedDB returns a *sql.DB whose statements follow s.
func scriptedDB(t *testing.T, s script) *sql.DB {
	t.Helper()

	db := sql.OpenDB(scriptedConnector{s})
	t.Cleanup(func() { _ = db.Close() })

	return db
}

// scriptedGorm returns a *gorm.DB over scriptedDB.
func scriptedGorm(t *testing.T, s script) *gorm.DB {
	t.Helper()

	g, err := gorm.Open(tests.DummyDialector{}, &gorm.Config{ConnPool: scriptedDB(t, s)})
	require.NoError(t, err)

	return g
}

func TestScanRow(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		script script
		// dest builds the scan destinations; nil means one int.
		dest   func() []any
		assert func(t *testing.T, got int, err error)
	}
	cases := []testCase{
		{
			name:   "a row is scanned",
			script: script{rows: 1},
			assert: func(t *testing.T, got int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, got)
			},
		},
		{
			name:   "no row is sql.ErrNoRows",
			script: script{},
			assert: func(t *testing.T, _ int, err error) { require.ErrorIs(t, err, sql.ErrNoRows) },
		},
		{
			name:   "a failure instead of the first row is reported, not taken for absence",
			script: script{rows: 1, failAt: 1, nextErr: errAtNext},
			assert: func(t *testing.T, _ int, err error) { require.ErrorIs(t, err, errAtNext) },
		},
		{
			name:   "a failure at close is reported, as sql.Row.Scan reports it",
			script: script{rows: 1, closeErr: errAtClose},
			assert: func(t *testing.T, _ int, err error) { require.ErrorIs(t, err, errAtClose) },
		},
		{
			name:   "a destination of the wrong count is a scan failure, not taken for a row",
			script: script{rows: 1},
			dest:   func() []any { return []any{new(int), new(int)} },
			assert: func(t *testing.T, _ int, err error) { require.Error(t, err) },
		},
		{
			name:   "a destination that cannot take the column is a scan failure",
			script: script{rows: 1},
			dest:   func() []any { return []any{new(struct{})} },
			assert: func(t *testing.T, _ int, err error) { require.Error(t, err) },
		},
		{
			name:   "a failure after the first row leaves the first row read",
			script: script{rows: 3, failAt: 2, nextErr: errAtNext},
			assert: func(t *testing.T, got int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, got)
			},
		},
	}

	for _, tc := range cases {
		for _, inTx := range []bool{false, true} {
			where := "on the pool"
			if inTx {
				where = "in a transaction"
			}
			t.Run(tc.name+" "+where, func(t *testing.T) {
				t.Parallel()

				g := scriptedGorm(t, tc.script).WithContext(t.Context())
				if inTx {
					g = g.Begin()
					require.NoError(t, g.Error)
					t.Cleanup(func() { g.Rollback() })
				}

				var got int
				dest := []any{&got}
				if tc.dest != nil {
					dest = tc.dest()
				}
				err := scanRow(g.Raw("SELECT 1"), dest...)
				tc.assert(t, got, err)

				// A transaction keeps its own connection; on the pool, none may be left in use.
				if !inTx {
					sdb, err := g.DB()
					require.NoError(t, err)
					assert.Zero(t, sdb.Stats().InUse, "the rows were closed, the connection released")
				}
			})
		}
	}
}

func TestScanOne(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		script script
		// dest builds the scan destinations; nil means one int.
		dest   func() []any
		assert func(t *testing.T, got int, err error)
	}
	cases := []testCase{
		{
			name:   "a row is scanned",
			script: script{rows: 1},
			assert: func(t *testing.T, got int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, got)
			},
		},
		{
			name:   "no row is sql.ErrNoRows",
			script: script{},
			assert: func(t *testing.T, _ int, err error) { require.ErrorIs(t, err, sql.ErrNoRows) },
		},
		{
			name:   "a failure instead of the first row is reported, not taken for absence",
			script: script{rows: 1, failAt: 1, nextErr: errAtNext},
			assert: func(t *testing.T, _ int, err error) { require.ErrorIs(t, err, errAtNext) },
		},
		{
			name:   "a failure at close is reported, as sql.Row.Scan reports it",
			script: script{rows: 1, closeErr: errAtClose},
			assert: func(t *testing.T, _ int, err error) { require.ErrorIs(t, err, errAtClose) },
		},
		{
			name:   "a destination of the wrong count is a scan failure, not taken for a row",
			script: script{rows: 1},
			dest:   func() []any { return []any{new(int), new(int)} },
			assert: func(t *testing.T, _ int, err error) { require.Error(t, err) },
		},
		{
			name:   "a destination that cannot take the column is a scan failure",
			script: script{rows: 1},
			dest:   func() []any { return []any{new(struct{})} },
			assert: func(t *testing.T, _ int, err error) { require.Error(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got int
			dest := []any{&got}
			if tc.dest != nil {
				dest = tc.dest()
			}
			db := scriptedDB(t, tc.script)
			err := scanOne(t.Context(), db, "SELECT 1", nil, dest...)
			tc.assert(t, got, err)
			assert.Zero(t, db.Stats().InUse, "the rows were closed, the connection released")
		})
	}
}
