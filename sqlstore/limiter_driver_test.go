package sqlstore_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/sqlstore"
)

// stubDriver is a database/sql driver that reaches no database: every Exec
// succeeds with driver.ResultNoRows, which reports no row count, and every
// query fails with errStubQuery. Each connection it opens is a stubConn.
type stubDriver struct{}

var errStubQuery = errors.New("stub driver: no rows to query")

func (stubDriver) Open(string) (driver.Conn, error) { return stubConn{}, nil }

type stubConn struct{}

func (stubConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("stub driver: no prepare")
}
func (stubConn) Close() error              { return nil }
func (stubConn) Begin() (driver.Tx, error) { return nil, errors.New("stub driver: no transactions") }

func (stubConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.ResultNoRows, nil
}

func (stubConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return nil, errStubQuery
}

var (
	_ driver.ExecerContext  = stubConn{}
	_ driver.QueryerContext = stubConn{}
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
func (stubConnector) Driver() driver.Driver                        { return stubDriver{} }

func TestLimiter_RecordSucceedsWhenDriverReportsNoRowCount(t *testing.T) {
	t.Parallel()

	l, err := sqlstore.NewLimiter(stubDB(t), "api-key", 3, time.Minute)
	require.NoError(t, err)

	assert.NoError(t, l.RecordFailure(t.Context(), "k"))
}

// TestLimiter_VerifyErrorsStartWithThePrefix pins the adapter's prefix on the
// shared core's errors.
func TestLimiter_VerifyErrorsStartWithThePrefix(t *testing.T) {
	t.Parallel()

	l, err := sqlstore.NewLimiter(stubDB(t), "api-key", 3, time.Minute)
	require.NoError(t, err)

	err = l.Verify(t.Context())
	require.ErrorIs(t, err, errStubQuery)
	assert.True(t, strings.HasPrefix(err.Error(), "sqlstore: "), "got %q", err)
}
