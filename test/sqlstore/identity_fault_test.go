package sqlstore_test

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// faultTxKey is where these tests attach the consumer handle their resolver
// returns.
type faultTxKey struct{}

// faultResolver is a consumer WithTxResolver returning the handle attached
// under faultTxKey.
func faultResolver() sqlstore.Option {
	return sqlstore.WithTxResolver(func(ctx context.Context) (sqlstore.DBTX, bool) {
		h, ok := ctx.Value(faultTxKey{}).(sqlstore.DBTX)
		return h, ok
	})
}

// faultingTx is a consumer's handle over a caller's transaction that runs
// hook once, the first time a statement satisfies matches: after that
// statement has run, the point where the store has written something and has
// more to write, when before is false; instead of running it at all,
// simulating a consumer wrapper that panics in place of the call, when
// before is true.
type faultingTx struct {
	*sql.Tx

	matches func(query string) bool
	before  bool
	hook    func()
	fired   bool
}

func (f *faultingTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if f.before && !f.fired && f.matches(query) {
		f.fired = true
		f.hook()
	}

	res, err := f.Tx.ExecContext(ctx, query, args...)

	if !f.before && !f.fired && f.matches(query) {
		f.fired = true
		f.hook()
	}

	return res, err
}

// cleanupPanickingTx is a consumer's handle over a caller's transaction that
// panics twice over: with fnPanic after running the user insert, the point
// where the store is mid-write, and with cleanupPanic in place of every
// ROLLBACK TO SAVEPOINT, so the store's best-effort cleanup of the first
// panic panics in turn.
type cleanupPanickingTx struct {
	*sql.Tx

	fnPanic, cleanupPanic string
}

func (c *cleanupPanickingTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if strings.HasPrefix(query, "ROLLBACK TO SAVEPOINT ") {
		panic(c.cleanupPanic)
	}

	res, err := c.Tx.ExecContext(ctx, query, args...)
	if query == pgschema.InsertUser {
		panic(c.fnPanic)
	}

	return res, err
}

// exact matches a query by exact text.
func exact(query string) func(string) bool {
	return func(q string) bool { return q == query }
}

// hasPrefix matches a query by prefix, for a statement whose text carries a
// value the test does not control, like the savepoint's generated name.
func hasPrefix(prefix string) func(string) bool {
	return func(q string) bool { return strings.HasPrefix(q, prefix) }
}

// userRowCount is the number of stored users named username, read outside
// every transaction.
func userRowCount(ctx context.Context, t *testing.T, db *sql.DB, username string) int {
	t.Helper()

	var n int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE username = $1`, username).Scan(&n))

	return n
}

// TestIdentityStore_Interrupted pins that a write the store cannot finish —
// a consumer generator or handle that panics or fails, a context cancelled
// between two of its statements — leaves nothing of its own behind: no open
// transaction, no held row lock, and no row in the caller's transaction.
func TestIdentityStore_Interrupted(t *testing.T) {
	t.Parallel()

	conn := migratedIdentityDB(t)

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, conn test.PostgresConn)
	}

	cases := []testCase{
		{
			name: "a generator panicking in an update's grant rebuild leaves the user unlocked",
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn) {
				plain := newIdentityStore(t, conn.DB)
				_, err := plain.Provision(ctx, "panicking-update", identity.WithUserRoles("admin"))
				require.NoError(t, err)

				panicking := newIdentityStore(t, conn.DB, sqlstore.WithIDGenerator(storefix.GeneratorFunc(
					func() (id.ID, error) { panic("generator exploded") })))
				require.PanicsWithValue(t, "generator exploded", func() {
					_, _ = panicking.Update(ctx, "panicking-update",
						identity.WithUserName("Half"), identity.WithUserRoles("viewer"))
				})

				wait, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				d, err := plain.Update(wait, "panicking-update", identity.WithUserName("After"))
				require.NoError(t, err, "the panicked update left its transaction open and the user's row locked")
				assert.Equal(t, "After", d.Name)
				require.Len(t, d.Roles, 1)
				assert.Equal(t, "admin", d.Roles[0].Name, "the panicked rebuild wrote no grant")
			},
		},
		{
			name: "a handle panicking under the savepoint leaves no row for the caller to commit",
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn) {
				s := newIdentityStore(t, conn.DB, faultResolver())
				tx, err := conn.DB.BeginTx(ctx, nil)
				require.NoError(t, err)
				_, err = s.Provision(context.WithValue(ctx, faultTxKey{}, sqlstore.DBTX(tx)), "earlier-in-caller-tx")
				require.NoError(t, err)

				h := &faultingTx{Tx: tx, matches: exact(pgschema.InsertUser), hook: func() { panic("handle exploded") }}
				txCtx := context.WithValue(ctx, faultTxKey{}, sqlstore.DBTX(h))
				require.PanicsWithValue(t, "handle exploded", func() {
					_, _ = s.Provision(txCtx, "panicking-provision", identity.WithUserRoles("admin"))
				})

				require.NoError(t, tx.Commit())
				assert.Zero(t, userRowCount(ctx, t, conn.DB, "panicking-provision"),
					"the panicked provision's user row was committed with the caller's work")
				assert.Equal(t, 1, userRowCount(ctx, t, conn.DB, "earlier-in-caller-tx"))
			},
		},
		{
			name: "a handle panicking on the savepoint's RELEASE after fn succeeds leaves no row for the caller to commit",
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn) {
				s := newIdentityStore(t, conn.DB, faultResolver())
				tx, err := conn.DB.BeginTx(ctx, nil)
				require.NoError(t, err)
				_, err = s.Provision(context.WithValue(ctx, faultTxKey{}, sqlstore.DBTX(tx)), "earlier-before-release-panic")
				require.NoError(t, err)

				// The hook panics in place of running RELEASE SAVEPOINT, the
				// point after fn has already written the user and its grant.
				h := &faultingTx{Tx: tx, matches: hasPrefix("RELEASE SAVEPOINT "), before: true,
					hook: func() { panic("release exploded") }}
				txCtx := context.WithValue(ctx, faultTxKey{}, sqlstore.DBTX(h))
				require.PanicsWithValue(t, "release exploded", func() {
					_, _ = s.Provision(txCtx, "release-panicking-provision", identity.WithUserRoles("admin"))
				})

				require.NoError(t, tx.Commit())
				assert.Zero(t, userRowCount(ctx, t, conn.DB, "release-panicking-provision"),
					"the write survived a panic while releasing the savepoint")
				assert.Equal(t, 1, userRowCount(ctx, t, conn.DB, "earlier-before-release-panic"))
			},
		},
		{
			name: "a handle panicking on the savepoint's ROLLBACK TO after fn fails leaves the caller's transaction usable",
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn) {
				// A reused identifier makes InsertUser itself fail with a
				// real constraint violation, aborting the transaction before
				// any grant is written, so ROLLBACK TO SAVEPOINT has
				// something genuine to recover.
				reissued := id.MustParse("0190a6f1-7c3b-7e2a-9a4d-3c1f2b5e6d79")
				s := newIdentityStore(t, conn.DB, faultResolver(),
					sqlstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) { return reissued, nil })))
				tx, err := conn.DB.BeginTx(ctx, nil)
				require.NoError(t, err)
				_, err = s.Provision(context.WithValue(ctx, faultTxKey{}, sqlstore.DBTX(tx)), "earlier-before-rollback-panic")
				require.NoError(t, err)

				h := &faultingTx{Tx: tx, matches: hasPrefix("ROLLBACK TO SAVEPOINT "), before: true,
					hook: func() { panic("rollback exploded") }}
				txCtx := context.WithValue(ctx, faultTxKey{}, sqlstore.DBTX(h))
				require.PanicsWithValue(t, "rollback exploded", func() {
					_, _ = s.Provision(txCtx, "rollback-panicking-provision")
				})

				// A transaction left aborted makes its own commit fail, or,
				// with a driver that accepts it, silently discard even the
				// earlier write.
				require.NoError(t, tx.Commit(), "the panic left the caller's transaction aborted")
				assert.Equal(t, 1, userRowCount(ctx, t, conn.DB, "earlier-before-rollback-panic"),
					"the earlier write was lost when the caller committed an aborted transaction")
				assert.Zero(t, userRowCount(ctx, t, conn.DB, "rollback-panicking-provision"))
			},
		},
		{
			name: "a handle panicking in the savepoint's cleanup does not mask the original panic",
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn) {
				s := newIdentityStore(t, conn.DB, faultResolver())
				tx, err := conn.DB.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = tx.Rollback() }()

				h := &cleanupPanickingTx{Tx: tx, fnPanic: "fn exploded", cleanupPanic: "cleanup exploded"}
				txCtx := context.WithValue(ctx, faultTxKey{}, sqlstore.DBTX(h))
				require.PanicsWithValue(t, "fn exploded", func() {
					_, _ = s.Provision(txCtx, "cleanup-panicking-provision", identity.WithUserRoles("admin"))
				}, "the cleanup's panic replaced the one that interrupted the write")
			},
		},
		{
			name: "a context cancelled between two writes in a caller's transaction leaves no row",
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn) {
				s := newIdentityStore(t, conn.DB, faultResolver())
				tx, err := conn.DB.BeginTx(ctx, nil)
				require.NoError(t, err)

				opCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				_, err = s.Provision(context.WithValue(ctx, faultTxKey{}, sqlstore.DBTX(tx)), "earlier-before-cancel")
				require.NoError(t, err)
				h := &faultingTx{Tx: tx, matches: exact(pgschema.InsertUser), hook: cancel}

				_, err = s.Provision(context.WithValue(opCtx, faultTxKey{}, sqlstore.DBTX(h)),
					"cancelled-provision", identity.WithUserRoles("admin"))
				require.ErrorIs(t, err, context.Canceled)

				require.NoError(t, tx.Commit(), "the caller's transaction stays usable")
				assert.Zero(t, userRowCount(ctx, t, conn.DB, "cancelled-provision"),
					"the cancelled provision's user row was committed with the caller's work")
				assert.Equal(t, 1, userRowCount(ctx, t, conn.DB, "earlier-before-cancel"))
			},
		},
		{
			name: "a generator failing in an update's grant rebuild writes nothing",
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn) {
				plain := newIdentityStore(t, conn.DB)
				_, err := plain.Provision(ctx, "failing-rebuild",
					identity.WithUserName("Before"), identity.WithUserRoles("admin"))
				require.NoError(t, err)

				genErr := errors.New("generator exhausted")
				s := newIdentityStore(t, conn.DB, sqlstore.WithIDGenerator(&failingIDs{failOn: 1, err: genErr}))
				_, err = s.Update(ctx, "failing-rebuild",
					identity.WithUserName("After"), identity.WithUserRoles("admin", "viewer"))
				require.ErrorIs(t, err, genErr)

				d, err := plain.LoadByUsername(ctx, "failing-rebuild")
				require.NoError(t, err)
				assert.Equal(t, "Before", d.Name, "the failed update renamed the user")
				require.Len(t, d.Roles, 1)
				assert.Equal(t, "admin", d.Roles[0].Name)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, t.Context(), conn)
		})
	}
}

// TestIdentityStore_ConstraintFailure pins that a write failing on a database
// constraint returns an error cut from the driver's: its detail fields carry
// the failing row, username and password hash included, and must not be
// reachable. The consumer's own check constraint stands in for any constraint
// whose detail shows the failing row. Its cases alter the users table, so
// they run one at a time on a database of their own.
func TestIdentityStore_ConstraintFailure(t *testing.T) {
	t.Parallel()

	conn := migratedIdentityDB(t)
	reissued := id.MustParse("0190a6f1-7c3b-7e2a-9a4d-3c1f2b5e6d7f")

	type testCase struct {
		name string
		// check adds, in the case's transaction, the consumer's check
		// constraint refusing the name "Forbidden".
		check  bool
		write  func(ctx context.Context, db *sql.DB, tx *sql.Tx) error
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "a consumer generator re-issuing a user identifier",
			write: func(ctx context.Context, db *sql.DB, _ *sql.Tx) error {
				s, err := sqlstore.NewIdentityStore(db,
					sqlstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) { return reissued, nil })))
				if err != nil {
					return err
				}
				if _, err := s.Provision(ctx, "reissued-first@example.test"); err != nil {
					return err
				}
				_, err = s.Provision(ctx, "reissued-second@example.test", identity.WithUserPassword([]byte("hash-reissued")))

				return err
			},
			assert: func(t *testing.T, err error) {
				assertCutFromDriver(t, err, "23505", "reissued-second@example.test", "hash-reissued", reissued.String())
			},
		},
		{
			name:  "a consumer check constraint refusing a provisioned row",
			check: true,
			write: func(ctx context.Context, db *sql.DB, tx *sql.Tx) error {
				s, err := sqlstore.NewIdentityStore(db)
				if err != nil {
					return err
				}
				_, err = s.Provision(sqlstore.WithTx(ctx, tx), "checked-provision@example.test",
					identity.WithUserName("Forbidden"), identity.WithUserPassword([]byte("hash-provision")))

				return err
			},
			assert: func(t *testing.T, err error) {
				assertCutFromDriver(t, err, "23514", "checked-provision@example.test", "hash-provision")
			},
		},
		{
			name:  "a consumer check constraint refusing an updated row",
			check: true,
			write: func(ctx context.Context, db *sql.DB, tx *sql.Tx) error {
				s, err := sqlstore.NewIdentityStore(db)
				if err != nil {
					return err
				}
				txCtx := sqlstore.WithTx(ctx, tx)
				if _, err := s.Provision(txCtx, "checked-update@example.test",
					identity.WithUserName("Allowed"), identity.WithUserPassword([]byte("hash-update"))); err != nil {
					return err
				}
				_, err = s.Update(txCtx, "checked-update@example.test", identity.WithUserName("Forbidden"))

				return err
			},
			assert: func(t *testing.T, err error) {
				assertCutFromDriver(t, err, "23514", "checked-update@example.test", "hash-update")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			tx, err := conn.DB.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			if tc.check {
				_, err = tx.ExecContext(ctx,
					`ALTER TABLE users ADD CONSTRAINT consumer_name_check CHECK (name <> 'Forbidden')`)
				require.NoError(t, err)
			}

			tc.assert(t, tc.write(ctx, conn.DB, tx))
		})
	}
}

// assertCutFromDriver asserts err is a database failure cut from the driver's
// error: the driver's value is not reachable, the text keeps its SQLSTATE,
// and no text in the chain carries the username, the hash (raw or as the hex
// PostgreSQL shows bytea in) or any of values.
func assertCutFromDriver(t *testing.T, err error, sqlstate, username, hash string, values ...string) {
	t.Helper()
	require.Error(t, err)

	var pgErr *pgconn.PgError
	assert.False(t, errors.As(err, &pgErr), "the driver's error is reachable, detail %q", detailOf(pgErr))
	assert.Contains(t, err.Error(), sqlstate, "the text keeps the driver's SQLSTATE")

	values = append(values, username, hash, hex.EncodeToString([]byte(hash)))
	for _, text := range storefix.ErrorTexts(err) {
		for _, v := range values {
			assert.NotContains(t, text, v)
		}
	}
}

// detailOf is the detail field of a driver error, or "" for none.
func detailOf(e *pgconn.PgError) string {
	if e == nil {
		return ""
	}

	return e.Detail
}

// scanFaultDB is a consumer's handle that substitutes, for one query, a
// statement returning a column database/sql cannot convert to its
// destination, so a Scan call fails the way a genuinely malformed row would,
// without touching the identity store's own statements. grants is the
// statement it runs in place of pgschema.GrantsByUser.
type scanFaultDB struct {
	*sql.DB

	grants string
}

func (h *scanFaultDB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if query == pgschema.GrantsByUser {
		query = h.grants
	}

	return h.DB.QueryContext(ctx, query, args...)
}

// TestIdentityStore_ScanErrorRedactsValue pins that a Scan call's failure
// names the operation and the column, index and name, never the value
// database/sql's own error text would quote, whatever the column's name.
func TestIdentityStore_ScanErrorRedactsValue(t *testing.T) {
	t.Parallel()

	conn := migratedIdentityDB(t)

	plain := newIdentityStore(t, conn.DB)
	_, err := plain.Provision(t.Context(), "scan-error-user", identity.WithUserRoles("viewer"))
	require.NoError(t, err)

	type testCase struct {
		name string
		// grants is the statement the handle runs in place of the store's
		// grant query; its third column holds a value that is no position.
		grants string
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "a plainly named column",
			grants: `SELECT id, role_name, 'not-a-position' AS position, is_primary, super_role,
  start_date, valid_until, created_at, updated_at
FROM assigned_roles WHERE user_id = $1`,
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), `scan error on column index 2, name "position"`,
					"the operation and column are named")
				assert.NotContains(t, err.Error(), "not-a-position", "the scanned value is not")
			},
		},
		{
			name: "a column whose name carries a quote",
			grants: `SELECT id, role_name, 'secret-value' AS "posi""tion", is_primary, super_role,
  start_date, valid_until, created_at, updated_at
FROM assigned_roles WHERE user_id = $1`,
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), `scan error on column index 2, name "posi\"tion"`,
					"the operation and column are named")
				assert.NotContains(t, err.Error(), "secret-value", "the scanned value is not")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			faulty := newIdentityStore(t, conn.DB, sqlstore.WithTxResolver(
				func(context.Context) (sqlstore.DBTX, bool) { return &scanFaultDB{DB: conn.DB, grants: tc.grants}, true }))

			_, err := faulty.LoadByUsername(t.Context(), "scan-error-user")
			tc.assert(t, err)
		})
	}
}

// failingHandle is a consumer's handle whose every statement fails with err,
// standing in for a driver that refuses a value or loses its connection.
type failingHandle struct{ err error }

func (h failingHandle) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return nil, h.err
}

func (h failingHandle) QueryContext(context.Context, string, ...any) (*sql.Rows, error) {
	return nil, h.err
}

func (h failingHandle) QueryRowContext(context.Context, string, ...any) *sql.Row {
	panic("failingHandle: QueryRowContext is not used by these cases")
}

// TestIdentityStore_DriverErrorText pins that a database failure's returned
// text is the library's own, naming the operation and the SQLSTATE a driver
// error reports through its SQLState method, and never the driver's message,
// which can quote a value; and that the driver's error is not in the chain,
// while the context sentinels it matched still are.
func TestIdentityStore_DriverErrorText(t *testing.T) {
	t.Parallel()

	quoting := &pgconn.PgError{
		Severity: "ERROR",
		Code:     "22P02",
		Message:  `invalid input syntax for type uuid: "secret-xyz"`,
		Detail:   "detail-secret",
	}

	type testCase struct {
		name   string
		err    error
		call   func(ctx context.Context, s *sqlstore.IdentityStore) error
		assert func(t *testing.T, err error)
	}

	provision := func(ctx context.Context, s *sqlstore.IdentityStore) error {
		_, err := s.Provision(ctx, "driver-text-user")
		return err
	}
	privileges := func(ctx context.Context, s *sqlstore.IdentityStore) error {
		_, err := s.LoadPrivileges(ctx, "driver-text-role")
		return err
	}

	assertQuotingCut := func(t *testing.T, err error, op string) {
		t.Helper()
		require.Error(t, err)

		var pgErr *pgconn.PgError
		assert.False(t, errors.As(err, &pgErr), "the driver's error is reachable")
		assert.Equal(t, "sqlstore: "+op+": database failure (SQLSTATE 22P02)", err.Error())
		for _, text := range storefix.ErrorTexts(err) {
			assert.NotContains(t, text, "secret-xyz", "the driver's message quotes a value")
			assert.NotContains(t, text, "invalid input syntax", "the driver's message is not kept")
			assert.NotContains(t, text, "detail-secret")
		}
	}

	cases := []testCase{
		{
			name: "a statement failing with a message quoting a value",
			err:  quoting,
			call: provision,
			assert: func(t *testing.T, err error) {
				assertQuotingCut(t, err, "provision user")
			},
		},
		{
			name: "a query failing with a message quoting a value",
			err:  quoting,
			call: privileges,
			assert: func(t *testing.T, err error) {
				assertQuotingCut(t, err, "load role privileges")
			},
		},
		{
			name: "a failure with no SQLSTATE carries no driver text",
			err:  errors.New("dial tcp 10.0.0.1:5432: secret-host"),
			call: provision,
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.Equal(t, "sqlstore: provision user: database failure", err.Error())
				for _, text := range storefix.ErrorTexts(err) {
					assert.NotContains(t, text, "secret-host")
					assert.NotContains(t, text, "10.0.0.1")
				}
			},
		},
		{
			name: "a cancellation stays matchable under fixed text",
			err:  fmt.Errorf("driver gave up at secret-stage: %w", context.Canceled),
			call: privileges,
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				require.ErrorIs(t, err, context.Canceled)
				assert.Equal(t, "sqlstore: load role privileges: database failure", err.Error())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newIdentityStore(t, unreachableDB(t), sqlstore.WithTxResolver(
				func(context.Context) (sqlstore.DBTX, bool) { return failingHandle{err: tc.err}, true }))

			tc.assert(t, tc.call(t.Context(), s))
		})
	}
}
