package pgxstore_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// faultTxKey is where these tests attach the consumer transaction their
// resolver returns.
type faultTxKey struct{}

// faultResolver is a consumer WithTxResolver returning the transaction
// attached under faultTxKey.
func faultResolver() pgxstore.Option {
	return pgxstore.WithTxResolver(func(ctx context.Context) (pgx.Tx, bool) {
		tx, ok := ctx.Value(faultTxKey{}).(pgx.Tx)
		return tx, ok
	})
}

// withFaultTx attaches tx where faultResolver finds it.
func withFaultTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, faultTxKey{}, tx)
}

// The statements that close a savepoint. The store sends them through Exec on
// the resolved transaction, followed by a savepoint name of its own, so the
// wrappers below match them by prefix.
const (
	releaseSavepoint  = "RELEASE SAVEPOINT"
	rollbackSavepoint = "ROLLBACK TO SAVEPOINT"
)

// faultState is a faultingTx's hook and when it fires: hook runs once, the first time a statement satisfies matches — after that
// statement has run, the point where the store has written something and has
// more to write, when before is false; instead of running it at all,
// simulating a consumer wrapper that panics in place of the call, when before
// is true.
type faultState struct {
	matches func(query string) bool
	before  bool
	hook    func()
	fired   bool
}

func (s *faultState) run(query string, before bool, call func()) {
	if before && s.before && !s.fired && s.matches(query) {
		s.fired = true
		s.hook()
	}
	call()
	if !before && !s.before && !s.fired && s.matches(query) {
		s.fired = true
		s.hook()
	}
}

// faultingTx is a consumer's transaction wrapper that runs its faultState's
// hook on the statements the store sends through Exec, its savepoint
// statements included.
type faultingTx struct {
	pgx.Tx

	state *faultState
}

func newFaultingTx(tx pgx.Tx, matches func(string) bool, before bool, hook func()) *faultingTx {
	return &faultingTx{Tx: tx, state: &faultState{matches: matches, before: before, hook: hook}}
}

func (f *faultingTx) Exec(ctx context.Context, query string, args ...any) (tag pgconn.CommandTag, err error) {
	call := func() { tag, err = f.Tx.Exec(ctx, query, args...) }
	f.state.run(query, true, func() {})
	f.state.run(query, false, call)

	return tag, err
}

// cleanupPanickingTx is a consumer's transaction wrapper that panics twice
// over: with fnPanic after running the user insert, the point where the store
// is mid-write, and with cleanupPanic in place of every statement that closes
// a savepoint, so the store's best-effort cleanup of the first panic panics in
// turn.
type cleanupPanickingTx struct {
	pgx.Tx

	fnPanic, cleanupPanic string
}

func (c *cleanupPanickingTx) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if strings.HasPrefix(query, rollbackSavepoint) || strings.HasPrefix(query, releaseSavepoint) {
		panic(c.cleanupPanic)
	}
	tag, err := c.Tx.Exec(ctx, query, args...)
	if query == pgschema.InsertUser {
		panic(c.fnPanic)
	}

	return tag, err
}

// exact matches a query by exact text.
func exact(query string) func(string) bool {
	return func(q string) bool { return q == query }
}

// prefixed matches a query that starts with prefix.
func prefixed(prefix string) func(string) bool {
	return func(q string) bool { return strings.HasPrefix(q, prefix) }
}

// TestIdentityStore_Interrupted pins that a write the store cannot finish —
// a consumer generator or handle that panics or fails, a context cancelled
// between two of its statements — leaves nothing of its own behind: no open
// transaction, no held row lock, and no row in the caller's transaction.
func TestIdentityStore_Interrupted(t *testing.T) {
	t.Parallel()

	db := migratedIdentity(t)

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, pool *pgxpool.Pool)
	}

	cases := []testCase{
		{
			name: "a generator panicking in an update's grant rebuild leaves the user unlocked",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				plain := newIdentityStore(t, pool)
				_, err := plain.Provision(ctx, "panicking-update", identity.WithUserRoles("admin"))
				require.NoError(t, err)

				panicking := newIdentityStore(t, pool, pgxstore.WithIDGenerator(storefix.GeneratorFunc(
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
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool, faultResolver())
				tx := beginTx(ctx, t, pool)
				_, err := s.Provision(withFaultTx(ctx, tx), "earlier-in-caller-tx")
				require.NoError(t, err)

				h := newFaultingTx(tx, exact(pgschema.InsertUser), false, func() { panic("handle exploded") })
				require.PanicsWithValue(t, "handle exploded", func() {
					_, _ = s.Provision(withFaultTx(ctx, h), "panicking-provision", identity.WithUserRoles("admin"))
				})

				require.NoError(t, tx.Commit(ctx))
				assert.Zero(t, userRowCount(ctx, t, pool, "panicking-provision"),
					"the panicked provision's user row was committed with the caller's work")
				assert.Equal(t, 1, userRowCount(ctx, t, pool, "earlier-in-caller-tx"))
			},
		},
		{
			name: "a handle panicking on the savepoint's release after fn succeeds leaves no row for the caller to commit",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool, faultResolver())
				tx := beginTx(ctx, t, pool)
				_, err := s.Provision(withFaultTx(ctx, tx), "earlier-before-release-panic")
				require.NoError(t, err)

				// The hook panics in place of releasing the savepoint, the
				// point after fn has already written the user and its grant.
				h := newFaultingTx(tx, prefixed(releaseSavepoint), true, func() { panic("release exploded") })
				require.PanicsWithValue(t, "release exploded", func() {
					_, _ = s.Provision(withFaultTx(ctx, h), "release-panicking-provision", identity.WithUserRoles("admin"))
				})

				require.NoError(t, tx.Commit(ctx))
				assert.Zero(t, userRowCount(ctx, t, pool, "release-panicking-provision"),
					"the write survived a panic while releasing the savepoint")
				assert.Equal(t, 1, userRowCount(ctx, t, pool, "earlier-before-release-panic"))
			},
		},
		{
			name: "a handle panicking on the savepoint's rollback after fn fails leaves the caller's transaction usable",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				// A reused identifier makes InsertUser itself fail with a
				// real constraint violation, aborting the transaction before
				// any grant is written, so the savepoint's rollback has
				// something genuine to recover.
				reissued := id.MustParse("0190a6f1-7c3b-7e2a-9a4d-3c1f2b5e6d79")
				s := newIdentityStore(t, pool, faultResolver(),
					pgxstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) { return reissued, nil })))
				tx := beginTx(ctx, t, pool)
				_, err := s.Provision(withFaultTx(ctx, tx), "earlier-before-rollback-panic")
				require.NoError(t, err)

				h := newFaultingTx(tx, prefixed(rollbackSavepoint), true, func() { panic("rollback exploded") })
				require.PanicsWithValue(t, "rollback exploded", func() {
					_, _ = s.Provision(withFaultTx(ctx, h), "rollback-panicking-provision")
				})

				// A transaction left aborted makes its own commit fail, or
				// silently turns it into a rollback of the earlier write.
				require.NoError(t, tx.Commit(ctx), "the panic left the caller's transaction aborted")
				assert.Equal(t, 1, userRowCount(ctx, t, pool, "earlier-before-rollback-panic"),
					"the earlier write was lost when the caller committed an aborted transaction")
				assert.Zero(t, userRowCount(ctx, t, pool, "rollback-panicking-provision"))
			},
		},
		{
			name: "a handle panicking in the savepoint's cleanup does not mask the original panic",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool, faultResolver())
				tx := beginTx(ctx, t, pool)

				h := &cleanupPanickingTx{Tx: tx, fnPanic: "fn exploded", cleanupPanic: "cleanup exploded"}
				require.PanicsWithValue(t, "fn exploded", func() {
					_, _ = s.Provision(withFaultTx(ctx, h), "cleanup-panicking-provision", identity.WithUserRoles("admin"))
				}, "the cleanup's panic replaced the one that interrupted the write")
			},
		},
		{
			name: "a context cancelled between two writes in a caller's transaction leaves no row",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool, faultResolver())
				tx := beginTx(ctx, t, pool)

				opCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				_, err := s.Provision(withFaultTx(ctx, tx), "earlier-before-cancel")
				require.NoError(t, err)
				h := newFaultingTx(tx, exact(pgschema.InsertUser), false, cancel)

				_, err = s.Provision(withFaultTx(opCtx, h), "cancelled-provision", identity.WithUserRoles("admin"))
				require.ErrorIs(t, err, context.Canceled)

				require.NoError(t, tx.Commit(ctx), "the caller's transaction stays usable")
				assert.Zero(t, userRowCount(ctx, t, pool, "cancelled-provision"),
					"the cancelled provision's user row was committed with the caller's work")
				assert.Equal(t, 1, userRowCount(ctx, t, pool, "earlier-before-cancel"))
			},
		},
		{
			name: "a generator failing in an update's grant rebuild writes nothing",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				plain := newIdentityStore(t, pool)
				_, err := plain.Provision(ctx, "failing-rebuild",
					identity.WithUserName("Before"), identity.WithUserRoles("admin"))
				require.NoError(t, err)

				genErr := errors.New("generator exhausted")
				s := newIdentityStore(t, pool, pgxstore.WithIDGenerator(&failingIDs{failOn: 1, err: genErr}))
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

			tc.assert(t, t.Context(), db.Pool)
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

	db := migratedIdentity(t)
	reissued := id.MustParse("0190a6f1-7c3b-7e2a-9a4d-3c1f2b5e6d7f")

	type testCase struct {
		name string
		// check adds, in the case's transaction, the consumer's check
		// constraint refusing the name "Forbidden".
		check  bool
		write  func(ctx context.Context, pool *pgxpool.Pool, tx pgx.Tx) error
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "a consumer generator re-issuing a user identifier",
			write: func(ctx context.Context, pool *pgxpool.Pool, _ pgx.Tx) error {
				s, err := pgxstore.NewIdentityStore(pool,
					pgxstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) { return reissued, nil })))
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
			write: func(ctx context.Context, pool *pgxpool.Pool, tx pgx.Tx) error {
				s, err := pgxstore.NewIdentityStore(pool)
				if err != nil {
					return err
				}
				_, err = s.Provision(pgxstore.WithTx(ctx, tx), "checked-provision@example.test",
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
			write: func(ctx context.Context, pool *pgxpool.Pool, tx pgx.Tx) error {
				s, err := pgxstore.NewIdentityStore(pool)
				if err != nil {
					return err
				}
				txCtx := pgxstore.WithTx(ctx, tx)
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

			tx := beginTx(ctx, t, db.Pool)
			if tc.check {
				_, err := tx.Exec(ctx,
					`ALTER TABLE users ADD CONSTRAINT consumer_name_check CHECK (name <> 'Forbidden')`)
				require.NoError(t, err)
			}

			tc.assert(t, tc.write(ctx, db.Pool, tx))
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
	assertNoneContains(t, err, values...)
}

// assertNoneContains asserts no text in err's chain contains any of values.
func assertNoneContains(t *testing.T, err error, values ...string) {
	t.Helper()

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

// scanFaultTx is a consumer's transaction wrapper that substitutes, for one
// query, a statement returning a column pgx cannot convert to its
// destination, so a Scan call fails the way a genuinely malformed row would,
// without touching the identity store's own statements. grants is the
// statement it runs in place of pgschema.GrantsByUser.
type scanFaultTx struct {
	pgx.Tx

	grants string
}

func (h *scanFaultTx) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	if query == pgschema.GrantsByUser {
		query = h.grants
	}

	return h.Tx.Query(ctx, query, args...)
}

// TestIdentityStore_ScanErrorRedactsValue pins that a Scan call's failure
// names the operation and the column, index and name, never the value pgx's
// own error text would quote, whatever the column's name.
func TestIdentityStore_ScanErrorRedactsValue(t *testing.T) {
	t.Parallel()

	db := migratedIdentity(t)

	plain := newIdentityStore(t, db.Pool)
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

			ctx := t.Context()
			tx := beginTx(ctx, t, db.Pool)
			faulty := newIdentityStore(t, db.Pool, pgxstore.WithTxResolver(
				func(context.Context) (pgx.Tx, bool) { return &scanFaultTx{Tx: tx, grants: tc.grants}, true }))

			_, err := faulty.LoadByUsername(ctx, "scan-error-user")
			tc.assert(t, err)
		})
	}
}

// erroringTx is a consumer's transaction wrapper that fails every statement
// sent through Exec, Query or QueryRow with err, the way a driver or a
// consumer wrapper reports a failed call.
type erroringTx struct {
	pgx.Tx

	err error
}

func (e erroringTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, e.err
}

func (e erroringTx) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, e.err }

func (e erroringTx) QueryRow(context.Context, string, ...any) pgx.Row { return erroringRow(e) }

// erroringRow is a row whose Scan fails with its transaction's error.
type erroringRow erroringTx

func (r erroringRow) Scan(...any) error { return r.err }

// TestIdentityStore_DriverErrorText pins that the text of an error a store
// call returns for a failed statement is the library's own: the operation
// and, for an error that reports one, its SQLSTATE, never the text of the
// driver's or wrapper's error, which can quote a value, and never the
// driver's error value in the chain.
func TestIdentityStore_DriverErrorText(t *testing.T) {
	t.Parallel()

	db := migratedIdentity(t)

	quoting := &pgconn.PgError{
		Severity: "ERROR",
		Code:     "22P02",
		Message:  `invalid input syntax for type uuid: "secret-xyz"`,
	}
	plain := errors.New("dial tcp 10.0.0.1:5432: secret-host")

	// driverCall is a store call that reaches the failing handle through Exec,
	// Query or QueryRow, and op is the name that call's own text uses.
	type driverCall struct {
		op  string
		run func(ctx context.Context, s *pgxstore.IdentityStore) error
	}

	// calls reaches each of Exec, Query and QueryRow: Provision's first
	// statement is sent through Exec, a privilege load through Query, and a
	// user load through QueryRow.
	calls := map[string]driverCall{
		"Exec": {
			op: "provision user",
			run: func(ctx context.Context, s *pgxstore.IdentityStore) error {
				_, err := s.Provision(ctx, "driver-text-user")
				return err
			},
		},
		"Query": {
			op: "load role privileges",
			run: func(ctx context.Context, s *pgxstore.IdentityStore) error {
				_, err := s.LoadPrivileges(ctx, "driver-text-role")
				return err
			},
		},
		"QueryRow": {
			op: "load user",
			run: func(ctx context.Context, s *pgxstore.IdentityStore) error {
				_, err := s.LoadByUsername(ctx, "driver-text-user")
				return err
			},
		},
	}

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, err error, op string)
	}

	cases := []testCase{
		{
			name: "a PostgreSQL error quoting a value",
			err:  quoting,
			assert: func(t *testing.T, err error, op string) {
				require.Error(t, err)
				var pgErr *pgconn.PgError
				assert.False(t, errors.As(err, &pgErr), "the driver's error is reachable")
				assert.Equal(t, "pgx: "+op+": database failure (SQLSTATE 22P02)", err.Error())
				assertNoneContains(t, err, "secret-xyz", "invalid input syntax")
			},
		},
		{
			name: "an error with no SQLSTATE",
			err:  plain,
			assert: func(t *testing.T, err error, op string) {
				require.Error(t, err)
				assert.False(t, errors.Is(err, plain), "the wrapper's error is reachable")
				assert.Equal(t, "pgx: "+op+": database failure", err.Error())
				assertNoneContains(t, err, "secret-host", "10.0.0.1", "dial tcp")
			},
		},
		{
			name: "a cancelled context stays matchable under fixed text",
			err:  fmt.Errorf("driver gave up at secret-stage: %w", context.Canceled),
			assert: func(t *testing.T, err error, op string) {
				require.Error(t, err)
				require.ErrorIs(t, err, context.Canceled)
				assert.Equal(t, "pgx: "+op+": database failure", err.Error())
			},
		},
	}

	for _, tc := range cases {
		for call, dc := range calls {
			t.Run(tc.name+" through "+call, func(t *testing.T) {
				t.Parallel()

				ctx := t.Context()
				tx := beginTx(ctx, t, db.Pool)
				s := newIdentityStore(t, db.Pool, pgxstore.WithTxResolver(
					func(context.Context) (pgx.Tx, bool) { return erroringTx{Tx: tx, err: tc.err}, true }))

				tc.assert(t, dc.run(ctx, s), dc.op)
			})
		}
	}
}
