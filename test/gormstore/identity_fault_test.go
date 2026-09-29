package gormstore_test

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// faultTxKey is where these tests attach the consumer handle their resolver
// returns.
type faultTxKey struct{}

// faultResolver is a consumer WithTxResolver returning the handle attached
// under faultTxKey.
func faultResolver() gormstore.Option {
	return gormstore.WithTxResolver(func(ctx context.Context) (*gormdb.DB, bool) {
		h, ok := ctx.Value(faultTxKey{}).(*gormdb.DB)
		return h, ok
	})
}

// overPool is a handle on tx's session state whose statements run on pool
// instead of tx's own connection: a consumer's *gorm.DB over a wrapped
// transaction or pool.
func overPool(ctx context.Context, tx *gormdb.DB, pool gormdb.ConnPool) *gormdb.DB {
	h := tx.Session(&gormdb.Session{NewDB: true, Context: ctx})
	h.Statement.ConnPool = pool

	return h
}

// faultingPool is a consumer's connection beneath a caller's transaction that
// runs hook once, the first time a statement satisfies matches: after that
// statement has run, the point where the store has written something and has
// more to write, when before is false; instead of running it at all,
// simulating a consumer wrapper that panics in place of the call, when
// before is true.
type faultingPool struct {
	gormdb.ConnPool

	matches func(query string) bool
	before  bool
	hook    func()
	fired   bool
}

func (f *faultingPool) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if f.before && !f.fired && f.matches(query) {
		f.fired = true
		f.hook()
	}

	res, err := f.ConnPool.ExecContext(ctx, query, args...)

	if !f.before && !f.fired && f.matches(query) {
		f.fired = true
		f.hook()
	}

	return res, err
}

// cleanupPanickingPool is a consumer's connection beneath a caller's
// transaction that panics twice over: with fnPanic after running the user
// insert, the point where the store is mid-write, and with cleanupPanic in
// place of every ROLLBACK TO SAVEPOINT, so the store's best-effort cleanup of
// the first panic panics in turn.
type cleanupPanickingPool struct {
	gormdb.ConnPool

	fnPanic, cleanupPanic string
}

func (c *cleanupPanickingPool) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if strings.HasPrefix(query, "ROLLBACK TO SAVEPOINT ") {
		panic(c.cleanupPanic)
	}

	res, err := c.ConnPool.ExecContext(ctx, query, args...)
	if isUserInsert(query) {
		panic(c.fnPanic)
	}

	return res, err
}

// userInsertPrefix begins the INSERT gorm builds for a provisioned user.
const userInsertPrefix = `INSERT INTO "users" `

// isUserInsert matches the INSERT of a provisioned user.
func isUserInsert(query string) bool { return strings.HasPrefix(query, userInsertPrefix) }

// hasPrefix matches a query by prefix, for a statement whose text carries a
// value the test does not control, like the savepoint's generated name.
func hasPrefix(prefix string) func(string) bool {
	return func(q string) bool { return strings.HasPrefix(q, prefix) }
}

// TestIdentityStore_Interrupted pins that a write the store cannot finish —
// a consumer generator or handle that panics or fails, a context cancelled
// between two of its statements — leaves nothing of its own behind: no open
// transaction, no held row lock, and no row in the caller's transaction.
func TestIdentityStore_Interrupted(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, d database)
	}

	cases := []testCase{
		{
			name: "a generator panicking in an update's grant rebuild leaves the user unlocked",
			assert: func(t *testing.T, ctx context.Context, d database) {
				plain := newIdentityStore(t, d.db)
				_, err := plain.Provision(ctx, "panicking-update", identity.WithUserRoles("admin"))
				require.NoError(t, err)

				panicking := newIdentityStore(t, d.db, gormstore.WithIDGenerator(storefix.GeneratorFunc(
					func() (id.ID, error) { panic("generator exploded") })))
				require.PanicsWithValue(t, "generator exploded", func() {
					_, _ = panicking.Update(ctx, "panicking-update",
						identity.WithUserName("Half"), identity.WithUserRoles("viewer"))
				})

				wait, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				got, err := plain.Update(wait, "panicking-update", identity.WithUserName("After"))
				require.NoError(t, err, "the panicked update left its transaction open and the user's row locked")
				assert.Equal(t, "After", got.Name)
				require.Len(t, got.Roles, 1)
				assert.Equal(t, "admin", got.Roles[0].Name, "the panicked rebuild wrote no grant")
			},
		},
		{
			name: "a handle panicking under the savepoint leaves no row for the caller to commit",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db, faultResolver())
				tx := beginGorm(ctx, t, d.db)
				_, err := s.Provision(context.WithValue(ctx, faultTxKey{}, tx), "earlier-in-caller-tx")
				require.NoError(t, err)

				h := &faultingPool{ConnPool: tx.Statement.ConnPool, matches: isUserInsert,
					hook: func() { panic("handle exploded") }}
				txCtx := context.WithValue(ctx, faultTxKey{}, overPool(ctx, tx, h))
				require.PanicsWithValue(t, "handle exploded", func() {
					_, _ = s.Provision(txCtx, "panicking-provision", identity.WithUserRoles("admin"))
				})
				require.True(t, h.fired, "the user insert was not matched")

				require.NoError(t, tx.Commit().Error)
				assert.Zero(t, userRowCount(ctx, t, d.conn.DB, "panicking-provision"),
					"the panicked provision's user row was committed with the caller's work")
				assert.Equal(t, 1, userRowCount(ctx, t, d.conn.DB, "earlier-in-caller-tx"))
			},
		},
		{
			name: "a handle panicking on the savepoint's RELEASE after fn succeeds leaves no row for the caller to commit",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db, faultResolver())
				tx := beginGorm(ctx, t, d.db)
				_, err := s.Provision(context.WithValue(ctx, faultTxKey{}, tx), "earlier-before-release-panic")
				require.NoError(t, err)

				// The hook panics in place of running RELEASE SAVEPOINT, the
				// point after fn has already written the user and its grant.
				h := &faultingPool{ConnPool: tx.Statement.ConnPool, matches: hasPrefix("RELEASE SAVEPOINT "),
					before: true, hook: func() { panic("release exploded") }}
				txCtx := context.WithValue(ctx, faultTxKey{}, overPool(ctx, tx, h))
				require.PanicsWithValue(t, "release exploded", func() {
					_, _ = s.Provision(txCtx, "release-panicking-provision", identity.WithUserRoles("admin"))
				})

				require.NoError(t, tx.Commit().Error)
				assert.Zero(t, userRowCount(ctx, t, d.conn.DB, "release-panicking-provision"),
					"the write survived a panic while releasing the savepoint")
				assert.Equal(t, 1, userRowCount(ctx, t, d.conn.DB, "earlier-before-release-panic"))
			},
		},
		{
			name: "a handle panicking on the savepoint's ROLLBACK TO after fn fails leaves the caller's transaction usable",
			assert: func(t *testing.T, ctx context.Context, d database) {
				// A reused identifier makes the user insert itself fail with a
				// real constraint violation, aborting the transaction before
				// any grant is written, so ROLLBACK TO SAVEPOINT has something
				// genuine to recover.
				reissued := id.MustParse("0190a6f1-7c3b-7e2a-9a4d-3c1f2b5e6d80")
				s := newIdentityStore(t, d.db, faultResolver(),
					gormstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) { return reissued, nil })))
				tx := beginGorm(ctx, t, d.db)
				_, err := s.Provision(context.WithValue(ctx, faultTxKey{}, tx), "earlier-before-rollback-panic")
				require.NoError(t, err)

				h := &faultingPool{ConnPool: tx.Statement.ConnPool, matches: hasPrefix("ROLLBACK TO SAVEPOINT "),
					before: true, hook: func() { panic("rollback exploded") }}
				txCtx := context.WithValue(ctx, faultTxKey{}, overPool(ctx, tx, h))
				require.PanicsWithValue(t, "rollback exploded", func() {
					_, _ = s.Provision(txCtx, "rollback-panicking-provision")
				})

				// A transaction left aborted makes its own commit fail, or,
				// with a driver that accepts it, silently discard even the
				// earlier write.
				require.NoError(t, tx.Commit().Error, "the panic left the caller's transaction aborted")
				assert.Equal(t, 1, userRowCount(ctx, t, d.conn.DB, "earlier-before-rollback-panic"),
					"the earlier write was lost when the caller committed an aborted transaction")
				assert.Zero(t, userRowCount(ctx, t, d.conn.DB, "rollback-panicking-provision"))
			},
		},
		{
			name: "a handle panicking in the savepoint's cleanup does not mask the original panic",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db, faultResolver())
				tx := beginGorm(ctx, t, d.db)

				h := &cleanupPanickingPool{ConnPool: tx.Statement.ConnPool,
					fnPanic: "fn exploded", cleanupPanic: "cleanup exploded"}
				txCtx := context.WithValue(ctx, faultTxKey{}, overPool(ctx, tx, h))
				require.PanicsWithValue(t, "fn exploded", func() {
					_, _ = s.Provision(txCtx, "cleanup-panicking-provision", identity.WithUserRoles("admin"))
				}, "the cleanup's panic replaced the one that interrupted the write")
			},
		},
		{
			name: "a context cancelled between two writes in a caller's transaction leaves no row",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db, faultResolver())
				tx := beginGorm(ctx, t, d.db)

				opCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				_, err := s.Provision(context.WithValue(ctx, faultTxKey{}, tx), "earlier-before-cancel")
				require.NoError(t, err)
				h := &faultingPool{ConnPool: tx.Statement.ConnPool, matches: isUserInsert, hook: cancel}

				_, err = s.Provision(context.WithValue(opCtx, faultTxKey{}, overPool(ctx, tx, h)),
					"cancelled-provision", identity.WithUserRoles("admin"))
				require.ErrorIs(t, err, context.Canceled)
				require.True(t, h.fired, "the user insert was not matched")

				require.NoError(t, tx.Commit().Error, "the caller's transaction stays usable")
				assert.Zero(t, userRowCount(ctx, t, d.conn.DB, "cancelled-provision"),
					"the cancelled provision's user row was committed with the caller's work")
				assert.Equal(t, 1, userRowCount(ctx, t, d.conn.DB, "earlier-before-cancel"))
			},
		},
		{
			name: "a generator failing in an update's grant rebuild writes nothing",
			assert: func(t *testing.T, ctx context.Context, d database) {
				plain := newIdentityStore(t, d.db)
				_, err := plain.Provision(ctx, "failing-rebuild",
					identity.WithUserName("Before"), identity.WithUserRoles("admin"))
				require.NoError(t, err)

				genErr := errors.New("generator exhausted")
				s := newIdentityStore(t, d.db, gormstore.WithIDGenerator(&failingIDs{failOn: 1, err: genErr}))
				_, err = s.Update(ctx, "failing-rebuild",
					identity.WithUserName("After"), identity.WithUserRoles("admin", "viewer"))
				require.ErrorIs(t, err, genErr)

				got, err := plain.LoadByUsername(ctx, "failing-rebuild")
				require.NoError(t, err)
				assert.Equal(t, "Before", got.Name, "the failed update renamed the user")
				require.Len(t, got.Roles, 1)
				assert.Equal(t, "admin", got.Roles[0].Name)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, t.Context(), d)
		})
	}
}

// TestIdentityStore_ConstraintFailure pins that a write failing on a database
// constraint returns an error cut from the driver's: its detail fields carry
// the failing row, username and password hash included, and must not be
// reachable, whatever gorm wraps it in. The consumer's own check constraint
// stands in for any constraint whose detail shows the failing row. Its cases
// alter the users table, so they run one at a time on a database of their own.
func TestIdentityStore_ConstraintFailure(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)
	reissued := id.MustParse("0190a6f1-7c3b-7e2a-9a4d-3c1f2b5e6d81")

	type testCase struct {
		name string
		// check adds, in the case's transaction, the consumer's check
		// constraint refusing the name "Forbidden".
		check  bool
		write  func(ctx context.Context, db, tx *gormdb.DB) error
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "a consumer generator re-issuing a user identifier",
			write: func(ctx context.Context, db, _ *gormdb.DB) error {
				s, err := gormstore.NewIdentityStore(db,
					gormstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) { return reissued, nil })))
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
			write: func(ctx context.Context, db, tx *gormdb.DB) error {
				s, err := gormstore.NewIdentityStore(db)
				if err != nil {
					return err
				}
				_, err = s.Provision(gormstore.WithTx(ctx, tx), "checked-provision@example.test",
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
			write: func(ctx context.Context, db, tx *gormdb.DB) error {
				s, err := gormstore.NewIdentityStore(db)
				if err != nil {
					return err
				}
				txCtx := gormstore.WithTx(ctx, tx)
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

			tx := beginGorm(ctx, t, d.db)
			defer tx.Rollback()
			if tc.check {
				require.NoError(t, tx.Exec(
					`ALTER TABLE users ADD CONSTRAINT consumer_name_check CHECK (name <> 'Forbidden')`).Error)
			}

			tc.assert(t, tc.write(ctx, d.db, tx))
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

// scanFaultPool is a consumer's connection that substitutes, for one query, a
// statement returning a column database/sql cannot convert to its
// destination, so a Scan call fails the way a genuinely malformed row would,
// without touching the identity store's own statements. grants is the
// statement it runs in place of pgschema.GrantsByUser.
type scanFaultPool struct {
	gormdb.ConnPool

	grants string
}

func (h *scanFaultPool) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if query == pgschema.GrantsByUser {
		query = h.grants
	}

	return h.ConnPool.QueryContext(ctx, query, args...)
}

// TestIdentityStore_ScanErrorRedactsValue pins that a Scan call's failure
// names the operation and the column, index and name, never the value
// database/sql's own error text would quote, whatever the column's name.
func TestIdentityStore_ScanErrorRedactsValue(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)

	plain := newIdentityStore(t, d.db)
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
			pool := &scanFaultPool{ConnPool: d.db.Statement.ConnPool, grants: tc.grants}
			faulty := newIdentityStore(t, d.db, gormstore.WithTxResolver(
				func(context.Context) (*gormdb.DB, bool) { return overPool(ctx, d.db, pool), true }))

			_, err := faulty.LoadByUsername(ctx, "scan-error-user")
			tc.assert(t, err)
		})
	}
}
