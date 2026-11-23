package adminfix

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/kartaladev/scrty/admin"
)

// Ambient opens a caller's transaction the adapter's store joins, the way a
// consumer attaches one with the adapter's WithTx, and returns a context
// carrying it, the backend process id of its connection, a function that
// commits it and one that rolls it back. The transaction is rolled back when t
// ends, if it was not already committed or rolled back.
type Ambient func(ctx context.Context, t *testing.T) (context.Context, int, func() error, func())

// SQLAmbient is Ambient over a database/sql handle and the adapter's WithTx.
func SQLAmbient(db *sql.DB, with func(context.Context, *sql.Tx) context.Context) Ambient {
	return func(ctx context.Context, t *testing.T) (context.Context, int, func() error, func()) {
		t.Helper()

		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)

		end := func() { _ = tx.Rollback() }
		t.Cleanup(end)

		var pid int
		require.NoError(t, tx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))

		return with(ctx, tx), pid, tx.Commit, end
	}
}

// PgxAmbient is Ambient over a pgx pool and the adapter's WithTx.
func PgxAmbient(pool *pgxpool.Pool, with func(context.Context, pgx.Tx) context.Context) Ambient {
	return func(ctx context.Context, t *testing.T) (context.Context, int, func() error, func()) {
		t.Helper()

		tx, err := pool.Begin(ctx)
		require.NoError(t, err)

		end := func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }
		t.Cleanup(end)

		var pid int
		require.NoError(t, tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid))

		commit := func() error { return tx.Commit(context.WithoutCancel(ctx)) }

		return with(ctx, tx), pid, commit, end
	}
}

// GormAmbient is Ambient over a gorm handle and the adapter's WithTx.
func GormAmbient(db *gorm.DB, with func(context.Context, *gorm.DB) context.Context) Ambient {
	return func(ctx context.Context, t *testing.T) (context.Context, int, func() error, func()) {
		t.Helper()

		tx := db.WithContext(ctx).Begin()
		require.NoError(t, tx.Error)

		end := func() { _ = tx.Rollback().Error }
		t.Cleanup(end)

		var pid int
		require.NoError(t, tx.Raw(`SELECT pg_backend_pid()`).Row().Scan(&pid))

		commit := func() error { return tx.Commit().Error }

		return with(ctx, tx), pid, commit, end
	}
}

// importQueueBound is how long the queue case waits for any one step: a
// deadlock the database breaks after deadlock_timeout (1s by default) ends
// well inside it, and a hang fails the case rather than the run.
const importQueueBound = 30 * time.Second

// runImportQueue checks that an import waits for another transaction's import
// of the same identifier before it takes any other lock. Caller B, inside its
// own transaction, imports a new user X with username probe-b and leaves it
// uncommitted. Import A of X with username probe-a then waits for B. B
// imports X again with username probe-a, which needs probe-a's identifier
// lock: had A taken it before waiting, A and B would wait on each other and
// the database would abort one of them as a deadlock.
func runImportQueue(t *testing.T, h Harness, newImported func(t *testing.T, roles ...string) admin.ImportedUser) {
	t.Parallel()

	ctx := t.Context()
	ctxB, pidB, _, rollbackB := h.Ambient(ctx, t)

	first := newImported(t)
	first.Username = uniq("probe-b")
	out, err := h.Imports.ImportUser(ctxB, first)
	require.NoError(t, err)
	require.Equal(t, admin.ImportCreated, out)

	second := first
	second.Username = uniq("probe-a")

	done := make(chan importResult, 1)
	ctxA, cancelA := context.WithTimeout(ctx, importQueueBound)
	defer cancelA()
	go func() {
		o, err := h.Imports.ImportUser(ctxA, second)
		done <- importResult{o, err}
	}()

	waitBlockedBy(t, h.DB, pidB, done)

	ctxB2, cancelB := context.WithTimeout(ctxB, importQueueBound)
	defer cancelB()
	out, err = h.Imports.ImportUser(ctxB2, second)
	require.NoError(t, err, "the caller's second import of the identifier must not deadlock with the waiting one")
	assert.Equal(t, admin.ImportUpdated, out)

	rollbackB()

	select {
	case a := <-done:
		require.NoError(t, a.err, "the waiting import must not deadlock with the caller's")
		assert.Equal(t, admin.ImportCreated, a.out, "with the caller's import rolled back, the waiting one creates the user")
	case <-time.After(importQueueBound):
		require.Fail(t, "the waiting import never finished")
	}

	t.Run("ImportLockNeverCollidesWithIdentifierLock", func(t *testing.T) { runImportKeySpace(t, h, newImported) })
}

// runImportKeySpace checks that the lock an import takes on its user
// identifier cannot be the lock of a username or an email. Caller B, inside its
// own transaction, updates user X's name and so holds X's row. An import of X
// takes its identifier lock and waits for the row. B then sets X's email to
// "scrty-import:" followed by X's identifier, the text the import lock was once
// derived from: had both locks shared a key, B would wait for the import and the
// import for B, and the database would abort one of them as a deadlock.
func runImportKeySpace(t *testing.T, h Harness, newImported func(t *testing.T, roles ...string) admin.ImportedUser) {
	t.Helper()

	ctx := t.Context()
	in := newImported(t)
	out, err := h.Imports.ImportUser(ctx, in)
	require.NoError(t, err)
	require.Equal(t, admin.ImportCreated, out)

	ctxB, pidB, _, rollbackB := h.Ambient(ctx, t)
	user, err := h.Users.GetUser(ctx, in.ID)
	require.NoError(t, err)

	name := "Renamed"
	user, err = h.Users.UpdateUser(ctxB, in.ID, user.Version, admin.UserChange{Name: &name})
	require.NoError(t, err)

	changed := in
	changed.Name = "Imported again"

	done := make(chan importResult, 1)
	ctxA, cancelA := context.WithTimeout(ctx, importQueueBound)
	defer cancelA()
	go func() {
		o, err := h.Imports.ImportUser(ctxA, changed)
		done <- importResult{o, err}
	}()

	waitBlockedBy(t, h.DB, pidB, done)

	email := "scrty-import:" + string(in.ID)
	ctxB2, cancelB := context.WithTimeout(ctxB, importQueueBound)
	defer cancelB()
	_, err = h.Users.UpdateUser(ctxB2, in.ID, user.Version, admin.UserChange{Email: &email})
	require.NoError(t, err, "an email that spells the import lock's text must not deadlock with the waiting import")

	rollbackB()

	select {
	case a := <-done:
		require.NoError(t, a.err, "the waiting import must not deadlock with the caller's update")
	case <-time.After(importQueueBound):
		require.Fail(t, "the waiting import never finished")
	}
}

// waitBlockedBy waits until a session of the database is blocked by the
// backend pid. A result on done first means the waiting call never waited,
// which fails the case: the race it sets up did not happen.
func waitBlockedBy[R any](t *testing.T, db *sql.DB, pid int, done <-chan R) {
	t.Helper()

	deadline := time.Now().Add(importQueueBound)
	for time.Now().Before(deadline) {
		var blocked bool
		err := db.QueryRowContext(t.Context(), `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
WHERE datname = current_database() AND $1::int = ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked)
		require.NoError(t, err)
		if blocked {
			return
		}

		select {
		case r := <-done:
			require.Fail(t, "the concurrent call finished without waiting for the caller's transaction",
				"result %+v", r)
		case <-time.After(20 * time.Millisecond):
		}
	}

	require.Fail(t, "the concurrent call never waited for the caller's transaction")
}

// importResult is what one import call returned.
type importResult struct {
	out admin.ImportOutcome
	err error
}
