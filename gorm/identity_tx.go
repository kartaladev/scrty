package gorm

import (
	"context"
	"errors"
	"strconv"

	gormdb "gorm.io/gorm"
)

// atomically runs fn as one unit on the handle ctx resolves to: under a
// savepoint inside a caller's transaction, otherwise in a transaction of the
// store's own begun on its *gorm.DB. fn receives a session with gorm's
// logger discarded, like every statement of this package.
func (s *IdentityStore) atomically(ctx context.Context, op string, fn func(q *gormdb.DB) error) error {
	q, ambient, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}

	if ambient {
		return s.underSavepoint(ctx, q, op, fn)
	}

	tx := q.Begin()
	if tx.Error != nil {
		return dbFailed(op, tx.Error)
	}
	// Rolled back on every way out but a commit, a panic in fn included, so
	// the transaction and the row locks it holds never outlive the call.
	// After a commit the rollback does nothing.
	defer func() { tx.Rollback() }()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit().Error; err != nil {
		return dbFailed(op, err)
	}

	return nil
}

// underSavepoint runs fn on q, a caller's transaction, under a savepoint of
// its own. When fn fails, the savepoint is rolled back, which undoes fn's
// writes and clears the aborted state a failed statement leaves, so the
// caller's transaction stays usable with its earlier writes intact; the
// savepoint is then released either way.
//
// When fn panics, or a panic interrupts one of the statements that closes
// the savepoint, the savepoint is rolled back and released before the panic
// goes on, so a caller that recovers it and commits commits none of fn's
// writes.
//
// SAVEPOINT and ROLLBACK TO SAVEPOINT are the statements gorm's PostgreSQL
// dialector sends for SavePoint and RollbackTo, run here through Exec so
// their errors are seen: the dialector discards them. RELEASE SAVEPOINT has
// no dialector counterpart, gorm never releasing a savepoint, and is run the
// same way. Like gorm's own SavePoint, all three bypass a
// prepared-statement connection, so no savepoint name is prepared and cached.
// The name comes from the store's own counter, never from input. The
// statements that close the savepoint run even when ctx is done, since
// leaving it open would leave the caller's transaction aborted, or would
// commit fn's writes with the caller's.
func (s *IdentityStore) underSavepoint(ctx context.Context, q *gormdb.DB, op string, fn func(q *gormdb.DB) error) error {
	name := "scrty_identity_" + strconv.FormatUint(s.savepoints.Add(1), 10)

	sp := savepointSession(ctx, q)
	if err := sp.Exec("SAVEPOINT " + name).Error; err != nil {
		return dbFailed(op, err)
	}

	closing := savepointSession(context.WithoutCancel(ctx), q)
	exec := func(stmt string) error { return closing.Exec(stmt + name).Error }

	// open tracks whether the savepoint is still open, not whether fn has
	// returned: fn returning is not the same as the savepoint being closed,
	// since the statements that close it can themselves panic. The defer
	// below runs its best-effort cleanup whenever a panic leaves the
	// savepoint open, whether the panic came from fn or from a statement
	// that was closing it; every normal return, success or failure, clears
	// the flag first, since by then this call already made its own attempt
	// at closing the savepoint and the defer must not repeat it.
	open := true
	defer func() {
		if !open {
			return
		}
		// The savepoint is still open: a panic interrupted fn, or a
		// statement that was closing it. Leave nothing of the call's writes
		// behind. A panic is already unwinding, so each cleanup statement
		// recovers its own: a handle that panics here too must not replace
		// the panic the caller will recover.
		bestEffort(func() { _ = exec("ROLLBACK TO SAVEPOINT ") })
		bestEffort(func() { _ = exec("RELEASE SAVEPOINT ") })
	}()

	err := fn(q)

	if err != nil {
		if rbErr := exec("ROLLBACK TO SAVEPOINT "); rbErr != nil {
			open = false
			return errors.Join(err, dbFailed(op, rbErr))
		}
		if relErr := exec("RELEASE SAVEPOINT "); relErr != nil {
			open = false
			return errors.Join(err, dbFailed(op, relErr))
		}
		open = false

		return err
	}

	if err := exec("RELEASE SAVEPOINT "); err != nil {
		open = false
		return dbFailed(op, err)
	}
	open = false

	return nil
}

// savepointSession is a session on q's connection, under ctx, for the
// savepoint statements: q's own, or the transaction beneath it when q runs
// on gorm's prepared-statement connection.
func savepointSession(ctx context.Context, q *gormdb.DB) *gormdb.DB {
	h := q.Session(&gormdb.Session{NewDB: true, Context: ctx})
	if p, ok := h.Statement.ConnPool.(*gormdb.PreparedStmtTX); ok {
		h.Statement.ConnPool = p.Tx
	}

	return h
}

// bestEffort runs f, recovering any panic it raises. It is only for cleanup
// that runs while another panic is already unwinding, where f's own panic
// would otherwise replace that one.
func bestEffort(f func()) {
	defer func() { _ = recover() }()
	f()
}
