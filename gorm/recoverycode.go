package gorm

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	gormdb "gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/recovery"
)

// RecoveryCodeStore keeps the hashes of saved recovery codes in the
// recovery_codes table the migrate package creates. It implements
// recovery.CodeStore, and is safe for concurrent use.
//
// Spend is one conditional update on "not yet spent", so of several callers
// racing on a code, on this process or on another replica, exactly one
// succeeds; an unknown and an already-spent code are both (false, nil), and
// the first spending time is kept. A database failure is returned wrapped
// with the operation's name, never as that refusal.
//
// ReplaceSet is a delete of the user's codes followed by an insert of each new
// hash, run as one unit: in a transaction of the store's own, or, inside a
// caller's transaction, under a savepoint of its own. A reader outside never
// sees a mix of the two sets, a failure leaves the previous set whole, and a
// failure inside a caller's transaction undoes only the replacement's own
// statements, leaving the caller's transaction usable. The savepoint names
// come from a counter of the store's own, never from input. A set naming one
// hash twice stores it once, as the in-memory store does.
//
// Replacements of one user's set are serialised by a per-user advisory lock
// taken as the replacement's first statement and held until its transaction
// ends, so of two overlapping replacements, on this process or on another
// replica, the later one leaves its set and only its set. Inside a caller's
// transaction the lock is the caller's until it commits or rolls back: a
// replacement of the same user elsewhere waits for that, which is the
// intended serialisation, and the caller should keep such a transaction
// short.
type RecoveryCodeStore struct {
	c *config

	// savepoints numbers the savepoints this store opens inside a caller's
	// transaction.
	savepoints atomic.Uint64
}

// NewRecoveryCodeStore returns a durable saved-code store on db.
//
// It honours WithTxResolver and WithIDGenerator (default id.NewV7Generator;
// the identifier of each recovery_codes row, which no caller sees), and
// refuses any other option. Every time it stores comes from the caller, so
// WithClock does not apply to it.
//
// Limits, stated: PostgreSQL text cannot hold a NUL byte or invalid UTF-8. A
// replacement for a user reference holding either is refused with an error
// that names the field, never the value, and nothing is written; a match,
// spend, count or delete by such a reference finds nothing. Stored times are
// UTC, truncated to the microsecond.
func NewRecoveryCodeStore(db *gormdb.DB, opts ...Option) (*RecoveryCodeStore, error) {
	c, err := newConfig(db, opts, optIDGenerator)
	if err != nil {
		return nil, err
	}

	return &RecoveryCodeStore{c: c}, nil
}

// ReplaceSet removes every code of user and stores hashes as the user's new
// set, all created at at, as one unit.
func (s *RecoveryCodeStore) ReplaceSet(ctx context.Context, user identity.UserID, hashes [][]byte, at time.Time) error {
	const op = "replace recovery codes"

	if err := storekit.CheckStorable(storekit.Text("user", string(user))); err != nil {
		return failed(op, err)
	}

	return s.atomically(ctx, op, func(q *gormdb.DB) error {
		if err := q.Exec(pgschema.RecoveryCodeLockUser, string(user)).Error; err != nil {
			return failed(op, err)
		}
		if err := q.Where("user_id = ?", string(user)).Delete(&recoveryCodeRow{}).Error; err != nil {
			return failed(op, err)
		}
		created := storekit.Time(at)
		for _, h := range hashes {
			rowID, err := s.c.ids.NewID()
			if err != nil {
				return failed(op, err)
			}
			row := recoveryCodeRow{ID: rowID, UserID: string(user), CodeHash: storekit.OrEmpty(h), CreatedAt: created}
			err = q.Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "user_id"}, {Name: "code_hash"}}, DoNothing: true,
			}).Create(&row).Error
			if err != nil {
				return failed(op, err)
			}
		}

		return nil
	})
}

// Match reports whether user holds an unspent code whose hash is hash. It
// writes nothing.
func (s *RecoveryCodeStore) Match(ctx context.Context, user identity.UserID, hash []byte) (bool, error) {
	const op = "match recovery code"

	if !storekit.Storable(string(user)) {
		return false, nil
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return false, failed(op, err)
	}
	var found bool
	if err := q.Raw(pgschema.RecoveryCodeMatch, string(user), storekit.OrEmpty(hash)).Row().Scan(&found); err != nil {
		return false, failed(op, err)
	}

	return found, nil
}

// Spend marks user's code whose hash is hash as spent at at, only while it is
// unspent, and reports whether this call spent it.
func (s *RecoveryCodeStore) Spend(ctx context.Context, user identity.UserID, hash []byte, at time.Time) (bool, error) {
	if !storekit.Storable(string(user)) {
		return false, nil
	}

	n, err := updateWhere[recoveryCodeRow](ctx, s.c, "spend recovery code",
		map[string]any{"spent_at": storekit.Time(at)},
		"user_id = ? AND code_hash = ? AND spent_at IS NULL", string(user), storekit.OrEmpty(hash))

	return n == 1, err
}

// Remaining counts user's unspent codes.
func (s *RecoveryCodeStore) Remaining(ctx context.Context, user identity.UserID) (int, error) {
	const op = "count recovery codes"

	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}
	var n int64
	if err := q.Model(&recoveryCodeRow{}).Where("user_id = ? AND spent_at IS NULL", string(user)).
		Count(&n).Error; err != nil {
		return 0, failed(op, err)
	}

	return int(n), nil
}

// DeleteUser removes every code of user, spent or not, and reports how many
// were removed.
func (s *RecoveryCodeStore) DeleteUser(ctx context.Context, user identity.UserID) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	return deleteWhere[recoveryCodeRow](ctx, s.c, "delete recovery codes", "user_id = ?", string(user))
}

// atomically runs fn as one unit on the handle ctx resolves to: under a
// savepoint inside a caller's transaction, otherwise in a transaction of the
// store's own begun on its *gorm.DB.
func (s *RecoveryCodeStore) atomically(ctx context.Context, op string, fn func(q *gormdb.DB) error) error {
	q, ambient, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}

	if ambient {
		return s.underSavepoint(ctx, q, op, fn)
	}

	tx := q.Begin()
	if tx.Error != nil {
		return failed(op, tx.Error)
	}
	// Rolled back on every way out but a commit, a panic in fn included, so
	// the transaction, its advisory lock and the row locks it holds never
	// outlive the call. After a commit the rollback does nothing.
	defer func() { tx.Rollback() }()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit().Error; err != nil {
		return failed(op, err)
	}

	return nil
}

// underSavepoint runs fn on q, a caller's transaction, under a savepoint of
// its own. When fn fails, the savepoint is rolled back, which undoes fn's
// writes and clears the aborted state a failed statement leaves, so the
// caller's transaction stays usable with its earlier writes intact; the
// savepoint is released either way. When fn panics, the savepoint is rolled
// back and released before the panic goes on, so a caller that recovers it
// and commits commits none of fn's writes.
//
// The savepoint statements run through Exec, as the identity store runs
// them, so their errors are seen, and bypass a prepared-statement
// connection. The statements that close the savepoint run even when ctx is
// done, since leaving it open would leave the caller's transaction aborted,
// or commit fn's writes with the caller's.
func (s *RecoveryCodeStore) underSavepoint(ctx context.Context, q *gormdb.DB, op string, fn func(q *gormdb.DB) error) error {
	name := "scrty_recovery_codes_" + strconv.FormatUint(s.savepoints.Add(1), 10)

	if err := savepointSession(ctx, q).Exec("SAVEPOINT " + name).Error; err != nil {
		return failed(op, err)
	}

	closing := savepointSession(context.WithoutCancel(ctx), q)
	exec := func(stmt string) error {
		if err := closing.Exec(stmt + name).Error; err != nil {
			return failed(op, err)
		}
		return nil
	}

	// open is cleared by every normal return, which has already closed the
	// savepoint or tried to; only a panic leaves it set.
	open := true
	defer func() {
		if open {
			bestEffort(func() { _ = exec("ROLLBACK TO SAVEPOINT ") })
			bestEffort(func() { _ = exec("RELEASE SAVEPOINT ") })
		}
	}()

	err := fn(q)

	if err != nil {
		if rbErr := exec("ROLLBACK TO SAVEPOINT "); rbErr != nil {
			open = false
			return errors.Join(err, rbErr)
		}
		relErr := exec("RELEASE SAVEPOINT ")
		open = false

		return errors.Join(err, relErr)
	}

	relErr := exec("RELEASE SAVEPOINT ")
	open = false

	return relErr
}

var _ recovery.CodeStore = (*RecoveryCodeStore)(nil)
