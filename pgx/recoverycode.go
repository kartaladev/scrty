package pgx

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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

// NewRecoveryCodeStore returns a durable saved-code store on pool.
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
func NewRecoveryCodeStore(pool *pgxpool.Pool, opts ...Option) (*RecoveryCodeStore, error) {
	c, err := newConfig(pool, opts, optIDGenerator)
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

	return s.atomically(ctx, op, func(q DBTX) error {
		if _, err := q.Exec(ctx, pgschema.RecoveryCodeLockUser, string(user)); err != nil {
			return failed(op, err)
		}
		if _, err := q.Exec(ctx, pgschema.RecoveryCodeDeleteUser, string(user)); err != nil {
			return failed(op, err)
		}
		created := storekit.Time(at)
		for _, h := range hashes {
			rowID, err := s.c.ids.NewID()
			if err != nil {
				return failed(op, err)
			}
			if _, err := q.Exec(ctx, pgschema.RecoveryCodeInsert,
				uuidArg(rowID), string(user), storekit.OrEmpty(h), created); err != nil {
				return failed(op, err)
			}
		}

		return nil
	})
}

// Match reports whether user holds an unspent code whose hash is hash. It
// writes nothing.
func (s *RecoveryCodeStore) Match(ctx context.Context, user identity.UserID, hash []byte) (bool, error) {
	if !storekit.Storable(string(user)) {
		return false, nil
	}

	var found bool
	if err := s.c.queryRow(ctx, "match recovery code", pgschema.RecoveryCodeMatch,
		[]any{string(user), storekit.OrEmpty(hash)}, &found); err != nil {
		return false, err
	}

	return found, nil
}

// Spend marks user's code whose hash is hash as spent at at, only while it is
// unspent, and reports whether this call spent it.
func (s *RecoveryCodeStore) Spend(ctx context.Context, user identity.UserID, hash []byte, at time.Time) (bool, error) {
	if !storekit.Storable(string(user)) {
		return false, nil
	}

	n, err := s.c.exec(ctx, "spend recovery code", pgschema.RecoveryCodeSpend,
		string(user), storekit.OrEmpty(hash), storekit.Time(at))

	return n == 1, err
}

// Remaining counts user's unspent codes.
func (s *RecoveryCodeStore) Remaining(ctx context.Context, user identity.UserID) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	return s.c.count(ctx, "count recovery codes", pgschema.RecoveryCodeRemaining, string(user))
}

// DeleteUser removes every code of user, spent or not, and reports how many
// were removed.
func (s *RecoveryCodeStore) DeleteUser(ctx context.Context, user identity.UserID) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	n, err := s.c.exec(ctx, "delete recovery codes", pgschema.RecoveryCodeDeleteUser, string(user))

	return int(n), err
}

// atomically runs fn as one unit on the handle ctx resolves to: under a
// savepoint inside a caller's transaction, otherwise in a transaction of the
// store's own on its pool.
func (s *RecoveryCodeStore) atomically(ctx context.Context, op string, fn func(q DBTX) error) error {
	q, ambient, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}

	if ambient {
		return s.underSavepoint(ctx, q, op, fn)
	}

	tx, err := s.c.base.Begin(ctx)
	if err != nil {
		return failed(op, err)
	}
	// Rolled back on every way out but a commit, a panic in fn included, so
	// the transaction, its advisory lock and the row locks it holds never
	// outlive the call, even when ctx is done. After a commit the rollback
	// does nothing.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
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
// and commits commits none of fn's writes. pgx's own nesting (Tx.Begin) is
// not used: its Rollback does not release the savepoint.
//
// The statements are issued through q's Exec, so a consumer's transaction
// wrapper sees them. The statements that close the savepoint run even when
// ctx is done, since leaving it open would leave the caller's transaction
// aborted, or commit fn's writes with the caller's.
func (s *RecoveryCodeStore) underSavepoint(ctx context.Context, q DBTX, op string, fn func(q DBTX) error) error {
	name := "scrty_recovery_codes_" + strconv.FormatUint(s.savepoints.Add(1), 10)

	if _, err := q.Exec(ctx, "SAVEPOINT "+name); err != nil {
		return failed(op, err)
	}

	closeCtx := context.WithoutCancel(ctx)
	exec := func(stmt string) error {
		if _, err := q.Exec(closeCtx, stmt+name); err != nil {
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
