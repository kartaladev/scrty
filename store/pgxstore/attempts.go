package pgxstore

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
)

// AttemptStore keeps failed login attempts in the login_attempts table the
// migrate package creates, one row per failure, so every replica counts the
// same failures. It also keeps each identifier's consecutive-failure streak in
// the login_failure_streaks table, one row per identifier. It implements
// policy.AttemptStore, lockout.AttemptReaper and lockout.FailureStreakStore, and
// is safe for concurrent use.
//
// The submitted identifier is stored and matched byte for byte, never folded
// or trimmed. Every instant comes from the caller.
type AttemptStore struct{ c *config }

// NewAttemptStore returns a durable login-attempt store on pool.
//
// Each failure's row is keyed by an identifier the store mints. It honours
// WithTxResolver and WithIDGenerator (default id.NewV7Generator), and refuses
// any other option.
//
// Limits, stated: PostgreSQL text cannot hold a NUL byte or invalid UTF-8. A
// failure recorded for an identifier holding either is refused with an error
// that does not echo it, and nothing is written; the identifier is never
// truncated or altered into another. A streak failure for such an identifier
// is refused the same way, and its streak reads as none. Counting or resetting
// such an identifier matches nothing. Stored times are UTC, truncated to the microsecond.
func NewAttemptStore(pool *pgxpool.Pool, opts ...Option) (*AttemptStore, error) {
	c, err := newConfig(pool, opts, optIDGenerator)
	if err != nil {
		return nil, err
	}

	return &AttemptStore{c: c}, nil
}

// RecordFailure records one failure for username at at.
func (s *AttemptStore) RecordFailure(ctx context.Context, username string, at time.Time) error {
	const op = "record login failure"

	if err := storekit.CheckStorable(storekit.Text("username", username)); err != nil {
		return failed(op, err)
	}
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return failed(op, err)
	}

	_, err = s.c.exec(ctx, op, pgschema.AttemptInsert, uuidArg(rowID), username, storekit.Time(at))

	return err
}

// Reset clears username's failures and its streak, hold included, in one
// statement; one with none is not an error.
func (s *AttemptStore) Reset(ctx context.Context, username string) error {
	if !storekit.Storable(username) {
		return nil
	}

	_, err := s.c.exec(ctx, "reset login failures", pgschema.AttemptAndStreakDeleteByUsername, username)

	return err
}

// FailureCount counts username's failures recorded strictly after since.
func (s *AttemptStore) FailureCount(ctx context.Context, username string, since time.Time) (int, error) {
	if !storekit.Storable(username) {
		return 0, nil
	}

	return s.c.count(ctx, "count login failures", pgschema.AttemptCountSince, username, storekit.Time(since))
}

// DeleteAttemptsBefore removes every failure recorded strictly before
// retainSince. A zero retainSince is refused with
// lockout.ErrRetainSinceRequired, and nothing is deleted.
func (s *AttemptStore) DeleteAttemptsBefore(ctx context.Context, retainSince time.Time) (int, error) {
	if retainSince.IsZero() {
		return 0, lockout.ErrRetainSinceRequired
	}

	n, err := s.c.exec(ctx, "purge login failures", pgschema.AttemptDeleteBefore, storekit.Time(retainSince))

	return int(n), err
}

var (
	_ policy.AttemptStore        = (*AttemptStore)(nil)
	_ lockout.AttemptReaper      = (*AttemptStore)(nil)
	_ lockout.FailureStreakStore = (*AttemptStore)(nil)
)

// AddStreakFailure adds one failure at at to username's streak, in one
// conditional upsert, and returns the streak after it. setHold is true only
// for the write that brings a streak not yet held to limit or above.
//
// The statement locks an existing streak before advancing it, so concurrent
// adds count exactly and exactly one reports setting the hold. A streak another
// writer creates between this write's snapshot and its insert makes the
// statement return no row, and it runs again while ctx is live, up to
// pgschema.StreakAddMaxRuns.
//
// Isolation: the count is exact only at READ COMMITTED, so on the pool each
// run is a READ COMMITTED transaction of its own, whatever the database's
// default is. Inside a caller's transaction stronger than READ COMMITTED it
// refuses with an error wrapping ErrIsolationTooStrong and naming the
// isolation, writes nothing and leaves the transaction usable.
func (s *AttemptStore) AddStreakFailure(
	ctx context.Context, username string, at, since time.Time, limit int,
) (lockout.FailureStreak, bool, error) {
	const op = "add to login failure streak"

	if err := storekit.CheckStorable(storekit.Text("username", username)); err != nil {
		return lockout.FailureStreak{}, false, failed(op, err)
	}

	q, ambient, err := s.c.conn(ctx)
	if err != nil {
		return lockout.FailureStreak{}, false, failed(op, err)
	}
	if ambient {
		if err := s.c.requireReadCommitted(ctx, q); err != nil {
			return lockout.FailureStreak{}, false, failed(op, err)
		}
	}

	for range pgschema.StreakAddMaxRuns {
		if err := ctx.Err(); err != nil {
			return lockout.FailureStreak{}, false, failed(op, err)
		}

		rowID, err := s.c.ids.NewID()
		if err != nil {
			return lockout.FailureStreak{}, false, failed(op, err)
		}

		var (
			got     lockout.FailureStreak
			heldAt  pgtype.Timestamptz
			setHold bool
		)
		run := func(q DBTX) error {
			return q.QueryRow(ctx, pgschema.StreakAdd,
				uuidArg(rowID), username, storekit.Time(at), storekit.Time(since), limit,
			).Scan(&got.Failures, &got.Newest, &heldAt, &setHold)
		}
		if ambient {
			err = run(q)
		} else {
			err = s.c.readCommitted(ctx, func(tx pgx.Tx) error { return run(tx) })
		}
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return lockout.FailureStreak{}, false, failed(op, err)
		}
		if got.HeldAt, err = fromNull(heldAt); err != nil {
			return lockout.FailureStreak{}, false, failed(op, err)
		}
		got.Newest = got.Newest.UTC()

		return got, setHold, nil
	}

	return lockout.FailureStreak{}, false, failed(op, storekit.ErrStreakContended)
}

// FailureStreak reads username's streak as of since. A streak not held whose
// newest failure is at or before since, no streak, and an identifier the
// table cannot hold all read as the zero FailureStreak.
func (s *AttemptStore) FailureStreak(ctx context.Context, username string, since time.Time) (lockout.FailureStreak, error) {
	const op = "read login failure streak"

	if !storekit.Storable(username) {
		return lockout.FailureStreak{}, nil
	}

	var (
		got    lockout.FailureStreak
		heldAt pgtype.Timestamptz
	)
	err := s.c.queryRow(ctx, op, pgschema.StreakRead,
		[]any{username, storekit.Time(since)}, &got.Failures, &got.Newest, &heldAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockout.FailureStreak{}, nil
	}
	if err != nil {
		return lockout.FailureStreak{}, err
	}
	if got.HeldAt, err = fromNull(heldAt); err != nil {
		return lockout.FailureStreak{}, failed(op, err)
	}
	got.Newest = got.Newest.UTC()

	return got, nil
}

// DeleteStreaksBefore removes every streak not held whose newest failure is
// strictly before retainSince; a held streak is never removed. A zero
// retainSince is refused with lockout.ErrRetainSinceRequired, and nothing is
// deleted.
func (s *AttemptStore) DeleteStreaksBefore(ctx context.Context, retainSince time.Time) (int, error) {
	if retainSince.IsZero() {
		return 0, lockout.ErrRetainSinceRequired
	}

	n, err := s.c.exec(ctx, "purge login failure streaks", pgschema.StreakDeleteBefore, storekit.Time(retainSince))

	return int(n), err
}
