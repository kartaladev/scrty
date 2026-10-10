package gorm

import (
	"context"
	"database/sql"
	"errors"
	"time"

	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/policy"
)

// AttemptStore keeps failed login attempts in the login_attempts table the
// migrate package creates, one row per failure, so every replica counts the
// same failures. It also keeps each identifier's consecutive-failure streak in
// the login_failure_streaks table, one row per identifier. It implements
// policy.AttemptStore, policy.AttemptReaper and policy.FailureStreakStore, and
// is safe for concurrent use.
//
// The submitted identifier is stored and matched byte for byte, never folded
// or trimmed. Every instant comes from the caller.
type AttemptStore struct{ c *config }

// NewAttemptStore returns a durable login-attempt store on db.
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
func NewAttemptStore(db *gormdb.DB, opts ...Option) (*AttemptStore, error) {
	c, err := newConfig(db, opts, optIDGenerator)
	if err != nil {
		return nil, err
	}

	return &AttemptStore{c: c}, nil
}

// RecordFailure records one failure for username at at: one INSERT.
func (s *AttemptStore) RecordFailure(ctx context.Context, username string, at time.Time) error {
	const op = "record login failure"

	if err := storekit.CheckStorable(storekit.Text("username", username)); err != nil {
		return failed(op, err)
	}
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return failed(op, err)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	row := loginAttemptRow{ID: rowID, Username: username, AttemptedAt: storekit.Time(at)}
	if err := q.Create(&row).Error; err != nil {
		return failed(op, err)
	}

	return nil
}

// Reset clears username's failures and its streak, hold included, in one
// statement; one with none is not an error.
func (s *AttemptStore) Reset(ctx context.Context, username string) error {
	if !storekit.Storable(username) {
		return nil
	}

	const op = "reset login failures"

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	if err := q.Exec(pgschema.AttemptAndStreakDeleteByUsername, username).Error; err != nil {
		return failed(op, err)
	}

	return nil
}

// FailureCount counts username's failures recorded strictly after since.
func (s *AttemptStore) FailureCount(ctx context.Context, username string, since time.Time) (int, error) {
	const op = "count login failures"

	if !storekit.Storable(username) {
		return 0, nil
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}
	var n int64
	err = q.Model(&loginAttemptRow{}).
		Where("username = ? AND attempted_at > ?", username, storekit.Time(since)).
		Count(&n).Error
	if err != nil {
		return 0, failed(op, err)
	}

	return int(n), nil
}

// DeleteAttemptsBefore removes every failure recorded strictly before
// retainSince. A zero retainSince is refused with
// policy.ErrRetainSinceRequired, and nothing is deleted.
func (s *AttemptStore) DeleteAttemptsBefore(ctx context.Context, retainSince time.Time) (int, error) {
	if retainSince.IsZero() {
		return 0, policy.ErrRetainSinceRequired
	}

	return deleteWhere[loginAttemptRow](ctx, s.c, "purge login failures",
		"attempted_at < ?", storekit.Time(retainSince))
}

var (
	_ policy.AttemptStore       = (*AttemptStore)(nil)
	_ policy.AttemptReaper      = (*AttemptStore)(nil)
	_ policy.FailureStreakStore = (*AttemptStore)(nil)
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
func (s *AttemptStore) AddStreakFailure(
	ctx context.Context, username string, at, since time.Time, limit int,
) (policy.FailureStreak, bool, error) {
	const op = "add to login failure streak"

	if err := storekit.CheckStorable(storekit.Text("username", username)); err != nil {
		return policy.FailureStreak{}, false, failed(op, err)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return policy.FailureStreak{}, false, failed(op, err)
	}

	for range pgschema.StreakAddMaxRuns {
		if err := ctx.Err(); err != nil {
			return policy.FailureStreak{}, false, failed(op, err)
		}

		rowID, err := s.c.ids.NewID()
		if err != nil {
			return policy.FailureStreak{}, false, failed(op, err)
		}

		var (
			got     policy.FailureStreak
			heldAt  *time.Time
			setHold bool
		)
		err = q.Raw(pgschema.StreakAdd,
			rowID, username, storekit.Time(at), storekit.Time(since), limit,
		).Row().Scan(&got.Failures, &got.Newest, &heldAt, &setHold)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return policy.FailureStreak{}, false, failed(op, err)
		}
		got.Newest = got.Newest.UTC()
		got.HeldAt = fromNull(heldAt)

		return got, setHold, nil
	}

	return policy.FailureStreak{}, false, failed(op, errStreakContended)
}

// FailureStreak reads username's streak as of since. A streak not held whose
// newest failure is at or before since, no streak, and an identifier the
// table cannot hold all read as the zero FailureStreak.
func (s *AttemptStore) FailureStreak(ctx context.Context, username string, since time.Time) (policy.FailureStreak, error) {
	const op = "read login failure streak"

	if !storekit.Storable(username) {
		return policy.FailureStreak{}, nil
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return policy.FailureStreak{}, failed(op, err)
	}

	var (
		got    policy.FailureStreak
		heldAt *time.Time
	)
	err = q.Raw(pgschema.StreakRead, username, storekit.Time(since)).
		Row().Scan(&got.Failures, &got.Newest, &heldAt)
	if errors.Is(err, sql.ErrNoRows) {
		return policy.FailureStreak{}, nil
	}
	if err != nil {
		return policy.FailureStreak{}, failed(op, err)
	}
	got.Newest = got.Newest.UTC()
	got.HeldAt = fromNull(heldAt)

	return got, nil
}

// DeleteStreaksBefore removes every streak not held whose newest failure is
// strictly before retainSince; a held streak is never removed. A zero
// retainSince is refused with policy.ErrRetainSinceRequired, and nothing is
// deleted.
func (s *AttemptStore) DeleteStreaksBefore(ctx context.Context, retainSince time.Time) (int, error) {
	const op = "purge login failure streaks"

	if retainSince.IsZero() {
		return 0, policy.ErrRetainSinceRequired
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}
	res := q.Exec(pgschema.StreakDeleteBefore, storekit.Time(retainSince))
	if res.Error != nil {
		return 0, failed(op, res.Error)
	}

	return int(res.RowsAffected), nil
}

// errStreakContended is AddStreakFailure's error when every run of the upsert
// lost a race to create the streak. It names no identifier.
var errStreakContended = errors.New("the streak was created and deleted concurrently on every run")
