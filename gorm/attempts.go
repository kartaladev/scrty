package gorm

import (
	"context"
	"time"

	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/policy"
)

// AttemptStore keeps failed login attempts in the login_attempts table the
// migrate package creates, one row per failure, so every replica counts the
// same failures. It implements policy.AttemptStore and policy.AttemptReaper,
// and is safe for concurrent use.
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
// truncated or altered into another. Counting or resetting such an identifier
// matches nothing. Stored times are UTC, truncated to the microsecond.
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

// Reset clears username's failures; one with none is not an error.
func (s *AttemptStore) Reset(ctx context.Context, username string) error {
	if !storekit.Storable(username) {
		return nil
	}

	_, err := deleteWhere[loginAttemptRow](ctx, s.c, "reset login failures", "username = ?", username)

	return err
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
	_ policy.AttemptStore  = (*AttemptStore)(nil)
	_ policy.AttemptReaper = (*AttemptStore)(nil)
)
