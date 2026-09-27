package pgx

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/internal/pgschema"
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

// NewAttemptStore returns a durable login-attempt store on pool.
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

	if err := checkStorable(op, textField{"username", username}); err != nil {
		return err
	}
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return failed(op, err)
	}

	_, err = s.c.exec(ctx, op, pgschema.AttemptInsert, uuidArg(rowID), username, ts(at))

	return err
}

// Reset clears username's failures; one with none is not an error.
func (s *AttemptStore) Reset(ctx context.Context, username string) error {
	if !storable(username) {
		return nil
	}

	_, err := s.c.exec(ctx, "reset login failures", pgschema.AttemptDeleteByUsername, username)

	return err
}

// FailureCount counts username's failures recorded strictly after since.
func (s *AttemptStore) FailureCount(ctx context.Context, username string, since time.Time) (int, error) {
	if !storable(username) {
		return 0, nil
	}

	return s.c.count(ctx, "count login failures", pgschema.AttemptCountSince, username, ts(since))
}

// DeleteAttemptsBefore removes every failure recorded strictly before
// retainSince. A zero retainSince is refused with
// policy.ErrRetainSinceRequired, and nothing is deleted.
func (s *AttemptStore) DeleteAttemptsBefore(ctx context.Context, retainSince time.Time) (int, error) {
	if retainSince.IsZero() {
		return 0, policy.ErrRetainSinceRequired
	}

	n, err := s.c.exec(ctx, "purge login failures", pgschema.AttemptDeleteBefore, ts(retainSince))

	return int(n), err
}

var (
	_ policy.AttemptStore  = (*AttemptStore)(nil)
	_ policy.AttemptReaper = (*AttemptStore)(nil)
)
