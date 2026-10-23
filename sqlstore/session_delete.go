package sqlstore

import (
	"context"

	"github.com/kartaladev/scrty/session"
)

// ErrDeleteDidNotSettle is wrapped by the error a user-wide session delete
// (DeleteByUser, DeleteByUserExcept, DeleteByExternalSession and
// DeleteByUserAndExternalIssuer) returns when each of its maxDeletePasses
// passes removed sessions. It is session.ErrDeleteDidNotSettle under this
// package's name, so errors.Is matches either.
var ErrDeleteDidNotSettle = session.ErrDeleteDidNotSettle

// maxDeletePasses bounds the passes of a user-wide session delete, as
// pgschema.StreakAddMaxRuns bounds a streak write's runs. A pass that removes
// something is followed by another only to reach the successor an in-flight
// supersession inserted, which one more pass does; sessions created as fast
// as the passes remove them would otherwise keep the delete running until its
// context ends, and the library's callers pass contexts that do not end.
const maxDeletePasses = 64

// deleteUntilSettled runs statement, a user-wide delete of sessions, through
// untilSettled.
func (s *sessionStore) deleteUntilSettled(ctx context.Context, op, statement string, args ...any) (int, error) {
	return untilSettled(op, func() (int, error) {
		n, err := s.c.exec(ctx, op, statement, args...)
		return int(n), err
	})
}

// untilSettled runs pass, a user-wide delete of sessions for op, until it
// removes nothing, at most maxDeletePasses times, and returns what every pass
// removed, those before an error included. When every pass removed
// something, the error wraps ErrDeleteDidNotSettle.
func untilSettled(op string, pass func() (int, error)) (int, error) {
	total := 0
	for range maxDeletePasses {
		n, err := pass()
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
		total += n
	}

	return total, failed(op, ErrDeleteDidNotSettle)
}
