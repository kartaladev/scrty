package pgx

import (
	"context"

	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/session"
)

// ErrDeleteDidNotSettle is wrapped by the error a user-wide session delete
// (DeleteByUser, DeleteByUserExcept, DeleteByExternalSession and
// DeleteByUserAndExternalIssuer) returns when each of its 64 bounded passes
// removed sessions. It is session.ErrDeleteDidNotSettle under this package's
// name, so errors.Is matches either.
var ErrDeleteDidNotSettle = session.ErrDeleteDidNotSettle

// deleteUntilSettled runs statement, a user-wide delete of sessions, through
// storekit.UntilSettled.
func (s *sessionStore) deleteUntilSettled(ctx context.Context, op, statement string, args ...any) (int, error) {
	return storekit.UntilSettled(op, func() (int, error) {
		n, err := s.c.exec(ctx, op, statement, args...)
		return int(n), err
	}, failed)
}
