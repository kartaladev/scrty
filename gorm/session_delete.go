package gorm

import "github.com/kartaladev/scrty/session"

// ErrDeleteDidNotSettle is wrapped by the error a user-wide session delete
// (DeleteByUser, DeleteByUserExcept, DeleteByExternalSession and
// DeleteByUserAndExternalIssuer) returns when each of its 64 bounded passes
// removed sessions. It is session.ErrDeleteDidNotSettle under this package's
// name, so errors.Is matches either.
var ErrDeleteDidNotSettle = session.ErrDeleteDidNotSettle
