// Package detach is the library's one helper for work that must outlive the
// caller's cancellation, such as recording a failed attempt or revoking a
// session after the client hung up.
//
// context.WithoutCancel also drops the caller's deadline, so detached work
// that calls a store or service needs a bound of its own. [Bounded] supplies
// it. The defaults are [WriteTimeout] for a write and [RevocationTimeout] for
// a revocation of a session family, session or credential. A site that
// already has its own bound keeps it and does not use these.
package detach

import (
	"context"
	"errors"
	"time"
)

// errBoundReached is the cause a [Bounded] context ends with when its bound
// passes. It is unexported so that only this package can mint it, and a caller
// can only ask [BoundReached].
var errBoundReached = errors.New("detach: the library's bound on detached work was reached")

// WriteTimeout is the default bound for a detached write.
const WriteTimeout = 5 * time.Second

// RevocationTimeout is the default bound for a detached revocation of a
// session family, session or credential.
const RevocationTimeout = 10 * time.Second

// Bounded returns a context that keeps ctx's values, is not cancelled when ctx
// is, and ends after d. The caller must call the returned CancelFunc to
// release the timer.
//
// A d of zero or less yields a context that is already done with
// context.DeadlineExceeded, so the detached call refuses rather than runs
// unbounded. ctx must not be nil; this internal helper is always given a
// request context, and a nil ctx panics as context.WithoutCancel does.
//
// When the bound passes, the context's error is still context.DeadlineExceeded,
// but its cause (context.Cause) is one [BoundReached] recognises. A bound that
// passed is the library's own limit on a slow dependency, not the caller
// leaving.
func Bounded(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeoutCause(context.WithoutCancel(ctx), d, errBoundReached)
}

// BoundReached reports whether ctx ended because a bound set by [Bounded]
// passed. It is false for a live context, for one cancelled by its returned
// CancelFunc or by a parent, and for a deadline that is not a [Bounded] bound.
//
// A dependency that fails because the library's own bound passed has failed:
// this is how a caller tells that apart from a client hanging up.
func BoundReached(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), errBoundReached)
}
