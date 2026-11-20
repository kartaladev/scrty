// Package detach is the library's one helper for work that must outlive the
// caller's cancellation, such as recording a failed attempt or revoking a
// session after the client hung up.
//
// context.WithoutCancel also drops the caller's deadline, so detached work
// that calls a store or service needs a bound of its own. [Bounded] supplies
// it. The defaults are [WriteTimeout] for a write and [RevocationTimeout] for
// a revocation of a session family, session or credential. A site that
// already has its own bound keeps it and does not use these.
//
// It depends on internal/porterr for the record of an aborted cause walk.
package detach

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/internal/porterr"
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
//
// The cause is read through [CauseIs], so a cause the walk gives up on is not
// the library's bound. Each call records an abort once, as [CauseIs] does, so
// several hang-up checks on one request each record: over-report, never
// silence.
func BoundReached(ctx context.Context) bool {
	matched, _ := CauseIs(ctx, errBoundReached)

	return matched
}

// CauseIs reports whether the cause ctx ended with (context.Cause) is, or
// wraps, target. A cause is consumer input: any middleware may cancel a
// context with one, so it is read under the library's bounded, recovering
// walk, never stdlib errors.Is, which hangs on a cyclic cause and dies on one
// whose Unwrap or Is method panics.
//
// A live context has no cause, and matches nothing. A cause the walk gives up
// on, a cycle, a fan-out of joins or a link whose Unwrap or Is method panics,
// answers matched false, as an unrelated cause does, and aborted true; its
// match is not guessed from a partial walk. The abort is recorded once, at
// error level, on the logger ctx carries (the chain's own) or else
// slog.Default(), with a constant message and the reason, never the error's
// text. A caller that holds the cause for another purpose, such as joining it
// into a returned error, leaves it out when aborted.
//
// The record is written once per call: several hang-up checks on one request
// each record, which over-reports and never silences.
func CauseIs(ctx context.Context, target error) (matched, aborted bool) {
	matched, abort := CauseWalk(ctx, target)
	if abort != nil {
		reportAbort(ctx, abort)

		return false, true
	}

	return matched, false
}

// CauseWalk is [CauseIs] that reports nothing: it returns the abort that
// stopped its walk, one of errwalk's own values, unwrapped, for a caller that
// already recorded the same cause's abort in the same request and would only
// repeat it. On an abort matched is false.
func CauseWalk(ctx context.Context, target error) (matched bool, abort error) {
	chain, abort := errwalk.Flatten(context.Cause(ctx))
	if abort != nil {
		return false, abort
	}

	return errwalk.Is(chain, target)
}

// reportAbort writes the one record of an aborted walk.
func reportAbort(ctx context.Context, abort error) {
	logger := ctxlog.From(ctx)
	if logger == nil {
		logger = slog.Default()
	}

	attrs := []slog.Attr{slog.String("reason", errwalk.Reason(abort))}

	if p, ok := abort.(*errwalk.PanicError); ok && p != nil { //nolint:errorlint // errwalk's own value, never wrapped
		attrs = append(attrs, diag.PanicAttrsFrom(p.Value, p.Frames)...)
	}

	logger.LogAttrs(ctx, slog.LevelError, porterr.MsgClassificationAborted, attrs...)
}
