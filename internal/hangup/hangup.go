// Package hangup tells a caller that left from a dependency that failed.
//
// A request or call whose own context ended before a dependency answered is a
// hang-up: no verdict was reached, so it is not a refusal, and nothing failed,
// so it is not an outage. Every path that tells a hang-up apart asks ByCaller,
// so they agree on what one is:
//
//   - the password provider's user load and the JWT provider's key
//     verification;
//   - the HTTP chain's identity resolution, bearer verification, API key owner
//     load, session renewal's load and the login password load;
//   - the recovery flows' password load, user lookups and credential issuing,
//     and the saved codes' failure logging, which write a hang-up at debug
//     level instead of error;
//   - token/onetime's failure logging, which does the same;
//   - the OIDC provider's code exchange, which tells a spent code's failed
//     reads apart from the caller leaving.
//
// A context that ended because the library's own bound on detached work passed
// ([detach.Bounded]) is never a hang-up: the caller did not leave, the
// dependency was too slow, and that is an outage.
//
// Other checks keep their own copies of the decision.
package hangup

import (
	"context"

	"github.com/kartaladev/scrty/internal/detach"
	"github.com/kartaladev/scrty/internal/errwalk"
)

// ByCaller reports whether err is ctx's own ending rather than a dependency
// failing on its own: ctx has ended, and err matches ctx's error or the cause
// ctx was cancelled with (context.Cause).
//
// It decides from ctx, never from err alone. A dependency that met a deadline
// of its own, while ctx was still live, returns an error matching
// context.DeadlineExceeded too; that is an outage, which is why a bare
// errors.Is(err, context.DeadlineExceeded) or context.Canceled is never asked.
// Nor is an error unrelated to ctx's end a hang-up just because ctx ended
// beside it.
//
// A context whose bound from [detach.Bounded] has passed is not the caller's
// ending, whatever err matches: the library gave up waiting on the dependency,
// so ByCaller reports false and the failure is an outage.
//
// err is walked once, under the library's bounded, recovering walk, and only
// once ctx has ended. An err the walk gives up on, a cyclic chain, a fan-out
// of joins or a link whose Unwrap or Is method panics, is not a hang-up: its
// match is not guessed from a partial walk, and the caller treats it as the
// failure it may be. ByCaller reports nothing and drops the abort, since it
// cannot know whether anything else will meet it; a caller that can report
// an abort asks [ByCallerWalk] instead.
func ByCaller(ctx context.Context, err error) bool {
	hungUp, _ := ByCallerWalk(ctx, err)

	return hungUp
}

// ByCallerWalk is [ByCaller], also returning the abort that stopped its walk
// of err: nil when the walk completed or never ran, because ctx is live or its
// bound from [detach.Bounded] has passed. On an abort hungUp is false, as
// ByCaller answers. The abort is one of errwalk's own values, unwrapped, so
// errwalk.Reason names it, and the caller decides whether and where to report
// it. ByCallerWalk reports nothing itself.
func ByCallerWalk(ctx context.Context, err error) (hungUp bool, abort error) {
	if detach.BoundReached(ctx) {
		return false, nil
	}

	ctxErr := ctx.Err()
	if ctxErr == nil {
		return false, nil
	}

	chain, abort := errwalk.Flatten(err)
	if abort != nil {
		return false, abort
	}

	for _, target := range [...]error{ctxErr, context.Cause(ctx)} {
		found, abort := errwalk.Is(chain, target)
		if abort != nil {
			return false, abort
		}

		if found {
			return true, nil
		}
	}

	return false, nil
}
