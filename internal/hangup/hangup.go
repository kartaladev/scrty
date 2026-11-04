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
// Other checks keep their own copies of the decision.
package hangup

import (
	"context"
	"errors"
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
func ByCaller(ctx context.Context, err error) bool {
	ctxErr := ctx.Err()
	if ctxErr == nil {
		return false
	}

	return errors.Is(err, ctxErr) || errors.Is(err, context.Cause(ctx))
}
