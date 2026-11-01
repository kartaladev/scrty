// Package hangup tells a caller that left from a dependency that failed.
//
// A request or call whose own context ended before a dependency answered is a
// hang-up: no verdict was reached, so it is not a refusal, and nothing failed,
// so it is not an outage. The paths that tell a hang-up apart for verification,
// resolution, renewal, the authentication provider, and the password and
// recovery loads ask ByCaller, so they agree on what one is. Other checks
// keep their own copies of the decision.
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
