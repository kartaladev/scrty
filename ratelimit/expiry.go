package ratelimit

import (
	"context"

	"github.com/kartaladev/scrty/expiry"
)

// ExpiryTask returns the expiry task for l, to run in an expiry.Runner beside
// the tasks of the stores that hold expired state.
//
// The task is named "ratelimit" and has no Interval, so a scheduler uses its
// own default and a manual run ignores it. A consumer with several limiters
// renames each copy, for example "ratelimit:apikey", so their results and any
// scheduler lock keys stay apart.
//
// It takes no cutoff: what Prune removes is decided by the limiter's own window,
// so a sweep can never shorten a limit. The inline sweep already bounds memory
// while traffic arrives, so this task matters for a limiter that goes quiet
// after a burst, whose keys would otherwise stay held until its next call.
// Run returns how many keys Prune removed and never fails.
func ExpiryTask(l *MemoryLimiter) expiry.Task {
	return expiry.Task{
		Name: "ratelimit",
		Run: func(context.Context) (int, error) {
			return l.Prune(), nil
		},
	}
}
