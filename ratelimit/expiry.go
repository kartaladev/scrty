package ratelimit

import (
	"context"

	"github.com/kartaladev/scrty/expiry"
)

// Pruner removes the keys a limiter no longer counts, by the window recorded for
// each key, and reports how many it removed. It accepts no cutoff, so a sweep
// can never shorten a limit: the only keys it can remove are those that window
// has already released.
//
// There are two built-in pruners: the in-memory limiter, *MemoryLimiter, and the
// PostgreSQL limiter factories of the sqlstore and pgx packages.
// A consumer may implement Pruner for a limiter of its own and hand it to
// ExpiryTask.
type Pruner interface {
	Prune(ctx context.Context) (removed int, err error)
}

var _ Pruner = (*MemoryLimiter)(nil)

// ExpiryTask returns the expiry task for p, to run in an expiry.Runner beside
// the tasks of the stores that hold expired state. The built-in pruners are the
// in-memory limiter and the PostgreSQL limiter factories of the sqlstore and
// pgx packages. p must not be nil.
//
// The task is named "ratelimit" and has no Interval, so a scheduler uses its
// own default and a manual run ignores it. A deployment with two pruners
// renames each copy so their results and any scheduler lock keys stay apart:
//
//	t := ratelimit.ExpiryTask(f)
//	t.Name = "ratelimit:postgres"
//
// It takes no cutoff: what Prune removes is decided by the window recorded for
// each key, so a sweep can never shorten a limit. The inline sweep of the
// in-memory limiter already bounds memory while traffic arrives, so this task
// matters for a limiter that goes quiet after a burst, whose keys would
// otherwise stay held until its next call. Run returns the count and the error
// the pruner reports; the in-memory limiter never fails.
func ExpiryTask(p Pruner) expiry.Task {
	return expiry.Task{Name: "ratelimit", Run: p.Prune}
}
