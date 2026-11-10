package recovery

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/internal/detach"
)

// bounded runs call under a context that keeps ctx's values, outlives its
// cancellation and ends after d. Only the call gets that context: a caller
// logs and classifies the call's failure under its own ctx, because a log
// level chosen from an expired bound would read the library's own deadline as
// the client hanging up.
func bounded(ctx context.Context, d time.Duration, call func(context.Context) error) error {
	bctx, cancel := detach.Bounded(ctx, d)
	defer cancel()

	return call(bctx)
}

// boundedValue is bounded for a call that also returns a value.
func boundedValue[T any](ctx context.Context, d time.Duration, call func(context.Context) (T, error)) (T, error) {
	bctx, cancel := detach.Bounded(ctx, d)
	defer cancel()

	return call(bctx)
}

// maybeBounded is bounded when d is above zero, and a plain call on ctx when it
// is not: the shared helpers that some callers run detached and others do not
// take the bound as a parameter.
func maybeBounded(ctx context.Context, d time.Duration, call func(context.Context) error) error {
	if d <= 0 {
		return call(ctx)
	}

	return bounded(ctx, d, call)
}

// maybeBoundedValue is maybeBounded for a call that also returns a value.
func maybeBoundedValue[T any](ctx context.Context, d time.Duration, call func(context.Context) (T, error)) (T, error) {
	if d <= 0 {
		return call(ctx)
	}

	return boundedValue(ctx, d, call)
}
