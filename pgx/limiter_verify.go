package pgx

import (
	"context"

	"github.com/kartaladev/scrty/internal/pglimiter"
	"github.com/kartaladev/scrty/ratelimit"
)

var (
	_ ratelimit.Verifier = (*LimiterFactory)(nil)
	_ ratelimit.Verifier = (*Limiter)(nil)
)

// limiterCheck is what Verify checks with: the runner over the pool, and the
// configuration whose clock and lock timeout the limiter's statements run
// with, so the probe runs them as the limiter does.
type limiterCheck struct {
	runner limiterRunner
	cfg    pglimiter.Config
}

func (c limiterCheck) verify(ctx context.Context) error {
	return pglimiter.Verify(ctx, c.runner, "pgx", c.cfg)
}
