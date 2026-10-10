package sqlstore

import (
	"context"

	"github.com/kartaladev/scrty/internal/pglimiter"
	"github.com/kartaladev/scrty/ratelimit"
)

var (
	_ ratelimit.Verifier = (*LimiterFactory)(nil)
	_ ratelimit.Verifier = (*Limiter)(nil)
)

// limiterCheck is what Verify checks with, and a factory's prune runs with:
// the runner over the handle, and the configuration whose clock and lock
// timeout the limiter's statements run with, so the probe runs them as the
// limiter does, and whose clock and batch size the prune uses.
type limiterCheck struct {
	runner limiterRunner
	cfg    pglimiter.Config
}

func (c limiterCheck) verify(ctx context.Context) error {
	return pglimiter.Verify(ctx, c.runner, "sqlstore", c.cfg)
}
