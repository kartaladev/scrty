package sweep

import (
	"time"

	"github.com/go-co-op/gocron/v2"
)

// SetIntervalForTest overwrites the interval recorded for task after New has
// validated it, so a test can make job registration fail partway through
// Start. It is the only way to reach that path: New refuses every interval
// gocron would reject.
func SetIntervalForTest(s *Sweeper, task string, d time.Duration) {
	s.setInterval(task, d)
}

// WithSchedulerOptionsForTest hands opts to gocron.NewScheduler after the
// options New derives, so a test can observe the scheduler (gocron.WithMonitor)
// in ways no exported option offers.
func WithSchedulerOptionsForTest(opts ...gocron.SchedulerOption) Option {
	return func(c *config) error {
		c.extraSchedOpts = append(c.extraSchedOpts, opts...)
		return nil
	}
}
