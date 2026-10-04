package httpsec

import (
	"time"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
)

// WithClock sets the time source the chain and the components it builds read.
// Default: clock.System(). Dependencies the consumer builds and hands to the
// chain keep their own clocks.
//
// The option governs the chain as a whole, so it may be given with or without
// any interceptor and in any position among the options: it applies to every
// interceptor, whether it is enabled before or after it. A nil clock is a
// configuration error, never a fallback to the system clock.
func WithClock(c clock.Clock) Option {
	return func(cfg *config) error {
		if nilcheck.IsNil(c) {
			return newConfigError("WithClock was given no clock; omit the option to use the system clock")
		}

		cfg.clock = c

		return nil
	}
}

// now reads the chain's time source when it is called, not when the
// interceptor that holds it was built, so WithClock takes effect wherever it
// stands among the options.
func (c *config) now() time.Time { return c.clock.Now() }
