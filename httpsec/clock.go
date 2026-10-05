package httpsec

import (
	"time"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
)

// WithClock sets the time source the chain reads. Default: clock.System().
//
// These follow the chain's clock: the interceptors and the sampling of their
// logs; the MFA challenge managers and their default store; the MFA
// verification throttle; the source guards; the default limiter factory's
// limiters, including the IPv6 aggregate and enrolment limiters; and the
// recovery core, unless it is given its own recovery.WithClock.
//
// These keep their own clock: the session manager, the token issuer and
// verifier, a challenge store given with WithMFAChallengeStore, a factory given
// with WithRateLimiterFactory and the limiters a consumer gives, and the
// managers a consumer builds. Mismatched clocks are allowed and are not
// checked: a consumer who gives one of these a clock other than the chain's
// owns the difference.
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
