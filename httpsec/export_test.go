package httpsec

import (
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/internal/assurance"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
)

// This file exposes what the package's tests need and consumers must not have.
// It is a test file, so nothing here reaches a production build.

// Committed reports whether w has already sent a status or a body. It is the
// unexported signal the default error handling reads before writing a status
// of its own.
func Committed(w ResponseWriter) bool {
	c, ok := w.(interface{ committed() bool })
	return ok && c.committed()
}

// PolicyDenyReason exposes the unexported reader every deny site refuses
// through, so a test can pin what a reduced decision refuses with.
var PolicyDenyReason = policyDenyReason

// Registration is one recorded registration, flattened for a test to read.
type Registration struct {
	Interceptor Interceptor
	Order       Order
	Seq         int
}

// Registrations applies opts to a fresh configuration and reports what they
// recorded, so a test can pin an option's effect before New exists.
func Registrations(opts ...Option) ([]Registration, error) {
	var c config
	for _, opt := range opts {
		if err := opt(&c); err != nil {
			return nil, err
		}
	}

	out := make([]Registration, 0, len(c.registrations))
	for _, r := range c.registrations {
		out = append(out, Registration{Interceptor: r.interceptor, Order: r.order, Seq: r.seq})
	}
	return out, nil
}

// TestBuiltInDeps stands in for the *Deps struct an Enable* option takes. The
// fields are `any` because the check under test is presence, not type: what is
// being pinned is that a dependency left out, or present but holding a typed
// nil, is refused before the chain exists.
type TestBuiltInDeps struct {
	Sessions any
	Users    any
}

// EnableTestBuiltIn is a built-in that exists only for the tests, registered
// through the same seam every real Enable* option uses. It lets the validation
// machinery be pinned on its own, before any interceptor has been written, and
// it is the worked example of what such an option has to do: capture its
// dependencies and hand config.enable the check over them.
func EnableTestBuiltIn(d TestBuiltInDeps) Option {
	const option = "EnableTestBuiltIn"

	return func(c *config) error {
		c.enable(option, func() error {
			if err := requireDep(option, "session manager", d.Sessions); err != nil {
				return err
			}
			return requireDep(option, "user loader", d.Users)
		})
		return nil
	}
}

// ChainSettings is what the options resolved, flattened for a test to read.
type ChainSettings struct {
	PolicyEngine       *policy.Engine
	Logger             *slog.Logger
	RateLimiter        ratelimit.Limiter
	IPv6SourcePrefix   int
	RefusalLogInterval time.Duration
	RefusalLogReporter func(key string, suppressed int)
}

// Settings reports the settings c was built with, so a test can pin both the
// default a consumer gets for free and the override that replaces it.
func Settings(c *Chain) ChainSettings {
	return ChainSettings{
		PolicyEngine:       c.engine,
		Logger:             c.logger,
		RateLimiter:        c.limiter,
		IPv6SourcePrefix:   c.ipv6Prefix,
		RefusalLogInterval: c.refusalInterval,
		RefusalLogReporter: c.refusalReporter,
	}
}

// WithSession exposes the unexported publisher, so a test can put a session on
// a context exactly as an interceptor does.
var WithSession = withSession

// ReadResponse exposes the reader the verify endpoint hands a method's
// response through, so its rules can be pinned without a chain.
var ReadResponse = readResponse

// EnableRecoveryGateForTest registers the recovery gate exactly as
// EnableAccountRecovery does, without the recovery endpoints, so a test can
// pin what the gate lets through before those endpoints exist.
func EnableRecoveryGateForTest() Option {
	return func(c *config) error {
		c.enableRecoveryGate(nil)
		return nil
	}
}

// WithRecoveryClockForTest replaces the clock the recovery endpoints judge
// time by, which is otherwise time.Now, so a test can judge the regeneration
// window on the same fake clock its sessions were created on.
func WithRecoveryClockForTest(now func() time.Time) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		i.now = now
		return nil
	}
}

// MintProofForTest mints the library's second-factor proof, which only library
// code can do, so a test can hand the login tail a login whose second factor
// was met at its first.
var MintProofForTest = assurance.New
