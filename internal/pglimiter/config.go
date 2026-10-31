package pglimiter

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

// Config is what the adapters' limiter options describe. Each adapter keeps
// it inside a configuration type of its own, so no exported identifier of an
// adapter names this package.
type Config struct {
	// Clock is the application clock; nil means the database's
	// clock_timestamp().
	Clock clock.Clock
	// ClockSet records that a clock option was given, so that a nil clock
	// passed to it is refused rather than read as "use the database's".
	ClockSet bool
	// Unavailable configures the decorator. It starts from
	// unavailable.DefaultConfig, so every field an option leaves alone keeps
	// the decorator's own default.
	Unavailable unavailable.Config
	// PruneBatchSize is how many keys one prune batch deletes at most, each
	// batch its own transaction. It starts at DefaultPruneBatchSize.
	PruneBatchSize int
}

// DefaultConfig returns the configuration with every default: the database's
// clock, the decorator's own defaults (unavailable.DefaultConfig), and prune
// batches of DefaultPruneBatchSize keys.
func DefaultConfig() Config {
	return Config{Unavailable: unavailable.DefaultConfig(), PruneBatchSize: DefaultPruneBatchSize}
}

// Validate refuses a configuration the limiter cannot run with, in this
// order: an operation timeout above the largest lock_timeout PostgreSQL
// accepts, a clock option given a nil clock (typed nil included), a prune
// batch below one key, and anything unavailable.ValidateConfig refuses. Every
// refusal wraps ratelimit.ErrConfig.
func (c Config) Validate() error {
	switch {
	case c.Unavailable.Timeout.Milliseconds() > pgschema.LimiterMaxLockTimeoutMS:
		return fmt.Errorf("%w: an operation timeout of %s is above the lock_timeout PostgreSQL accepts, at most %dms",
			ratelimit.ErrConfig, c.Unavailable.Timeout, pgschema.LimiterMaxLockTimeoutMS)
	case c.ClockSet && nilcheck.IsNil(c.Clock):
		return fmt.Errorf("%w: the limiter clock is nil", ratelimit.ErrConfig)
	case c.PruneBatchSize < 1:
		return fmt.Errorf("%w: a prune batch of %d keys removes nothing", ratelimit.ErrConfig, c.PruneBatchSize)
	}
	return unavailable.ValidateConfig(c.Unavailable)
}

// ValidatePolicy refuses a namespace, limit or window the limiter cannot
// count with, in this order: an empty namespace, one containing a colon, one
// that is not valid UTF-8 or contains a NUL byte, one longer than
// pgschema.LimiterMaxNamespace bytes, a limit below 1 or above
// pgschema.LimiterMaxLimit, and a window shorter than one microsecond. Every
// refusal wraps ratelimit.ErrConfig.
func ValidatePolicy(namespace string, limit int, window time.Duration) error {
	switch {
	case namespace == "":
		return fmt.Errorf("%w: the namespace is empty, so this limiter would share buckets with every other", ratelimit.ErrConfig)
	case strings.Contains(namespace, ":"):
		return fmt.Errorf("%w: the namespace %q contains a colon, which separates it from the key", ratelimit.ErrConfig, namespace)
	case !utf8.ValidString(namespace) || strings.ContainsRune(namespace, 0):
		return fmt.Errorf("%w: the namespace must be valid UTF-8 without NUL bytes, which PostgreSQL's text type cannot store", ratelimit.ErrConfig)
	case len(namespace) > pgschema.LimiterMaxNamespace:
		return fmt.Errorf("%w: the namespace is %d bytes, longer than the %d bytes a bucket's row holds",
			ratelimit.ErrConfig, len(namespace), pgschema.LimiterMaxNamespace)
	case limit <= 0:
		return fmt.Errorf("%w: a limit of %d throttles every source from its first attempt", ratelimit.ErrConfig, limit)
	case limit > pgschema.LimiterMaxLimit:
		return fmt.Errorf("%w: a limit of %d is above %d, the most failure stamps a bucket's row holds",
			ratelimit.ErrConfig, limit, pgschema.LimiterMaxLimit)
	case window < time.Microsecond:
		return fmt.Errorf("%w: a window of %s is shorter than the microsecond stamps are stored in", ratelimit.ErrConfig, window)
	}
	return nil
}

// LockTimeout is the record's lock_timeout for an operation timeout d: whole
// milliseconds, at least one, since zero would turn the setting off.
func LockTimeout(d time.Duration) string {
	return fmt.Sprintf("%dms", max(d.Milliseconds(), 1))
}

// Now is the statements' now parameter for clk: nil, which they read as the
// database's clock_timestamp(), or the application clock in UTC and whole
// microseconds, the precision stamps are stored in.
func Now(clk clock.Clock) any {
	if clk == nil {
		return nil
	}
	return clk.Now().UTC().Truncate(time.Microsecond)
}

// Policy is the limit and window a namespace was built with.
type Policy struct {
	Limit  int
	Window time.Duration
}

// String reports the policy as "<limit> per <window>", as the conflict error
// names it.
func (p Policy) String() string { return fmt.Sprintf("%d per %s", p.Limit, p.Window) }

// Registry records the policy each namespace a factory built was first built
// with, so the factory refuses the same namespace with another policy. It is
// safe for concurrent use. The zero value is not usable; use NewRegistry.
type Registry struct {
	mu sync.Mutex
	// built holds the policy each namespace was first built with.
	built map[string]Policy
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{built: map[string]Policy{}}
}

// Claim builds through build, under the registry's lock, unless namespace
// already holds a different policy, and records the policy only when build
// succeeds, so a refused request does not claim the namespace.
//
// A namespace already built with another policy is an error wrapping
// ratelimit.ErrConfig, naming the namespace and both policies, and build is
// not called. A build error is returned as it is. On error the limiter is nil.
func (r *Registry) Claim(namespace string, p Policy, build func() (ratelimit.Limiter, error)) (ratelimit.Limiter, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if held, ok := r.built[namespace]; ok && held != p {
		return nil, fmt.Errorf("%w: namespace %q is already built with %s, and was asked for %s; one bucket cannot hold two policies",
			ratelimit.ErrConfig, namespace, held, p)
	}
	l, err := build()
	if err != nil {
		return nil, err
	}
	r.built[namespace] = p

	return l, nil
}
