package scrtyredis

import (
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

// DefaultKeyPrefix is the prefix every key the limiter stores starts with,
// unless WithKeyPrefix replaces it. A stored key is the prefix, the namespace,
// a colon and the caller's key: scrty:ratelimit:api-key:203.0.113.7.
const DefaultKeyPrefix = "scrty:ratelimit:"

// Option configures a Limiter. Every default NewLimiter applies has an option
// here that replaces it. A nil Option is skipped.
type Option func(*config)

// config is what the options describe.
type config struct {
	prefix string
	// clock is the application clock; nil means the server's TIME.
	clock clock.Clock
	// clockSet records that WithLimiterClock was given, so that a nil clock
	// passed to it is refused rather than read as "use the server's".
	clockSet bool
	// unavailable configures the decorator. It starts from
	// unavailable.DefaultConfig, so every field an option leaves alone keeps
	// the decorator's own default.
	unavailable unavailable.Config
	// evictionCheck is whether Verify reads the eviction policy.
	evictionCheck bool
}

// newConfig returns the configuration opts describe, over the defaults.
func newConfig(opts []Option) config {
	cfg := config{
		prefix:        DefaultKeyPrefix,
		unavailable:   unavailable.DefaultConfig(),
		evictionCheck: true,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// WithKeyPrefix replaces DefaultKeyPrefix, the prefix every stored key starts
// with. Use it to keep the limiter's keys under a prefix of the application's
// own, or to run two independent sets of limits on one server.
//
// No prefix in use on one server may begin with another, the default
// included. Prefix "scrty:ratelimit:" with namespace "staging" and key
// "api-key:x" stores the same key as prefix "scrty:ratelimit:staging:" with
// namespace "api-key" and key "x", so the two sets of limits would share that
// bucket. To separate deployments, give each a sibling prefix such as
// "app-staging:ratelimit:" rather than a nested one; the limiter cannot detect
// the overlap, because it never sees the other prefix.
//
// An empty prefix fails construction with ratelimit.ErrConfig: it would put
// the limiter's keys among the application's own, unmarked.
func WithKeyPrefix(p string) Option {
	return func(c *config) { c.prefix = p }
}

// WithLimiterClock makes the limiter stamp failures and compute its window
// from clk, passed to the server as an argument, in place of the default: the
// server's own clock, read with TIME inside each operation.
//
// The default orders every replica's stamps by one clock. With an application
// clock, a replica whose clock runs ahead writes stamps the others count for
// longer, and one that runs behind counts failures that have already expired,
// so the replicas' clocks must agree to well within the window. It serves
// tests, and deployments that trust their own clock discipline more than the
// server's. clk is read to whole microseconds, the precision the limiter
// stores.
//
// clk also becomes the clock the outage handling measures its probe interval
// and record-error hold by, which otherwise is the system clock.
//
// A nil clock, typed nil included, fails construction with ratelimit.ErrConfig.
func WithLimiterClock(clk clock.Clock) Option {
	return func(c *config) {
		c.clock = clk
		c.clockSet = true
		c.unavailable.Clock = clk
	}
}

// WithOnUnavailable sets what the limiter does while the server cannot be
// reached. Default: ratelimit.UnavailableRefuse, which answers every check as
// exceeded, so every guarded flow refuses until the server is back.
//
// ratelimit.UnavailableFallBackToLocal counts in this process for the outage,
// so the effective limit is multiplied by the number of replicas while it
// lasts; it is the recommended mode for second-factor flows, whose users would
// otherwise be locked out of sign-in by an outage. ratelimit.UnavailableAllow
// lifts the limit for the outage, and suits only a flow with another bound in
// front of it.
//
// A mode other than the three ratelimit declares fails construction with
// ratelimit.ErrConfig.
func WithOnUnavailable(m ratelimit.UnavailableMode) Option {
	return func(c *config) { c.unavailable.Mode = m }
}

// WithOperationTimeout bounds each call to the server, records included, even
// when the caller's context has no deadline. Default: 250ms.
//
// Only a call cut off by this timeout counts as an outage. A caller whose own
// deadline is shorter ends first, and is not taken for one; a deployment whose
// request deadlines are shorter than this timeout lowers it below them.
//
// A zero or negative timeout fails construction with ratelimit.ErrConfig.
func WithOperationTimeout(d time.Duration) Option {
	return func(c *config) { c.unavailable.Timeout = d }
}

// WithUnavailableProbeInterval sets how long the limiter answers from its
// unavailable mode, without calling the server, after a call has failed; then
// one call probes it. Default: 1s. It applies in every mode, so that refusing
// during an outage costs nothing and does not exhaust the connection pool.
//
// A zero or negative interval fails construction with ratelimit.ErrConfig.
func WithUnavailableProbeInterval(d time.Duration) Option {
	return func(c *config) { c.unavailable.ProbeInterval = d }
}

// WithUnavailableLogInterval sets how long, in ratelimit.UnavailableAllow
// mode, one written outage record suppresses further ones for the namespace.
// Default: ratelimit.DefaultLogInterval, one minute.
//
// An outage in allow mode produces a record per call, and without sampling the
// traffic chooses how much the logging costs. Each written record, and a
// summary when the server is back, carries how many records were suppressed,
// so nothing is lost by suppressing them. An interval of zero or less writes
// every record, for a consumer whose own handler samples. The other modes
// write only their transitions, and are not sampled.
func WithUnavailableLogInterval(d time.Duration) Option {
	return func(c *config) { c.unavailable.LogInterval = d }
}

// WithLogger sets where the limiter writes its outage records: the move to
// and from a degraded mode. Default: slog.Default().
//
// A nil logger fails construction with ratelimit.ErrConfig, because the
// outage records would be lost.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) { c.unavailable.Logger = l }
}

// WithEvictionPolicyCheck sets whether Verify reads the server's
// maxmemory-policy. Default: true.
//
// With the check, Verify refuses any policy but noeviction with
// ratelimit.ErrConfig, because an evicting policy (allkeys-*, or volatile-*,
// since every limiter key has a lifetime) can drop a key while its failures
// still count, and so disarm that source's limit. A policy Verify cannot read,
// as on a managed service that blocks CONFIG, writes one WARN naming the
// requirement, and passes.
//
// Turning it off gives up that guarantee: Verify neither reads the policy nor
// warns, and the consumer vouches for noeviction having been verified out of
// band.
func WithEvictionPolicyCheck(enabled bool) Option {
	return func(c *config) { c.evictionCheck = enabled }
}
