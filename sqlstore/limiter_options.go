package sqlstore

import (
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

// LimiterOption configures a Limiter or a LimiterFactory. Every default
// NewLimiter applies has an option here that replaces it. A nil LimiterOption
// is skipped.
//
// The limiter has an option type of its own, apart from the stores' Option,
// because the stores' options (WithTxResolver, WithIDGenerator, ...) mean
// nothing to it: it never joins a transaction, and stores no record with an
// identity.
type LimiterOption func(*limiterConfig)

// limiterConfig is what the limiter options describe.
type limiterConfig struct {
	// clock is the application clock; nil means the database's
	// clock_timestamp().
	clock clock.Clock
	// clockSet records that WithLimiterClock was given, so that a nil clock
	// passed to it is refused rather than read as "use the database's".
	clockSet bool
	// unavailable configures the decorator. It starts from
	// unavailable.DefaultConfig, so every field an option leaves alone keeps
	// the decorator's own default.
	unavailable unavailable.Config
}

// newLimiterConfig returns the configuration opts describe, over the
// defaults.
func newLimiterConfig(opts []LimiterOption) limiterConfig {
	cfg := limiterConfig{unavailable: unavailable.DefaultConfig()}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// WithLimiterClock makes the limiter stamp failures, compute its window and
// prune from clk, passed to the database as a parameter, in place of the
// default: the database's clock_timestamp(), read once per statement.
//
// The default orders every replica's stamps by one clock, the primary's. With
// an application clock, a replica whose clock runs ahead writes stamps the
// others count for longer, and one that runs behind counts failures that have
// already expired, so the replicas' clocks must agree to well within the
// window. It serves tests, and deployments that trust their own clock
// discipline more than the database's. clk is read to whole microseconds, the
// precision the limiter stores.
//
// clk also becomes the clock the outage handling measures its probe interval
// and record-error hold by, which otherwise is the system clock.
//
// A nil clock, typed nil included, fails construction with
// ratelimit.ErrConfig.
func WithLimiterClock(clk clock.Clock) LimiterOption {
	return func(c *limiterConfig) {
		c.clock = clk
		c.clockSet = true
		c.unavailable.Clock = clk
	}
}

// WithLimiterOnUnavailable sets what the limiter does while the database
// cannot be reached. Default: ratelimit.UnavailableRefuse, which answers
// every check as exceeded, so every guarded flow refuses until the database
// is back.
//
// ratelimit.UnavailableFallBackToLocal counts in this process for the outage,
// so the effective limit is multiplied by the number of replicas while it
// lasts; it is the recommended mode for second-factor flows, whose users
// would otherwise be locked out of sign-in by an outage.
// ratelimit.UnavailableAllow lifts the limit for the outage, and suits only a
// flow with another bound in front of it.
//
// A mode other than the three ratelimit declares fails construction with
// ratelimit.ErrConfig.
func WithLimiterOnUnavailable(m ratelimit.UnavailableMode) LimiterOption {
	return func(c *limiterConfig) { c.unavailable.Mode = m }
}

// WithLimiterOperationTimeout bounds each call to the database, records
// included, even when the caller's context has no deadline. Default: 250ms.
//
// A record also tells the server to stop waiting for a row another session
// holds after the same time (lock_timeout, transaction-local, in whole
// milliseconds and at least one), so a held row cannot queue records behind
// it on the server after the caller has given up.
//
// Only a call cut off by this timeout counts as an outage. A caller whose own
// deadline is shorter ends first, and is not taken for one; a deployment
// whose request deadlines are shorter than this timeout lowers it below them.
//
// A zero or negative timeout fails construction with ratelimit.ErrConfig.
func WithLimiterOperationTimeout(d time.Duration) LimiterOption {
	return func(c *limiterConfig) { c.unavailable.Timeout = d }
}

// WithLimiterProbeInterval sets how long the limiter answers from its
// unavailable mode, without calling the database, after a call has failed;
// then one call probes it. Default: 1s. It applies in every mode, so that
// refusing during an outage costs nothing and does not exhaust the
// connection pool.
//
// A zero or negative interval fails construction with ratelimit.ErrConfig.
func WithLimiterProbeInterval(d time.Duration) LimiterOption {
	return func(c *limiterConfig) { c.unavailable.ProbeInterval = d }
}

// WithLimiterUnavailableLogInterval sets how long, in
// ratelimit.UnavailableAllow mode, one written outage record suppresses
// further ones for the namespace. Default: ratelimit.DefaultLogInterval, one
// minute.
//
// Each written record, and a summary when the database is back, carries how
// many records were suppressed. An interval of zero or less writes every
// record, for a consumer whose own handler samples. The other modes write
// only their transitions, and are not sampled.
func WithLimiterUnavailableLogInterval(d time.Duration) LimiterOption {
	return func(c *limiterConfig) { c.unavailable.LogInterval = d }
}

// WithLimiterLogger sets where the limiter writes its outage records: the
// move to and from a degraded mode. Default: slog.Default().
//
// A nil logger fails construction with ratelimit.ErrConfig, because the
// outage records would be lost.
func WithLimiterLogger(l *slog.Logger) LimiterOption {
	return func(c *limiterConfig) { c.unavailable.Logger = l }
}
