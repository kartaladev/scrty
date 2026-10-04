package ratelimit

import (
	"errors"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
)

// ErrConfig is wrapped by every error this package's constructors return for a
// wiring mistake, so a consumer can tell a contradictory configuration from a
// runtime failure without matching on message text. A configuration that cannot
// work is refused at construction, before any traffic depends on it.
var ErrConfig = errors.New("ratelimit: invalid configuration")

// MemoryOption configures a MemoryLimiter. Every default NewMemoryLimiter
// applies has an option here that replaces it.
type MemoryOption func(*MemoryLimiter)

// WithMemoryLimiterClock sets the time source failures are stamped from and the
// window is measured against. Default: clock.System().
//
// A nil clock, typed nil included, fails construction with ErrConfig: a
// limiter with no clock could not stamp a failure at all.
func WithMemoryLimiterClock(clk clock.Clock) MemoryOption {
	return func(l *MemoryLimiter) { l.clock = clk }
}

// WithMemoryLimiterLogger sets where the limiter writes its per-replica warning.
// Default: slog.Default.
//
// The warning is written once, on first use. Sending it to a logger the consumer
// controls is what lets it be routed or silenced; it is not suppressible by
// option, because a limit that is silently multiplied by the replica count is
// exactly the misunderstanding worth one record.
func WithMemoryLimiterLogger(logger *slog.Logger) MemoryOption {
	return func(l *MemoryLimiter) { l.logger = logger }
}

// KeyerOption configures a SourceKeyer.
type KeyerOption func(*SourceKeyer)

// WithIPv6SourcePrefix sets the prefix length IPv6 sources are keyed by.
// Default: 64, the smallest allocation an IPv6 host is normally given.
//
// It must be between 1 and 128; anything else fails construction. A wider prefix
// (a smaller number, such as 48) counts a whole allocation as one source, which
// is stricter and pools tenants who share it. A narrower one (up to 128, per
// address) lets a source move within its own allocation to buy a fresh
// allowance. IPv4 is unaffected: it is always keyed per address.
func WithIPv6SourcePrefix(bits int) KeyerOption {
	return func(k *SourceKeyer) { k.ipv6Prefix = bits }
}

// GuardOption configures a SourceGuard. Every default NewSourceGuard applies has
// an option here that replaces it.
type GuardOption func(*SourceGuard)

// WithSourceGuardKeyer sets how client addresses are canonicalised into keys.
// Default: a SourceKeyer with its own defaults. A nil keyer fails construction,
// because a guard that cannot key an address cannot limit anything.
func WithSourceGuardKeyer(keyer *SourceKeyer) GuardOption {
	return func(g *SourceGuard) { g.keyer = keyer }
}

// WithSourceGuardLogger sets where the guard writes its refusal records.
// Default: slog.Default.
//
// A record about a throttled source names its address on purpose — the point
// of the record is to say who was refused. A record about the limiter itself
// failing carries a fixed reason and the error's Go type instead of the
// limiter's own text, which a dependency's error can quote along with values
// the library never saw; a consumer who wants that detail logs it inside
// their own Limiter.
func WithSourceGuardLogger(logger *slog.Logger) GuardOption {
	return func(g *SourceGuard) { g.logger = logger }
}

// WithSourceGuardClock sets the time source the guard samples its refusal
// records by. Default: clock.System().
//
// It does not affect the limiter's own sense of time, which belongs to the
// Limiter and is configured there.
//
// A nil clock, typed nil included, fails construction with ErrConfig: a
// guard with no clock could not sample its refusal records at all.
func WithSourceGuardClock(clk clock.Clock) GuardOption {
	return func(g *SourceGuard) { g.clock = clk }
}

// WithSourceGuardLogInterval sets how long one written refusal record suppresses
// further records about the same flow, source and reason. Default:
// DefaultLogInterval, one minute.
//
// An attacker at its limit produces a refusal per attempt, and without sampling
// it chooses how much the defender's logging costs. Every written record states
// how many refusals it stands for, and SourceGuard.Flush reports what is still
// pending, so nothing is lost by suppressing it.
//
// An interval of zero or less writes every refusal, for a consumer whose own
// handler samples. It governs this guard alone: another guard, and any other
// part of this library that samples its own records, keeps its own window.
func WithSourceGuardLogInterval(d time.Duration) GuardOption {
	return func(g *SourceGuard) { g.logInterval = d }
}

// WithSourceGuardLogReporter sends the refusal counts the guard's sampling
// suppressed to fn, in place of the default: one summary record at WARN through
// the guard's logger (WithSourceGuardLogger) naming the flow, the sampler key
// and the count.
//
// fn receives the sampler key and how many records it stood for. The key is
// "throttled:<flow>:<canonical source>" for a throttled source,
// "throttled:<flow>:<aggregate prefix>" for a throttled IPv6 aggregate
// (WithSourceGuardIPv6Aggregate), or "limiter:<flow>:" for a limiter that
// failed, the latter with an empty detail.
// A canonical IPv6 source contains colons itself, so the key splits safely only
// on its first two separators. It is
// called when a key's window lapses before the key recurs, and by
// SourceGuard.Flush, on the goroutine that triggered either, so it must be fast
// and must not panic. A consumer uses it to count suppressed refusals in a
// metric, or to route them to the same reporter as the rest of its refusal
// records.
//
// A nil fn, like a nil keyer, logger or clock, fails construction with
// ErrConfig: with no reporter at all the counts of a key that goes quiet would
// simply be dropped, and the suppressed totals would stop adding up. Omit the
// option to keep the default summary record.
func WithSourceGuardLogReporter(fn func(key string, suppressed int)) GuardOption {
	return func(g *SourceGuard) { g.reporter = fn }
}

// WithSourceGuardIPv6Aggregate also counts every IPv6 source under its
// enclosing /bits prefix, in limiter, so that a client rotating through the /64s
// of its own allocation cannot buy a fresh allowance with each one. A check is
// refused when either the source or its aggregate is over its limit, and a
// recorded failure counts against both.
//
// Default: off. A guard cannot invent a limit for a limiter it was not given,
// and an aggregate needs a limit of its own — wider than the source's, since it
// is shared by every source inside it — which a Limiter cannot vary per key.
// httpsec's chain turns it on for the guards it builds, where the flow's limit
// is known.
//
// The aggregate is counted under "<flow>:<prefix>", for example
// "api-key:2001:db8:1::/56". IPv4 sources, including IPv4-mapped IPv6
// addresses, have no aggregate and never consult limiter. A limiter shared with
// other guards keeps the counts apart only if the flow names differ, as for the
// source limiter.
//
// Construction fails with ErrConfig when limiter is nil (typed nil included),
// when bits is outside 1..127, or when bits is not strictly less than the
// keyer's IPv6Prefix (WithSourceGuardKeyer): an aggregate no wider than the
// source would count exactly what the source key already does.
func WithSourceGuardIPv6Aggregate(bits int, limiter Limiter) GuardOption {
	return func(g *SourceGuard) {
		g.aggregateSet = true
		g.aggregateBits = bits
		g.aggregate = limiter
	}
}
