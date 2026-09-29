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
