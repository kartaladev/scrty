package mfa

import (
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/ratelimit"
)

// ThrottleOption configures the throttle NewVerifyThrottle returns. Every
// default that constructor applies has an option here that replaces it.
//
// A nil option is ignored.
type ThrottleOption func(*VerifyThrottle)

// WithVerifyLimiter replaces the in-memory limiter of 5 failures per 15
// minutes.
//
// A deployment running more than one replica wants one here that its replicas
// share, or the limit is per process and an attacker simply spreads their
// guesses. The key is composed by this package — see VerifyThrottleKey — and is
// opaque to the limiter. It takes precedence over WithVerifyLimiterFactory.
//
// For this second-factor flow, a shared limiter in
// ratelimit.UnavailableFallBackToLocal mode is the recommended choice: during an
// outage of the shared store each replica still bounds guessing on its own, and
// users are not locked out of sign-in.
//
// A nil limiter is a configuration error.
func WithVerifyLimiter(l ratelimit.Limiter) ThrottleOption {
	return func(t *VerifyThrottle) {
		t.limiter = l
		t.limiterSet = true
	}
}

// WithVerifyLimiterFactory builds the verification limiter through f, under the
// namespace "mfa-verify" with this flow's own limit and window: 5 failures per
// 15 minutes.
//
// Default: ratelimit.MemoryLimiterFactory, logging through the throttle's
// logger and clock, so the limit holds in this process alone. Precedence: a
// limiter given with WithVerifyLimiter wins, and f is then never asked; then f;
// then the in-memory default.
//
// For this second-factor flow, a shared limiter in
// ratelimit.UnavailableFallBackToLocal mode is the recommended choice: during an
// outage of the shared store each replica still bounds guessing on its own, and
// users are not locked out of sign-in.
//
// A nil factory, typed nil included, is an error wrapping ErrConfig, as is an
// error from f, which names the namespace.
func WithVerifyLimiterFactory(f ratelimit.LimiterFactory) ThrottleOption {
	return func(t *VerifyThrottle) {
		t.factory = f
		t.factorySet = true
	}
}

// WithVerifyLogInterval replaces the one-minute window that throttle-refusal
// records are sampled over.
//
// An interval of zero or less writes every record. It governs MFA verification
// records alone: no other part of the library is quieted by it, so a user being
// guessed at cannot drown out or silence anything else.
func WithVerifyLogInterval(d time.Duration) ThrottleOption {
	return func(t *VerifyThrottle) { t.logInterval = d }
}

// WithVerifyLogger replaces slog.Default as the destination for throttle
// records. A nil logger is a configuration error; a consumer who wants silence
// supplies a logger with a discarding handler, which says so at the wiring.
//
// A limiter-failure record carries a fixed reason ("limiter-error" or
// "record-error") and the limiter's error's Go type, never its text; a
// throttled record carries the reason alone. A consumer who wants the
// limiter's own detail logs it inside their own implementation of Limiter.
func WithVerifyLogger(l *slog.Logger) ThrottleOption {
	return func(t *VerifyThrottle) { t.logger = l }
}
