package mfa

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/ratelimit"
)

//go:generate mockgen -destination=limiter_mock_test.go -package=mfa_test -typed github.com/kartaladev/scrty/ratelimit Limiter,LimiterFactory

// throttleFlow prefixes every bucket key, so this flow's failures never share a
// bucket with another flow's when a consumer hands the same limiter to both.
const throttleFlow = "mfa-verify"

// The reasons a refusal is recorded under. They are the sampler's keys, so an
// outage and a genuine throttling never silence one another.
const (
	reasonThrottled    = "throttled"
	reasonLimiterError = "limiter-error"
	reasonRecordError  = "record-error"
)

// The messages this throttle writes. They are constants because a test asserts
// on them and a consumer may route on them.
const (
	msgThrottled    = "mfa: verification throttled"
	msgLimiterError = "mfa: verification throttle could not be consulted"
	msgRecordError  = "mfa: verification failure could not be recorded"
)

// defaultVerifyLimit and defaultVerifyWindow are the allowance a user gets
// before verification is refused. Five wrong codes is far more than a person
// mistypes and far fewer than an attacker needs against six digits.
const (
	defaultVerifyLimit  = 5
	defaultVerifyWindow = 15 * time.Minute

	// namespaceVerify names this flow to a limiter factory.
	namespaceVerify = "mfa-verify"
)

// VerifyThrottle limits how many failed code verifications one user may
// accumulate.
//
// It is keyed by the user reference rather than by the request's source,
// because by the time a second factor is being verified the attacker already
// holds the first — a password — and can present codes from as many addresses
// as they like. The user is the resource under attack, so the user is what is
// counted.
//
// The price is stated plainly: an attacker who holds a user's password can lock
// that user out of MFA verification for the window. That is accepted, and both
// the window and the limiter are replaceable.
//
// It is safe for concurrent use.
type VerifyThrottle struct {
	limiter     ratelimit.Limiter
	logger      *slog.Logger
	sampler     *logsample.Sampler
	clock       clock.Clock
	logInterval time.Duration

	// limiterSet records that WithVerifyLimiter was given, so a limiter passed
	// as nil is told apart from one never mentioned. The first is a wiring
	// mistake; the second asks for the default.
	limiterSet bool

	// factory builds the limiter when no limiter was given, and factorySet
	// records that WithVerifyLimiterFactory was given, for the same reason as
	// limiterSet.
	factory    ratelimit.LimiterFactory
	factorySet bool
}

// NewVerifyThrottle builds the throttle.
//
// Defaults: an in-memory limiter of 5 failures per 15 minutes
// (WithVerifyLimiter), a one-minute log-sampling window (WithVerifyLogInterval),
// slog.Default (WithVerifyLogger) and clock.System() (WithVerifyClock). The log
// interval governs MFA verification records alone, so an attacker hammering
// one user cannot silence any other part of the library.
//
// A limiter, logger or clock given as nil — including a non-nil interface holding a
// nil pointer — is a configuration error rather than a silent fallback to the
// default: a consumer who passed the option meant to replace something.
func NewVerifyThrottle(opts ...ThrottleOption) (*VerifyThrottle, error) {
	t := &VerifyThrottle{
		logger:      slog.Default(),
		clock:       clock.System(),
		logInterval: time.Minute,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(t)
		}
	}

	if t.logger == nil {
		return nil, errors.New("mfa: verification throttle logger must not be nil")
	}

	if nilcheck.IsNil(t.clock) {
		return nil, fmt.Errorf("%w: verification throttle clock must not be nil", ErrConfig)
	}

	if err := t.resolveLimiter(); err != nil {
		return nil, err
	}

	t.sampler = logsample.New(t.logInterval, logsample.WithReporter(t.reportSuppressed))

	return t, nil
}

// resolveLimiter settles the limiter by precedence: the limiter
// WithVerifyLimiter gave, then one built by the factory WithVerifyLimiterFactory
// gave, then the in-memory default logging through the throttle's logger and
// clock. A limiter or factory replaced with nothing is refused, the factory
// even beside an explicit limiter that would have won.
func (t *VerifyThrottle) resolveLimiter() error {
	if t.factorySet && nilcheck.IsNil(t.factory) {
		return fmt.Errorf("%w: verification throttle limiter factory must not be nil", ErrConfig)
	}

	if t.limiterSet {
		if nilcheck.IsNil(t.limiter) {
			return fmt.Errorf("%w: verification throttle limiter must not be nil", ErrConfig)
		}

		return nil
	}

	factory := t.factory
	if !t.factorySet {
		factory = ratelimit.MemoryLimiterFactory(
			ratelimit.WithMemoryLimiterLogger(t.logger),
			ratelimit.WithMemoryLimiterClock(t.clock),
		)
	}

	l, err := factory.NewLimiter(namespaceVerify, defaultVerifyLimit, defaultVerifyWindow)
	if err != nil {
		return fmt.Errorf("%w: limiter for namespace %q: %w", ErrConfig, namespaceVerify, err)
	}

	t.limiter = l

	return nil
}

// Check reports whether user may present another code.
//
// It is asked before the code is read, so a user at the limit is refused
// without their guess being compared against anything.
//
// A limiter that cannot answer refuses. An undecidable limiter is an outage,
// and an outage that let guesses through would turn a dependency failure into
// an open door.
func (t *VerifyThrottle) Check(ctx context.Context, user identity.UserID) error {
	exceeded, err := t.limiter.Exceeded(ctx, VerifyThrottleKey(user))
	if err != nil {
		t.sampledFailure(ctx, slog.LevelError, msgLimiterError, reasonLimiterError, err)

		return ErrVerifyThrottled
	}

	if exceeded {
		t.sampled(ctx, slog.LevelWarn, msgThrottled, reasonThrottled)

		return ErrVerifyThrottled
	}

	return nil
}

// RecordFailure counts one failed verification against user.
//
// A successful verification records nothing: the limit is on guessing, and a
// user who gets it right has not guessed.
//
// It reports nothing back. A limiter that cannot record is an outage, not a
// judgement about the caller, so the failure it was asked to count is the only
// thing the caller has to report.
func (t *VerifyThrottle) RecordFailure(ctx context.Context, user identity.UserID) {
	// The limiter is given a context with its cancellation stripped, as that
	// port's RecordFailure says to expect: values still travel, but a client
	// that hung up mid-attempt cannot take the guess it already made off the
	// count. Check is left alone on purpose — refusing a question nobody is
	// waiting for is right; declining to charge an answer already given is not.
	if err := t.limiter.RecordFailure(context.WithoutCancel(ctx), VerifyThrottleKey(user)); err != nil {
		t.sampledFailure(ctx, slog.LevelError, msgRecordError, reasonRecordError, err)
	}
}

// VerifyThrottleKey is the bucket key this throttle uses for user.
//
// It is exported because a consumer who supplies their own limiter, shared with
// other flows, needs to know which bucket these failures land in — to read it,
// to clear it after an administrative unlock, or to keep their own keys from
// colliding with it. The user reference travels through unparsed.
func VerifyThrottleKey(user identity.UserID) string {
	return throttleFlow + "|" + string(user)
}

// FlushRefusalLogs reports every record held back but not yet counted, then
// forgets every key. It reports no error, and exists for shutdown.
func (t *VerifyThrottle) FlushRefusalLogs() error {
	t.sampler.Flush()

	return nil
}

// sampled writes one record unless the sampler is holding this reason's window
// open, in which case the event is counted and reported later.
//
// The record names the reason and nothing else. It carries no user reference,
// because the sampler's key is the reason: one record stands for every refusal
// in the window, and naming one user on it would read as though that user
// accounted for all of them. It carries no presented code and no secret, which
// it has never been given.
func (t *VerifyThrottle) sampled(ctx context.Context, level slog.Level, msg, reason string) {
	write, suppressed := t.sampler.Allow(reason, t.clock.Now())
	if !write {
		return
	}

	t.logger.LogAttrs(ctx, level, msg,
		slog.String("reason", reason),
		slog.Int("suppressed", suppressed))
}

// sampledFailure is sampled, for the reasons that name a limiter failure
// rather than a verdict: it carries the failure's Go type through
// diag.Failure in place of the bare reason attribute, never the limiter's own
// error text. A consumer who wants that detail logs it inside their own
// implementation of Limiter.
func (t *VerifyThrottle) sampledFailure(ctx context.Context, level slog.Level, msg, reason string, err error) {
	write, suppressed := t.sampler.Allow(reason, t.clock.Now())
	if !write {
		return
	}

	t.logger.LogAttrs(ctx, level, msg,
		append(diag.Failure(reason, err), slog.Int("suppressed", suppressed))...)
}

// reportSuppressed accounts for counts the sampler is about to discard, so a
// burst that stops before its window closes is still visible as a number.
func (t *VerifyThrottle) reportSuppressed(key string, suppressed int) {
	t.logger.LogAttrs(context.Background(), slog.LevelWarn,
		"mfa: verification refusals suppressed",
		slog.String("reason", key),
		slog.Int("suppressed", suppressed))
}
