package policy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// ErrAccountLocked is the reason an AccountLockoutPolicy denies a
// pre-authentication for an identifier that has failed too often too recently.
//
// It says nothing about whether the identifier names a user, and a caller that
// reports it must be as careful: an error that distinguishes a locked account
// from an unknown one tells an attacker which identifiers are worth attacking.
var ErrAccountLocked = errors.New("policy: account locked after repeated failures")

const (
	// defaultLockoutThreshold is how many recent failures lock an account with
	// nothing configured. Five is high enough that someone mistyping a
	// password they know is not locked out of their own account, and low
	// enough that an attacker gets very few guesses per window.
	defaultLockoutThreshold = 5

	// defaultLockoutWindow is how far back failures are counted with nothing
	// configured, and so also how long a locked account stays locked once the
	// failures stop. A quarter of an hour costs a legitimate user one coffee
	// break and costs an attacker most of their guessing rate.
	defaultLockoutWindow = 15 * time.Minute

	// lockoutPolicyName is what this policy calls itself in logs and in an
	// engine's configuration errors.
	lockoutPolicyName = "account-lockout"
)

// AccountLockoutPolicy denies pre-authentication for an identifier that has
// accumulated the threshold number of failures inside the window.
//
// It is the rule that turns an unlimited guessing rate into a bounded one, and
// it runs before credentials are checked precisely because it must apply
// whether or not the submitted secret is correct.
//
// With no options it counts five failures over fifteen minutes in an in-memory
// store. A consumer replaces the store with WithAttemptStore — which is what a
// deployment of more than one replica needs — the count with
// WithLockoutThreshold, the span with WithLockoutWindow and the clock with
// WithLockoutClock.
//
// There is no unlock call and no lock record. An account is locked exactly
// while the failures inside the window reach the threshold, so a lockout
// expires by itself as the failures age out, and a successful authentication
// clears it through Reset. Nothing has to run on a timer for a locked-out user
// to get back in.
//
// A policy is safe for concurrent use as far as its store is: it holds no
// mutable state of its own after construction.
type AccountLockoutPolicy struct {
	store     AttemptStore
	threshold int
	window    time.Duration
	now       func() time.Time
}

// LockoutOption configures an AccountLockoutPolicy. Every option names the
// default it replaces, and every default works with no configuration at all.
type LockoutOption func(*AccountLockoutPolicy)

// WithAttemptStore replaces where failures are counted. The default is
// NewMemoryAttemptStore, which counts within one replica and does not survive
// a restart.
//
// A nil store is a configuration error rather than a silent fallback to
// memory: a consumer who passed one meant to supply their own, and a lockout
// that silently counts per replica is a lockout an attacker divides by the
// number of replicas.
func WithAttemptStore(s AttemptStore) LockoutOption {
	return func(p *AccountLockoutPolicy) { p.store = s }
}

// WithLockoutThreshold replaces how many failures inside the window lock the
// account. The default is 5. Zero or less is a configuration error: it would
// lock every account, including those that have never failed.
func WithLockoutThreshold(n int) LockoutOption {
	return func(p *AccountLockoutPolicy) { p.threshold = n }
}

// WithLockoutWindow replaces how far back failures are counted, which is also
// how long a lockout lasts once the failures stop. The default is 15 minutes.
//
// Zero or less is a configuration error: no failure is ever inside a window of
// zero, so lockout would be disabled while reading, at every call site, exactly
// like a lockout that works.
func WithLockoutWindow(d time.Duration) LockoutOption {
	return func(p *AccountLockoutPolicy) { p.window = d }
}

// WithLockoutClock replaces the time source. The default is time.Now.
//
// The policy needs one of its own for the work no request drives — recording a
// failure, and choosing a purge cutoff — while an evaluation judges against the
// instant the phase carries, so that every policy in a phase agrees about when
// now is. A nil clock is a configuration error rather than a silent fallback:
// falling back to the wall clock would make a test whose clock never advances
// look like one that does.
func WithLockoutClock(now func() time.Time) LockoutOption {
	return func(p *AccountLockoutPolicy) { p.now = now }
}

// NewAccountLockoutPolicy returns a policy that locks an account after
// repeated failures.
//
// Defaults: a threshold of 5 (WithLockoutThreshold) over a window of 15
// minutes (WithLockoutWindow), counted in an in-memory store
// (WithAttemptStore) against the system clock (WithLockoutClock).
//
// A threshold or window of zero or less is a configuration error wrapping
// ErrConfig, rather than something evaluation copes with. Either one produces
// a policy that reads like a lockout at every call site and is not one: a
// window of zero contains no failure, so nothing ever locks, and a threshold
// of zero is already reached by an account that has never failed, so everyone
// is locked out. A constructor can report that before any traffic arrives,
// which is the difference between a line of wiring being wrong and a login
// page being down. A missing store or clock is refused for the same reason.
func NewAccountLockoutPolicy(opts ...LockoutOption) (*AccountLockoutPolicy, error) {
	p := &AccountLockoutPolicy{
		store:     NewMemoryAttemptStore(),
		threshold: defaultLockoutThreshold,
		window:    defaultLockoutWindow,
		now:       time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}

	if p.threshold <= 0 {
		return nil, fmt.Errorf(
			"%w: the lockout threshold must be positive, got %d: no failure at all is already "+
				"at or above it, so every account would be locked", ErrConfig, p.threshold)
	}
	if p.window <= 0 {
		return nil, fmt.Errorf(
			"%w: the lockout window must be positive, got %s: no failure is ever inside it, so "+
				"lockout would be disabled while every call site still reads like a lockout",
			ErrConfig, p.window)
	}
	if nilcheck.IsNil(p.store) {
		return nil, fmt.Errorf("%w: attempt store must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(p.now) {
		return nil, fmt.Errorf("%w: clock must not be nil", ErrConfig)
	}

	return p, nil
}

// Name identifies this policy in logs and in an engine's configuration errors.
func (p *AccountLockoutPolicy) Name() string { return lockoutPolicyName }

// Phases reports that this policy runs before credentials are checked, and
// nowhere else: the rule applies whether or not the submitted secret is
// correct, and a locked account must not be able to spend a request's worth of
// work proving its password is right.
func (p *AccountLockoutPolicy) Phases() []Phase { return []Phase{PreAuthentication} }

// Threshold reports how many failures inside the window lock an account, which
// is what WithLockoutThreshold configured.
func (p *AccountLockoutPolicy) Threshold() int { return p.threshold }

// Window reports how far back failures are counted, which is what
// WithLockoutWindow configured.
func (p *AccountLockoutPolicy) Window() time.Duration { return p.window }

// Evaluate denies when the submitted identifier has at least the threshold
// number of failures recorded strictly inside the window before now, and
// allows otherwise.
//
// Now is the instant the phase carries, so every policy in the phase judges
// the same request against the same moment; the policy's own clock answers
// only when the caller left that instant zero.
//
// The identifier is counted exactly as it was submitted. An empty one is not
// special-cased: it is an identifier like any other, and a deployment that
// records failures under it locks it like any other account.
//
// A store that cannot answer denies, with a reason of fixed text that matches
// ErrPolicyDenied and wraps the store's error, reachable through errors.Is and
// errors.As but not repeated in the text. Failing open would let an attacker who can break the store disable lockout
// altogether, so the one thing this policy will not do is treat "I do not know"
// as "nothing recorded".
func (p *AccountLockoutPolicy) Evaluate(ctx context.Context, in *Input) Decision {
	if in == nil {
		// Nothing to key on, and allowing would make a wiring mistake look
		// exactly like an account in good standing.
		return Decision{
			Outcome: Deny,
			Reason:  fmt.Errorf("%w: the lockout policy was given no request to judge", ErrPolicyDenied),
		}
	}

	now := in.Now
	if now.IsZero() {
		now = p.now()
	}

	count, err := p.store.FailureCount(ctx, in.Username, now.Add(-p.window))
	if err != nil {
		// Failing open here would make breaking the attempt store a way to
		// disable lockout: an attacker who can take the store down gets an
		// unlimited guessing rate, and the outage looks like a quiet morning.
		// The refusal carries the cause by identity, not by text, so the outage
		// is still diagnosable without the store's words reaching a log; and
		// it does not claim the account is locked, which it does not know.
		return Decision{
			Outcome: Deny,
			Reason: diag.Wrap(err,
				"policy: denied by policy: the attempt store could not say how often this identifier has failed",
				ErrPolicyDenied),
		}
	}

	if count >= p.threshold {
		return Decision{
			Outcome: Deny,
			Reason: fmt.Errorf("%w: %d failures within %s",
				ErrAccountLocked, count, p.window),
		}
	}

	return Decision{}
}

// RecordFailure records one failed authentication for username, at the
// policy's own instant.
//
// It is the consumer's login flow that decides what counts as a failure — a
// wrong password, an unknown identifier, a refused second factor — so the flow
// reports it here rather than the policy inferring it.
//
// A store that cannot record says so, and the caller must not treat that as
// recorded: a failure nobody counted is a guess the attacker got for free.
// The store's own error comes back behind fixed library text; it stays
// reachable through errors.Is and errors.As, but its text never is.
func (p *AccountLockoutPolicy) RecordFailure(ctx context.Context, username string) error {
	if err := p.store.RecordFailure(ctx, username, p.now()); err != nil {
		return diag.Wrap(err, "policy: record a failed attempt")
	}

	return nil
}

// Reset clears username's failures, which is what a successful authentication
// does: the account is back in good standing, and the failures before it must
// not be able to lock it on the next mistyped password.
//
// The store's own error comes back behind fixed library text; it stays
// reachable through errors.Is and errors.As, but its text never is.
func (p *AccountLockoutPolicy) Reset(ctx context.Context, username string) error {
	if err := p.store.Reset(ctx, username); err != nil {
		return diag.Wrap(err, "policy: clear failed attempts")
	}

	return nil
}

// PurgeExpired deletes the failures that have aged out of the window and
// reports how many went.
//
// It takes no window of its own. The cutoff is this policy's own window behind
// its own clock, so the failures the policy would still count are exactly the
// ones the sweep leaves: a caller cannot pass a shorter retention and unlock
// an account that is locked right now, and a sweep is therefore safe to run at
// any moment, as often as the deployment likes.
//
// Purging is a capability a store may not have, so it is a separate contract.
// A store that does not implement AttemptReaper — the default in-memory one
// among them — reports ErrReapUnsupported rather than a sweep that removed
// nothing: in a metric those two are the same number, and only one of them
// means the store is growing without bound.
//
// A reaper that cannot sweep has its own error returned behind fixed library
// text; it stays reachable through errors.Is and errors.As, but its text
// never is. ErrRetainSinceRequired — the sentinel a reaper reports for a zero
// cutoff, which this policy never passes — is the one bare exception: it
// comes back as itself, since it carries no dependency text of its own.
func (p *AccountLockoutPolicy) PurgeExpired(ctx context.Context) (int, error) {
	reaper, ok := p.store.(AttemptReaper)
	if !ok {
		return 0, fmt.Errorf("%w: %T", ErrReapUnsupported, p.store)
	}

	removed, err := reaper.DeleteAttemptsBefore(ctx, p.now().Add(-p.window))
	if err != nil {
		if err == ErrRetainSinceRequired { //nolint:errorlint // identity: a bare sentinel carries no store text
			return 0, err
		}

		return 0, diag.Wrap(err, "policy: purge stale failed attempts")
	}

	return removed, nil
}

var _ Policy = (*AccountLockoutPolicy)(nil)
