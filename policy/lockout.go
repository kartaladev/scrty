package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
)

// ErrAccountLocked is the reason an AccountLockoutPolicy denies a
// pre-authentication for an identifier that has failed too often too recently.
// The policy's refusal is a *LockoutError, which matches it.
//
// It says nothing about whether the identifier names a user, and a caller that
// reports it must be as careful: an error that distinguishes a locked account
// from an unknown one tells an attacker which identifiers are worth attacking.
var ErrAccountLocked = errors.New(accountLockedText)

// accountLockedText is the text of ErrAccountLocked, which every
// *LockoutError starts with.
const accountLockedText = "policy: account locked after repeated failures"

const (
	// defaultLockoutThreshold is how many failures in the window are free
	// before a wait is owed. Five is high enough that someone mistyping a
	// password they know is not made to wait, and low enough that an attacker
	// gets very few guesses at full rate.
	defaultLockoutThreshold = 5

	// defaultLockoutWindow is how far back failures are counted. A day bounds
	// what the store holds while keeping a slow, steady guesser's failures in
	// view; a successful authentication clears them sooner, through Reset.
	// Failures older than the window no longer count toward anything, the
	// ceiling included.
	defaultLockoutWindow = 24 * time.Hour

	// defaultLockoutFirstWait and defaultLockoutLongestWait are the ends of
	// NIST SP 800-63B's example range for waits that grow as an account
	// nears its cap: thirty seconds up to an hour.
	defaultLockoutFirstWait   = 30 * time.Second
	defaultLockoutLongestWait = time.Hour

	// defaultLockoutCeiling is how many failures inside the window refuse an
	// identifier outright. It borrows the number NIST SP 800-63B-4 §3.2.2
	// uses, but it is not that section's cap: NIST counts consecutive failures
	// in total and disables the authenticator until it is bound again, while
	// this ceiling counts only the window and lifts as failures age out. With
	// the default waits a guesser who respects them makes about 24 guesses a
	// day, so the ceiling bounds bursts of concurrent requests, not a patient
	// guesser's total.
	defaultLockoutCeiling = 100

	// lockoutPolicyName is what this policy calls itself in logs and in an
	// engine's configuration errors.
	lockoutPolicyName = "account-lockout"
)

// AccountLockoutPolicy denies pre-authentication for an identifier that has
// failed too often too recently.
//
// It is the rule that turns an unlimited guessing rate into a bounded one, and
// it runs before credentials are checked precisely because it must apply
// whether or not the submitted secret is correct.
//
// By default it makes a failing identifier wait, and the wait escalates. The
// first 5 failures in a 24-hour window are free. From the threshold on, the
// identifier owes a wait of 30 seconds, doubled for each failure beyond the
// threshold and never more than an hour, and it is refused while its newest
// failure is more recent than that wait. Once the wait has passed, the next
// attempt is judged on its merits. At 100 failures in the window it is refused
// however long it has waited, until failures leave the window or a successful
// authentication clears them. That ceiling limits the guessing rate, about 24
// guesses a day under the default waits, not the total. It is not NIST SP
// 800-63B-4 §3.2.2's cap on consecutive failures, which disables the
// authenticator until it is bound again; this policy never disables anything.
//
// Waiting rather than locking is the point. A hard lock lets anyone who knows
// a username keep its owner out for as long as they keep failing; an
// escalating wait slows an attacker to about one guess an hour per request in
// flight when a wait lapses, while its owner, once the wait has passed, gets
// in with the right password. Checking and then recording through the
// AttemptStore port is not atomic, so a concurrent burst gets one guess per
// in-flight request; the per-source login guard bounds that burst per source.
// A login flow must therefore not record an attempt this policy refused, or an
// attacker could keep the wait running without making a guess; the library's
// own login endpoints record nothing for it.
//
// A consumer replaces the store with WithAttemptStore — which is what a
// deployment of more than one replica needs — the free failures with
// WithLockoutThreshold, the span with WithLockoutWindow, the waits with
// WithLockoutWait, the cap with WithLockoutCeiling and the clock with
// WithLockoutClock. WithSlidingLockout replaces the escalating wait with a
// sliding lock, which limits the failure rate within a window; WithLockoutWait
// with equal waits gives a lock of fixed duration instead. WithLockoutObserver
// adds an observer told of lockout transitions, recorded through the policy's
// view of its store, Attempts; by default nothing is reported.
//
// A refusal for a locked identifier is a *LockoutError, which matches
// ErrAccountLocked and carries the wait owed.
//
// There is no unlock call and no lock record. Whether an identifier is refused
// is worked out from its failures at every evaluation, so a wait or lock
// expires by itself as the failures age, and a successful authentication
// clears it through Reset. Nothing has to run on a timer for a refused user to
// get back in.
//
// A policy is safe for concurrent use as far as its store is: it holds no
// mutable state of its own after construction.
type AccountLockoutPolicy struct {
	store     AttemptStore
	threshold int
	window    time.Duration
	clock     clock.Clock

	firstWait   time.Duration
	longestWait time.Duration
	ceiling     int

	// sliding selects the sliding lock WithSlidingLockout configures, whose
	// threshold and window replace the escalating ones at construction.
	sliding          bool
	slidingThreshold int
	slidingWindow    time.Duration

	// The set flags record which escalating options a consumer passed, so
	// that combining one with WithSlidingLockout is refused whatever the
	// order of the options.
	setThreshold, setWindow, setWait, setCeiling bool

	// observer is told of lockout transitions recorded through attempts;
	// setObserver records that WithLockoutObserver was passed, so a nil one
	// is refused rather than read as "none".
	observer    LockoutObserver
	setObserver bool
	logger      *slog.Logger

	// attempts is the view Attempts hands out, and the one RecordFailure and
	// Reset go through: the store itself when there is no observer.
	attempts AttemptStore
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

// WithLockoutThreshold replaces how many failures inside the window are free
// before a wait is owed. The default is 5.
//
// Zero or less is a configuration error: it would make every account wait,
// including those that have never failed. So is a threshold at or above the
// ceiling (WithLockoutCeiling, 100 by default), which would refuse an account
// outright before it ever owed a wait. It cannot be combined with
// WithSlidingLockout, which sets its own.
func WithLockoutThreshold(n int) LockoutOption {
	return func(p *AccountLockoutPolicy) {
		p.threshold = n
		p.setThreshold = true
	}
}

// WithLockoutWindow replaces how far back failures are counted, which is also
// how long an account at the ceiling stays refused once the failures stop, and
// the cutoff PurgeExpired sweeps behind. The default is 24 hours.
//
// Zero or less is a configuration error: no failure is ever inside a window of
// zero, so lockout would be disabled while reading, at every call site, exactly
// like a lockout that works. It cannot be combined with WithSlidingLockout, which
// sets its own.
func WithLockoutWindow(d time.Duration) LockoutOption {
	return func(p *AccountLockoutPolicy) {
		p.window = d
		p.setWindow = true
	}
}

// WithLockoutClock replaces the time source. The default is clock.System().
//
// The policy needs one of its own for the work no request drives — recording a
// failure, and choosing a purge cutoff — while an evaluation judges against the
// instant the phase carries, so that every policy in a phase agrees about when
// now is. A nil clock, typed nil included, is a configuration error rather
// than a silent fallback: falling back to the wall clock would make a test
// whose clock never advances look like one that does.
func WithLockoutClock(clk clock.Clock) LockoutOption {
	return func(p *AccountLockoutPolicy) { p.clock = clk }
}

// WithLockoutWait replaces the escalating wait: first is owed at the
// threshold, doubled for each failure beyond it, and never more than longest.
// The defaults are 30 seconds and 1 hour, the ends of NIST SP 800-63B's
// example range.
//
// A first wait of zero or less is a configuration error, since it never starts
// the escalation, and so is a longest wait shorter than the first. A longest
// wait equal to the first is allowed and makes the wait flat. It cannot be
// combined with WithSlidingLockout, which has no wait.
//
// Equal waits make a lock of fixed duration. WithLockoutWait(15*time.Minute,
// 15*time.Minute) refuses an identifier that has reached the threshold for
// exactly 15 minutes after its newest failure, and lets it try again at the
// instant they have passed. Refused attempts are not recorded, so the lock
// runs from the failure that reached the threshold. Unlike the CIS benchmark's
// lockout, the count is not cleared when the lock ends: the failures stay in
// the window, so each further failure locks again for the full duration, one
// guess per duration rather than a fresh threshold's worth. This is the
// configuration for an audit that asks for a minimum lock duration;
// WithSlidingLockout does not provide one. The ceiling (WithLockoutCeiling)
// still applies: a guesser who keeps to one failure per duration reaches it,
// 100 failures by default, within about a day, and is then refused until
// failures age out of the window, so "exactly" holds only below the ceiling.
func WithLockoutWait(first, longest time.Duration) LockoutOption {
	return func(p *AccountLockoutPolicy) {
		p.firstWait, p.longestWait = first, longest
		p.setWait = true
	}
}

// WithLockoutCeiling replaces how many failures in the window refuse an
// identifier however long it has waited. The default is 100.
//
// A ceiling not above the threshold is a configuration error: it would refuse
// an account outright before it ever owed a wait. A ceiling above 100 is
// allowed. The ceiling counts failures inside the window, which age out; it is
// not a cap on consecutive failures in total and never disables the
// authenticator (see AccountLockoutPolicy). It cannot be combined with
// WithSlidingLockout, which has no ceiling.
func WithLockoutCeiling(n int) LockoutOption {
	return func(p *AccountLockoutPolicy) {
		p.ceiling = n
		p.setCeiling = true
	}
}

// WithSlidingLockout replaces the escalating wait with a sliding lock: an
// identifier is refused while at least threshold of its failures fall inside
// the last window, however long ago its newest failure was, and is allowed
// again as soon as enough of them leave the window. The default is the
// escalating wait, with no sliding lock.
//
// It limits the failure rate, not how long a lock lasts. Failures bunched
// together lock for nearly the whole window; failures spread across it lock
// only until the oldest ages out, which can be seconds. A deployment that must
// hold a lock for a fixed duration sets equal waits instead (see
// WithLockoutWait).
//
// Know what it gives up: anyone who knows a username can keep its owner
// refused for as long as they keep failing, which the escalating wait exists
// to prevent.
//
// A threshold or window of zero or less is a configuration error, as for
// WithLockoutThreshold and WithLockoutWindow. Combining it with
// WithLockoutThreshold, WithLockoutWindow, WithLockoutWait or
// WithLockoutCeiling is a configuration error whatever the order, since each
// would mean something different, or nothing, under a sliding lock. A refusal
// under a sliding lock carries no wait.
func WithSlidingLockout(threshold int, window time.Duration) LockoutOption {
	return func(p *AccountLockoutPolicy) {
		p.slidingThreshold, p.slidingWindow = threshold, window
		p.sliding = true
	}
}

// NewAccountLockoutPolicy returns a policy that makes an account wait, longer
// each time, after repeated failures.
//
// Defaults: a threshold of 5 free failures (WithLockoutThreshold) in a window
// of 24 hours (WithLockoutWindow); a wait of 30 seconds doubling up to 1 hour
// (WithLockoutWait); a ceiling of 100 failures in the window
// (WithLockoutCeiling); an in-memory store (WithAttemptStore) and the system
// clock (WithLockoutClock); no lockout observer (WithLockoutObserver), and
// slog.Default for its records (WithLockoutLogger). WithSlidingLockout replaces
// the escalating wait with a sliding lock.
//
// Every misconfiguration is an error wrapping ErrConfig, rather than something
// evaluation copes with: a threshold, window or first wait of zero or less; a
// longest wait shorter than the first; a ceiling not above the threshold;
// WithSlidingLockout combined with any threshold, window, wait or ceiling
// option; and a missing store or clock. Each produces a policy that reads like
// a lockout at every call site and is not one — a window of zero contains no
// failure, so nothing ever locks, and a threshold of zero is already reached by
// an account that has never failed, so everyone is locked out. A constructor
// can report that before any traffic arrives, which is the difference between
// a line of wiring being wrong and a login page being down. A nil lockout
// observer is refused too: a consumer who passed one meant to be told, and
// would hear nothing.
func NewAccountLockoutPolicy(opts ...LockoutOption) (*AccountLockoutPolicy, error) {
	p := &AccountLockoutPolicy{
		store:     NewMemoryAttemptStore(),
		threshold: defaultLockoutThreshold,
		window:    defaultLockoutWindow,
		clock:     clock.System(),

		firstWait:   defaultLockoutFirstWait,
		longestWait: defaultLockoutLongestWait,
		ceiling:     defaultLockoutCeiling,
		logger:      slog.Default(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}

	if p.sliding {
		var conflicts []string
		for _, c := range []struct {
			set  bool
			name string
		}{
			{p.setThreshold, "WithLockoutThreshold"},
			{p.setWindow, "WithLockoutWindow"},
			{p.setWait, "WithLockoutWait"},
			{p.setCeiling, "WithLockoutCeiling"},
		} {
			if c.set {
				conflicts = append(conflicts, c.name)
			}
		}
		if len(conflicts) > 0 {
			return nil, fmt.Errorf(
				"%w: WithSlidingLockout sets its own threshold and window and has no wait or ceiling, so "+
					"combining it with %s would silently change what that option means",
				ErrConfig, strings.Join(conflicts, ", "))
		}
		p.threshold, p.window = p.slidingThreshold, p.slidingWindow
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
	if !p.sliding {
		if err := p.validateEscalation(); err != nil {
			return nil, err
		}
	}
	if nilcheck.IsNil(p.store) {
		return nil, fmt.Errorf("%w: attempt store must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(p.clock) {
		return nil, fmt.Errorf("%w: clock must not be nil", ErrConfig)
	}

	if p.setObserver && p.observer == nil {
		return nil, fmt.Errorf("%w: lockout observer must not be nil: a consumer who passed "+
			"one meant to be told, and would hear nothing", ErrConfig)
	}

	p.attempts = p.store
	if p.observer != nil {
		p.attempts = &observedAttempts{p: p}
	}

	return p, nil
}

// validateEscalation refuses an escalating wait that would not escalate, or
// whose ceiling leaves no wait at all between it and the threshold.
func (p *AccountLockoutPolicy) validateEscalation() error {
	if p.firstWait <= 0 {
		return fmt.Errorf(
			"%w: the first lockout wait must be positive, got %s: a wait of nothing never starts the "+
				"escalation, so an account past the threshold would still be guessed at full rate",
			ErrConfig, p.firstWait)
	}
	if p.longestWait < p.firstWait {
		return fmt.Errorf("%w: the longest lockout wait %s is shorter than the first wait %s",
			ErrConfig, p.longestWait, p.firstWait)
	}
	if p.ceiling <= p.threshold {
		return fmt.Errorf(
			"%w: the lockout ceiling must be above the threshold, got ceiling %d and threshold %d: "+
				"an account would be refused outright before it ever owed a wait",
			ErrConfig, p.ceiling, p.threshold)
	}

	return nil
}

// Name identifies this policy in logs and in an engine's configuration errors.
func (p *AccountLockoutPolicy) Name() string { return lockoutPolicyName }

// Phases reports that this policy runs before credentials are checked, and
// nowhere else: the rule applies whether or not the submitted secret is
// correct, and a locked account must not be able to spend a request's worth of
// work proving its password is right.
func (p *AccountLockoutPolicy) Phases() []Phase { return []Phase{PreAuthentication} }

// Threshold reports how many failures inside the window are free before a wait
// is owed, or lock the account under a sliding lock: what WithLockoutThreshold or
// WithSlidingLockout configured.
func (p *AccountLockoutPolicy) Threshold() int { return p.threshold }

// Window reports how far back failures are counted: what WithLockoutWindow or
// WithSlidingLockout configured.
func (p *AccountLockoutPolicy) Window() time.Duration { return p.window }

// Evaluate denies when the submitted identifier owes a wait or has reached the
// ceiling, and allows otherwise.
//
// It counts the failures recorded strictly inside the window before now. Below
// the threshold that one query is all it asks, and the request is allowed. At
// the ceiling it denies with no wait. Between the two it asks a second
// question, whether any failure is more recent than the wait owed, and denies
// if one is. Counting is strictly after each cutoff, so a newest failure
// exactly as old as the wait has served it. Under WithSlidingLockout it denies
// whenever the threshold is reached in the window.
//
// A locked identifier's reason is a *LockoutError matching ErrAccountLocked,
// whose Wait is the wait owed, or zero at the ceiling and under a sliding lock.
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
// errors.As but not repeated in the text. That holds for either query, so a
// store that answers the window but not the wait still denies. Failing open
// would let an attacker who can break the store disable lockout altogether, so
// the one thing this policy will not do is treat "I do not know" as "nothing
// recorded".
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
		now = p.clock.Now()
	}

	count, err := p.store.FailureCount(ctx, in.Username, now.Add(-p.window))
	if err != nil {
		return storeDenied(err)
	}

	if p.sliding {
		if count >= p.threshold {
			return lockedDecision(count, p.window, 0)
		}

		return Decision{}
	}

	if count >= p.ceiling {
		return lockedDecision(count, p.window, 0)
	}
	if count < p.threshold {
		return Decision{}
	}

	wait := p.waitFor(count)
	recent, err := p.store.FailureCount(ctx, in.Username, now.Add(-wait))
	if err != nil {
		return storeDenied(err)
	}
	if recent > 0 {
		return lockedDecision(count, p.window, wait)
	}

	return Decision{}
}

// waitFor is the wait an identifier with n failures in the window owes: the
// first wait doubled once for each failure beyond the threshold, and never
// more than the longest wait.
//
// The doubling stops as soon as the next one would pass the longest wait, so
// no failure count, however large, can overflow time.Duration into a short or
// negative wait.
func (p *AccountLockoutPolicy) waitFor(n int) time.Duration {
	wait := p.firstWait
	for range n - p.threshold {
		if wait > p.longestWait/2 {
			return p.longestWait
		}
		wait *= 2
	}

	return min(wait, p.longestWait)
}

// storeDenied is the refusal for an attempt store that could not answer.
//
// Failing open here would make breaking the attempt store a way to disable
// lockout: an attacker who can take the store down gets an unlimited guessing
// rate, and the outage looks like a quiet morning. The refusal carries the
// cause by identity, not by text, so the outage is still diagnosable without
// the store's words reaching a log; and it does not claim the account is
// locked, which it does not know.
func storeDenied(err error) Decision {
	return Decision{
		Outcome: Deny,
		Reason: diag.Wrap(err,
			"policy: denied by policy: the attempt store could not say how often this identifier has failed",
			ErrPolicyDenied),
	}
}

// lockedDecision is the refusal for an identifier that is locked: failures in
// the window, owing wait, which is zero where no wait lifts the lock.
func lockedDecision(failures int, window, wait time.Duration) Decision {
	return Decision{
		Outcome: Deny,
		Reason:  &LockoutError{Wait: wait, failures: failures, window: window},
	}
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
//
// It records through Attempts, so a failure that leaves username locked is
// reported to the observer given by WithLockoutObserver.
func (p *AccountLockoutPolicy) RecordFailure(ctx context.Context, username string) error {
	if err := p.attempts.RecordFailure(ctx, username, p.clock.Now()); err != nil {
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
//
// It clears through Attempts, so an administrator's reset that removed
// failures is reported to the observer given by WithLockoutObserver, just as
// a login's is.
func (p *AccountLockoutPolicy) Reset(ctx context.Context, username string) error {
	if err := p.attempts.Reset(ctx, username); err != nil {
		return diag.Wrap(err, "policy: clear failed attempts")
	}

	return nil
}

// PurgeExpired deletes the failures that have aged out of the window — the
// policy's own, 24 hours by default or the sliding lock's — and reports how many
// went.
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

	removed, err := reaper.DeleteAttemptsBefore(ctx, p.clock.Now().Add(-p.window))
	if err != nil {
		if err == ErrRetainSinceRequired { //nolint:errorlint // identity: a bare sentinel carries no store text
			return 0, err
		}

		return 0, diag.Wrap(err, "policy: purge stale failed attempts")
	}

	return removed, nil
}

var _ Policy = (*AccountLockoutPolicy)(nil)
