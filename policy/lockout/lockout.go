package lockout

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/policy"
)

// ErrAccountLocked is the reason a Policy denies a
// pre-authentication for an identifier that has failed too often too recently.
// The policy's refusal is a *Error, which matches it.
//
// It says nothing about whether the identifier names a user, and a caller that
// reports it must be as careful: an error that distinguishes a locked account
// from an unknown one tells an attacker which identifiers are worth attacking.
var ErrAccountLocked = errors.New(accountLockedText)

// accountLockedText is the text of ErrAccountLocked, which every
// *Error starts with.
const accountLockedText = "lockout: account locked after repeated failures"

// Error is the reason a Policy denies an identifier it
// holds locked. errors.Is matches it to ErrAccountLocked, so a caller that
// only needs to know "locked" keeps matching the sentinel, and errors.As
// reaches it for the wait.
//
// Wait is the full escalated wait the identifier owed when it was refused,
// which is an upper bound on what remains: the attempt store answers counts,
// not instants, so the policy cannot tell how much of the wait has already
// passed. The refusal lifts no later than the window after the newest failure,
// so a Wait longer than the configured window overstates it. Wait is zero
// where no wait lifts the lock — at the window failure limit, under WithSliding,
// and for an identifier held by the streak limit (WithFailureStreakLimit) — and a caller must
// not read zero as "try now".
//
// The refusal of a held identifier also matches ErrAccountHeld, so a consumer
// can tell its user to reset their password rather than wait. Every other
// refusal does not.
//
// A consumer that discloses locks may render Wait as an HTTP Retry-After
// header; the library writes none itself. A consumer that does not disclose
// locks should not let Wait reach the client at all, since a wait is only
// owed by an account that exists and has failed.
//
// Its text is fixed library text naming the failure count and the window,
// never anything an attempt store said.
type Error struct {
	// Wait is the escalated wait owed, or zero at the window failure limit, under a
	// sliding lock and for a hold.
	Wait time.Duration

	failures int
	window   time.Duration

	// held marks the refusal of an identifier held by the failure-streak
	// limit; failures is then the streak's count, and window is unused.
	held bool
}

// Error reports the lock in the library's own words: the failures in the
// window, or, for a hold, the consecutive failures that set it. An Error
// built by a consumer, which carries no failure count, reads as
// ErrAccountLocked.
func (e *Error) Error() string {
	if e.failures == 0 {
		return accountLockedText
	}
	if e.held {
		return fmt.Sprintf("%s: held after %d consecutive failures", accountLockedText, e.failures)
	}

	return fmt.Sprintf("%s: %d failures within %s", accountLockedText, e.failures, e.window)
}

// Is reports whether target is ErrAccountLocked, the sentinel every
// account-locked refusal matches, or ErrAccountHeld, which only the refusal of
// an identifier held by the failure-streak limit matches.
func (e *Error) Is(target error) bool {
	//nolint:errorlint // identity: Is compares against its own sentinels
	return target == ErrAccountLocked || (e.held && target == ErrAccountHeld)
}

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
	// window failure limit included.
	defaultLockoutWindow = 24 * time.Hour

	// defaultLockoutFirstWait and defaultLockoutLongestWait are the ends of
	// NIST SP 800-63B's example range for waits that grow as an account
	// nears a failure-streak limit: thirty seconds up to an hour.
	defaultLockoutFirstWait   = 30 * time.Second
	defaultLockoutLongestWait = time.Hour

	// defaultLockoutCeiling is how many failures inside the window refuse an
	// identifier outright. It borrows the number NIST SP 800-63B-4 §3.2.2
	// uses, but it is not that section's limit: NIST counts consecutive failures
	// in total and disables the authenticator until it is bound again, while
	// this window failure limit counts only the window and lifts as failures age out. With
	// the default waits a guesser who respects them makes about 24 guesses a
	// day, so the window failure limit bounds bursts of concurrent requests, not a patient
	// guesser's total.
	defaultLockoutCeiling = 100

	// lockoutPolicyName is what this policy calls itself in logs and in an
	// engine's configuration errors.
	lockoutPolicyName = "account-lockout"
)

// Policy denies pre-authentication for an identifier that has
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
// authentication clears them. That limit bounds the guessing rate, about 24
// guesses a day under the default waits, not the total. It is not NIST SP
// 800-63B-4 §3.2.2's limit on consecutive failures, which disables the
// authenticator until it is bound again. The failure-streak limit is opt-in: WithFailureStreakLimit
// holds an identifier until its failures are cleared.
//
// Waiting rather than locking is the point. A hard lock lets anyone who knows
// a username keep its owner out for as long as they keep failing; an
// escalating wait slows an attacker to about one guess an hour per request in
// flight when a wait lapses, while its owner, once the wait has passed, gets
// in with the right password. Checking and then recording through the
// policy.AttemptStore port is not atomic, so a concurrent burst gets one guess per
// in-flight request; the per-source login guard bounds that burst per source.
// A login flow must therefore not record an attempt this policy refused, or an
// attacker could keep the wait running without making a guess; the library's
// own login endpoints record nothing for it.
//
// A consumer replaces the store with WithAttemptStore — which is what a
// deployment of more than one replica needs — the free failures with
// WithWaitThreshold, the span with WithFailureWindow, the waits with
// WithWait, the failures a window may hold with WithWindowFailureLimit and
// the clock with WithClock. WithFailureStreakLimit adds a limit on consecutive failures, which
// holds an identifier until its failures are cleared; by default there is
// none. WithSliding replaces the escalating wait with a sliding lock,
// which limits the failure rate within a window; WithWait with equal
// waits gives a lock of fixed duration instead. WithObserver
// adds an observer told of lockout transitions, recorded through the policy's
// view of its store, Attempts; by default nothing is reported.
//
// A refusal for a locked identifier is a *Error, which matches
// ErrAccountLocked and carries the wait owed.
//
// A wait or lock has no record of its own. Whether an identifier owes one is
// worked out from its failures at every evaluation, so it expires by itself as
// the failures age, and a successful authentication clears it through Reset.
// Nothing has to run on a timer for a refused user to get back in.
//
// A failure-streak limit is the exception (WithFailureStreakLimit). Under one, the store keeps a
// record of each identifier's consecutive failures, and the record of one
// that reached the streak limit is a hold: it is refused until its failures are
// cleared, by a password change through the chain or by Reset, which is the
// unlock call. A hold never expires.
//
// A policy is safe for concurrent use as far as its store is: it holds no
// mutable state of its own after construction.
type Policy struct {
	store     policy.AttemptStore
	threshold int
	window    time.Duration
	clock     clock.Clock

	firstWait   time.Duration
	longestWait time.Duration
	ceiling     int

	// sliding selects the sliding lock WithSliding configures, whose
	// threshold and window replace the escalating ones at construction.
	sliding          bool
	slidingThreshold int
	slidingWindow    time.Duration

	// The set flags record which escalating options a consumer passed, so
	// that combining one with WithSliding is refused whatever the
	// order of the options.
	setThreshold, setWindow, setWait, setCeiling bool

	// observer is told of lockout transitions recorded through attempts;
	// setObserver records that WithObserver was passed, so a nil one
	// is refused rather than read as "none".
	observer    Observer
	setObserver bool
	logger      *slog.Logger

	// capLimit and capRetention are WithFailureStreakLimit's limit and
	// WithFailureStreakRetention's retention; the set flags record which of them
	// a consumer passed, so a retention without a limit is refused. streaks is
	// the store's FailureStreakStore half, and is nil exactly when there is no
	// failure-streak limit.
	capLimit                int
	capRetention            time.Duration
	setCap, setCapRetention bool
	streaks                 FailureStreakStore

	// attempts is the view Attempts hands out, and the one RecordFailure and
	// Reset go through: the store itself when there is no observer.
	attempts policy.AttemptStore
}

// New returns a policy that makes an account wait, longer
// each time, after repeated failures.
//
// Defaults: a threshold of 5 free failures (WithWaitThreshold) in a window
// of 24 hours (WithFailureWindow); a wait of 30 seconds doubling up to 1 hour
// (WithWait); a limit of 100 failures in the window
// (WithWindowFailureLimit); a bounded in-memory store (WithAttemptStore), which
// keeps failures only as long as this policy needs them (the window, or the
// failure-streak retention when longer), and the system clock (WithClock); no lockout observer (WithObserver), and
// slog.Default for its records (WithLogger). WithSliding replaces
// the escalating wait with a sliding lock.
//
// Every misconfiguration is an error wrapping policy.ErrConfig, rather than something
// evaluation copes with: a threshold, window or first wait of zero or less; a
// longest wait shorter than the first; a window failure limit not above the threshold;
// WithSliding combined with any threshold, window, wait or window failure limit
// option; and a missing store or clock. Each produces a policy that reads like
// a lockout at every call site and is not one — a window of zero contains no
// failure, so nothing ever locks, and a threshold of zero is already reached by
// an account that has never failed, so everyone is locked out. A constructor
// can report that before any traffic arrives, which is the difference between
// a line of wiring being wrong and a login page being down. A nil lockout
// observer is refused too: a consumer who passed one meant to be told, and
// would hear nothing.
func New(opts ...Option) (*Policy, error) {
	store, err := NewMemoryAttemptStore()
	if err != nil {
		return nil, err
	}

	p := &Policy{
		store:     store,
		threshold: defaultLockoutThreshold,
		window:    defaultLockoutWindow,
		clock:     clock.System(),

		firstWait:   defaultLockoutFirstWait,
		longestWait: defaultLockoutLongestWait,
		ceiling:     defaultLockoutCeiling,
		logger:      slog.Default(),

		capRetention: defaultLockoutCapRetention,
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
			{p.setThreshold, "WithWaitThreshold"},
			{p.setWindow, "WithFailureWindow"},
			{p.setWait, "WithWait"},
			{p.setCeiling, "WithWindowFailureLimit"},
		} {
			if c.set {
				conflicts = append(conflicts, c.name)
			}
		}
		if len(conflicts) > 0 {
			return nil, fmt.Errorf(
				"%w: WithSliding sets its own threshold and window and has no wait or window failure limit, so "+
					"combining it with %s would silently change what that option means",
				policy.ErrConfig, strings.Join(conflicts, ", "))
		}
		p.threshold, p.window = p.slidingThreshold, p.slidingWindow
	}

	if p.threshold <= 0 {
		return nil, fmt.Errorf(
			"%w: the lockout threshold must be positive, got %d: no failure at all is already "+
				"at or above it, so every account would be locked", policy.ErrConfig, p.threshold)
	}
	if p.window <= 0 {
		return nil, fmt.Errorf(
			"%w: the lockout window must be positive, got %s: no failure is ever inside it, so "+
				"lockout would be disabled while every call site still reads like a lockout",
			policy.ErrConfig, p.window)
	}
	if !p.sliding {
		if err := p.validateEscalation(); err != nil {
			return nil, err
		}
	}
	if nilcheck.IsNil(p.store) {
		return nil, fmt.Errorf("%w: attempt store must not be nil", policy.ErrConfig)
	}
	if nilcheck.IsNil(p.clock) {
		return nil, fmt.Errorf("%w: clock must not be nil", policy.ErrConfig)
	}

	if p.setCapRetention && !p.setCap {
		return nil, fmt.Errorf("%w: WithFailureStreakRetention has no failure-streak limit to retain counts for: "+
			"pass WithFailureStreakLimit too, or drop it", policy.ErrConfig)
	}
	if p.setCap {
		if err := p.validateCap(); err != nil {
			return nil, err
		}
	}

	if p.setObserver && p.observer == nil {
		return nil, fmt.Errorf("%w: lockout observer must not be nil: a consumer who passed "+
			"one meant to be told, and would hear nothing", policy.ErrConfig)
	}

	if mem, ok := p.store.(*MemoryAttemptStore); ok {
		retention := p.window
		if p.streaks != nil {
			retention = max(retention, p.capRetention)
		}
		mem.retainFor(retention, p.clock)
	}

	p.attempts = p.store
	if p.observer != nil || p.streaks != nil {
		p.attempts = &observedAttempts{p: p}
	}

	return p, nil
}

// validateEscalation refuses an escalating wait that would not escalate, or
// whose window failure limit leaves no wait at all between it and the threshold.
func (p *Policy) validateEscalation() error {
	if p.firstWait <= 0 {
		return fmt.Errorf(
			"%w: the first lockout wait must be positive, got %s: a wait of nothing never starts the "+
				"escalation, so an account past the threshold would still be guessed at full rate",
			policy.ErrConfig, p.firstWait)
	}
	if p.longestWait < p.firstWait {
		return fmt.Errorf("%w: the longest lockout wait %s is shorter than the first wait %s",
			policy.ErrConfig, p.longestWait, p.firstWait)
	}
	if p.ceiling <= p.threshold {
		return fmt.Errorf(
			"%w: the window failure limit must be above the threshold, got limit %d and threshold %d: "+
				"an account would be refused outright before it ever owed a wait",
			policy.ErrConfig, p.ceiling, p.threshold)
	}

	return nil
}

// validateCap refuses a failure-streak limit the policy could not enforce, or whose retention
// would let a count expire while the window still counts its failures. On
// success it keeps the store's FailureStreakStore half, which is what turns
// the limit on.
func (p *Policy) validateCap() error {
	if p.capLimit <= 0 {
		return fmt.Errorf("%w: WithFailureStreakLimit must be positive, got %d: "+
			"leave the option out for no failure-streak limit", policy.ErrConfig, p.capLimit)
	}
	if p.capLimit <= p.threshold {
		return fmt.Errorf("%w: WithFailureStreakLimit must be above the threshold, got limit %d and threshold %d: "+
			"the first lock would already be a hold", policy.ErrConfig, p.capLimit, p.threshold)
	}
	if p.capRetention <= 0 {
		return fmt.Errorf("%w: WithFailureStreakRetention must be positive, got %s", policy.ErrConfig, p.capRetention)
	}
	if p.capRetention < p.window {
		return fmt.Errorf("%w: WithFailureStreakRetention %s is shorter than the lockout window %s: "+
			"a count would expire while the window still counts its failures",
			policy.ErrConfig, p.capRetention, p.window)
	}
	streaks, ok := p.store.(FailureStreakStore)
	if !ok {
		return fmt.Errorf("%w: WithFailureStreakLimit needs an attempt store that keeps consecutive failures "+
			"(lockout.FailureStreakStore), and %T does not", policy.ErrConfig, p.store)
	}
	p.streaks = streaks

	return nil
}

// Name identifies this policy in logs and in an engine's configuration errors.
func (p *Policy) Name() string { return lockoutPolicyName }

// Phases reports that this policy runs before credentials are checked, and
// nowhere else: the rule applies whether or not the submitted secret is
// correct, and a locked account must not be able to spend a request's worth of
// work proving its password is right.
func (p *Policy) Phases() []policy.Phase { return []policy.Phase{policy.PreAuthentication} }

// WaitThreshold reports how many failures inside the window are free before a wait
// is owed, or lock the account under a sliding lock: what WithWaitThreshold or
// WithSliding configured.
func (p *Policy) WaitThreshold() int { return p.threshold }

// FailureWindow reports how far back failures are counted: what WithFailureWindow or
// WithSliding configured.
func (p *Policy) FailureWindow() time.Duration { return p.window }

// FailureStreakLimit reports the failure-streak limit WithFailureStreakLimit configured, or zero
// when there is none.
func (p *Policy) FailureStreakLimit() int { return p.capLimit }

// FailureStreakRetention reports how long a consecutive count below the streak limit lives after
// its newest failure: what WithFailureStreakRetention configured, or 30 days. It
// only applies when FailureStreakLimit is not zero.
func (p *Policy) FailureStreakRetention() time.Duration { return p.capRetention }

// Evaluate denies when the submitted identifier owes a wait or has reached the
// window failure limit, and allows otherwise.
//
// It counts the failures recorded strictly inside the window before now. Below
// the threshold that one query is all it asks, and the request is allowed. At
// the window failure limit it denies with no wait. Between the two it asks a second
// question, whether any failure is more recent than the wait owed, and denies
// if one is. Counting is strictly after each cutoff, so a newest failure
// exactly as old as the wait has served it. Under WithSliding it denies
// whenever the threshold is reached in the window.
//
// A locked identifier's reason is a *Error matching ErrAccountLocked,
// whose Wait is the wait owed, or zero at the window failure limit and under a sliding lock.
//
// With a failure-streak limit (WithFailureStreakLimit), it first reads the identifier's consecutive
// failures, and a held identifier is denied there and then, whatever the
// window holds: its reason is a *Error matching both ErrAccountLocked
// and ErrAccountHeld, with no wait. Evaluating never writes, so a request
// refused here, whatever password it carries, leaves the hold as it was. An
// identifier that is not held is judged by the window exactly as without a
// failure-streak limit.
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
// policy.ErrDenied and wraps the store's error, reachable through errors.Is and
// errors.As but not repeated in the text. That holds for every query, so a
// store that answers the window but not the wait, or the window but not
// whether the identifier is held, still denies. Failing open
// would let an attacker who can break the store disable lockout altogether, so
// the one thing this policy will not do is treat "I do not know" as "nothing
// recorded".
func (p *Policy) Evaluate(ctx context.Context, in *policy.Input) policy.Decision {
	if in == nil {
		// Nothing to key on, and allowing would make a wiring mistake look
		// exactly like an account in good standing.
		return policy.Decision{
			Outcome: policy.Deny,
			Reason:  fmt.Errorf("%w: the lockout policy was given no request to judge", policy.ErrDenied),
		}
	}

	now := in.Now
	if now.IsZero() {
		now = p.clock.Now()
	}

	if p.streaks != nil {
		// A hold is checked first and decides alone: it outlives every
		// window, so the windowed count has nothing to add to it.
		streak, err := p.streaks.FailureStreak(ctx, in.Username, now.Add(-p.capRetention))
		if err != nil {
			return storeDenied(err)
		}
		if streak.Held() {
			return policy.Decision{Outcome: policy.Deny, Reason: &Error{failures: streak.Failures, held: true}}
		}
	}

	count, err := p.store.FailureCount(ctx, in.Username, now.Add(-p.window))
	if err != nil {
		return storeDenied(err)
	}

	if p.sliding {
		if count >= p.threshold {
			return lockedDecision(count, p.window, 0)
		}

		return policy.Decision{}
	}

	if count >= p.ceiling {
		return lockedDecision(count, p.window, 0)
	}
	if count < p.threshold {
		return policy.Decision{}
	}

	wait := p.waitFor(count)
	recent, err := p.store.FailureCount(ctx, in.Username, now.Add(-wait))
	if err != nil {
		return storeDenied(err)
	}
	if recent > 0 {
		return lockedDecision(count, p.window, wait)
	}

	return policy.Decision{}
}

// waitFor is the wait an identifier with n failures in the window owes: the
// first wait doubled once for each failure beyond the threshold, and never
// more than the longest wait.
//
// The doubling stops as soon as the next one would pass the longest wait, so
// no failure count, however large, can overflow time.Duration into a short or
// negative wait.
func (p *Policy) waitFor(n int) time.Duration {
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
func storeDenied(err error) policy.Decision {
	return policy.Decision{
		Outcome: policy.Deny,
		Reason: diag.Wrap(err,
			policy.ErrDenied.Error()+": the attempt store could not say how often this identifier has failed", //nolint:forbidigo // the library's own sentinel text, not the dependency's
			policy.ErrDenied),
	}
}

// lockedDecision is the refusal for an identifier that is locked: failures in
// the window, owing wait, which is zero where no wait lifts the lock.
func lockedDecision(failures int, window, wait time.Duration) policy.Decision {
	return policy.Decision{
		Outcome: policy.Deny,
		Reason:  &Error{Wait: wait, failures: failures, window: window},
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
// reported to the observer given by WithObserver.
func (p *Policy) RecordFailure(ctx context.Context, username string) error {
	if err := p.attempts.RecordFailure(ctx, username, p.clock.Now()); err != nil {
		return diag.Wrap(err, "lockout: record a failed attempt")
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
// It is also the unlock an administrator or a support tool calls. With a failure-streak limit
// (WithFailureStreakLimit) it lifts a hold, which nothing else in the policy does: the
// store's Reset clears the hold and the consecutive count together with the
// failures in the window, so the identifier is neither held nor waiting
// afterwards. It is not an error for an identifier with nothing to clear.
//
// It clears through Attempts, so an administrator's reset that removed
// failures is reported to the observer given by WithObserver, just as
// a login's is, and one that lifted a hold is reported as ReportReleased.
func (p *Policy) Reset(ctx context.Context, username string) error {
	if err := p.attempts.Reset(ctx, username); err != nil {
		return diag.Wrap(err, "lockout: clear failed attempts")
	}

	return nil
}

// PurgeExpired deletes the failures that have aged out of the window — the
// policy's own, 24 hours by default or the sliding lock's — and reports how many
// went.
//
// With a failure-streak limit (WithFailureStreakLimit) it then deletes the consecutive counts that have
// aged out of the retention (WithFailureStreakRetention) and adds them to the
// total. It never deletes a count the policy still counts, nor a hold. Without a failure-streak limit it never touches the counts.
//
// It takes no window of its own. The cutoff is this policy's own window behind
// its own clock, so the failures the policy would still count are exactly the
// ones the sweep leaves: a caller cannot pass a shorter retention and unlock
// an account that is locked right now, and a sweep is therefore safe to run at
// any moment, as often as the deployment likes.
//
// When an error is returned the count is 0, even if some attempts were already
// removed.
//
// Purging is a capability a store may not have, so it is a separate contract.
// The default in-memory store has it. A consumer's store that does not
// implement AttemptReaper reports ErrReapUnsupported rather than a sweep that
// removed nothing: in a metric those two are the same number, and only one of
// them means the store is growing without bound.
//
// A reaper that cannot sweep has its own error returned behind fixed library
// text; it stays reachable through errors.Is and errors.As, but its text
// never is. ErrRetainSinceRequired — the sentinel a reaper reports for a zero
// cutoff, which this policy never passes — is the one bare exception: it
// comes back as itself, since it carries no dependency text of its own.
func (p *Policy) PurgeExpired(ctx context.Context) (int, error) {
	reaper, ok := p.store.(AttemptReaper)
	if !ok {
		return 0, fmt.Errorf("%w: %T", ErrReapUnsupported, p.store)
	}

	now := p.clock.Now()

	removed, err := reaper.DeleteAttemptsBefore(ctx, now.Add(-p.window))
	if err != nil {
		return 0, purgeFailed(err, "lockout: purge stale failed attempts")
	}

	if p.streaks == nil {
		return removed, nil
	}

	streaks, err := p.streaks.DeleteStreaksBefore(ctx, now.Add(-p.capRetention))
	if err != nil {
		return 0, purgeFailed(err, "lockout: purge inactive consecutive failures")
	}

	return removed + streaks, nil
}

// purgeFailed puts a store's purge error behind the fixed text msg, except
// ErrRetainSinceRequired, which carries no store text and comes back as
// itself.
func purgeFailed(err error, msg string) error {
	if err == ErrRetainSinceRequired { //nolint:errorlint // identity: a bare sentinel carries no store text
		return err
	}

	return diag.Wrap(err, msg)
}

// RequiredAttemptView reports the policy's view, Attempts, and true when a failure-streak limit
// is configured (WithFailureStreakLimit): only the view advances the consecutive
// count, so a failure recorded straight into the store would never bring an
// identifier closer to its hold. Without a failure-streak limit it reports false, and any store
// the policy reads will do, as before.
func (p *Policy) RequiredAttemptView() (policy.AttemptStore, bool) {
	return p.attempts, p.capLimit > 0
}

var _ policy.Policy = (*Policy)(nil)

// ExpiryTask returns the task that deletes the login failures of p that
// have aged out of its lockout window, through p.PurgeExpired.
//
// The task is named "login-attempts". It sets no Interval, because only the
// deployment knows its cadence, and it accepts no cutoff: the cutoff is p's own
// window behind p's own clock (24 hours by default, or what WithFailureWindow
// or WithSliding set). It never deletes a failure the policy would still
// count, so a sweep cannot unlock an account that is locked.
//
// With a failure-streak limit (WithFailureStreakLimit) the task also deletes the consecutive counts
// that have aged out of the failure-streak retention (WithFailureStreakRetention), and never
// a hold: a held identifier stays held however many sweeps run.
//
// A store that cannot purge, the default in-memory one among them, yields an
// error that matches both expiry.ErrPurgeUnsupported and ErrReapUnsupported,
// never a run that removed nothing.
func ExpiryTask(p *Policy) expiry.Task {
	return expiry.Task{
		Name: "login-attempts",
		Run: func(ctx context.Context) (int, error) {
			removed, err := p.PurgeExpired(ctx)
			if errors.Is(err, ErrReapUnsupported) {
				return removed, errors.Join(err, expiry.ErrPurgeUnsupported)
			}

			return removed, err
		},
	}
}
