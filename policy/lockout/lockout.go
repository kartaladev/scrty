package lockout

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
// authentication clears them. That ceiling limits the guessing rate, about 24
// guesses a day under the default waits, not the total. It is not NIST SP
// 800-63B-4 §3.2.2's cap on consecutive failures, which disables the
// authenticator until it is bound again. That cap is opt-in: WithCap
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
// WithThreshold, the span with WithWindow, the waits with
// WithWait, the cap with WithCeiling and the clock with
// WithClock. WithCap adds a cap on consecutive failures, which
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
// A cap is the exception (WithCap). Under one, the store keeps a
// record of each identifier's consecutive failures, and the record of one
// that reached the cap is a hold: it is refused until its failures are
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

	// capLimit and capRetention are WithCap's cap and
	// WithCapRetention's retention; the set flags record which of them
	// a consumer passed, so a retention without a cap is refused. streaks is
	// the store's FailureStreakStore half, and is nil exactly when there is no
	// cap.
	capLimit                int
	capRetention            time.Duration
	setCap, setCapRetention bool
	streaks                 FailureStreakStore

	// attempts is the view Attempts hands out, and the one RecordFailure and
	// Reset go through: the store itself when there is no observer.
	attempts policy.AttemptStore
}

// Option configures a Policy. Every option names the
// default it replaces, and every default works with no configuration at all.
type Option func(*Policy)

// WithAttemptStore replaces where failures are counted. The default is
// NewMemoryAttemptStore, which counts within one replica, does not survive a
// restart, and holds at most 100,000 identifiers, denying logins for new ones
// while it is full. A MemoryAttemptStore passed here is told this policy's
// retention, exactly as the default one is. Only a *MemoryAttemptStore itself
// is told: a consumer wrapper around one never learns the retention, never
// sweeps, and once full refuses every new identifier until reset. Build a
// wrapper over a store the consumer sweeps itself, or give the policy the inner
// *MemoryAttemptStore and have the wrapper forward to it.
//
// A nil store is a configuration error rather than a silent fallback to
// memory: a consumer who passed one meant to supply their own, and a lockout
// that silently counts per replica is a lockout an attacker divides by the
// number of replicas.
func WithAttemptStore(s policy.AttemptStore) Option {
	return func(p *Policy) { p.store = s }
}

// WithThreshold replaces how many failures inside the window are free
// before a wait is owed. The default is 5.
//
// Zero or less is a configuration error: it would make every account wait,
// including those that have never failed. So is a threshold at or above the
// ceiling (WithCeiling, 100 by default), which would refuse an account
// outright before it ever owed a wait. It cannot be combined with
// WithSliding, which sets its own.
func WithThreshold(n int) Option {
	return func(p *Policy) {
		p.threshold = n
		p.setThreshold = true
	}
}

// WithWindow replaces how far back failures are counted, which is also
// how long an account at the ceiling stays refused once the failures stop, and
// the cutoff PurgeExpired sweeps behind. The default is 24 hours.
//
// Zero or less is a configuration error: no failure is ever inside a window of
// zero, so lockout would be disabled while reading, at every call site, exactly
// like a lockout that works. It cannot be combined with WithSliding, which
// sets its own.
func WithWindow(d time.Duration) Option {
	return func(p *Policy) {
		p.window = d
		p.setWindow = true
	}
}

// WithClock replaces the time source. The default is clock.System().
//
// The policy needs one of its own for the work no request drives — recording a
// failure, and choosing a purge cutoff — while an evaluation judges against the
// instant the phase carries, so that every policy in a phase agrees about when
// now is. A nil clock, typed nil included, is a configuration error rather
// than a silent fallback: falling back to the wall clock would make a test
// whose clock never advances look like one that does.
func WithClock(clk clock.Clock) Option {
	return func(p *Policy) { p.clock = clk }
}

// WithWait replaces the escalating wait: first is owed at the
// threshold, doubled for each failure beyond it, and never more than longest.
// The defaults are 30 seconds and 1 hour, the ends of NIST SP 800-63B's
// example range.
//
// A first wait of zero or less is a configuration error, since it never starts
// the escalation, and so is a longest wait shorter than the first. A longest
// wait equal to the first is allowed and makes the wait flat. It cannot be
// combined with WithSliding, which has no wait.
//
// Equal waits make a lock of fixed duration. WithWait(15*time.Minute,
// 15*time.Minute) refuses an identifier that has reached the threshold for
// exactly 15 minutes after its newest failure, and lets it try again at the
// instant they have passed. Refused attempts are not recorded, so the lock
// runs from the failure that reached the threshold. Unlike the CIS benchmark's
// lockout, the count is not cleared when the lock ends: the failures stay in
// the window, so each further failure locks again for the full duration, one
// guess per duration rather than a fresh threshold's worth. This is the
// configuration for an audit that asks for a minimum lock duration;
// WithSliding does not provide one. The ceiling (WithCeiling)
// still applies: a guesser who keeps to one failure per duration reaches it,
// 100 failures by default, within about a day, and is then refused until
// failures age out of the window, so "exactly" holds only below the ceiling.
func WithWait(first, longest time.Duration) Option {
	return func(p *Policy) {
		p.firstWait, p.longestWait = first, longest
		p.setWait = true
	}
}

// WithCeiling replaces how many failures in the window refuse an
// identifier however long it has waited. The default is 100.
//
// A ceiling not above the threshold is a configuration error: it would refuse
// an account outright before it ever owed a wait. A ceiling above 100 is
// allowed. The ceiling counts failures inside the window, which age out; it is
// not a cap on consecutive failures in total and never disables the
// authenticator (see Policy). It cannot be combined with
// WithSliding, which has no ceiling.
func WithCeiling(n int) Option {
	return func(p *Policy) {
		p.ceiling = n
		p.setCeiling = true
	}
}

// WithSliding replaces the escalating wait with a sliding lock: an
// identifier is refused while at least threshold of its failures fall inside
// the last window, however long ago its newest failure was, and is allowed
// again as soon as enough of them leave the window. The default is the
// escalating wait, with no sliding lock.
//
// It limits the failure rate, not how long a lock lasts. Failures bunched
// together lock for nearly the whole window; failures spread across it lock
// only until the oldest ages out, which can be seconds. A deployment that must
// hold a lock for a fixed duration sets equal waits instead (see
// WithWait).
//
// Know what it gives up: anyone who knows a username can keep its owner
// refused for as long as they keep failing, which the escalating wait exists
// to prevent.
//
// A threshold or window of zero or less is a configuration error, as for
// WithThreshold and WithWindow. Combining it with
// WithThreshold, WithWindow, WithWait or
// WithCeiling is a configuration error whatever the order, since each
// would mean something different, or nothing, under a sliding lock. A refusal
// under a sliding lock carries no wait.
func WithSliding(threshold int, window time.Duration) Option {
	return func(p *Policy) {
		p.slidingThreshold, p.slidingWindow = threshold, window
		p.sliding = true
	}
}

// NISTCap is the limit NIST SP 800-63B-4 §3.2.2 sets on consecutive
// failed attempts for one account: 100. Pass it to WithCap to hold an
// identifier at that limit. It is a documented value to pass, not a default:
// a policy has no cap unless WithCap sets one.
const NISTCap = 100

// defaultLockoutCapRetention is how long a consecutive count below the cap
// lives after its newest failure, once WithCap sets a cap.
const defaultLockoutCapRetention = 30 * 24 * time.Hour

// WithCap holds an identifier once n consecutive failures have been
// recorded for it, however many days they are spread over. The default is no
// cap: an identifier is never held, and only the windowed waits and ceiling
// apply. NISTCap is the value to pass for NIST's limit.
//
// A held identifier is refused before its password is checked, with a
// *Error that matches both ErrAccountLocked and ErrAccountHeld and
// carries no wait. The hold is a record in the attempt store, kept until the
// identifier's failures are cleared, and only that lifts it:
//   - a password change through the httpsec chain, including the one that
//     completes an account recovery;
//   - the policy's Reset, which is the unlock for an administrator or a
//     support tool.
//
// There is no time-based release: no wait, window or retention ends a hold,
// and neither does a correct password, which is never checked while the hold
// stands.
//
// NIST SP 800-63B-4 §3.2.2 limits consecutive failed attempts for one account
// to 100. A lower cap is within that limit; a cap above NISTCap is
// accepted, and no longer meets it.
//
// A hold is a denial of service in the hands of anyone who knows a username:
// they can hold its account by failing on purpose, which is why the cap is
// opt-in. What bounds that risk:
//   - account recovery with saved recovery codes still works while an account
//     is held and needs no password, and the password change after it lifts
//     the hold;
//   - the per-source password-login guard of the httpsec chain (50 failures
//     per 15 minutes by default) bounds what one source can send;
//   - the escalating waits allow one identifier about 24 failures a day after
//     the first day, so reaching a cap of 100 takes about four days, in which
//     the owner's own successful login clears the count.
//
// The policy cannot tell an identifier that names an account from one that
// does not, and holds them alike. Held records are never pruned, by the
// retention or by PurgeExpired, so a spray of unknown identifiers leaves one
// held record per name; a consumer clears them with Reset.
//
// A cap needs an attempt store that keeps consecutive failures
// (FailureStreakStore); the default in-memory store and the library's durable
// stores do. Failures count toward the cap only when recorded through the
// policy's view, Attempts, or its RecordFailure, so the view, not the bare
// store, is what the chain's login endpoints must record into. The httpsec
// chain checks this at construction, but only for policies registered in its
// engine before httpsec.New runs; a capped policy added later is not checked.
// A count below the cap expires after the retention (WithCapRetention,
// 30 days by default).
//
// It is a configuration error for n to be zero or less, or not above the
// threshold (the first lock would already be a hold), and for the store not to
// implement FailureStreakStore.
func WithCap(n int) Option {
	return func(p *Policy) {
		p.capLimit = n
		p.setCap = true
	}
}

// WithCapRetention replaces how long a consecutive count below the cap
// lives after its newest failure. The default is 30 days. A count whose newest
// failure is older is no longer counted, the next failure starts a new count,
// and PurgeExpired removes it. A hold never expires this way, and is never
// purged.
//
// It is a configuration error for d to be zero or less, for it to be given
// without WithCap, which makes it meaningless, and for it to be shorter
// than the lockout window, since a count would then expire while the window
// still counts its failures.
func WithCapRetention(d time.Duration) Option {
	return func(p *Policy) {
		p.capRetention = d
		p.setCapRetention = true
	}
}

// New returns a policy that makes an account wait, longer
// each time, after repeated failures.
//
// Defaults: a threshold of 5 free failures (WithThreshold) in a window
// of 24 hours (WithWindow); a wait of 30 seconds doubling up to 1 hour
// (WithWait); a ceiling of 100 failures in the window
// (WithCeiling); a bounded in-memory store (WithAttemptStore), which
// keeps failures only as long as this policy needs them (the window, or the
// cap's retention when longer), and the system clock (WithClock); no lockout observer (WithObserver), and
// slog.Default for its records (WithLogger). WithSliding replaces
// the escalating wait with a sliding lock.
//
// Every misconfiguration is an error wrapping policy.ErrConfig, rather than something
// evaluation copes with: a threshold, window or first wait of zero or less; a
// longest wait shorter than the first; a ceiling not above the threshold;
// WithSliding combined with any threshold, window, wait or ceiling
// option; and a missing store or clock. Each produces a policy that reads like
// a lockout at every call site and is not one — a window of zero contains no
// failure, so nothing ever locks, and a threshold of zero is already reached by
// an account that has never failed, so everyone is locked out. A constructor
// can report that before any traffic arrives, which is the difference between
// a line of wiring being wrong and a login page being down. A nil lockout
// observer is refused too: a consumer who passed one meant to be told, and
// would hear nothing.
func New(opts ...Option) (*Policy, error) {
	p := &Policy{
		store:     NewMemoryAttemptStore(),
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
		return nil, fmt.Errorf("%w: WithLockoutCapRetention has no cap to retain counts for: "+
			"pass WithLockoutCap too, or drop it", policy.ErrConfig)
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
// whose ceiling leaves no wait at all between it and the threshold.
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
			"%w: the lockout ceiling must be above the threshold, got ceiling %d and threshold %d: "+
				"an account would be refused outright before it ever owed a wait",
			policy.ErrConfig, p.ceiling, p.threshold)
	}

	return nil
}

// validateCap refuses a cap the policy could not enforce, or whose retention
// would let a count expire while the window still counts its failures. On
// success it keeps the store's FailureStreakStore half, which is what turns
// the cap on.
func (p *Policy) validateCap() error {
	if p.capLimit <= 0 {
		return fmt.Errorf("%w: WithLockoutCap must be positive, got %d: "+
			"leave the option out for no cap", policy.ErrConfig, p.capLimit)
	}
	if p.capLimit <= p.threshold {
		return fmt.Errorf("%w: WithLockoutCap must be above the threshold, got cap %d and threshold %d: "+
			"the first lock would already be a hold", policy.ErrConfig, p.capLimit, p.threshold)
	}
	if p.capRetention <= 0 {
		return fmt.Errorf("%w: WithLockoutCapRetention must be positive, got %s", policy.ErrConfig, p.capRetention)
	}
	if p.capRetention < p.window {
		return fmt.Errorf("%w: WithLockoutCapRetention %s is shorter than the lockout window %s: "+
			"a count would expire while the window still counts its failures",
			policy.ErrConfig, p.capRetention, p.window)
	}
	streaks, ok := p.store.(FailureStreakStore)
	if !ok {
		return fmt.Errorf("%w: WithLockoutCap needs an attempt store that keeps consecutive failures "+
			"(policy.FailureStreakStore), and %T does not", policy.ErrConfig, p.store)
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

// Threshold reports how many failures inside the window are free before a wait
// is owed, or lock the account under a sliding lock: what WithThreshold or
// WithSliding configured.
func (p *Policy) Threshold() int { return p.threshold }

// Window reports how far back failures are counted: what WithWindow or
// WithSliding configured.
func (p *Policy) Window() time.Duration { return p.window }

// Cap reports the consecutive-failure cap WithCap configured, or zero
// when there is none.
func (p *Policy) Cap() int { return p.capLimit }

// CapRetention reports how long a consecutive count below the cap lives after
// its newest failure: what WithCapRetention configured, or 30 days. It
// only applies when Cap is not zero.
func (p *Policy) CapRetention() time.Duration { return p.capRetention }

// Evaluate denies when the submitted identifier owes a wait or has reached the
// ceiling, and allows otherwise.
//
// It counts the failures recorded strictly inside the window before now. Below
// the threshold that one query is all it asks, and the request is allowed. At
// the ceiling it denies with no wait. Between the two it asks a second
// question, whether any failure is more recent than the wait owed, and denies
// if one is. Counting is strictly after each cutoff, so a newest failure
// exactly as old as the wait has served it. Under WithSliding it denies
// whenever the threshold is reached in the window.
//
// A locked identifier's reason is a *Error matching ErrAccountLocked,
// whose Wait is the wait owed, or zero at the ceiling and under a sliding lock.
//
// With a cap (WithCap), it first reads the identifier's consecutive
// failures, and a held identifier is denied there and then, whatever the
// window holds: its reason is a *Error matching both ErrAccountLocked
// and ErrAccountHeld, with no wait. Evaluating never writes, so a request
// refused here, whatever password it carries, leaves the hold as it was. An
// identifier that is not held is judged by the window exactly as without a
// cap.
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
// policy.ErrPolicyDenied and wraps the store's error, reachable through errors.Is and
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
			"policy: denied by policy: the attempt store could not say how often this identifier has failed",
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
// It is also the unlock an administrator or a support tool calls. With a cap
// (WithCap) it lifts a hold, which nothing else in the policy does: the
// store's Reset clears the hold and the consecutive count together with the
// failures in the window, so the identifier is neither held nor waiting
// afterwards. It is not an error for an identifier with nothing to clear.
//
// It clears through Attempts, so an administrator's reset that removed
// failures is reported to the observer given by WithObserver, just as
// a login's is, and one that lifted a hold is reported as ReportReleased.
func (p *Policy) Reset(ctx context.Context, username string) error {
	if err := p.attempts.Reset(ctx, username); err != nil {
		return diag.Wrap(err, "policy: clear failed attempts")
	}

	return nil
}

// PurgeExpired deletes the failures that have aged out of the window — the
// policy's own, 24 hours by default or the sliding lock's — and reports how many
// went.
//
// With a cap (WithCap) it then deletes the consecutive counts that have
// aged out of the retention (WithCapRetention) and adds them to the
// total. It never deletes a count the policy still counts, nor a hold. Without a cap it never touches the counts.
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
		return 0, purgeFailed(err, "policy: purge stale failed attempts")
	}

	if p.streaks == nil {
		return removed, nil
	}

	streaks, err := p.streaks.DeleteStreaksBefore(ctx, now.Add(-p.capRetention))
	if err != nil {
		return 0, purgeFailed(err, "policy: purge inactive consecutive failures")
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

// RequiredAttemptView reports the policy's view, Attempts, and true when a cap
// is configured (WithCap): only the view advances the consecutive
// count, so a failure recorded straight into the store would never bring an
// identifier closer to its hold. Without a cap it reports false, and any store
// the policy reads will do, as before.
func (p *Policy) RequiredAttemptView() (policy.AttemptStore, bool) {
	return p.attempts, p.capLimit > 0
}

var _ policy.Policy = (*Policy)(nil)
