package lockout

import (
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/policy"
)

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
