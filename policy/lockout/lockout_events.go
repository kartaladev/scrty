package lockout

import (
	"context"
	"sync"
	"time"

	"github.com/kartaladev/scrty/internal/secevent"
	"github.com/kartaladev/scrty/security"
)

// WithSecurityEvents gives the policy a security-event sink of its own, for
// the locks it decides on a failure recorded outside an HTTP chain: a
// consumer's own login flow recording through Policy.RecordFailure or the
// policy's view, Attempts. The default is none, and such a lock is reported
// nowhere.
//
// The failure that takes an identifier to a lock reports
// security.AuthnLoginFailMax and then security.AuthnLoginLock, once per lock
// (see Attempts). On a request a chain built with
// httpsec.EnableSecurityEvents reports for, the lock is reported through the
// chain and this sink is not called, so one lock is reported once; a chain
// built without that option leaves the report to this sink.
//
// The sink is called synchronously, on the goroutine that recorded the
// failure, with a context from which the caller's cancellation has been
// removed. It cannot change the outcome: a panic in it is recovered and logged
// through WithLogger without the event's contents. A sink that blocks holds
// the login that recorded the failure, which is the consumer's to manage.
//
// A nil sink, or the option given twice, is a configuration error wrapping
// policy.ErrConfig from New.
func WithSecurityEvents(sink security.Sink) Option {
	return func(p *Policy) { p.events.Set(sink) }
}

// eventsWatched reports whether a lock decided on ctx would reach a sink: the
// chain's delivery ctx carries, or the policy's own sink.
func (p *Policy) eventsWatched(ctx context.Context) bool {
	return secevent.Enabled(ctx) || p.events.Sink() != nil
}

// reportLock reports the lock a failure recorded at at decided:
// authn_login_fail_max, then authn_login_lock. Neither names a user, since
// the policy counts identifiers and does not know whether one is an account,
// and both carry the first factor the request names, if it names one.
func (p *Policy) reportLock(ctx context.Context, at time.Time) {
	kind := secevent.FactorOf(ctx)

	for _, name := range []string{security.AuthnLoginFailMax, security.AuthnLoginLock} {
		p.events.Report(ctx, security.Event{
			Name:    name,
			At:      at,
			Outcome: security.OutcomeFailure,
			Factor:  kind,
		}, p.logger)
	}
}

// lockState is what the policy's own rule said of an identifier just before
// a failure was recorded for it: whether it was held by the failure-streak
// limit, how many failures its window held, whether it was locked, and the
// error that kept the store from saying. A held identifier is locked, and its
// window is not counted: Evaluate does not count it either.
type lockState struct {
	held   bool
	count  int
	locked bool
	err    error
}

// lockedAt reads whether username was locked at at, before a failure at at is
// recorded, by the rule Evaluate judges by: under a failure-streak limit, a
// held identifier is locked whatever its window holds; otherwise, under the
// sliding lock, the window's count against the threshold; under the
// escalating wait, the count against the window failure limit, and between
// the threshold and that limit whether any failure is more recent than the
// wait the count owes. The count alone cannot tell a wait still running from
// one that has run out, so the recency costs a second read, and only for a
// count between the two.
func (p *Policy) lockedAt(ctx context.Context, username string, at time.Time) lockState {
	if p.streaks != nil {
		streak, err := p.streaks.FailureStreak(ctx, username, at.Add(-p.capRetention))
		if err != nil {
			return lockState{err: err}
		}
		if streak.Held() {
			return lockState{held: true, locked: true}
		}
	}

	count, err := p.store.FailureCount(ctx, username, at.Add(-p.window))
	if err != nil {
		return lockState{err: err}
	}

	switch {
	case count < p.threshold:
		return lockState{count: count}
	case p.sliding || count >= p.ceiling:
		return lockState{count: count, locked: true}
	}

	recent, err := p.store.FailureCount(ctx, username, at.Add(-p.waitFor(count)))
	if err != nil {
		return lockState{err: err}
	}

	return lockState{count: count, locked: recent > 0}
}

// locks reports whether a failure that left after failures in the window
// locked its identifier, which before describes as it was just before: it
// took the identifier from allowed to locked, or, under the escalating wait,
// took the count to the window failure limit, where no wait lifts the lock.
//
// A failure recorded at or past the threshold leaves its identifier locked by
// either rule, since it is itself more recent than any wait it owes.
//
// A failure for an identifier that was held locks nothing new, whatever its
// window now holds: the hold stands, and Evaluate refuses before the window
// is looked at.
func (p *Policy) locks(before lockState, after int) bool {
	if before.held {
		return false
	}

	if !before.locked && after >= p.threshold {
		return true
	}

	return !p.sliding && before.count < p.ceiling && after >= p.ceiling
}

// identifierLocks serializes, within one process, the failures recorded for
// one identifier while a sink watches, so that each reads whether the
// identifier was locked before its own write, and counts the window after it,
// with no other failure of this process in between, and one of them sees the
// transition into a lock.
//
// An identifier is held only while a failure for it is being recorded, and
// released however that ends, a panic included, so what it holds is bounded
// by the logins in flight, not by the identifiers ever seen.
type identifierLocks struct {
	mu    sync.Mutex
	locks map[string]*identifierLock
}

// identifierLock is one identifier's lock and how many failures hold or wait
// for it.
type identifierLock struct {
	mu   sync.Mutex
	refs int
}

// lock takes username's lock and returns its release.
func (l *identifierLocks) lock(username string) func() {
	l.mu.Lock()
	if l.locks == nil {
		l.locks = make(map[string]*identifierLock)
	}

	held := l.locks[username]
	if held == nil {
		held = &identifierLock{}
		l.locks[username] = held
	}
	held.refs++
	l.mu.Unlock()

	held.mu.Lock()

	return func() {
		held.mu.Unlock()

		l.mu.Lock()
		defer l.mu.Unlock()

		held.refs--
		if held.refs == 0 {
			delete(l.locks, username)
		}
	}
}
