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

// crossed reports whether a failure that took the identifier's count in the
// window from before to after took it to a lock: past the threshold, or,
// under the escalating wait, past the window failure limit.
func (p *Policy) crossed(before, after int) bool {
	if before < p.threshold && after >= p.threshold {
		return true
	}

	return !p.sliding && before < p.ceiling && after >= p.ceiling
}

// identifierLocks serializes, within one process, the failures recorded for
// one identifier while a sink watches, so that each reads the window's count
// before and after its own write with no other failure of this process in
// between, and exactly one of them sees the count cross into a lock.
//
// An identifier is held only while a failure for it is being recorded, so
// what it holds is bounded by the logins in flight, not by the identifiers
// ever seen.
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
