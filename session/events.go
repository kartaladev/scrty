package session

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/internal/eventsink"
)

// WithSecurityEvents gives the manager a security-event sink of its own, for
// the reuse it detects outside an HTTP chain: a consumer's own code loading
// or renewing a session through the manager. The default is none, and such a
// reuse is reported nowhere but the reuse observer (WithReuseObserver) and
// the warning the manager always logs.
//
// A detected reuse (ErrReused) is reported as event.AuthnTokenReuse, once
// its family has been revoked, naming the session's user and first factor
// and the presented session by its digest, never its identifier. On a request
// a chain built with httpsec.EnableSecurityEvents reports for, the reuse is
// reported through the chain and this sink is not called, so one reuse is
// reported once; a chain built without that option leaves the report to this
// sink. A configured reuse observer is called either way.
//
// The sink is called synchronously, on the request that presented the reused
// session, with a context from which that request's cancellation has been
// removed. It cannot change the outcome: a panic in it is recovered and
// logged through WithLogger without the event's contents. A sink that blocks
// holds that request, which is the consumer's to manage.
//
// A nil sink, or the option given twice, is a configuration error wrapping
// ErrConfig from New.
//
// The library gives the sink's context no deadline; bound your own work.
func WithSecurityEvents(sink event.Sink) Option {
	return func(m *Sessions) { m.events.Set(sink) }
}

// reportReuse reports the reuse of s, detected at now, after its family was
// revoked.
func (m *Sessions) reportReuse(ctx context.Context, s *Session, now time.Time) {
	m.events.Report(ctx, event.Event{
		Name:    event.AuthnTokenReuse,
		At:      now,
		Outcome: event.OutcomeFailure,
		User:    s.UserID,
		Factor:  s.FirstFactor,
		Session: eventsink.SessionDigest(s.ID),
	}, m.logger)
}
