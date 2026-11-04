package oidcprovider

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync/atomic"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/eventsink"
)

// WithSecurityEvents gives the provider a security-event sink of its own, for the outcomes it decides:
// a grant created; consent given, denied or revoked; a client authentication refused; a code replayed; a
// refresh token reused; a grant revoked, with its cause; and a back-channel logout that could not be
// delivered. Each names the client and the user when known, and none carries a code, handle, token,
// assertion or secret. Their names are in package event.
//
// The default is none: nothing is reported, and every outcome is the same without it, a replayed code
// still refused and still revoking its grant. On a request a chain built with httpsec.EnableSecurityEvents
// reports for, the event goes through the chain, which adds the client address, and this sink is not
// called, so an outcome is reported once.
//
// The sink is called synchronously, on the request that decided the outcome, with a context from which
// that request's cancellation has been removed, and cannot change the outcome: a panic in it is recovered
// and logged through WithLogger without the event's contents. A sink that blocks holds that request, which
// is the consumer's to manage. The failed delivery of a logout token is the exception, because no request
// decided it and a logout must not wait for a sink: a worker's report reaches the sink on that worker, and
// a drop, which would run on the logout's own goroutine, reaches it on a goroutine of its own, at most 64
// at once, so a sink that blocks never holds a logout. Shutdown waits for those goroutines, as
// it does for every delivery, and returns its context's error if the sink still holds one then.
//
// A nil sink, or the option given twice, is a configuration error wrapping ErrConfig from New.
func WithSecurityEvents(sink event.Sink) Option {
	return func(c *config) { c.events.Set(sink) }
}

// watched says whether an event reported on ctx would go anywhere, so that with no sink nothing is built,
// and no clock is read.
func (p *Provider) watched(ctx context.Context) bool {
	return p.cfg.events.Sink() != nil || eventsink.Enabled(ctx)
}

// report delivers e, an outcome the provider decided on ctx, stamped with the provider's clock.
func (p *Provider) report(ctx context.Context, e event.Event) {
	if !p.watched(ctx) {
		return
	}
	e.At = p.cfg.clock.Now()
	p.cfg.events.Report(ctx, e, p.cfg.logger)
}

// reportGrantCreated reports a grant stored for an exchanged code.
func (p *Provider) reportGrantCreated(ctx context.Context, g *Grant) {
	p.report(ctx, event.Event{Name: event.GrantCreated, Outcome: event.OutcomeSuccess, User: g.User, Client: g.ClientID})
}

// reportGrantRevoked reports one grant revoked, once the revocation is stored. cause is a word the
// provider or the consumer chose, never a value a request supplied.
func (p *Provider) reportGrantRevoked(ctx context.Context, clientID string, user identity.UserID, cause RevocationCause) {
	p.report(ctx, event.Event{
		Name: event.GrantRevoked, Outcome: event.OutcomeSuccess, User: user, Client: clientID, Cause: string(cause),
	})
}

// reportRevoked reports each grant a store says it newly revoked.
func (p *Provider) reportRevoked(ctx context.Context, ended []Grant, cause RevocationCause) {
	for i := range ended {
		p.reportGrantRevoked(ctx, ended[i].ClientID, ended[i].User, cause)
	}
}

// reportEnded reports the grants a sign-in's end revoked. The store marks each grant it returns as having
// outlived its sign-in, and revokes those that do not: without offline_access, or tied to the sign-in.
// A grant that survives is not a revocation, and is not reported.
func (p *Provider) reportEnded(ctx context.Context, ended []Grant) {
	for i := range ended {
		if g := &ended[i]; !g.Offline || g.EndsWithSignIn {
			p.reportGrantRevoked(ctx, g.ClientID, g.User, CauseSignInEnded)
		}
	}
}

// reportConsent reports consent answered or withdrawn. A denial is a refusal, so a failure outcome.
func (p *Provider) reportConsent(ctx context.Context, name string, user identity.UserID, clientID string) {
	outcome := event.OutcomeSuccess
	if name == event.ConsentDenied {
		outcome = event.OutcomeFailure
	}
	p.report(ctx, event.Event{Name: name, Outcome: outcome, User: user, Client: clientID})
}

// reportClientRefused reports a client authentication refused as invalid_client. clientID is the
// client the registry held for the identifier presented, and empty when it held none, so that a
// stranger's text is never carried into an event.
func (p *Provider) reportClientRefused(ctx context.Context, clientID string) {
	p.report(ctx, event.Event{Name: event.ClientAuthRefused, Outcome: event.OutcomeFailure, Client: clientID})
}

// reuseNote carries what a refresh request knows of its grant to wherever the lineage manager's
// verdict is acted on, and makes sure the reuse it finds is reported once whichever path finds it
// first: the row marked ahead of the manager, the manager's observer, or the failure path that
// marks the row when the family cannot be deleted.
type reuseNote struct {
	client string
	user   identity.UserID
	done   atomic.Bool
}

type reuseNoteKey struct{}

// withReuseNote returns ctx carrying a note for the grant a refresh presents.
func withReuseNote(ctx context.Context, g *Grant) context.Context {
	return context.WithValue(ctx, reuseNoteKey{}, &reuseNote{client: g.ClientID, user: g.User})
}

// reportReuse reports a refresh token reused and the grant revoked for it, once per request, after
// the revocation is stored. Without a note, which no path of a refresh lacks, only the user the
// manager's report names is known.
func (p *Provider) reportReuse(ctx context.Context, fallback identity.UserID) {
	note, _ := ctx.Value(reuseNoteKey{}).(*reuseNote)
	if note == nil {
		note = &reuseNote{user: fallback}
	}
	if !note.done.CompareAndSwap(false, true) {
		return
	}

	p.report(ctx, event.Event{Name: event.RefreshReused, Outcome: event.OutcomeFailure, User: note.user, Client: note.client})
	p.reportGrantRevoked(ctx, note.client, note.user, CauseReuse)
}

// reportCodeReplay reports a code replayed and the grant revoked for it.
func (p *Provider) reportCodeReplay(ctx context.Context, record *CodeRecord) {
	p.report(ctx, event.Event{
		Name: event.CodeReplayed, Outcome: event.OutcomeFailure, User: record.SignIn.User, Client: record.ClientID,
	})
	p.reportGrantRevoked(ctx, record.ClientID, record.SignIn.User, CauseCodeReplay)
}

// dropReasons are the failures that leave before anything is read of the client, so the report cannot
// say whether the client had a URI to be told at.
var dropReasons = []string{failureQueueFull, failureShutdown, failureBusy}

// reportLogoutFailed reports a failed back-channel delivery.
//
// A delivery that failed on a worker says it reached its client's URI, and is reported on that worker.
// A drop says nothing of the client: a client that registered no URI takes a queue place too, because
// what a client registered is read only when it is told. So a drop is reported on a goroutine of its
// own, which reads the client as it stands, and reports only one that has someone to tell. That goroutine
// is also why a sink cannot hold the logout whose drop it is, or Shutdown past its context: a drop's
// report would otherwise run on the goroutine of the logout that handed the client on. Those goroutines
// are counted apart from the deliveries, so a sink that blocks cannot starve them, and bounded by
// maxLogoutReports, so a flood of drops cannot grow them without end: past it the report is dropped and
// logged. Shutdown waits for them.
func (p *Provider) reportLogoutFailed(ctx context.Context, f logoutFailure) {
	if !p.watched(ctx) {
		return
	}
	e := event.Event{
		Name: event.LogoutDeliveryFailed, Outcome: event.OutcomeFailure, User: f.User, Client: f.ClientID, Cause: f.Reason,
	}
	if !slices.Contains(dropReasons, f.Reason) {
		p.report(ctx, e)

		return
	}

	pool := p.logouts
	if !pool.enterReport() {
		p.cfg.logger.LogAttrs(ctx, slog.LevelWarn,
			"oidcprovider: a failed logout delivery was not reported as an event, for want of a goroutine to report it on",
			slog.String("client_id", f.ClientID), slog.String("reason", f.Reason))

		return
	}
	detached := context.WithoutCancel(ctx)
	go func() {
		defer pool.leaveReport()

		if p.hasSomeoneToTell(detached, f.ClientID) {
			p.report(detached, e)
		}
	}()
}

// maxLogoutReports bounds the goroutines reporting dropped deliveries at one time.
const maxLogoutReports = 64

// enterReport takes a place for a goroutine reporting a dropped delivery, and says whether there was one.
func (q *logoutPool) enterReport() bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.reports >= maxLogoutReports {
		return false
	}
	q.reports++

	return true
}

// leaveReport gives the place back.
func (q *logoutPool) leaveReport() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.reports--
	q.settle()
}

// hasSomeoneToTell reads the client as it stands, within the delivery's own bound. A client that has
// gone, or registered no URI, has no one to tell. A registry that cannot answer leaves it unknown,
// and unknown is reported: an event for a client that could not be told is better lost to a registry's
// outage than silent about a client that should have been.
func (p *Provider) hasSomeoneToTell(ctx context.Context, clientID string) bool {
	bounded, cancel := context.WithTimeout(ctx, p.cfg.logoutTimeout)
	defer cancel()

	rc, err := p.client(bounded, clientID)
	switch {
	case errors.Is(err, ErrClientNotFound):
		return false
	case err != nil:
		return true
	}

	return rc.BackChannelLogoutURI != ""
}
