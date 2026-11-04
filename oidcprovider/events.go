package oidcprovider

import (
	"context"
	"errors"
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
// that request's cancellation has been removed. It cannot change what was stored: a panic in it is
// recovered and logged through WithLogger without the event's contents. A sink that blocks holds that
// request, which is the consumer's to manage, and on a revocation it can spend the budget the request has
// for its writes, and so change the answer. RevokeConsent gives its grants' write and its consent's write
// a budget each, so a sink cannot spend the one from the other. The failed delivery of a logout token is the exception, because no request decided it, and neither a logout nor a worker may
// wait for a sink: it reaches the sink on a goroutine of its own, at most 64 at once, with at most 1024
// more waiting, and is stamped when it reaches it. Past those the newest loses its event and keeps its log
// line, and how many did so is logged. What Shutdown finds still queued has room of its own, as does a
// post it cuts off, which an end arriving after it cannot take. Shutdown waits for those goroutines, as it
// does for every delivery, and returns its context's error if the sink still holds one then. The limit has
// no option, as it protects the provider from the sink: a consumer who cannot afford it gives a sink that
// returns promptly, onto a queue of its own.
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
// A grant that survives is not a revocation, and is not reported. Nor is one that an earlier revocation
// had already ended: it keeps that first cause, and was reported when it happened. A revocation of
// the consumer's, whatever it spelled its cause as, is told from the end's own by its time: an end
// revokes at the time it marks the grant, which an earlier revocation cannot have done.
func (p *Provider) reportEnded(ctx context.Context, ended []Grant) {
	for i := range ended {
		g := &ended[i]
		survives := g.Offline && !g.EndsWithSignIn
		endedEarlier := g.Revoked && (g.RevokeCause != CauseSignInEnded || !g.RevokedAt.Equal(g.SignInEndedAt))
		if !survives && !endedEarlier {
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
// marks the row when the family cannot be deleted. It also holds the request's own context, which
// is what the report goes out on, as the observer is handed the one quietLineage made.
type reuseNote struct {
	client string
	user   identity.UserID
	origin context.Context
	done   atomic.Bool
}

type reuseNoteKey struct{}

// withReuseNote returns ctx carrying a note for the grant a refresh presents.
func withReuseNote(ctx context.Context, g *Grant) context.Context {
	return context.WithValue(ctx, reuseNoteKey{}, &reuseNote{client: g.ClientID, user: g.User, origin: ctx})
}

// quietLineage is the context a lineage manager's renewal runs on: ctx with no chain to report through.
// One reuse is the provider's to report, as a reused refresh token and the grant revoked for it. The
// manager would also find a chain's delivery and report it as authn_token_reuse, of a session no one
// signed in with, and it has no sink of its own for that to reach here. Everything else on ctx stays,
// a consumer's transaction among it.
func quietLineage(ctx context.Context) context.Context {
	return eventsink.With(ctx, nil)
}

// reportReuse reports a refresh token reused, once per request, and the grant revoked for it when newly
// says this request is what revoked it, after the revocation is stored. Without a note, which no path
// of a refresh lacks, only the user the manager's report names is known.
func (p *Provider) reportReuse(ctx context.Context, fallback identity.UserID, newly bool) {
	note, _ := ctx.Value(reuseNoteKey{}).(*reuseNote)
	if note == nil {
		note = &reuseNote{user: fallback, origin: ctx}
	}
	if !note.done.CompareAndSwap(false, true) {
		return
	}

	//nolint:contextcheck // the request's own context, which quietLineage derived what ctx may be from
	p.report(note.origin, event.Event{Name: event.RefreshReused, Outcome: event.OutcomeFailure, User: note.user, Client: note.client})
	if newly {
		//nolint:contextcheck // as above
		p.reportGrantRevoked(note.origin, note.client, note.user, CauseReuse)
	}
}

// reportCodeReplay reports a code replayed, which every valid presentation is, and the grant revoked
// for it when newly says this one is what revoked it.
func (p *Provider) reportCodeReplay(ctx context.Context, record *CodeRecord, newly bool) {
	p.report(ctx, event.Event{
		Name: event.CodeReplayed, Outcome: event.OutcomeFailure, User: record.SignIn.User, Client: record.ClientID,
	})
	if newly {
		p.reportGrantRevoked(ctx, record.ClientID, record.SignIn.User, CauseCodeReplay)
	}
}

// dropReasons are the failures that may leave before anything is read of the client, so the report cannot
// say whether the client had a URI to be told at.
var dropReasons = []string{failureQueueFull, failureShutdown, failureBusy}

// reportLogoutFailed reports a failed back-channel delivery, on a goroutine of the events lane, so that no
// sink or registry holds the logout or the worker that found the failure. With no sink it starts nothing.
//
// A delivery that failed on a worker says it reached its client's URI. A drop says nothing of the client: a
// client that registered no URI takes a queue place too, because what a client registered is read only when
// it is told. So a drop's report reads the client as it stands, and reports only one that has someone to tell.
func (p *Provider) reportLogoutFailed(ctx context.Context, f logoutFailure) {
	if !p.watched(ctx) {
		return
	}
	e := event.Event{
		Name: event.LogoutDeliveryFailed, Outcome: event.OutcomeFailure, User: f.User, Client: f.ClientID, Cause: f.Reason,
	}
	dropped := slices.Contains(dropReasons, f.Reason)
	p.logouts.toSink(f.refused, func() {
		if !dropped || p.hasSomeoneToTell(ctx, f.ClientID) {
			p.report(ctx, e)
		}
	})
}

// hasSomeoneToTell reads the client as it stands, within the delivery's own bound. A client that has
// gone, or registered no URI, has no one to tell. A registry that cannot answer leaves it unknown,
// and unknown is reported: an event about a client with no one to tell costs less than silence about
// a client that should have been told. A registry that panics has not answered either. One that ends the
// goroutine takes the event with it, as nothing can stop that, so the event is counted as lost.
func (p *Provider) hasSomeoneToTell(ctx context.Context, clientID string) (tell bool) {
	answered := false
	defer func() {
		switch {
		case answered:
		case recover() != nil:
			tell = true
		default:
			p.logouts.eventLost()
		}
	}()

	bounded, cancel := context.WithTimeout(ctx, p.cfg.logoutTimeout)
	defer cancel()

	rc, err := p.client(bounded, clientID)
	answered = true
	switch {
	case errors.Is(err, ErrClientNotFound):
		return false
	case err != nil:
		return true
	}

	return rc.BackChannelLogoutURI != ""
}
