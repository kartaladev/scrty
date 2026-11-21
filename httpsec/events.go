package httpsec

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/internal/eventsink"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/session"
)

// EnableSecurityEvents reports every security outcome the chain decides to
// sink, as an event.Event named from the OWASP Logging Vocabulary or under
// the scrty_ prefix (event.Names lists them).
//
// Default: no sink, and nothing is reported. Once enabled, the chain hands its
// sink to every component it builds that decides an outcome, and reaches a
// component the consumer built and registered on it, the account-lockout
// policy, the session manager, an API-key manager, a verification throttle, a
// recoverer, through the request's context, so one sink receives every event.
// A component the consumer also calls outside any chain takes a sink of its
// own (apikey.WithSecurityEvents, lockout.WithSecurityEvents,
// mfa.WithThrottleSecurityEvents, mfa.WithResetSecurityEvents,
// recovery.WithSecurityEvents, session.WithSecurityEvents), each defaulting
// to none, which is not called on a request this chain reports for, so one
// outcome is reported once; signing-key rotation, which runs on no request,
// reports only to signingkey.WithSecurityEvents.
//
// The lockout observer's and the session-reuse observer's reports also reach
// the sink, as authn_login_lock and authn_token_reuse, and the observers are
// still called. A lock is reported by the account-lockout policy's view
// (lockout.Policy.Attempts) where it decides the lock, so form login and
// Basic report one only when they record into that view.
//
// The sink is called synchronously, on the request that decided the outcome,
// with a context from which the request's cancellation has been removed. It
// cannot change the outcome, the status or the error the chain returns: a
// panic in it is recovered and logged through the chain's logger
// (WithLogger) without the event's contents. A sink that blocks holds that
// request, which is the consumer's to manage (see event.Sink), and a sink
// should do no work that depends on whether an event names an account: a
// recovery start is reported alike for a username that names an account and
// one that names none, so that its latency does not tell them apart.
//
// Each event carries the time from the chain's clock (WithClock), the client
// address the chain resolved (through EnableTrustedProxies when trusted
// proxies are configured), the user when one is known, the first factor where
// one applies, and the SHA-256 digest of the session's identifier, never the
// identifier. No event carries a password, token, code, link secret, key,
// DPoP proof, certificate, CSRF token or stored hash.
//
// Only what happened is reported. A session's creation and its credential are
// reported once the session is stored and the credential handed out, so a
// credential issued and then discarded, by a racing redemption that won or a
// creating write that failed, reports nothing. A request whose own context
// ended before a verdict, and a dependency that failed, report no failure or
// refusal.
//
// A nil sink, or the option given twice, is a configuration error.
//
// The library gives the sink's context no deadline; bound your own work.
func EnableSecurityEvents(sink event.Sink) Option {
	const option = "EnableSecurityEvents"

	return func(c *config) error {
		if sink == nil {
			return newConfigError("%s was given no sink: give it the function that receives the events, "+
				"or leave the option out to report none", option)
		}

		if c.events != nil {
			return newConfigError("%s was given twice; one chain reports to one sink", option)
		}

		c.events = sink

		return nil
	}
}

// eventEmitter is the chain's delivery of its events to the consumer's sink.
type eventEmitter struct {
	sink event.Sink
	now  func() time.Time
	log  *slog.Logger
}

// newEventEmitter is the emitter for c's sink, and nil when c has none.
func newEventEmitter(c *config) *eventEmitter {
	if c.events == nil {
		return nil
	}

	return &eventEmitter{sink: c.events, now: c.now, log: c.logger}
}

// emit fills in what the request knows and the deciding component did not
// say, the time and the resolved client address, and delivers e.
func (em *eventEmitter) emit(ctx context.Context, e event.Event) {
	if e.At.IsZero() {
		e.At = em.now()
	}

	if e.ClientIP == "" {
		if client, ok := ClientFromContext(ctx); ok {
			e.ClientIP = client.IP
		}
	}

	eventsink.Deliver(ctx, em.sink, e, em.log)
}

// emitEvent reports e on the request ctx belongs to, and does nothing on a
// request no sink watches.
func emitEvent(ctx context.Context, e event.Event) {
	eventsink.Send(ctx, e)
}

// sessionEvent is an event named name, with outcome, about the session s: its
// user, its first factor and its identifier's digest.
func sessionEvent(name, outcome string, s *session.Session) event.Event {
	e := event.Event{Name: name, Outcome: outcome}

	if s != nil {
		e.User = s.UserID
		e.Factor = s.FirstFactor
		e.Session = sessionDigest(s.ID)
	}

	return e
}

// callerEvent is sessionEvent for ex's session, naming the caller ex
// authenticated when it carries no session, as Basic and API keys do not.
func callerEvent(name, outcome string, ex *Exchange) event.Event {
	e := sessionEvent(name, outcome, ex.Session)

	if e.User == "" && ex.Authentication != nil && ex.Authentication.Principal != nil {
		e.User = ex.Authentication.Principal.ID
	}

	return e
}

// userEvent is an event named name, with outcome, about user and the first
// factor kind.
func userEvent(name, outcome string, user identity.UserID, kind factor.Kind) event.Event {
	return event.Event{Name: name, Outcome: outcome, User: user, Factor: kind}
}

// sessionDigest is the digest an event names a session by
// (eventsink.SessionDigest).
func sessionDigest(id string) string { return eventsink.SessionDigest(id) }

// refusalEvents maps the refusals the chain reports wherever they arise to
// their event, in the order they are matched. Each sentinel is only ever a
// refusal, never a dependency failure, so matching it is the decision.
var refusalEvents = []struct {
	err  error
	name string
}{
	// A request asked to retry with the server's nonce is the protocol's
	// normal first step, not a refused proof, and also matches
	// ErrInvalidDPoPProof, so it is matched first and reports nothing.
	{ErrDPoPNonceRequired, ""},
	{ErrInvalidDPoPProof, event.DPoPRefused},
	{ErrCertificateBinding, event.CertificateBindingRefused},
	{ErrCrossSiteRequest, event.MaliciousCSRF},
	{ErrChallengeRequired, event.ChallengeRefused},
}

// emitRefusal reports the refusal err the chain answers ex with, when err is
// one refusalEvents names, the request's own context had not ended, and err is
// answered below 500.
//
// The event follows StatusForError: an error the library marks as a
// dependency failure (ErrChallengeUnavailable, an issuing failure, an
// unrecognised error) is answered at 500 even when a refusal sentinel stays
// reachable beneath it, and the chain refused nothing, so a refusal answered
// at 500 reports no refusal event. A plain error of a consumer's port that
// wraps a sentinel, such as ErrCrossSiteRequest, maps through the status table
// (403) and is reported, consistently with that answer.
//
// It reports once per exchange: a chain whose Assemble runs inside another
// chain's answers the same exchange with the same error as it leaves each of
// them, and the refusal was decided once.
//
// err is the consumer's as often as the library's, so every check of it, the
// hang-up check included, reads it under the bounded walk. A check whose walk
// gives up reports no event, since its match is not guessed from a partial
// walk, and the abort is reported once for the exchange (abortReported), by
// the quiet sites' rule: the hang-up check runs before the lookup, so it
// reports through reportQuietly; the event's own check runs after a lookup
// that answered below 500, so the dispatch will not meet its abort, and it
// reports whoever answers. Either way the refusal is marked reported, so a
// chain this run is nested in does not walk it again.
func emitRefusal(ex *Exchange, err error) {
	ctx := ex.Context()
	if ex.refusalReported || !eventsink.Enabled(ctx) {
		return
	}

	hungUp, abort := hangup.ByCallerWalk(ctx, err)
	if abort != nil {
		ex.reportQuietlyOnce(ctx, err, abort)
		ex.refusalReported = true

		return
	}

	if hungUp || ex.answeringChain().statusQuietly(ctx, err) >= http.StatusInternalServerError {
		return
	}

	walk := walkRefusal(err)

	for _, r := range refusalEvents {
		if !walk.is(r.err) {
			if walk.abort != nil {
				if !ex.abortReported {
					ex.abortReported = true
					ex.answeringChain().reportAbort(ctx, walk.abort)
				}

				ex.refusalReported = true

				return
			}

			continue
		}

		if r.name != "" {
			emitEvent(ctx, callerEvent(r.name, event.OutcomeFailure, ex))
			ex.refusalReported = true
		}

		return
	}
}

// refused reports whether err is a refusal the chain decided rather than a
// dependency failure or a request whose own context ended: an error the
// default status mapping answers below 500 that is neither the user store's
// outage (authenticate.ErrUnavailable) nor ctx's own ending.
//
// err is walked under the library's bounded, recovering walk, the hang-up
// check included. An err the walk gives up on is not a refusal, so no event
// reports it. The checks here run before or beside the dispatch's lookup, and
// a link whose Is method panics only for a sentinel asked here (the outage,
// the context's error) is one that lookup never meets, so an abort is
// reported through c, the exchange's answering chain, by the quiet sites'
// rule (reportQuietly). The status lookup reports its own abort as
// statusQuietly does: only under a consumer's error handler, where the
// dispatch classifies nothing. A nil c reports to the logger the context carries, else to
// slog.Default() when the record is written.
func refused(ctx context.Context, c *Chain, err error) bool {
	if err == nil {
		return false
	}

	hungUp, abort := hangup.ByCallerWalk(ctx, err)
	if abort != nil {
		c.reportQuietly(ctx, err, abort)

		return false
	}

	if hungUp {
		return false
	}

	walk := walkRefusal(err)
	outage := walk.is(authenticate.ErrUnavailable)

	if walk.abort != nil {
		c.reportQuietly(ctx, err, walk.abort)

		return false
	}

	if outage {
		return false
	}

	return c.statusQuietly(ctx, err) < http.StatusInternalServerError
}

// refusalWalk is a refused error flattened once, for an inspection of it on the
// refusal path other than the status lookup: refused, the refusal event, the
// authorization stage, the signal stream's checks and DPoP's challenge. Each
// reads this one list under the walk's bound and recovery, so a cyclic or
// panicking error cannot hang or crash the request before the lookup's bound
// applies. Once abort is set, by the flattening or by a link's Is or As method
// panicking, the walk matches nothing more, and the site takes its fail-closed
// path: no outage claim, no throttle mark, no event and no challenge.
type refusalWalk struct {
	chain errwalk.Chain
	abort error
}

// walkRefusal flattens err.
func walkRefusal(err error) refusalWalk {
	chain, abort := errwalk.Flatten(err)

	return refusalWalk{chain: chain, abort: abort}
}

// is reports whether a link of the walk matches any of targets, asking them in
// order, as errors.Is(err, t0) || errors.Is(err, t1) would. It reports false
// once the walk has aborted.
func (w *refusalWalk) is(targets ...error) bool {
	if w.abort != nil {
		return false
	}

	for _, target := range targets {
		found, abort := errwalk.Is(w.chain, target)
		if abort != nil {
			w.chain, w.abort = nil, abort

			return false
		}

		if found {
			return true
		}
	}

	return false
}

// refusalAs is errors.As over w: the first link that is a T. It reports false
// once the walk has aborted.
func refusalAs[T error](w *refusalWalk) (T, bool) {
	var zero T

	if w.abort != nil {
		return zero, false
	}

	found, ok, abort := errwalk.As[T](w.chain)
	if abort != nil {
		w.chain, w.abort = nil, abort

		return zero, false
	}

	return found, ok
}

// reportQuietly reports abort, the abort that stopped a refusal-path
// inspection of err running before or beside the status lookup, so that each
// request whose classification aborted writes one record:
//
//   - Under a consumer's error handler (WithErrorHandler) the chain's dispatch
//     classifies nothing, so the site always reports, as statusQuietly does.
//   - Otherwise the dispatch looks err up and reports an abort it meets. The
//     site reports only when that lookup does not abort: a link whose Is or As
//     method panics only for the sentinel this site asked about is one the
//     dispatch never meets. When both abort, the site stays quiet.
//
// The lookup runs here, on the abort path alone, so a request whose
// inspections do not abort pays nothing for the rule. A record goes through
// c's logger and sampler, or, when no chain is running, to the logger the
// context carries, else to slog.Default() when the record is written.
func (c *Chain) reportQuietly(ctx context.Context, err, abort error) {
	if c != nil && c.errorHandler != nil {
		c.logClassificationAborted(ctx, abort)

		return
	}

	if lookupAbort(err) == nil {
		c.reportAbort(ctx, abort)
	}
}

// reportAbort reports abort, met by an inspection that runs after the lookup
// answered: the dispatch will not meet it, so it is reported whatever handler
// answers, through c's logger and sampler, or, when no chain is running,
// through porterr.ReportAbort's routing: the logger ctx carries, else
// slog.Default() at record time.
func (c *Chain) reportAbort(ctx context.Context, abort error) {
	if c == nil {
		porterr.ReportAbort(ctx, nil, abort)

		return
	}

	c.logClassificationAborted(ctx, abort)
}

// reportAbortSampled writes abort's record through porterr.ReportAbort, at
// most once per reason per window of s (classificationAbortedKey), with the
// count of the records it stands in for as "suppressed" when there are any. A
// nil s, or one built with an interval of zero or less, writes every record. A
// nil log resolves as porterr.ReportAbort resolves it.
func reportAbortSampled(ctx context.Context, s *logsample.Sampler, log *slog.Logger, now time.Time, abort error) {
	write, suppressed := s.Allow(classificationAbortedKey(abort), now)
	if !write {
		return
	}

	if suppressed > 0 {
		// Attached only when it says something, as logSampled does.
		porterr.ReportAbort(ctx, log, abort, slog.Int("suppressed", suppressed))

		return
	}

	porterr.ReportAbort(ctx, log, abort)
}

// reportQuietlyOnce reports abort by the quiet sites' rule (reportQuietly)
// through ex's answering chain, unless a refusal-path check on ex has already
// reported one (abortReported). It is for a check that every chain on the
// exchange runs on the same refused error, the DPoP challenge and the refusal
// event's, so that with one chain assembled inside another and sampling off,
// the outer run meeting the abort the inner run reported writes no second
// record. The mark is set even when the rule leaves the report to the
// dispatch: the outer run would leave it there too.
func (ex *Exchange) reportQuietlyOnce(ctx context.Context, err, abort error) {
	if ex.abortReported {
		return
	}

	ex.abortReported = true
	ex.answeringChain().reportQuietly(ctx, err, abort)
}

// lookupAbort is the status lookup a guard behind a chain asks about its
// refusal (guardauth.LookupAborts): the abort that stopped lookup of err, nil
// when none did. It writes no record. A guard reports an abort its own walk
// met only when this lookup, which the guard's answer runs, does not abort.
func lookupAbort(err error) error {
	_, _, abort := lookup(err)

	return abort
}
