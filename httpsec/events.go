package httpsec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/secevent"
	"github.com/kartaladev/scrty/security"
	"github.com/kartaladev/scrty/session"
)

// EnableSecurityEvents reports every security outcome the chain decides to
// sink, as a security.Event named from the OWASP Logging Vocabulary or under
// the scrty_ prefix (security.Names lists them).
//
// Default: no sink, and nothing is reported. Once enabled, the chain hands its
// sink to every component it builds that decides an outcome, and reaches a
// component the consumer built and registered on it, the account-lockout
// policy, through the request's context, so one sink receives every event.
// A component that decides outside any request is given its own sink:
// signingkey.WithSecurityEvents.
//
// The sink is called synchronously, on the request that decided the outcome,
// with a context from which the request's cancellation has been removed. It
// cannot change the outcome, the status or the error the chain returns: a
// panic in it is recovered and logged through the chain's logger
// (WithLogger) without the event's contents. A sink that blocks holds that
// request, which is the consumer's to manage (see security.Sink).
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
func EnableSecurityEvents(sink security.Sink) Option {
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
	sink security.Sink
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
func (em *eventEmitter) emit(ctx context.Context, e security.Event) {
	if e.At.IsZero() {
		e.At = em.now()
	}

	if e.ClientIP == "" {
		if client, ok := ClientFromContext(ctx); ok {
			e.ClientIP = client.IP
		}
	}

	secevent.Deliver(ctx, em.sink, e, em.log)
}

// emitEvent reports e on the request ctx belongs to, and does nothing on a
// request no sink watches.
func emitEvent(ctx context.Context, e security.Event) {
	secevent.Send(ctx, e)
}

// sessionEvent is an event named name, with outcome, about the session s: its
// user, its first factor and its identifier's digest.
func sessionEvent(name, outcome string, s *session.Session) security.Event {
	e := security.Event{Name: name, Outcome: outcome}

	if s != nil {
		e.User = s.UserID
		e.Factor = s.FirstFactor
		e.Session = sessionDigest(s.ID)
	}

	return e
}

// callerEvent is sessionEvent for ex's session, naming the caller ex
// authenticated when it carries no session, as Basic and API keys do not.
func callerEvent(name, outcome string, ex *Exchange) security.Event {
	e := sessionEvent(name, outcome, ex.Session)

	if e.User == "" && ex.Authentication != nil && ex.Authentication.Principal != nil {
		e.User = ex.Authentication.Principal.ID
	}

	return e
}

// userEvent is an event named name, with outcome, about user and the first
// factor kind.
func userEvent(name, outcome string, user identity.UserID, kind factor.Kind) security.Event {
	return security.Event{Name: name, Outcome: outcome, User: user, Factor: kind}
}

// sessionDigest is the lower-case hexadecimal SHA-256 digest of a session
// identifier, and empty for an empty one. A session identifier is a
// high-entropy random credential, so its digest names the session without
// revealing it.
func sessionDigest(id string) string {
	if id == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(id))

	return hex.EncodeToString(sum[:])
}

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
	{ErrInvalidDPoPProof, security.DPoPRefused},
	{ErrCertificateBinding, security.CertificateBindingRefused},
	{ErrCrossSiteRequest, security.CSRFRefused},
	{ErrChallengeRequired, security.ChallengeRefused},
}

// emitRefusal reports the refusal err the chain answers ex with, when err is
// one refusalEvents names and the request's own context had not ended.
func emitRefusal(ex *Exchange, err error) {
	ctx := ex.Context()
	if !secevent.Enabled(ctx) || hangup.ByCaller(ctx, err) {
		return
	}

	for _, r := range refusalEvents {
		if !errors.Is(err, r.err) {
			continue
		}

		if r.name != "" {
			emitEvent(ctx, callerEvent(r.name, security.OutcomeFailure, ex))
		}

		return
	}
}

// refused reports whether err is a refusal the chain decided rather than a
// dependency failure or a request whose own context ended: an error the
// default status mapping answers below 500 that is neither the user store's
// outage (authenticate.ErrUnavailable) nor ctx's own ending.
func refused(ctx context.Context, err error) bool {
	if err == nil || hangup.ByCaller(ctx, err) {
		return false
	}

	if errors.Is(err, authenticate.ErrUnavailable) {
		return false
	}

	return StatusForError(err) < 500
}
