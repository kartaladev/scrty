package httpsec

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

//go:generate mockgen -destination=authorizer_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/authorize Authorizer

// authorization is the chain's authorization stage.
//
// It is registered for every chain, with or without rules, because its first
// job is to publish the authorizer that the per-endpoint guards behind it read.
// Its second job — enforcing the centralized rule set — is the one the consumer
// switches on by giving rules.
type authorization struct {
	// authorizer is what the guards downstream judge by, and nil when the
	// consumer enabled no authorization at all. Nothing is published then, so a
	// guard finds no judge and fails closed rather than judging by nothing.
	authorizer authorize.Authorizer

	// rules is the centralized set, and nil when the consumer gave none. An
	// empty set is not the same as a permitting one: it says authorization
	// belongs at the operations, and the guards there still decide.
	rules *authorize.Rules[Request]

	// gated is the built-in challenges whose gate the chain registers, in the
	// order the gates run, handed over at assembly (wire). It is empty before
	// then, and on a chain with no gate.
	gated []policy.ChallengeKind

	// methods looks up the second-factor methods a refusal of a session owing
	// one offers: the chain's challengeMethods, handed over at assembly
	// (wire). It is nil only before then, and a refusal offers no methods.
	methods challengeMethodsFunc

	// chain is the chain the stage belongs to, handed over at assembly (wire),
	// for the logger and sampler of its refusal record. It is read when a
	// refusal happens, so what the options settled on is what it finds. Nil
	// before assembly, and nothing is logged then.
	chain *Chain
}

// msgOwingAtAuthorization is the record a refused owing session leaves.
const msgOwingAtAuthorization = "httpsec: session owing a built-in challenge reached the authorization stage"

// owingAtAuthorizationHint is the record's explanation: the gates were
// bypassed, and where an authenticator belongs.
const owingAtAuthorizationHint = "the gates were bypassed; register the authenticator at OrderBearerToken"

// owingAtAuthorizationKey is the sampling key of that record.
const owingAtAuthorizationKey = "owing-session-at-authorization"

// logOwing writes the record of a refused owing session, sampled per chain. It
// names neither the session, its family nor its user: it is a wiring mistake,
// and what an operator needs is that it happened. A stage with no chain, or a
// chain with no logger, writes nothing.
func (a *authorization) logOwing(ex *Exchange) {
	c := a.chain
	if c == nil || c.logger == nil || c.perRequest == nil {
		return
	}

	logSampled(ex.Context(), c.sampler, c.logger, slog.LevelError, c.perRequest.now(),
		owingAtAuthorizationKey, msgOwingAtAuthorization, slog.String("hint", owingAtAuthorizationHint))
}

// gateOrder is the built-in challenges in the order their gates run:
// recovery, enrolment and second factor, then password change.
var gateOrder = [...]policy.ChallengeKind{
	policy.ChallengeAccountRecovery,
	policy.ChallengeMFAEnrolment,
	policy.ChallengeMFA,
	policy.ChallengePasswordChange,
}

// wire hands the stage the chain's method lookup and the challenges whose
// gate the chain registers, once every option has been applied.
func (a *authorization) wire(c *Chain) {
	a.methods = c.challengeMethods
	a.chain = c

	registered := make(map[policy.ChallengeKind]bool, len(gateOrder))

	for _, r := range c.registrations {
		if kind, ok := gateKind(r.interceptor); ok {
			registered[kind] = true
		}
	}

	a.gated = a.gated[:0]

	for _, kind := range gateOrder {
		if registered[kind] {
			a.gated = append(a.gated, kind)
		}
	}
}

// gateKind is the built-in challenge i is the gate for, and false when i is
// not a built-in gate.
func gateKind(i Interceptor) (policy.ChallengeKind, bool) {
	switch i.(type) {
	case *recoveryGate:
		return policy.ChallengeAccountRecovery, true
	case *enrolmentInterceptor:
		return policy.ChallengeMFAEnrolment, true
	case *mfaInterceptor:
		return policy.ChallengeMFA, true
	case *passwordChangeGate:
		return policy.ChallengePasswordChange, true
	default:
		return policy.ChallengeNone, false
	}
}

// Intercept refuses a session that still owes a built-in challenge, then
// publishes the authorizer and applies the centralized rules.
//
// The stage always runs, even with no rules: a per-endpoint guard reads the
// authorizer from the request context, and a guard that finds none fails
// closed. Publishing it here means a consumer wires the authorizer once, and
// every guard behind the chain judges by the same one.
//
// A session owing a recovery, an enrolment, a second factor or a password
// change, on a chain that registers the gate for it, never reaches the rules or
// the handler (owedRefusal). The gate refuses it first; this holds the line for
// a session a consumer put on the exchange past the gates by assigning the
// field directly. The refusal also leaves one sampled error record per chain,
// without identifiers, because it means a gate was bypassed.
//
// The stage sees the session on the exchange when it runs. A session assigned
// after it, by an interceptor registered After(OrderAuthorizer) or a slot-mate
// at the stage's slot registered after it, is out of its reach. Such an
// assignment changes only ex.Session, not the request context handlers read.
func (a *authorization) Intercept(ex *Exchange, next Next) error {
	if err := a.owedRefusal(ex); err != nil {
		return err
	}

	if a.authorizer != nil {
		ex.SetContext(authorize.WithAuthorizer(ex.Context(), a.authorizer))
	}

	if a.rules == nil {
		return next(ex)
	}

	if err := a.rules.Evaluate(ex.Context(), ex.Request); err != nil {
		if errors.Is(err, authorize.ErrAuthenticationRequired) {
			return authenticationRequired(err)
		}

		// Returned as it came. A rule's requirement answers with a denial, with
		// a demand to authenticate, or with the outage it hit, and rewriting any
		// of those here would turn a store that was unreachable into a decision
		// about the caller. Only the denial is reported.
		if errors.Is(err, authorize.ErrAccessDenied) && refused(ex.Context(), err) {
			emitEvent(ex.Context(), callerEvent(event.AuthzFail, event.OutcomeFailure, ex))
		}

		return err
	}

	return next(ex)
}

// owedRefusal refuses ex when its session still owes a built-in challenge
// whose gate the chain registers, with the error that gate returns, and
// reports nil when it owes none, or there is no session: an anonymous request
// is the rules' business, as before.
//
// Of several challenges owed, the one refused is the one the gates would have
// met first: recovery, enrolment and second factor before a password change.
// The refusal carries the session and no token, as a gate's does, and a
// second-factor refusal carries the methods the gate offers. A method lookup
// that fails is returned in place of the challenge, behind the gate's fixed
// text, rather than a challenge offering a partial list.
//
// A challenge whose gate the chain does not register is not refused here, as
// no gate would have refused it: the stage backs the gates up and does not
// stand in for a gate the chain left out.
func (a *authorization) owedRefusal(ex *Exchange) error {
	s := ex.Session
	if s == nil {
		return nil
	}

	for _, kind := range a.gated {
		if !owes(s, kind) {
			continue
		}

		var methods []MFAMethod

		if a.methods != nil {
			found, err := a.methods(ex.Context(), kind, s.UserID, s.FirstFactor)
			if err != nil {
				a.logOwing(ex)

				return err
			}

			methods = found
		}

		a.logOwing(ex)

		return &ChallengeError{Kind: kind, Session: s, Methods: methods}
	}

	return nil
}

// owes reports whether s owes kind, a built-in challenge, by the same reading
// of the session the gate for kind makes. A recovery-pending session owes the
// recovery alone of the three second-factor states; a password change is owed
// beside any of them.
func owes(s *session.Session, kind policy.ChallengeKind) bool {
	switch kind {
	case policy.ChallengeAccountRecovery:
		return s.MFA == session.MFARecoveryPending
	case policy.ChallengeMFAEnrolment:
		return s.MFA == session.MFAEnrolmentPending
	case policy.ChallengeMFA:
		return s.MFA == session.MFAPending
	case policy.ChallengePasswordChange:
		return s.PasswordChangePending
	default:
		return false
	}
}

// authenticationRequired refuses a request that has not said who it is.
//
// The refusal matches both this package's sentinel and the authorization
// core's, so a consumer who matches either identity reaches it and does not
// have to know whether the chain's stage or a per-endpoint guard refused. cause
// is the core's own error where one was produced, so the message it carries
// survives; with none, the core sentinel stands in for it.
func authenticationRequired(cause error) error {
	if cause == nil {
		cause = authorize.ErrAuthenticationRequired
	}

	return fmt.Errorf("%w: %w", ErrAuthenticationRequired, cause)
}

// EnableAuthorization judges requests through az, applying rules centrally.
//
// Default: without this option the chain still runs its authorization stage,
// but publishes no authorizer and enforces nothing, so every per-endpoint
// guard behind it fails closed. With it and no rules, the authorizer reaches
// the route and the guards there decide alone.
//
// The rules are an ordered set: the first whose matcher accepts the request
// decides, and a request no rule matches is denied, so an endpoint added
// without a rule is closed rather than open. A consumer opts out of that
// default with a trailing rule that matches everything and requires
// authorize.PermitAll — one line, visible where the rules are read.
//
// Calling it more than once appends: the rules of every call form one set in
// the order the calls were made, so wiring split across modules still reads top
// to bottom. The authorizer of the last call is the one the chain judges by,
// because a chain has one authorizer and a second call is the consumer
// replacing their first choice rather than adding a second judge. Every call's
// authorizer is checked when that call is applied, so a nil one is refused even
// when a later call supplies a valid one.
//
// A matcher sees the whole Request — path, method, headers — through the same
// abstraction every interceptor reads, so one rule set is written once and
// applies behind whichever framework the chain is mounted on.
//
// A matcher judges the path as sent, which is not always the path a router
// serves. On fiber, letter case and a trailing slash reach one route by
// default, so a rule must cover those spellings, and a predicate written for
// GET must also cover HEAD, which a router may answer from a GET route. A path
// with a "." or ".." segment never reaches a rule: the chain refuses it first.
func EnableAuthorization(az authorize.Authorizer, rules ...authorize.Rule[Request]) Option {
	const option = "EnableAuthorization"

	return func(c *config) error {
		if err := requireDep(option, "authorizer", az); err != nil {
			return err
		}

		c.authorizer = az
		c.authzRules = append(c.authzRules, rules...)

		c.enable(option, func() error {
			return requireDep(option, "authorizer", az)
		})

		return nil
	}
}
