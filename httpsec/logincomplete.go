package httpsec

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

//go:generate mockgen -destination=policy_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/policy Policy
//go:generate mockgen -destination=sessionstore_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/session Store
//go:generate mockgen -destination=tokengenerator_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/token Generator

// msgTokenNotIssued is the text an access token the consumer's generator could
// not issue is refused with, at login and at the second factor alike.
//
//nolint:gosec // G101: an error message naming what failed, not a credential
const msgTokenNotIssued = "httpsec: the access token could not be issued"

// policyDenyReason is the error a deny is refused with.
//
// policy.Engine already guarantees a deny carries a reason, substituting
// policy.ErrPolicyDenied where the policy left it nil, so this is a named
// reader rather than a fallback: every deny site refuses with the reason the
// engine reduced to, and none of them returns nil for a refusal.
func policyDenyReason(d policy.Decision) error { return d.Reason }

// loginTailDeps is what the login tail needs to end a login.
type loginTailDeps struct {
	engine   *policy.Engine
	sessions *session.Manager
	tokens   token.Generator

	// enrolmentLifetime is how long a session marked for an enrolment
	// challenge may live. The chain hands it to each first factor at assembly.
	enrolmentLifetime time.Duration

	// enforced holds the challenge kinds something on the chain enforces.
	enforced map[policy.ChallengeKind]bool

	// challengeMethods looks up the methods a raised challenge offers: the
	// chain's challengeMethods, handed to each first factor at assembly, so a
	// second-factor challenge carries the usable methods. Nil offers none,
	// which only a test seam leaves it.
	challengeMethods challengeMethodsFunc

	// decided is the post-authentication decision already made for this
	// login, nil when none was. A redemption decides in its check, before the
	// one-time credential is spent, and hands that decision on here: the tail
	// evaluating the policies again would run them after the spend, where a
	// lookup failure would refuse the login and cost the holder the
	// credential. Form login spends nothing, so it leaves this nil and the
	// tail evaluates.
	decided *policy.Decision

	// cancelHeld cancels the user's held account recoveries, and is nil when
	// the chain holds none: account recovery is off, or configured with no
	// hold. The chain hands it to each first factor at assembly. The tail
	// calls it before anything else, ahead of the policy phase.
	cancelHeld heldRecoveryCanceller
}

// heldRecoveryCanceller cancels every pending recovery of a user: the
// recovery core's CancelPending, which reports a store failure behind fixed
// text.
type heldRecoveryCanceller func(ctx context.Context, user identity.UserID) error

// postAuthenticationInput builds the policy input for a login that has just
// succeeded.
//
// Every field is a parameter rather than a struct literal each caller fills in,
// so an interceptor cannot quietly omit one: a missing passwordChangedAt
// disables a password-age gate on that interceptor's path alone, which is
// exactly the kind of hole nobody notices. first is a factor.Kind rather than a
// string so it cannot be transposed with username, and the two times are
// adjacent so every call site's argument order is pinned by a test that fires
// the challenge.
//
// username is the identifier the caller submitted, which is not always the one
// the principal resolved to: a policy keying on what was typed must see what
// was typed.
func postAuthenticationInput(
	p *identity.Principal,
	first factor.Kind,
	username string,
	passwordChangedAt, now time.Time,
) *policy.Input {
	in := &policy.Input{
		Username:          username,
		Principal:         p,
		FirstFactor:       first,
		PasswordChangedAt: passwordChangedAt,
		Now:               now,
	}
	if p != nil {
		in.User = p.ID
	}

	return in
}

// WithCaller publishes an authentication result and the caller it resolved on a
// context derived from ctx.
//
// A consumer writing their own first factor calls this rather than
// authenticate.WithAuthentication, which publishes only the event. The two
// answer different questions: an interceptor asks what authenticated this
// request, while a guard and the consumer's own handler ask who the caller is.
// Publishing only the event leaves every guard reading
// identity.PrincipalFromContext refusing a caller the chain has just
// authenticated, and that refusal is indistinguishable from a missing
// credential. They are published together here so no call site — the library's
// own or a consumer's — can publish one without the other.
//
// The built-in first factors publish through it, so an interceptor a consumer
// registers is left holding nothing a built-in has.
//
// A nil authentication, or one carrying no principal, publishes nothing under
// the principal key, so a reader that checks is never handed an absence
// dressed as a caller. It derives rather than replaces: everything already on
// ctx, including an upstream request identifier and the client's cancellation,
// is still there.
func WithCaller(ctx context.Context, a *authenticate.Authentication) context.Context {
	ctx = authenticate.WithAuthentication(ctx, a)
	if a == nil || a.Principal == nil {
		return ctx
	}

	return identity.WithPrincipal(ctx, a.Principal)
}

// challengeMarker records on a session that a challenge is owed, in the fields
// the gate enforcing it reads.
//
// sessions is the manager the session belongs to, whose clock an enrolment
// mark's deadlines are drawn from, and enrolmentLifetime is how long an
// enrolment-only session may live, handed over when the chain is built.
type challengeMarker struct {
	sessions          *session.Manager
	enrolmentLifetime time.Duration
}

// refuseUnenforced refuses a challenge of a kind nothing on the chain
// enforces, with a configuration error, before anything is marked. A kind only
// a built-in gate raises is refused the same way, whatever is enabled; see
// refuseGateOnly.
//
// Chain assembly refuses a policy that declares such a kind, but it can only
// read the policies registered when the chain is built. A policy added to the
// engine afterwards escapes it, and a challenge it raises would otherwise be
// marked on the session and then served: the gate that should refuse the
// request is not there. Refusing the request instead makes the wiring mistake
// visible on the first request that reaches it, and satisfies nothing it
// should not.
func refuseUnenforced(enforced map[policy.ChallengeKind]bool, kind policy.ChallengeKind) error {
	if err := refuseGateOnly(kind, "a policy raised"); err != nil {
		return err
	}

	if enforced[kind] {
		return nil
	}

	if b, ok := builtInEnforcers[kind]; ok {
		return newConfigError("a policy raised %s, a challenge for %s, but nothing on this "+
			"chain enforces it: add %s, and register every policy before the chain is built "+
			"so assembly checks it", kind, b.what, b.option)
	}

	return newConfigError("a policy raised %s, but nothing on this chain enforces it: "+
		"register your gate for it and declare it with WithChallengeEnforcer, and register "+
		"every policy before the chain is built so assembly checks it", kind)
}

// mark records kind on s, in memory; the caller persists it.
//
// An enrolment challenge sets the enrolment-pending state and its marker and
// lowers the session's deadlines, in one change, so the session saved next is
// already the short-lived, confined one.
//
// A kind this package does not know marks nothing: the session has no field
// for it. By the time mark runs, refuseUnenforced has already refused such a
// kind unless the consumer declared it with WithChallengeEnforcer. At login
// the caller then refuses with the challenge; per request the bearer records
// the kind on the exchange (Exchange.RaisedChallenge) and continues, and the
// consumer's declared gate enforces it.
func (m challengeMarker) mark(s *session.Session, kind policy.ChallengeKind) {
	switch kind {
	case policy.ChallengeMFA:
		s.MFA = session.MFAPending
	case policy.ChallengePasswordChange:
		s.PasswordChangePending = true
	case policy.ChallengeMFAEnrolment:
		m.sessions.MarkEnrolmentPending(s, m.enrolmentLifetime)
	case policy.ChallengeNone:
	}
}

// completeLogin is the tail every first factor shares: policy, session, token.
//
// It exists so a redemption flow added by another capability cannot end a login
// differently from form login — the same phase, the same marking and the same
// ordering guarantee, written once and reused rather than restated.
//
// It returns the token it issued alongside the challenge error, because a
// consumer prompting for a second factor needs the credential the prompt will
// be answered with.
//
// A dependency's failure comes back behind fixed text, never the dependency's
// own, because that text may quote values the library never saw: the session
// manager already words its store's failures so, and a token generator's error
// is wrapped here. The dependency's error still matches through errors.Is and
// errors.As, so the status it maps to is unchanged. A policy's reason is the
// policy's own, and is returned as itself.
//
// When the chain may hold account recoveries, the user's held recoveries are
// cancelled first, as soon as the first factor has authenticated: before the
// policy phase and before the session is created. A login the policy then
// denies or challenges has still cancelled them, since completing the first
// factor is the evidence the real user still has access. A failure to cancel
// refuses the login (see loginTailDeps.cancelHeld).
//
// A caller that has already decided the phase for this login passes the
// decision in deps.decided, and the tail acts on it rather than evaluating
// again (see loginTailDeps.decided).
//
// With no policy engine wired the phase allows, which is the documented default
// of WithPolicyEngine: a consumer who registers no policies rests on
// authentication alone rather than on a phase that refuses everything.
//
// opts are the caller's own attributes for the session, applied in the write
// that creates it and before the first factor the tail records from in. A
// federated login passes its provider session here, so the session is never
// stored, even briefly, without it. Form login and magic-link pass none.
//
// The first factor recorded is always in.FirstFactor, the tail's own: it is
// applied last, so a caller's own session.WithFirstFactor in opts cannot
// replace the factor the policy phase was just evaluated on.
//
// When in.SecondFactorAtLogin holds — the library's proof, which only its
// passkey login mints — the phase sees it and the session is created with
// session.WithSecondFactorAtLogin, satisfied in the creating write. A
// challenge the phase still raises is marked on that session as for any
// login. A zero proof, which every other first factor passes, changes
// nothing.
//
// When in.FederatedAssurance asserts something — evidence only the library's
// OIDC redemption mints, from the record the callback wrote — the phase sees
// it, and its amr and acr are recorded on the session with
// session.WithFederatedAssurance in the creating write, after the caller's
// options so none of them can replace it. It is evidence, not a verdict: the
// second factor is not marked satisfied and the met-at-first-factor marker is
// not set, so every later request matches the stored values again. Zero
// evidence, which every other first factor passes, records nothing.
func completeLogin(ex *Exchange, deps loginTailDeps, in *policy.Input, opts ...session.CreateOption) (string, error) {
	ctx := ex.Context()

	// A user who completes a first factor can still get into their account,
	// so a recovery held for it is cancelled here, before the policy phase:
	// a login the policy denies still showed the user holds their first
	// factor. A cancellation that cannot be recorded refuses the login, which
	// fails closed: letting the recovery stand would let it finish later
	// against a user who showed they had not lost their account. As for a
	// session-store failure below, a one-time login credential may already be
	// spent.
	if deps.cancelHeld != nil {
		if err := deps.cancelHeld(ctx, in.User); err != nil {
			return "", err
		}
	}

	d := policy.Decision{Outcome: policy.Allow}

	switch {
	case deps.decided != nil:
		d = *deps.decided
	case deps.engine != nil:
		d = deps.engine.EvaluatePhase(ctx, policy.PostAuthentication, in)
	}

	if d.Outcome == policy.Deny {
		return "", policyDenyReason(d)
	}

	// Refused before the session exists, so an unenforced challenge leaves
	// neither a marked session nor a token behind. The methods the challenge
	// offers are looked up here too, for the same reason: a lookup that fails
	// refuses the login before a pending session is written that nobody holds
	// a credential for.
	var methods []MFAMethod

	if d.Outcome == policy.Challenge {
		if err := refuseUnenforced(deps.enforced, d.Challenge); err != nil {
			return "", err
		}

		if deps.challengeMethods != nil {
			var err error

			methods, err = deps.challengeMethods(ctx, d.Challenge, in.User, in.FirstFactor)
			if err != nil {
				return "", err
			}
		}
	}

	// The caller's own attributes first, then the first factor: a federated
	// login records its provider session here, in the write that creates the
	// session, so no request ever sees the session without it. The first
	// factor is applied last so it always wins, even if opts happens to carry
	// its own session.WithFirstFactor — the factor the policy phase was just
	// evaluated on is the one that gets recorded.
	//
	// A login carrying the library's proof that its second factor was met at
	// the first is created satisfied, in that same write, so the session never
	// exists unsatisfied. It is applied after the caller's options, so none of
	// them can undo it, and before any challenge mark: a challenge the phase
	// still raises, such as a password change, is marked on the satisfied
	// session and refused as for any login.
	create := make([]session.CreateOption, 0, len(opts)+3)
	create = append(create, opts...)
	if ev := in.FederatedAssurance; ev.Asserted() {
		create = append(create, session.WithFederatedAssurance(ev.AMR(), ev.ACR()))
	}
	if in.SecondFactorAtLogin.Holds() {
		create = append(create, session.WithSecondFactorAtLogin())
	}
	create = append(create, session.WithFirstFactor(in.FirstFactor))

	s, err := deps.sessions.Create(ctx, in.User, create...)
	if err != nil {
		return "", err
	}

	if d.Outcome == policy.Challenge {
		// Marked and saved before the token exists. A token issued first would
		// be a credential for a session whose pending flag never persisted —
		// that is, one that answers requests as though the challenge had been
		// met.
		challengeMarker{sessions: deps.sessions, enrolmentLifetime: deps.enrolmentLifetime}.
			mark(s, d.Challenge)

		if err := deps.sessions.Save(ctx, s); err != nil {
			return "", err
		}
	}

	// The session identifier is the token's jti, which is how a later bearer
	// request finds the session the token was issued for. The generator is the
	// consumer's, so its error comes back behind fixed text.
	tok, err := deps.tokens.Generate(ctx, s.ID, in.Principal)
	if err != nil {
		return "", diag.Wrap(err, msgTokenNotIssued)
	}

	// Published on the challenge path too, so a consumer rendering the prompt
	// still reads who is being challenged.
	ex.Session = s
	ex.SetContext(withSession(WithCaller(ctx, ex.Authentication), s))

	if d.Outcome == policy.Challenge {
		return tok, &ChallengeError{Kind: d.Challenge, Session: s, Token: tok, Methods: methods}
	}

	return tok, nil
}
