package httpsec

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

// redemptionCheck is the shape the magic-link endpoint's own policy check is
// built in, which magiclink.Check has. The OIDC redemption builds its check in
// oidc.RedeemCheck's shape instead (oidcRedemptionCheck), because its
// candidate also carries the federated assurance the policies decide on. Both
// share one decision (redemptionDecision) and one set of guards, so every
// endpoint that spends a single-use credential is decided the same way.
type redemptionCheck = func(ctx context.Context, p identity.Principal, passwordChangedAt time.Time) error

// policyOutcome is what a redemption's own refusal check decided, escaping the
// check so the endpoint can read it afterwards.
type policyOutcome struct {
	evaluated bool
	decision  policy.Decision

	// principal and passwordChangedAt are what decision was made on, so the
	// login tail reuses it only for the login it was made for (see
	// guardRedemption).
	principal         identity.Principal
	passwordChangedAt time.Time

	// federated is the assurance evidence decision was made on: the zero
	// value for a login with no federated assurance, such as a magic link
	// (see guardFederatedAssurance).
	federated policy.FederatedAssurance

	denyErr  error
	checkErr error

	// unenforcedErr is the configuration error a challenge of a kind nothing
	// on the chain enforces was refused with, nil when there was none.
	unenforcedErr error

	// issueErr is the error the redemption's login could not be built or
	// issued with inside the checks (redemptionLogin.issue), nil when there
	// was none or a later issue succeeded. It is a dependency failure, and
	// never counted against the source (see countsAgainstSource).
	issueErr error

	// methods are the methods the check found the raised challenge of kind
	// methodsKind offers, and looked reports that it looked them up.
	methods     []MFAMethod
	methodsKind policy.ChallengeKind
	looked      bool
}

// challengeMethods is the lookup the login tail offers a raised challenge's
// methods through, when the redemption issues its login: the methods the
// policy check already looked up for a challenge of the same kind, and lookup
// for any other. The tail acts on the check's own decision
// (loginTailDeps.decided), so the kinds agree; they are compared rather than
// assumed all the same, so a tail handed some other decision can never offer
// the wrong kind's methods.
func (out *policyOutcome) challengeMethods(lookup challengeMethodsFunc) challengeMethodsFunc {
	return func(ctx context.Context, kind policy.ChallengeKind, user identity.UserID, first factor.Kind) ([]MFAMethod, error) {
		if out.looked && kind == out.methodsKind {
			return out.methods, nil
		}

		if lookup == nil {
			return nil, nil
		}

		return lookup(ctx, kind, user, first)
	}
}

// redemptionPolicyCheck builds the refusal check a redemption runs for a login
// whose first factor is first, and the record of what it decided.
//
// The decision has to escape the check, because the check's return value alone
// cannot distinguish "allowed" from "never ran" — and a redeemer that never ran
// the checks would otherwise look exactly like one whose checks passed.
//
// enforced is the chain's enforcer set. A challenge of a kind outside it is
// refused here, inside the check, so the redeemer stops before it spends the
// credential: the login tail would refuse it anyway (see refuseUnenforced), and
// refusing it only there would cost the user a credential for a wiring fault
// that was never theirs.
//
// methods looks up what a raised challenge offers, and it is asked here too,
// inside the check, for the same reason: a lookup that fails refuses the login,
// and it must do so before the credential is spent, not after. The methods it
// found are kept on the outcome for the login tail (policyOutcome.
// challengeMethods), so the tail does not look them up a second time. A nil
// methods looks nothing up.
//
// The check carries no federated assurance. A federated redemption builds its
// check with oidcRedemptionCheck instead, which shares this one's decision and
// record.
func redemptionPolicyCheck(
	engine *policy.Engine,
	enforced map[policy.ChallengeKind]bool,
	methods challengeMethodsFunc,
	first factor.Kind,
	now func() time.Time,
) (redemptionCheck, *policyOutcome) {
	decide, out := redemptionDecision(engine, enforced, methods)

	check := func(ctx context.Context, p identity.Principal, passwordChangedAt time.Time) error {
		return decide(ctx, postAuthenticationInput(&p, first, "", passwordChangedAt, now()))
	}

	return check, out
}

// oidcRedemptionCheck builds the refusal check an OIDC handoff redemption
// runs, and the record of what it decided: redemptionPolicyCheck's decision
// for the oidc first factor, with the federated assurance the candidate's
// record carries minted as the evidence the policies decide on.
//
// The evidence is minted from the candidate alone, which the redeemer filled
// from the record the library wrote at the callback, from the verified ID
// token. Nothing the redemption request carries reaches it.
func oidcRedemptionCheck(
	engine *policy.Engine,
	enforced map[policy.ChallengeKind]bool,
	methods challengeMethodsFunc,
	now func() time.Time,
) (oidc.RedeemCheck, *policyOutcome) {
	decide, out := redemptionDecision(engine, enforced, methods)

	check := func(ctx context.Context, c oidc.RedeemCandidate) error {
		in := postAuthenticationInput(&c.Principal, factor.OIDC, "", c.PasswordChangedAt, now())
		in.FederatedAssurance = mintFederated(c.Provider, c.Issuer, c.AMR, c.ACR)

		return decide(ctx, in)
	}

	return check, out
}

// redemptionDecision is the decision every redemption check shares: it
// evaluates the post-authentication phase on the input the check built,
// records what it decided and on what, and refuses a deny, an unenforced
// challenge and a failed methods lookup (see redemptionPolicyCheck).
func redemptionDecision(
	engine *policy.Engine,
	enforced map[policy.ChallengeKind]bool,
	methods challengeMethodsFunc,
) (func(ctx context.Context, in *policy.Input) error, *policyOutcome) {
	out := &policyOutcome{}

	decide := func(ctx context.Context, in *policy.Input) error {
		d := evaluatePhase(ctx, engine, policy.PostAuthentication, in)

		out.evaluated = true
		out.decision = d
		out.principal, out.passwordChangedAt = *in.Principal, in.PasswordChangedAt
		out.federated = in.FederatedAssurance

		if d.Outcome == policy.Deny {
			// Never nil for a refusal. A nil return reads as "no refusal" to
			// the redemption, which would go on to spend the credential: the
			// user would lose it and be refused anyway. *policy.Engine already
			// substitutes this reason itself, so the fallback is defence in
			// depth against a future change in how the engine reports a
			// deny, not a doubt about a chain wired with no engine at all —
			// that case allows outright rather than reaching this branch.
			reason := d.Reason
			if reason == nil {
				reason = policy.ErrDenied
			}

			out.denyErr = reason

			return reason
		}

		if d.Outcome == policy.Challenge {
			if err := refuseUnenforced(enforced, d.Challenge); err != nil {
				out.unenforcedErr = err

				return err
			}

			if methods != nil {
				offered, err := methods(ctx, d.Challenge, in.User, in.FirstFactor)
				if err != nil {
					return err
				}

				out.methods, out.methodsKind, out.looked = offered, d.Challenge, true
			}
		}

		// A challenge of an enforced kind is not a refusal. The session is
		// built with the challenge pending and its credential issued, the
		// single-use credential is spent, the session is stored, and the
		// caller is prompted.
		return nil
	}

	return decide, out
}

// wrapChecks returns the consumer's own checks, each recording the error it
// refused with.
//
// The record is what a count-refusals opt-out matches against: without it, "the
// consumer's check refused" and "the redeemer failed for a reason of its own"
// would be indistinguishable, and exempting the second from the source count is
// exactly what an attacker would want.
func wrapChecks[C ~func(context.Context, identity.Principal, time.Time) error](
	checks []C, out *policyOutcome,
) []C {
	if len(checks) == 0 {
		return nil
	}

	wrapped := make([]C, 0, len(checks))

	for _, check := range checks {
		wrapped = append(wrapped,
			func(ctx context.Context, p identity.Principal, changed time.Time) error {
				err := check(ctx, p, changed)
				if err != nil {
					out.checkErr = err
				}

				return err
			})
	}

	return wrapped
}

// guardRedemption refuses a redemption whose policy check was denied, raised a
// challenge nothing on the chain enforces, was skipped, or was made for a
// login other than the one the redeemer returned (p and passwordChangedAt).
//
// "Never evaluated" is a denial rather than an allow: a redeemer that did not
// run the checks has not shown the login is permitted, and the safe reading of
// "I do not know" is no.
//
// The login tail acts on the check's decision rather than evaluating again,
// so that decision must be the returned login's. A redeemer that checked one
// user, or one password-change time, and returned another has not shown the
// returned login is permitted, and is refused the same way. "Another" means a
// different user reference, or a password-change time that is not the same
// instant. It is not deep equality: a redeemer that loads the same user again
// returns a separate value, and may carry its times in another location, and
// that is still the login the check decided on. The built-in redeemers check
// exactly what they return.
//
// What this cannot do is un-spend a credential such an implementation already
// consumed. The refusal protects the session, not the credential.
func guardRedemption(out *policyOutcome, p identity.Principal, passwordChangedAt time.Time) error {
	if !out.evaluated {
		return policy.ErrDenied
	}

	if out.principal.ID != p.ID || !out.passwordChangedAt.Equal(passwordChangedAt) {
		return policy.ErrDenied
	}

	if out.unenforcedErr != nil {
		return out.unenforcedErr
	}

	if out.decision.Outcome != policy.Deny {
		return nil
	}

	if out.denyErr != nil {
		return out.denyErr
	}

	return policy.ErrDenied
}

// guardFederatedAssurance refuses a federated redemption whose redeemer
// returned assurance other than the evidence its policy check decided on: a
// different provider, a different issuer, a different amr (in content or
// order), or a different acr.
//
// It runs after guardRedemption, which has already refused a check that never
// ran. The login tail acts on the check's decision and records the returned
// assurance on the session, where every later request matches it again, so a
// redeemer that reported assurance its check never saw would have the session
// carry evidence no policy decided on at login. That is refused with
// policy.ErrDenied, as a redeemer returning another user is. The
// built-in redeemer returns exactly what it handed its checks.
func guardFederatedAssurance(out *policyOutcome, provider, issuer string, amr []string, acr string) error {
	ev := out.federated
	if ev.Provider() != provider || ev.Issuer() != issuer ||
		!slices.Equal(ev.AMR(), amr) || ev.ACR() != acr {
		return policy.ErrDenied
	}

	return nil
}

// countsAgainstSource decides whether a redemption failure counts against the
// source.
//
// By default (countRefusals) every failure counts, including a policy denial
// or a consumer check refusal of a valid credential: an attacker holding one
// the policy refuses could otherwise replay it without limit for as long as it
// lives, and each attempt would cost a store read and a policy evaluation.
//
// The opt-out exempts exactly two things, each matched against the very error
// the run recorded: the refusal the endpoint's own check produced, and the
// consumer's own check error. Everything else is still recorded — including a
// failure from a redeemer that discarded the denial and then failed for some
// other reason, which is not the refusal the consumer opted out of, and an
// enrolment-store outage while the check looks up the methods a raised
// challenge offers, which is a failure of the check rather than its refusal.
// A policy that denies because it could not read enrolment has produced the
// refusal, and is exempted like any denial.
//
// A failure to build or issue the login's credential is never counted, by
// default or under the opt-out: it is a dependency failure, which says nothing
// about the source, and the credential it was for is still unspent. It is
// recognised in any error carrying an issuing failure for as long as no later
// issue succeeded; once one did, the failure is forgotten and a later refusal
// is charged as any other.
func countsAgainstSource(countRefusals bool, err error, out *policyOutcome) bool {
	if out.issueErr != nil {
		// Each failed issue is a new *issueFailure, so a redeemer that
		// retried and returned an earlier attempt's error, or joined it
		// beside a refusal, is recognised by the mark, not by identity.
		var issuing *issueFailure

		if errors.Is(err, out.issueErr) || errors.As(err, &issuing) {
			return false
		}
	}

	if countRefusals {
		return true
	}

	if out.denyErr != nil && errors.Is(err, out.denyErr) {
		return false
	}

	return out.checkErr == nil || !errors.Is(err, out.checkErr)
}

// redemptionLogin builds and issues the login a redemption completes, inside
// the redeemer's refusal checks, so that a credential that cannot be issued
// leaves the single-use credential unspent: the redeemer consumes only after
// every check passed, and the session is stored only after the consume.
//
// Its check (issue) is the last one a redemption hands its redeemer, after
// the endpoint's policy check and the consumer's own, so it issues only for a
// login every check allowed. Issuing writes no state: the session it builds
// loads nothing until committed, so racing redemptions of one credential can
// each issue, and the ones that lose the consume drop what they issued, with
// nothing to undo. A redeemer that runs the checks more than once issues once.
type redemptionLogin struct {
	deps  loginTailDeps
	out   *policyOutcome
	login *preparedLogin
}

// newRedemptionLogin is the issuing step for a redemption whose policy check
// records into out. deps are the tail's dependencies; the login acts on the
// decision the check made (loginTailDeps.decided) and offers the methods the
// check found, rather than deciding or looking them up again.
func newRedemptionLogin(deps loginTailDeps, out *policyOutcome) *redemptionLogin {
	deps.decided = &out.decision
	deps.challengeMethods = out.challengeMethods(deps.challengeMethods)

	return &redemptionLogin{deps: deps, out: out}
}

// issue builds the session for in, marks any challenge on it and issues its
// credential (prepareLogin), storing nothing, and holds the result until the
// redemption commits it.
//
// It first refuses what guardRedemption refuses: a policy check that never
// ran, denied, raised an unenforced challenge, or decided on another login
// than in. A redeemer that calls it again for the login it has already issued
// for is answered nil without issuing a second time, and one that calls it
// for any other login is refused with policy.ErrDenied.
//
// A failure to build or issue is recorded on the outcome (policyOutcome.
// issueErr), until a later issue for the redemption succeeds and clears it,
// and returned as it is, a dependency failure behind fixed text; the
// redeemer hands it back unchanged, so the endpoint answers it as an outage,
// never as an invalid credential, and does not count it against the source.
func (r *redemptionLogin) issue(ctx context.Context, in *policy.Input) error {
	if err := guardRedemption(r.out, *in.Principal, in.PasswordChangedAt); err != nil {
		return err
	}

	if r.login != nil {
		if r.login.decidedAs(r.out) {
			return nil
		}

		return policy.ErrDenied
	}

	login, err := prepareLogin(ctx, r.deps, in)
	if err != nil {
		r.out.issueErr = err

		return err
	}

	// A later issue that succeeds forgets an earlier failure, so a redeemer
	// that retried its checks is charged for a later refusal as any other.
	r.out.issueErr = nil
	r.login = login

	return nil
}

// redeemed is the login issued for the redemption the redeemer reported, for
// the endpoint to commit once guardRedemption has accepted that redemption. A
// redeemer that never reached the issuing check, or ran the policy check again
// afterwards for another login or to another verdict, has not shown the login
// it was issued for is the one the checks allowed, and is refused with
// policy.ErrDenied.
func (r *redemptionLogin) redeemed() (*preparedLogin, error) {
	if r.login == nil || !r.login.decidedAs(r.out) {
		return nil, policy.ErrDenied
	}

	return r.login, nil
}

// decidedAs reports whether l was issued for the login out last decided on,
// to the same verdict: the same user and password-change time, the same
// outcome and challenge, and the same federated assurance.
func (l *preparedLogin) decidedAs(out *policyOutcome) bool {
	ev := l.in.FederatedAssurance

	return l.in.User == out.principal.ID &&
		l.in.PasswordChangedAt.Equal(out.passwordChangedAt) &&
		l.decision.Outcome == out.decision.Outcome &&
		l.decision.Challenge == out.decision.Challenge &&
		ev.Provider() == out.federated.Provider() && ev.Issuer() == out.federated.Issuer() &&
		slices.Equal(ev.AMR(), out.federated.AMR()) && ev.ACR() == out.federated.ACR()
}
