package httpsec

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
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

	// methods are the methods the check found the raised challenge of kind
	// methodsKind offers, and looked reports that it looked them up.
	methods     []MFAMethod
	methodsKind policy.ChallengeKind
	looked      bool
}

// challengeMethods is the lookup the login tail offers a raised challenge's
// methods through, after the credential is spent: the methods the check
// already looked up for a challenge of the same kind, and lookup for any
// other. The tail acts on the check's own decision (loginTailDeps.decided), so
// the kinds agree; they are compared rather than assumed all the same, so a
// tail handed some other decision can never offer the wrong kind's methods.
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
				reason = policy.ErrPolicyDenied
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

		// A challenge of an enforced kind is not a refusal. The credential is
		// spent, the session is created with the challenge pending, and the
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
		return policy.ErrPolicyDenied
	}

	if out.principal.ID != p.ID || !out.passwordChangedAt.Equal(passwordChangedAt) {
		return policy.ErrPolicyDenied
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

	return policy.ErrPolicyDenied
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
// policy.ErrPolicyDenied, as a redeemer returning another user is. The
// built-in redeemer returns exactly what it handed its checks.
func guardFederatedAssurance(out *policyOutcome, provider, issuer string, amr []string, acr string) error {
	ev := out.federated
	if ev.Provider() != provider || ev.Issuer() != issuer ||
		!slices.Equal(ev.AMR(), amr) || ev.ACR() != acr {
		return policy.ErrPolicyDenied
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
func countsAgainstSource(countRefusals bool, err error, out *policyOutcome) bool {
	if countRefusals {
		return true
	}

	if out.denyErr != nil && errors.Is(err, out.denyErr) {
		return false
	}

	return out.checkErr == nil || !errors.Is(err, out.checkErr)
}
