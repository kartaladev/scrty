package httpsec

import (
	"context"
	"errors"
	"time"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

// redemptionCheck is the shape every single-use credential redemption runs its
// refusal checks in: magiclink.Check and oidc.RedeemCheck both have it, so one
// policy check and one set of guards serve every endpoint that spends one.
type redemptionCheck = func(ctx context.Context, p identity.Principal, passwordChangedAt time.Time) error

// policyOutcome is what a redemption's own refusal check decided, escaping the
// check so the endpoint can read it afterwards.
type policyOutcome struct {
	evaluated bool
	decision  policy.Decision
	denyErr   error
	checkErr  error
}

// redemptionPolicyCheck builds the refusal check a redemption runs for a login
// whose first factor is first, and the record of what it decided.
//
// The decision has to escape the check, because the check's return value alone
// cannot distinguish "allowed" from "never ran" — and a redeemer that never ran
// the checks would otherwise look exactly like one whose checks passed.
func redemptionPolicyCheck(
	engine *policy.Engine, first factor.Kind, now func() time.Time,
) (redemptionCheck, *policyOutcome) {
	out := &policyOutcome{}

	check := func(ctx context.Context, p identity.Principal, passwordChangedAt time.Time) error {
		d := evaluatePhase(ctx, engine, policy.PostAuthentication, postAuthenticationInput(
			&p, first, "", passwordChangedAt, now()))

		out.evaluated = true
		out.decision = d

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

		// A challenge is not a refusal. The credential is spent, the session
		// is created with the challenge pending, and the caller is prompted.
		return nil
	}

	return check, out
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

// guardRedemption refuses a redemption whose policy check was denied or
// skipped.
//
// "Never evaluated" is a denial rather than an allow: a redeemer that did not
// run the checks has not shown the login is permitted, and the safe reading of
// "I do not know" is no.
//
// What this cannot do is un-spend a credential such an implementation already
// consumed. The refusal protects the session, not the credential.
func guardRedemption(out *policyOutcome) error {
	if !out.evaluated {
		return policy.ErrPolicyDenied
	}

	if out.decision.Outcome != policy.Deny {
		return nil
	}

	if out.denyErr != nil {
		return out.denyErr
	}

	return policy.ErrPolicyDenied
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
// other reason, which is not the refusal the consumer opted out of.
func countsAgainstSource(countRefusals bool, err error, out *policyOutcome) bool {
	if countRefusals {
		return true
	}

	if out.denyErr != nil && errors.Is(err, out.denyErr) {
		return false
	}

	return out.checkErr == nil || !errors.Is(err, out.checkErr)
}
