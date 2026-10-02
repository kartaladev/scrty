package policy

import (
	"context"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
)

// The requirement policy answers LoginAdmission, so a component judging a
// login ahead of time asks the policy that will evaluate it.
var _ LoginAdmission = (*mfaRequirementPolicy)(nil)

// errTextAdmissionLookup is the fixed text a failed requirement lookup is
// returned under, so the lookup's own text never reaches the caller's output.
const errTextAdmissionLookup = "policy: whether this user must use a second factor could not be read, " +
	"and a requirement that cannot be read is not absent"

// AdmitsWithoutLocalSecondFactor reports whether a login of kind for user
// would be admitted by this policy without a local second factor, whatever
// its provider asserts. It answers in the order Evaluate decides in:
//
//  1. kind is on the factor.Federated channel and the policy is in
//     FederatedAssuranceExempt mode: true, before anything is looked up;
//  2. the exemption rule (WithMFAExemption, default factor.Kind.MFAExempt)
//     marks kind exempt: true, before anything is looked up;
//  3. the user is not required to use a second factor: true. With
//     WithMFARequiredForAll every user is required and the lookup is not
//     consulted. A lookup that fails returns its error under fixed text,
//     never true or false;
//  4. otherwise false.
//
// Provider assurance is never assumed: it is known only at a login, so a
// required user's federated login, which only a met assurance would admit, is
// answered false. That fails safe for the way-back check, which then asks the
// user to keep another way back in.
func (p *mfaRequirementPolicy) AdmitsWithoutLocalSecondFactor(
	ctx context.Context,
	user identity.UserID,
	kind factor.Kind,
) (bool, error) {
	if kind.Channel() == factor.Federated && p.federatedMode == FederatedAssuranceExempt {
		return true, nil
	}
	if p.exempt(kind) {
		return true, nil
	}

	required, err := p.isRequired(ctx, &Input{User: user, FirstFactor: kind})
	if err != nil {
		return false, diag.Wrap(err, errTextAdmissionLookup)
	}

	return !required, nil
}
