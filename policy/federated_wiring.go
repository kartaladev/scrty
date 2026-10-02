package policy

import (
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// FederatedAssuranceUser is implemented by a policy that can decide federated
// logins on provider assurance, so the component that admits federated logins
// can check, before it serves, that the policy has a source to decide with.
//
// It is optional and asked the way Challenger is: Engine.UnwiredFederatedAssurance
// reads it, and a policy that does not implement it is taken to need no
// source. A consumer whose own policy consults a FederatedAssuranceSource
// implements it so the same wiring check covers that policy too.
type FederatedAssuranceUser interface {
	// NeedsFederatedAssuranceSource reports whether the policy decides
	// federated logins on provider assurance and was given no source, so
	// every federated login it judges would be decided as unmet.
	NeedsFederatedAssuranceSource() bool
}

// NeedsFederatedAssuranceSource reports whether the requirement policy decides
// federated logins on provider assurance with no source to match it against.
//
// It does in FederatedAssuranceChallenge and FederatedAssuranceRefuse mode
// when WithFederatedAssuranceSource was not given. It does not in
// FederatedAssuranceExempt mode, nor when the exemption rule
// (WithMFAExemption) exempts the oidc kind, since both allow a federated login
// before any assurance is consulted.
func (p *mfaRequirementPolicy) NeedsFederatedAssuranceSource() bool {
	if p.federatedMode == FederatedAssuranceExempt || p.exempt(factor.OIDC) {
		return false
	}

	return nilcheck.IsNil(p.federated.src)
}

var _ FederatedAssuranceUser = (*mfaRequirementPolicy)(nil)
