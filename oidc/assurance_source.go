package oidc

import (
	"context"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

//go:generate mockgen -source=assurance_source.go -package=oidc_test -destination=assurance_source_mock_test.go -typed

// AssuranceInput is what an AssuranceEvaluator decides on: the user, the
// provider and verified issuer of the login, and the amr and acr its verified
// ID token asserted. It never carries the raw token.
//
// AMR is in the order the provider asserted it, without duplicates, and is the
// evaluator's own copy. Either AMR or ACR may be empty, meaning nothing of
// that kind was asserted.
type AssuranceInput struct {
	User             identity.UserID
	Provider, Issuer string
	AMR              []string
	ACR              string
}

// AssuranceEvaluator decides whether a federated login's asserted values meet
// assurance, in place of the per-provider matching. A consumer supplies one
// through WithAssuranceEvaluator; with none, the manager matches the values
// against the provider's Assurance.
type AssuranceEvaluator interface {
	// MeetsAssurance reports whether in meets assurance. It must be fast and
	// free of side effects, since it runs on every policy evaluation of a
	// federated login. An error fails closed: the MFA policies deny with it
	// as the reason.
	MeetsAssurance(ctx context.Context, in AssuranceInput) (bool, error)
}

// MeetsAssurance reports whether ev meets the assurance configured for its
// provider, for user. It makes the manager the policy.FederatedAssuranceSource
// the MFA policies are given (policy.WithFederatedAssuranceSource).
//
// Evidence that asserts nothing, names a provider the registry does not hold,
// or names an issuer other than that provider's registered one is never met,
// and is answered false with no error without consulting anything: a provider
// removed from the registry stops meeting assurance for every session it
// created. Otherwise the evaluator given by WithAssuranceEvaluator decides:
// its answer is returned, or its error unchanged with false. With none, the
// asserted amr and acr are matched against the provider's current Assurance,
// so a tightened configuration applies to existing sessions at their next
// evaluation.
func (m *Manager) MeetsAssurance(ctx context.Context, user identity.UserID, ev policy.FederatedAssurance) (bool, error) {
	if !ev.Asserted() {
		return false, nil
	}
	p, ok := m.registry.Lookup(ev.Provider())
	if !ok || p.Issuer != ev.Issuer() {
		return false, nil
	}

	if m.evaluator != nil {
		met, err := m.evaluator.MeetsAssurance(ctx, AssuranceInput{
			User:     user,
			Provider: ev.Provider(),
			Issuer:   ev.Issuer(),
			AMR:      ev.AMR(),
			ACR:      ev.ACR(),
		})
		if err != nil {
			// Never met alongside an error, whatever the evaluator answered.
			return false, err
		}
		return met, nil
	}

	// The provider is registered, checked above; were it not, the zero
	// Assurance would match nothing anyway.
	a, _ := m.assuranceFor(ev.Provider())
	return matchAssurance(a, ev.AMR(), ev.ACR()), nil
}

var _ policy.FederatedAssuranceSource = (*Manager)(nil)
