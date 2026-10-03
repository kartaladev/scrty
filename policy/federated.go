package policy

import (
	"context"
	"fmt"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/assurance"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

//go:generate mockgen -source=federated.go -package=policy_test -destination=federated_mock_test.go -typed

// FederatedAssurance is evidence of the assurance an OpenID Connect provider
// asserted for a login: the provider's registered name, the verified issuer,
// and the amr and acr values its verified ID token named, read through
// Provider, Issuer, AMR and ACR.
//
// It is evidence, not a verdict: the MFA policies never read it as "met". They
// hand it to the FederatedAssuranceSource they were given, which matches it
// against the provider's current configuration every time it is asked.
//
// The type has no public constructor and its zero value asserts nothing
// (Asserted reports false). Only the library mints evidence that asserts
// anything: the OIDC handoff redemption, from the record the library wrote at
// the callback, and the per-request evaluation of a federated session, from
// the session's library-owned fields. A consumer can name the type and copy a
// value it was handed, and nothing more.
//
// It is not a SecondFactorProof, and never sets the session's met-by-first-
// factor marker or its satisfied second-factor state.
type FederatedAssurance = assurance.Federated

// FederatedAssuranceSource decides whether federated assurance evidence meets
// the assurance configured for its provider. The OIDC manager implements it
// from its per-provider configuration; a consumer may supply their own.
//
// The MFA policies consult it only for a login whose first factor is on the
// factor.Federated channel and whose evidence asserts something: the
// requirement policy for a required user, at login and again on every
// request, and the second-factor challenge policy only under
// WithFederatedChallengeWhenUnmet(true). With no source configured
// (WithFederatedAssuranceSource), the library meets nothing: no federated
// login is ever treated as having met a second factor at its provider.
//
// An implementation must answer from the provider's current configuration,
// not from an earlier answer, because the requirement policy relies on it to
// re-match a live session after the configuration changes. It is expected to
// be safe for concurrent use.
type FederatedAssuranceSource interface {
	// MeetsAssurance reports whether ev meets the assurance configured for
	// its provider, for user. A provider the source does not know never
	// meets it.
	//
	// An error fails closed: the policy denies with a reason wrapping it, and
	// never reads it as met.
	MeetsAssurance(ctx context.Context, user identity.UserID, ev FederatedAssurance) (bool, error)
}

// FederatedAssuranceSourceOption is returned by WithFederatedAssuranceSource.
// It is accepted by both NewMFAPolicy and NewMFARequirementPolicy, so a
// deployment wires its source once and gives the same value to each.
type FederatedAssuranceSourceOption struct {
	src FederatedAssuranceSource
}

func (o FederatedAssuranceSourceOption) applyMFA(p *mfaPolicy) {
	p.federated = federatedSource{src: o.src, set: true}
}

func (o FederatedAssuranceSourceOption) applyMFARequirement(p *mfaRequirementPolicy) {
	p.federated = federatedSource{src: o.src, set: true}
}

// WithFederatedAssuranceSource gives the MFA policies the source that decides
// whether a federated login's provider assurance meets the configuration.
//
// The default is no source, under which no federated login meets assurance:
// a required user's OIDC login is then decided by the requirement policy's
// federated-assurance mode as an unmet one (see WithFederatedAssurance), and
// the challenge policy refuses WithFederatedChallengeWhenUnmet(true) at
// construction, because it would have nothing to decide with.
//
// An absent source, nil or a non-nil interface holding a nil pointer, is a
// configuration error at construction: passing one says a source was meant,
// and a policy that silently had none would decide every federated login as
// unmet.
func WithFederatedAssuranceSource(src FederatedAssuranceSource) FederatedAssuranceSourceOption {
	return FederatedAssuranceSourceOption{src: src}
}

// federatedSource is the source an MFA policy was given, and whether one was
// given at all, so an absent value passed on purpose can be refused.
type federatedSource struct {
	src FederatedAssuranceSource
	set bool
}

// validate refuses an option that was given an absent source.
func (f federatedSource) validate(policyName string) error {
	if f.set && nilcheck.IsNil(f.src) {
		return fmt.Errorf(
			"%w: the %s was given an absent federated assurance source", ErrConfig, policyName)
	}

	return nil
}

// federatedMet is the one rule both MFA policies decide federated assurance
// by. It meets nothing, and asks no one, when there is no source, when the
// first factor is not on the federated channel, or when the evidence asserts
// nothing. Otherwise the source decides, and its error is returned unchanged
// for the caller to deny with.
func federatedMet(ctx context.Context, src FederatedAssuranceSource, in *Input) (bool, error) {
	if nilcheck.IsNil(src) ||
		in.FirstFactor.Channel() != factor.Federated ||
		!in.FederatedAssurance.Asserted() {
		return false, nil
	}

	met, err := src.MeetsAssurance(ctx, in.User, in.FederatedAssurance)
	if err != nil {
		return false, err
	}

	return met, nil
}
