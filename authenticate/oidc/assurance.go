package oidc

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

//go:generate mockgen -source=assurance.go -package=oidc_test -destination=assurance_mock_test.go -typed

// AssuranceMatch says how the criteria of an Assurance combine. A criterion
// is the amr criterion or the acr criterion, and it counts as configured only
// when its accepted set is not empty.
type AssuranceMatch int

const (
	// AssuranceMatchAny meets assurance when any configured criterion holds. It is
	// the zero value, and so the default.
	AssuranceMatchAny AssuranceMatch = iota

	// AssuranceMatchAll meets assurance only when every configured criterion holds. A
	// criterion with an empty accepted set is skipped, and a configuration
	// with both sets empty never meets assurance.
	AssuranceMatchAll
)

// defined reports whether the mode is one the library defines.
func (x AssuranceMatch) defined() bool { return x == AssuranceMatchAny || x == AssuranceMatchAll }

// Assurance is a provider's assurance configuration: which values asserted by
// its verified ID token show that the user authenticated strongly enough to
// stand in for a local second factor.
//
// Values are matched exactly and case-sensitively, as the provider asserts
// them. They are provider data the library does not interpret: acr values in
// particular are matched as a set, never as an ordered minimum, so a consumer
// who wants "silver or above" lists every value at or above silver.
//
// A provider with no WithProviderAssurance option uses
// Assurance{AcceptedAMR: []string{"mfa"}}: it accepts the amr value "mfa"
// only, accepts no acr, requests none, and matches any.
type Assurance struct {
	// AcceptedAMR is the set of authentication method references (RFC 8176)
	// any one of which, asserted in the ID token's amr, satisfies the amr
	// criterion.
	//
	// The default, when the provider has no WithProviderAssurance option, is
	// ["mfa"]: RFC 8176's value asserting that more than one authentication
	// method was used. Single-method values such as "otp", "hwk", "sms" or
	// "pwd" each name one method only, so on their own they do not show that
	// a second factor was used; accept one only when the provider is known to
	// assert it beside a first factor. An empty or nil AcceptedAMR, once
	// configured, accepts no amr at all: the default does not fill it back
	// in.
	AcceptedAMR []string

	// AcceptedACR is the set of authentication context class references, one
	// of which, asserted as the ID token's acr, satisfies the acr criterion.
	// The default accepts none.
	AcceptedACR []string

	// RequestACR is sent to the provider as the space-separated acr_values
	// parameter of the authorization redirect, in this order. A value may not
	// be empty or contain whitespace, since it would be sent as two values;
	// construction fails on either. When configured, it replaces any
	// acr_values already present on a consumer-pinned authorization endpoint.
	// It is a request the provider may ignore, never evidence: only the
	// returned ID token's acr is matched, against AcceptedACR. The default
	// requests none, and then the redirect carries no acr_values parameter.
	// Requesting an acr while accepting none is valid, for a consumer who asks
	// for a stronger context and verifies it through amr.
	RequestACR []string

	// Match says how the amr and acr criteria combine. The default, the zero
	// value, is AssuranceMatchAny.
	Match AssuranceMatch
}

// defaultAssurance is the configuration of a provider with no
// WithProviderAssurance option. It returns a fresh value on each call.
func defaultAssurance() Assurance {
	return Assurance{AcceptedAMR: []string{"mfa"}}
}

// clone returns a copy of a whose slices the caller owns. A nil slice stays
// nil and an empty one stays empty, so a configured empty set is kept.
func (a Assurance) clone() Assurance {
	a.AcceptedAMR = slices.Clone(a.AcceptedAMR)
	a.AcceptedACR = slices.Clone(a.AcceptedACR)
	a.RequestACR = slices.Clone(a.RequestACR)
	return a
}

// validate refuses an empty value in any set, a RequestACR value containing
// whitespace (acr_values is space-separated, so it would be sent as two
// values), and an undefined match mode. Its error names the provider and the field, never a configured value.
func (a Assurance) validate(provider string) error {
	sets := []struct {
		field  string
		values []string
	}{
		{"AcceptedAMR", a.AcceptedAMR},
		{"AcceptedACR", a.AcceptedACR},
		{"RequestACR", a.RequestACR},
	}
	for _, s := range sets {
		if slices.Contains(s.values, "") {
			return fmt.Errorf("%w: WithProviderAssurance for provider %q: %s contains an empty value",
				ErrConfig, provider, s.field)
		}
	}
	if slices.ContainsFunc(a.RequestACR, func(v string) bool { return strings.ContainsFunc(v, unicode.IsSpace) }) {
		return fmt.Errorf("%w: WithProviderAssurance for provider %q: RequestACR contains a value with whitespace",
			ErrConfig, provider)
	}
	if !a.Match.defined() {
		return fmt.Errorf("%w: WithProviderAssurance for provider %q: Match is not a defined mode",
			ErrConfig, provider)
	}
	return nil
}

// assuranceFor returns the assurance configuration of the named provider:
// the one WithProviderAssurance gave, kept as given even when its sets are
// empty, or the default when none was given. It reports false, with the zero
// Assurance, for a provider the registry does not hold.
//
// The returned slices are the manager's own; callers only read them.
func (m *RelyingParty) assuranceFor(provider string) (Assurance, bool) {
	if _, ok := m.registry.Lookup(provider); !ok {
		return Assurance{}, false
	}
	if a, ok := m.assurance[provider]; ok {
		return a, true
	}
	return defaultAssurance(), true
}

// checkAssuranceProviders refuses an assurance configuration for a provider
// the registry does not hold, which would otherwise never apply and never say
// so.
func (m *RelyingParty) checkAssuranceProviders() error {
	for _, name := range slices.Sorted(maps.Keys(m.assurance)) {
		if _, ok := m.registry.Lookup(name); !ok {
			return fmt.Errorf("%w: WithProviderAssurance names provider %q, which is not registered",
				ErrConfig, name)
		}
	}
	return nil
}

// matchAssurance reports whether the amr and acr a verified ID token asserted
// meet a. It is pure: it reads only its arguments.
//
// The amr criterion holds when any asserted value is in a.AcceptedAMR; the
// acr criterion holds when acr is non-empty and in a.AcceptedACR. Both
// compare exactly. A criterion whose accepted set is empty is not configured:
// under AssuranceMatchAny it cannot hold, and under AssuranceMatchAll it is skipped, though a
// configuration with no criterion at all never matches. An undefined mode
// never matches.
func matchAssurance(a Assurance, amr []string, acr string) bool {
	amrSet, acrSet := len(a.AcceptedAMR) > 0, len(a.AcceptedACR) > 0
	amrHolds := amrSet && slices.ContainsFunc(amr, func(v string) bool { return slices.Contains(a.AcceptedAMR, v) })
	acrHolds := acrSet && acr != "" && slices.Contains(a.AcceptedACR, acr)

	switch a.Match {
	case AssuranceMatchAny:
		return amrHolds || acrHolds
	case AssuranceMatchAll:
		return (amrSet || acrSet) && (!amrSet || amrHolds) && (!acrSet || acrHolds)
	default:
		return false
	}
}

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
func (m *RelyingParty) MeetsAssurance(ctx context.Context, user identity.UserID, ev policy.FederatedAssurance) (bool, error) {
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

var _ policy.FederatedAssuranceSource = (*RelyingParty)(nil)
