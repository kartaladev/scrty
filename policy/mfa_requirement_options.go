package policy

import (
	"context"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
)

// FederatedAssuranceMode is what the requirement policy does with a required
// user's login on the factor.Federated channel whose provider assurance is not
// met. Met assurance allows in every mode.
type FederatedAssuranceMode int

const (
	// FederatedAssuranceChallenge challenges an unmet login for the library's
	// own second factor, and sends a user with no usable enrolment down the
	// enrolment path when it admits the login, or refuses them with
	// ErrMFAEnrolmentRequired. It is the default.
	FederatedAssuranceChallenge FederatedAssuranceMode = iota

	// FederatedAssuranceRefuse denies an unmet login with
	// ErrFederatedAssuranceNotMet, for a deployment in which the provider
	// must be the only authority on the second factor.
	FederatedAssuranceRefuse

	// FederatedAssuranceExempt allows every federated login, met or not,
	// before the requirement is looked up and without consulting the
	// assurance source or any enrolment. It is a total exemption: a required
	// user who logs in through a provider that checked only a password gets
	// in on that password. Choose it only when every provider is trusted to
	// enforce the second factor itself. A consumer exemption rule that marks
	// factor.OIDC exempt (WithMFAExemption) is equivalent. The second-factor
	// challenge policy, under WithMFAFederatedChallengeWhenUnmet(true), may still
	// challenge such a login.
	FederatedAssuranceExempt
)

// String names the mode, or prints an unnamed value as a number.
func (m FederatedAssuranceMode) String() string {
	switch m {
	case FederatedAssuranceChallenge:
		return "FederatedAssuranceChallenge"
	case FederatedAssuranceRefuse:
		return "FederatedAssuranceRefuse"
	case FederatedAssuranceExempt:
		return "FederatedAssuranceExempt"
	default:
		return unnamed("FederatedAssuranceMode", int(m))
	}
}

// WithMFARequirementFederatedAssurance replaces what the policy does with a required user's
// federated login whose provider assurance is not met. The default is
// FederatedAssuranceChallenge, which challenges it for the library's own
// second factor; FederatedAssuranceRefuse denies it with
// ErrFederatedAssuranceNotMet instead.
//
// FederatedAssuranceExempt is a bypass, not a stricter check: it lets a
// required user in on the provider's word alone, whatever the provider
// asserted, without looking up the requirement, the source or any enrolment.
// A consumer exemption rule that marks factor.OIDC exempt (WithMFAExemption)
// is the same bypass.
//
// Whether assurance is met is decided only by the source given to
// WithFederatedAssuranceSource; with none, it is never met. Met assurance
// allows in every mode. The mode governs this policy alone: the second-factor
// challenge policy has its own WithMFAFederatedChallengeWhenUnmet. A value that
// names no mode is a configuration error at construction.
func WithMFARequirementFederatedAssurance(mode FederatedAssuranceMode) MFARequirementOption {
	return mfaRequirementOption(func(p *MFARequirement) { p.federatedMode = mode })
}

// MFARequirementOption configures the policy NewMFARequirement returns.
// Every default that constructor applies has an option that replaces it.
//
// It is an interface rather than a function type so that WithMFAExemption,
// which governs a rule both MFA policies hold, can be given to either
// constructor under one name. A consumer implements nothing.
type MFARequirementOption interface {
	applyMFARequirement(*MFARequirement)
}

// mfaRequirementOption adapts a plain function into an MFARequirementOption.
type mfaRequirementOption func(*MFARequirement)

func (f mfaRequirementOption) applyMFARequirement(p *MFARequirement) { f(p) }

// WithMFARequiredForAll requires a second factor of every non-exempt user,
// without consulting the requirement lookup at all.
//
// The default is to ask the lookup per user. With this set the lookup is never
// called, so it may be omitted entirely — but a method must be configured, or
// the policy would demand of everyone something nobody could present.
//
// # Enrol users before enabling it
//
// By default this option locks out every user who has not enrolled. A user with
// no usable enrolment is refused at every non-exempt login, and a refusal is all
// they get: an enrolment offered to whoever just presented a first factor is a
// second factor an attacker can enrol for themselves, so it is not offered
// unless the consumer chooses to.
//
// So either enrol users first — out of band, or through a session established
// by a login this policy exempts — and enable this afterwards, or turn on the
// enrolment path with WithMFAEnrolmentPath, which sends such a user to a
// confined enrolment session instead, and accept what that path documents it
// gives a first factor. WithEnrolmentPathUntil closes the path again once the
// rollout is done.
func WithMFARequiredForAll() MFARequirementOption {
	return mfaRequirementOption(func(p *MFARequirement) { p.requiredForAll = true })
}

// WithMFARequirementLogger replaces where the policy writes its refusal and
// lookup-failure records. The default is slog.Default.
//
// Every record names the user by the opaque reference in Input.User, on
// purpose. A lookup-failure record carries the fixed reason
// "requirement-lookup" and the error's Go type, never its text; a consumer who
// wants the lookup's full error logs it inside their own
// identity.MFARequirementLookup.
//
// A nil logger is ignored rather than refused, so configuring logging stays
// optional.
func WithMFARequirementLogger(l *slog.Logger) MFARequirementOption {
	return mfaRequirementOption(func(p *MFARequirement) {
		if l != nil {
			p.logger = l
		}
	})
}

// WithMFARequirementLogInterval replaces how long one written record suppresses
// further records about the same thing. The default is DefaultLogInterval, one
// minute.
//
// An interval of zero or less writes every record. It governs this policy
// alone: the second-factor challenge policy keeps its own window under
// WithMFALogInterval, so an outage of the requirement lookup cannot
// silence the same-channel warnings.
func WithMFARequirementLogInterval(d time.Duration) MFARequirementOption {
	return mfaRequirementOption(func(p *MFARequirement) { p.logInterval = d })
}

// WithMFARequirementClock replaces the time source the policy samples its
// records by. The default is clock.System(), and a nil clock, typed nil
// included, is a configuration error.
//
// It is not the instant a decision is judged against — that is Input.Now, taken
// from the caller's clock so that every policy in a phase agrees.
func WithMFARequirementClock(clk clock.Clock) MFARequirementOption {
	return mfaRequirementOption(func(p *MFARequirement) { p.clock = clk })
}

// WithMFARequirementPhaseSource replaces how the policy learns which phase it
// is being evaluated in. The default reads the phase from the context, where
// Engine.EvaluatePhase puts it.
//
// The policy answers differently per phase and Input carries no phase, so it
// has to be told. A consumer whose call path cannot reach the context — or who
// would rather derive the phase from the request itself — supplies a rule here
// instead. The rule reports the phase and whether it could identify one at all;
// reporting false refuses the evaluation with ErrMFARequired, which is the safe
// answer when a login and a stateless request cannot be told apart.
//
// A nil rule is a configuration error: the policy would refuse every request.
func WithMFARequirementPhaseSource(
	phaseOf func(ctx context.Context, in *Input) (Phase, bool),
) MFARequirementOption {
	return mfaRequirementOption(func(p *MFARequirement) { p.phaseOf = phaseOf })
}
