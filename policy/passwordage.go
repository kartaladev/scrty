package policy

import (
	"context"
	"fmt"
	"time"
)

// defaultMaxPasswordAge is how old a password may be before this policy asks
// for a new one, with nothing configured. Ninety days is the rotation period
// most deployments are held to; it is a default rather than a rule, because a
// deployment with a stronger story about credential compromise is better
// served by a longer one than by users appending a digit every quarter.
const defaultMaxPasswordAge = 90 * 24 * time.Hour

// UnknownPasswordAge is what a PasswordAgePolicy does about a login whose
// password change time it does not know.
//
// It is its own type rather than a ChallengeKind so that the two cannot be
// confused: this says whether an unknown change time is challenged at all,
// while the challenge the policy then raises is always
// ChallengePasswordChange.
type UnknownPasswordAge int

const (
	// AllowUnknown lets a login through when the password change time is
	// unknown. It is the zero value, and so the default: a deployment that has
	// not started recording the change time keeps working, rather than
	// challenging every user at once the day the policy is registered.
	AllowUnknown UnknownPasswordAge = iota

	// ChallengeUnknown challenges such a login for a password change instead.
	// It is for the deployment that means every user to have a known, recent
	// password, and would rather a missing record be treated as an overdue
	// one.
	ChallengeUnknown
)

// PasswordAgeOption configures a PasswordAgePolicy. Every option names the
// default it replaces, and every default works with no configuration at all.
type PasswordAgeOption func(*PasswordAgePolicy)

// WithMaxPasswordAge replaces how old a password may be before the policy asks
// for a new one. The default is 90 days.
//
// Zero or less is a configuration error: every password ever set is older than
// zero, so the policy would challenge every login and the caller could never
// get past it to set a new one.
func WithMaxPasswordAge(d time.Duration) PasswordAgeOption {
	return func(p *PasswordAgePolicy) { p.maxAge = d }
}

// WithUnknownPasswordAge replaces what the policy does about a login whose
// password change time is unknown. The default is AllowUnknown.
//
// Passing ChallengeUnknown is how a deployment that treats a missing record as
// an overdue password gets that, without giving up the policy's behaviour for
// every user whose change time is recorded.
func WithUnknownPasswordAge(mode UnknownPasswordAge) PasswordAgeOption {
	return func(p *PasswordAgePolicy) { p.unknown = mode }
}

// PasswordAgePolicy challenges a login whose password is older than the
// maximum age, asking for a new password before the caller goes any further.
//
// It challenges rather than denies: the caller has proved who they are, and
// what is owed is a new password, not a refusal they can do nothing about.
// Every challenge it raises is ChallengePasswordChange.
//
// The age is measured from Input.PasswordChangedAt to Input.Now, so every
// policy in the phase judges the login against the same instant. A password
// exactly at the maximum age still passes; the age has to exceed it.
//
// # What it cannot see
//
// The policy reads Input.PasswordChangedAt and nothing else, and so it
// enforces nothing for a user whose change time is never written. By default
// an unknown change time allows, and WithUnknownPasswordAge(ChallengeUnknown)
// turns it into a challenge instead.
//
// Nothing in this package writes that value. Whoever stores the password owns
// it — the consumer, or the default identity store — and a deployment that
// never fills the column has registered a policy that can never fire. That is
// a property of the deployment, not a failure this policy can report: an
// unwritten change time is indistinguishable from a user who has never had a
// password.
//
// Do not refresh it from every federated login. A value rewritten whenever
// somebody signs in measures the age of the last sign-in rather than the age
// of the password, so it never exceeds the maximum and the policy silently
// never fires. Write it when the password itself changes, and at no other
// time.
//
// A PasswordAgePolicy is safe for concurrent use and holds no state between
// logins.
type PasswordAgePolicy struct {
	maxAge  time.Duration
	unknown UnknownPasswordAge
}

// Compile-time proof that this policy is one an Engine can hold.
var _ Policy = (*PasswordAgePolicy)(nil)

// NewPasswordAgePolicy returns a policy that challenges overdue passwords,
// with a maximum age of 90 days and an unknown change time allowed unless opts
// replace them.
//
// A maximum age of zero or less is a configuration error wrapping ErrConfig: it
// would challenge every login, including the one the caller needs in order to
// set a new password.
func NewPasswordAgePolicy(opts ...PasswordAgeOption) (*PasswordAgePolicy, error) {
	p := &PasswordAgePolicy{
		maxAge:  defaultMaxPasswordAge,
		unknown: AllowUnknown,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}

	if p.maxAge <= 0 {
		return nil, fmt.Errorf(
			"%w: maximum password age must be positive, got %s, or the policy "+
				"would challenge every login, including the one the caller "+
				"needs in order to set a new password",
			ErrConfig, p.maxAge)
	}
	if p.unknown != AllowUnknown && p.unknown != ChallengeUnknown {
		return nil, fmt.Errorf(
			"%w: unknown-password-age mode %d names neither AllowUnknown nor "+
				"ChallengeUnknown, and what it would do about an unrecorded "+
				"change time is nobody's decision",
			ErrConfig, int(p.unknown))
	}

	return p, nil
}

// Name identifies this policy in logs and in configuration errors.
func (p *PasswordAgePolicy) Name() string { return "password-age" }

// Phases reports that this policy runs once a login has succeeded, which is
// the last moment at which a login can still be turned into a challenge.
func (p *PasswordAgePolicy) Phases() []Phase { return []Phase{PostAuthentication} }

// Evaluate challenges for a password change when the password's age exceeds
// the maximum, and allows otherwise.
//
// An unknown change time — the zero time — is answered by the configured
// UnknownPasswordAge, which allows unless the consumer chose otherwise.
func (p *PasswordAgePolicy) Evaluate(_ context.Context, in *Input) Decision {
	var overdue bool
	if in.PasswordChangedAt.IsZero() {
		overdue = p.unknown == ChallengeUnknown
	} else {
		overdue = in.Now.Sub(in.PasswordChangedAt) > p.maxAge
	}

	if !overdue {
		return Decision{}
	}

	return Decision{Outcome: Challenge, Challenge: ChallengePasswordChange}
}
