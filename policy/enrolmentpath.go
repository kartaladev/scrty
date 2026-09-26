package policy

import (
	"fmt"
	"time"

	"github.com/kartaladev/scrty/factor"
)

// EnrolmentPathOption configures the enrolment path WithMFAEnrolmentPath turns
// on. Every default the path applies has an option that replaces it.
//
// It is an interface so that a consumer implements nothing: the options this
// package returns are the only values that satisfy it.
type EnrolmentPathOption interface {
	applyEnrolmentPath(*enrolmentPath)
}

// enrolmentPathOption adapts a plain function into an EnrolmentPathOption.
type enrolmentPathOption func(*enrolmentPath)

func (f enrolmentPathOption) applyEnrolmentPath(e *enrolmentPath) { f(e) }

// WithMFAEnrolmentPath turns on the enrolment path: a user who must use a
// second factor, and has no usable enrolment, is challenged with
// ChallengeMFAEnrolment instead of being refused with ErrMFAEnrollmentRequired.
//
// The default is off, and with it off every decision is the one the policy
// made before the path existed.
//
// # What it gives a first factor
//
// With the path on, whoever holds a first factor the path admits — a password,
// by default — may bind a second factor for the user. That is a change in the
// threat model, which is why the path is off unless a consumer turns it on. The
// chain's enrolment interceptor carries the mitigations: a session confined to
// the enrolment endpoints, an emailed code that proves the mailbox before an
// enrolment counts, and a notification when one does.
//
// # What it admits
//
// The path is entered only when every one of these holds; otherwise the policy
// refuses with ErrMFAEnrollmentRequired, as it would with the path off:
//
//   - the path has not been closed (WithEnrolmentPathUntil);
//   - the phase is post-authentication or per-request — a stateless request has
//     no session to confine, and is refused with ErrMFARequired as before;
//   - the first factor's kind is on the path's allowlist
//     (WithEnrolmentFirstFactors);
//   - the MFA method's channel differs from the first factor's, because an
//     enrolment on the first factor's own channel would leave the user no more
//     usable than before.
//
// A failed enrolment lookup is refused whether the path is on or off.
//
// # Pair it with the chain
//
// With the path on the policy declares ChallengeMFAEnrolment through
// Challenger, so a chain that has no enrolment interceptor refuses to assemble.
// Turn the path on here and enable the enrolment interceptor on the chain
// together.
//
// # The same method on both sides
//
// The MFAMethodLookup this policy was built with and the method the chain's
// EnableMFA was given must be the same method. Nothing can check it: the policy
// sees only the lookup. If they differ, the same-channel test above uses the
// lookup's channel while the enrolment begin uses the method's, so a login
// the policy admits to the path can be refused at begin as same-channel, and
// that user stays confined until the enrolment-only session ends.
func WithMFAEnrolmentPath(opts ...EnrolmentPathOption) MFARequirementOption {
	return mfaRequirementOption(func(p *mfaRequirementPolicy) {
		e := &enrolmentPath{firstFactors: defaultEnrolmentFirstFactors()}
		for _, opt := range opts {
			if opt != nil {
				opt.applyEnrolmentPath(e)
			}
		}

		p.enrolment = e
	})
}

// WithEnrolmentFirstFactors replaces the allowlist of first-factor kinds whose
// logins may enter the enrolment path. The default is factor.Password,
// factor.MagicLink and the empty kind — a login that did not record its first
// factor. The kinds given replace that list; they are not added to it, so a
// consumer who wants to keep a default kind lists it.
//
// The list governs only whether a login the policy would otherwise refuse with
// ErrMFAEnrollmentRequired enters the path. It changes neither whether a user
// is required to use a second factor nor which first factors are exempt
// (WithMFAExemption): an exempt login is allowed before the path is consulted,
// whatever the list says.
//
// # Adding OIDC
//
// factor.OIDC is off the default list. A stolen identity-provider account
// usually includes its mailbox, so the emailed code the enrolment path sends
// adds no assurance after a federated login, and the notification may reach
// the attacker too. Adding it is a deliberate choice to accept that. By default
// an OIDC login is exempt and never reaches the path; the list matters only to
// a consumer whose exemption rule makes it non-exempt.
//
// The same limit holds, less starkly, for factor.MagicLink, whose login already
// proved control of the mailbox. A consumer who finds that unacceptable leaves
// it off.
//
// # Kinds that can never be listed
//
// factor.APIKey and factor.Basic authenticate statelessly and have no session
// to confine, so listing either fails construction, wrapping ErrConfig. So does
// an empty list: the path would admit nothing, yet the policy would still
// declare the enrolment challenge and demand its interceptor.
func WithEnrolmentFirstFactors(kinds ...factor.Kind) EnrolmentPathOption {
	return enrolmentPathOption(func(e *enrolmentPath) {
		e.firstFactors = make(map[factor.Kind]bool, len(kinds))
		for _, k := range kinds {
			e.firstFactors[k] = true
		}
	})
}

// WithEnrolmentPathUntil closes the enrolment path at an instant. From that
// instant on, a required user with no usable enrolment is refused with
// ErrMFAEnrollmentRequired, as with the path off. The default is no instant: the
// path stays open for as long as it is enabled. The zero time also means no
// instant.
//
// It is meant for a require-for-all rollout: open the path, let the user base
// enrol, and close it at a date chosen in advance, without redeploying.
//
// The instant is compared with Input.Now, the instant every policy in the phase
// judges against, and not with the clock WithMFARequirementClock replaces,
// which only samples records.
func WithEnrolmentPathUntil(t time.Time) EnrolmentPathOption {
	return enrolmentPathOption(func(e *enrolmentPath) { e.until = t })
}

// enrolmentPath is the enrolment path's configuration. It is fixed at
// construction, so it is safe for concurrent use.
type enrolmentPath struct {
	// firstFactors is the allowlist of first-factor kinds that may enter the
	// path.
	firstFactors map[factor.Kind]bool

	// until is the instant the path closes at. The zero time leaves it open.
	until time.Time
}

// defaultEnrolmentFirstFactors is the allowlist a path starts with: password,
// magic link, and a first factor the login did not record.
func defaultEnrolmentFirstFactors() map[factor.Kind]bool {
	return map[factor.Kind]bool{factor.Password: true, factor.MagicLink: true, "": true}
}

// admits reports whether a required user with no usable enrolment is
// challenged for enrolment rather than refused. method is never nil here: a
// policy with no method refuses before it asks.
func (e *enrolmentPath) admits(in *Input, phase Phase, method MFAMethodLookup) bool {
	if phase != PostAuthentication && phase != PerRequest {
		return false
	}

	if !e.until.IsZero() && !in.Now.Before(e.until) {
		return false
	}

	if !e.firstFactors[in.FirstFactor] {
		return false
	}

	return method.Channel() != in.FirstFactor.Channel()
}

// validate reports a path that could never work as configured.
func (e *enrolmentPath) validate() error {
	if len(e.firstFactors) == 0 {
		return fmt.Errorf("%w: the enrolment path admits no first factor, so it could never be "+
			"entered", ErrConfig)
	}

	for _, k := range []factor.Kind{factor.APIKey, factor.Basic} {
		if e.firstFactors[k] {
			return fmt.Errorf("%w: the enrolment path cannot admit the %q first factor: it "+
				"authenticates statelessly and has no session to confine", ErrConfig, k)
		}
	}

	return nil
}
