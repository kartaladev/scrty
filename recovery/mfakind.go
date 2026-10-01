package recovery

//go:generate mockgen -destination=mfamethod_mock_test.go -package=recovery_test -typed github.com/kartaladev/scrty/mfa Method,EnrolmentRemover

import (
	"context"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/mfa"
)

// MFAKind is the Kind of the authenticators MFAEnrolments lists: one reference
// per enrolled method, with the method's name as the identifier, as
// {"mfa", "totp"}.
const MFAKind = "mfa"

const (
	errTextMFALookup  = "recovery: mfa enrolment lookup failed"
	errTextMFARemoval = "recovery: mfa enrolment removal failed"
)

// MFAEnrolments returns the authenticator kind over a set of MFA methods, so a
// recovery resets the user's second factors. Its Kind is MFAKind.
//
// Held lists, in the order the methods are given, every method whose Enrolled
// reports a confirmed enrolment for the user. A lookup that fails is returned
// as an error, never taken as holding nothing, so a recovery is refused rather
// than planned over an incomplete list.
//
// Remove removes each named enrolment through that method's
// mfa.EnrolmentRemover, in the order of the references, and stops at the first
// error. A reference to a method not in the set is ignored.
//
// Every method must implement mfa.EnrolmentRemover, since a method whose
// enrolment a recovery cannot remove would stay valid after the user reported
// it lost. The set is validated by mfa.LookupsFor, so an empty set, a nil
// method, duplicate names or any other wrongly declared method is refused too.
// Every refusal wraps ErrConfig.
//
// There is no default set: the library cannot guess which methods a consumer
// serves.
func MFAEnrolments(methods ...mfa.Method) (AuthenticatorKind, error) {
	if _, err := mfa.LookupsFor(methods...); err != nil {
		return nil, fmt.Errorf("%w: mfa enrolments: %w", ErrConfig, err)
	}

	k := mfaKind{methods: slices.Clone(methods), removers: make(map[string]mfa.EnrolmentRemover, len(methods))}
	for i, m := range methods {
		r, ok := m.(mfa.EnrolmentRemover)
		if !ok {
			return nil, fmt.Errorf("%w: mfa enrolments: method %d (%q) cannot remove enrolments", ErrConfig, i, m.Name())
		}

		k.removers[m.Name()] = r
	}

	return k, nil
}

// mfaKind is the AuthenticatorKind over a validated set of MFA methods.
type mfaKind struct {
	methods  []mfa.Method
	removers map[string]mfa.EnrolmentRemover
}

func (mfaKind) Kind() string { return MFAKind }

func (k mfaKind) Held(ctx context.Context, user identity.UserID) ([]AuthenticatorRef, error) {
	var refs []AuthenticatorRef

	for _, m := range k.methods {
		enrolled, err := m.Enrolled(ctx, user)
		if err != nil {
			return nil, diag.Wrap(err, errTextMFALookup)
		}

		if enrolled {
			refs = append(refs, AuthenticatorRef{Kind: MFAKind, ID: m.Name()})
		}
	}

	return refs, nil
}

func (k mfaKind) Remove(ctx context.Context, user identity.UserID, refs []AuthenticatorRef) error {
	for _, ref := range refs {
		r, ok := k.removers[ref.ID]
		if !ok || ref.Kind != MFAKind {
			continue
		}

		if err := r.RemoveEnrolment(ctx, user); err != nil {
			return diag.Wrap(err, errTextMFARemoval)
		}
	}

	return nil
}
