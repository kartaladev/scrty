package recovery

//go:generate mockgen -source=reset.go -destination=reset_mock_test.go -package=recovery_test -typed

import (
	"context"
	"fmt"
	"strings"

	"github.com/kartaladev/scrty/identity"
)

// AuthenticatorRef names one authenticator a user holds: the kind that manages
// it, and the kind's own identifier for it. The MFA kind, for one, names each
// enrolment by its method, as {"mfa", "totp"}.
//
// Neither part is ever empty, and neither contains a newline. The kind never
// contains a colon; the identifier may.
type AuthenticatorRef struct {
	Kind string
	ID   string
}

// String returns the reference as "kind:id", the form a recovery request names
// a reported loss in and a durable record stores.
func (r AuthenticatorRef) String() string { return r.Kind + ":" + r.ID }

// ParseAuthenticatorRef reads a "kind:id" reference. The kind ends at the first
// colon, so an identifier may itself contain colons.
//
// Text with no colon, an empty kind or identifier, or a newline anywhere is
// ErrMalformed.
func ParseAuthenticatorRef(s string) (AuthenticatorRef, error) {
	if strings.Contains(s, "\n") {
		return AuthenticatorRef{}, fmt.Errorf("%w: authenticator reference contains a newline", ErrMalformed)
	}

	kind, ref, ok := strings.Cut(s, ":")
	if !ok || kind == "" || ref == "" {
		return AuthenticatorRef{}, fmt.Errorf("%w: authenticator reference is not kind:id", ErrMalformed)
	}

	return AuthenticatorRef{Kind: kind, ID: ref}, nil
}

// AuthenticatorKind is one kind of authenticator a recovery can reset: it lists
// what a user holds, and removes what it is told to.
//
// A recovery lists every registered kind before anything is spent, and removes
// the planned authenticators when the recovery completes. MFAEnrolments is the
// kind the library provides; a consumer's own authenticators take part in the
// reset by implementing this interface.
type AuthenticatorKind interface {
	// Kind names this kind. It is constant, not empty, unique among the kinds
	// registered, and contains neither a colon nor a newline.
	Kind() string

	// Held lists the authenticators user holds, each with Kind set to this
	// kind. A lookup that fails is an error, never an empty list: a recovery
	// planned over a list that silently lost an authenticator would leave it
	// valid.
	Held(ctx context.Context, user identity.UserID) ([]AuthenticatorRef, error)

	// Remove removes user's authenticators named by refs, all of this kind.
	// A reference to something the user no longer holds is not an error.
	Remove(ctx context.Context, user identity.UserID, refs []AuthenticatorRef) error
}
