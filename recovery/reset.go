package recovery

//go:generate mockgen -source=reset.go -destination=reset_mock_test.go -package=recovery_test -typed

import (
	"context"
	"fmt"
	"strings"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
)

// AuthenticatorRef names one authenticator a user holds: the kind that manages
// it, and the kind's own identifier for it. The MFA kind, for one, names each
// enrolment by its method, as {"mfa", "totp"}.
//
// Neither part is ever empty, and neither contains a newline. The kind never
// contains a colon; the identifier may.
//
// Channel is the medium the authenticator's codes travel over, where it has
// one, such as factor.Email for an MFA method that mails its codes. It is
// reported by a kind's UsableLister for the way-back check, which does not
// pair an email-channel authenticator with an issued code, since both would
// arrive in one mailbox. MFAEnrolments fills it from each method's declared
// channel; it is empty for a password or a passkey. It is not part of the
// reference's identity: String omits it, a parsed reference has none, and the
// recovery reset compares references by Kind and ID alone.
type AuthenticatorRef struct {
	Kind    string
	ID      string
	Channel factor.Channel
}

// String returns the reference as "kind:id", the form a recovery request names
// a reported loss in and a durable record stores. Channel is not included.
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
//
// The way-back check also reads registered kinds, counting every held
// authenticator as one the user can sign in with. A kind that can hold
// authenticators which cannot authenticate now also implements UsableLister,
// so the check counts only its usable ones while the reset still removes
// everything Held lists.
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

// UsableLister is implemented by an AuthenticatorKind that can hold
// authenticators which cannot authenticate now, such as a passkey awaiting
// confirmation or one suspended as a suspected clone, or that reports each
// usable authenticator's delivery channel in AuthenticatorRef.Channel.
//
// The way-back check counts what Usable lists, so an authenticator the user
// cannot sign in with is never their way back in. The recovery reset keeps
// using Held, so it still removes every authenticator the user holds, usable
// or not. A kind that does not implement it has every held authenticator
// counted as usable, with no channel. MFAEnrolments implements it to report
// each enrolled method's channel, so an email-channel method is not counted as
// pairing with an issued code.
type UsableLister interface {
	// Usable lists the authenticators user holds that can authenticate now,
	// each with Kind set to this kind and Channel set where the authenticator
	// has a delivery channel. A lookup that fails is an error, never an empty
	// list, so the check never reports no on a failed lookup.
	Usable(ctx context.Context, user identity.UserID) ([]AuthenticatorRef, error)
}
