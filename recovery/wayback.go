package recovery

//go:generate mockgen -destination=userloader_mock_test.go -package=recovery_test -typed github.com/kartaladev/scrty/identity UserLoader
//go:generate mockgen -destination=requirementlookup_mock_test.go -package=recovery_test -typed github.com/kartaladev/scrty/identity MFARequirementLookup

import (
	"context"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

const (
	errTextWayBackUser  = "recovery: user lookup failed"
	errTextWayBackLinks = "recovery: linked-login lookup failed"
	errTextWayBackAdmit = "recovery: linked-login admission lookup failed"
)

// WayBackDeps are what a WayBackCheck reads.
type WayBackDeps struct {
	// Users loads the user, for whether they have a password. Required.
	Users identity.UserLoader

	// Codes reports the user's unspent saved codes. Required.
	Codes *Codes

	// Kinds are the authenticator kinds registered with the recovery reset,
	// such as MFAEnrolments. A user holding a usable authenticator of any of
	// them can pair it with an issued code; see UsableLister. None is allowed:
	// then only a password counts for pairing.
	Kinds []AuthenticatorKind

	// IssuedCodes reports whether issued codes are enabled, so a password or
	// an authenticator can pair with one. The default, false, counts neither.
	IssuedCodes bool

	// LinkedLogins lists the kinds of the federated logins linked to the user.
	// Optional: with none, linked logins do not count.
	LinkedLogins func(ctx context.Context, user identity.UserID) ([]factor.Kind, error)

	// Admits reports whether a login of a linked identity's kind would admit
	// the user without a local second factor, whatever its provider asserts.
	// A linked identity counts as a way back only when it says true. An error
	// fails the check, which returns it under fixed text, never no or yes.
	//
	// The default, when nil, is factor.Kind.MFAExempt, which exempts api-key
	// alone: under it a linked OIDC identity never counts. A consumer who links
	// OIDC identities and wants them counted wires the MFA requirement policy's
	// own answer, so the check and the login cannot disagree:
	//
	//	adm := requirementPolicy.(policy.LoginAdmission)
	//	deps.Admits = adm.AdmitsWithoutLocalSecondFactor
	//
	// That answer is yes in FederatedAssuranceExempt mode, for a kind the
	// policy's exemption rule marks, and for a user not required to use a
	// second factor. Provider assurance is never assumed: it is known only at
	// a login, so a required user's linked identity does not count on a
	// provider's word it has not yet given.
	//
	// The answer is the requirement policy's alone. The second-factor
	// challenge policy under policy.WithFederatedChallengeWhenUnmet(true)
	// still challenges an enrolled user's federated login whose provider
	// assurance is not met, required or not. A consumer who sets that option
	// wires an Admits that answers false for such users, or the check may
	// count a login the challenge policy would then challenge.
	Admits func(ctx context.Context, user identity.UserID, kind factor.Kind) (bool, error)
}

// WayBackOption configures a WayBackCheck. None exists yet; the parameter is
// there so options can be added without changing NewWayBackCheck's signature.
type WayBackOption func(*WayBackCheck)

// WayBackCheck reports whether a user has a way back into their account other
// than saved codes they have yet to generate. A registration flow that creates
// an account with no password, for one, asks it before letting the user go
// without saved codes.
type WayBackCheck struct {
	users        identity.UserLoader
	codes        *Codes
	kinds        []AuthenticatorKind
	issuedCodes  bool
	linkedLogins func(ctx context.Context, user identity.UserID) ([]factor.Kind, error)
	admits       func(ctx context.Context, user identity.UserID, kind factor.Kind) (bool, error)
}

// NewWayBackCheck returns a way-back check over deps.
//
// A nil Users (typed nil included), a nil Codes or a nil kind is a
// configuration error wrapping ErrConfig. A nil Admits counts a linked login
// only when factor.Kind.MFAExempt exempts its kind. A nil option is ignored.
func NewWayBackCheck(deps WayBackDeps, opts ...WayBackOption) (*WayBackCheck, error) {
	if nilcheck.IsNil(deps.Users) {
		return nil, fmt.Errorf("%w: way-back check: user loader must not be nil", ErrConfig)
	}
	if deps.Codes == nil {
		return nil, fmt.Errorf("%w: way-back check: codes must not be nil", ErrConfig)
	}
	for i, k := range deps.Kinds {
		if nilcheck.IsNil(k) {
			return nil, fmt.Errorf("%w: way-back check: authenticator kind %d is nil", ErrConfig, i)
		}
	}

	c := &WayBackCheck{
		users:        deps.Users,
		codes:        deps.Codes,
		kinds:        slices.Clone(deps.Kinds),
		issuedCodes:  deps.IssuedCodes,
		linkedLogins: deps.LinkedLogins,
		admits:       deps.Admits,
	}
	if c.admits == nil {
		c.admits = admittedByKind
	}

	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}

	return c, nil
}

// HasWayBack reports whether user has another way back in. It is yes when any
// of these holds:
//   - the user holds at least one unspent saved code;
//   - issued codes are enabled, and the user has a password or holds a usable
//     authenticator of a registered kind, either of which pairs with an issued
//     code. A kind implementing UsableLister is counted by what Usable lists,
//     so a pending or suspended authenticator does not count; any other kind
//     is counted by what Held lists;
//   - a linked login would be admitted without a local second factor, as
//     WayBackDeps.Admits answers. Provider assurance is never assumed.
//
// It checks in that order, cheapest first, and stops at the first yes. With
// issued codes disabled it neither loads the user nor lists their
// authenticators, since neither could count. Any lookup that fails, including
// a user the loader does not find, is returned as an error, never as no.
//
// Linked logins count only when WayBackDeps.LinkedLogins is supplied. The
// identity-linking store cannot list a user's links, so with no lookup the
// library cannot see them, and they do not count. That fails safe: a user
// with a linked login is asked for saved codes they may not need, rather than
// let go without a way back they may not have.
func (c *WayBackCheck) HasWayBack(ctx context.Context, user identity.UserID) (bool, error) {
	count, err := c.codes.Remaining(ctx, user)
	if err != nil {
		return false, err
	}
	if count.N > 0 {
		return true, nil
	}

	if c.issuedCodes {
		ok, err := c.pairsWithIssuedCode(ctx, user)
		if err != nil || ok {
			return ok, err
		}
	}

	if c.linkedLogins == nil {
		return false, nil
	}

	kinds, err := c.linkedLogins(ctx, user)
	if err != nil {
		return false, diag.Wrap(err, errTextWayBackLinks)
	}

	for _, k := range kinds {
		ok, err := c.admits(ctx, user, k)
		if err != nil {
			return false, diag.Wrap(err, errTextWayBackAdmit)
		}
		if ok {
			return true, nil
		}
	}

	return false, nil
}

// admittedByKind is WayBackDeps.Admits' default: a login is admitted without a
// local second factor only when its kind is exempt by factor.Kind.MFAExempt.
func admittedByKind(_ context.Context, _ identity.UserID, kind factor.Kind) (bool, error) {
	return kind.MFAExempt(), nil
}

// pairsWithIssuedCode reports whether user has a password or holds a usable
// authenticator of a registered kind.
func (c *WayBackCheck) pairsWithIssuedCode(ctx context.Context, user identity.UserID) (bool, error) {
	d, err := c.users.LoadByUserID(ctx, user)
	if err != nil {
		return false, diag.Wrap(err, errTextWayBackUser)
	}
	if len(d.Password) > 0 {
		return true, nil
	}

	for _, k := range c.kinds {
		refs, err := usable(ctx, k, user)
		if err != nil {
			return false, diag.Wrap(err, errTextResetListing)
		}
		if len(refs) > 0 {
			return true, nil
		}
	}

	return false, nil
}

// usable lists the authenticators of kind k that user can authenticate with
// now: what k's UsableLister reports when k implements it, and everything k
// holds otherwise.
func usable(ctx context.Context, k AuthenticatorKind, user identity.UserID) ([]AuthenticatorRef, error) {
	if u, ok := k.(UsableLister); ok {
		return u.Usable(ctx, user)
	}

	return k.Held(ctx, user)
}
