package recovery

//go:generate mockgen -source=reset.go -destination=reset_mock_test.go -package=recovery_test -typed

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
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

const (
	errTextResetListing = "recovery: authenticator listing failed"
	errTextResetPolicy  = "recovery: reset policy failed"
	errTextResetRemoval = "recovery: authenticator removal failed"
)

// errHeldRefInvalid is the cause behind a listing refused because a kind
// listed a reference that is not its own, has no identifier, or has one with a
// newline in it. It names no reference, since the kind is consumer code and
// its identifiers are its own business.
var errHeldRefInvalid = errors.New("recovery: an authenticator kind listed a malformed reference")

// errListingFailed marks every listing refusal, so the recovery can tell an
// outage it must not count against the user from a refusal it must.
var errListingFailed = errors.New(errTextResetListing)

// ResetInput is what a ResetPolicy decides from, for one recovery.
//
// Held is every authenticator the user holds, listed from every registered
// kind in registration order. Reported is what the user named as lost in the
// recovery request. Proven is what the user proved possession of in this
// recovery, such as {"mfa", "totp"} when a TOTP code was one of the proofs.
// The slices are the policy's own copies.
type ResetInput struct {
	User     identity.UserID
	Held     []AuthenticatorRef
	Reported []AuthenticatorRef
	Proven   []AuthenticatorRef
}

// ResetPolicy decides which of a user's authenticators a recovery removes. It
// replaces the default, which removes everything the user holds except what
// they proved in this recovery.
//
// It runs before anything is spent. The references it returns are removed
// when the recovery completes; any it returns that the user does not hold are
// ignored. An error refuses the recovery, and nothing is spent.
//
// A policy that returns nothing keeps every authenticator, and so leaves
// possibly compromised authenticators valid: the user recovered because they
// could not use them, and whoever holds them now still can. NIST SP 800-63B
// requires an authenticator reported lost or compromised to be invalidated.
// There is no built-in mode that keeps everything, so this is the only way to
// get that behaviour, and it is the consumer's decision to make and to own.
type ResetPolicy func(ctx context.Context, in ResetInput) ([]AuthenticatorRef, error)

// resetMode is how a planner decides what to remove.
type resetMode int

const (
	// resetAll removes everything held except what was proven. It is the
	// default.
	resetAll resetMode = iota
	// resetReported removes what the user reported lost, each of which must
	// be held. It trusts the user's report at the moment they are least sure
	// what happened to their authenticators: one they did not report stays
	// valid, even if it is in someone else's hands.
	resetReported
	// resetCustom removes what the consumer's ResetPolicy returns, among what
	// is held.
	resetCustom
)

// planner decides a recovery's authenticator reset before anything is spent,
// and carries it out when the recovery completes.
type planner struct {
	kinds  []AuthenticatorKind
	mode   resetMode
	policy ResetPolicy
}

// newPlanner validates the registered kinds and the mode. No kind, a nil kind,
// a Kind that is empty or contains a colon or a newline, two kinds sharing a
// Kind, or the custom mode with no policy is a configuration error wrapping
// ErrConfig.
func newPlanner(kinds []AuthenticatorKind, mode resetMode, policy ResetPolicy) (planner, error) {
	if len(kinds) == 0 {
		return planner{}, fmt.Errorf("%w: at least one authenticator kind is required", ErrConfig)
	}

	seen := make(map[string]bool, len(kinds))
	for i, k := range kinds {
		if nilcheck.IsNil(k) {
			return planner{}, fmt.Errorf("%w: authenticator kind %d is nil", ErrConfig, i)
		}

		name := k.Kind()
		if name == "" || strings.ContainsAny(name, ":\n") {
			return planner{}, fmt.Errorf("%w: authenticator kind %d has a name that is empty or contains a colon or newline", ErrConfig, i)
		}
		if seen[name] {
			return planner{}, fmt.Errorf("%w: authenticator kind %q is registered twice", ErrConfig, name)
		}

		seen[name] = true
	}

	if mode == resetCustom && policy == nil {
		return planner{}, fmt.Errorf("%w: a reset policy must not be nil", ErrConfig)
	}

	return planner{kinds: slices.Clone(kinds), mode: mode, policy: policy}, nil
}

// plan lists what user holds from every kind and decides what to remove.
//
// A listing failure refuses with no plan, and so does a listed reference that
// is not the listing kind's own, has an empty identifier, or has a newline in
// its identifier: records store references newline-joined, and a plan over a
// reference the kind does not own could not be carried out. Both are refused
// behind the same fixed text, since neither is the caller's mistake.
//
// In the reported mode, a request that reports nothing, reports an
// authenticator not held, or reports one it proved in the same recovery is
// ErrMalformed. A policy error refuses with no plan.
func (p planner) plan(ctx context.Context, user identity.UserID, reported, proven []AuthenticatorRef) ([]AuthenticatorRef, error) {
	return p.planOver(ctx, user, reported, proven, false)
}

// replan is plan as Finish runs it, over a held recovery's kept proofs and
// reported losses and what the user holds now. It differs in one way: in the
// reported mode a reported loss the user no longer holds is dropped rather
// than refused, since the user removed it during the hold and its loss is
// already remedied. Everything else is refused exactly as plan refuses it.
func (p planner) replan(ctx context.Context, user identity.UserID, reported, proven []AuthenticatorRef) ([]AuthenticatorRef, error) {
	return p.planOver(ctx, user, reported, proven, true)
}

// planOver lists what user holds and decides what to remove. dropUnheld makes
// the reported mode drop a reported loss that is not held, rather than refuse
// it.
func (p planner) planOver(
	ctx context.Context, user identity.UserID, reported, proven []AuthenticatorRef, dropUnheld bool,
) ([]AuthenticatorRef, error) {
	var held []AuthenticatorRef

	for _, k := range p.kinds {
		refs, err := k.Held(ctx, user)
		if err != nil {
			return nil, diag.Wrap(err, errTextResetListing, errListingFailed)
		}

		name := k.Kind()
		for _, r := range refs {
			if r.Kind != name || r.ID == "" || strings.Contains(r.ID, "\n") {
				return nil, diag.Wrap(errHeldRefInvalid, errTextResetListing, errListingFailed)
			}

			// The channel is not part of a reference's identity: reported
			// losses and proven authenticators carry none, so the plan
			// compares by kind and identifier alone.
			held = append(held, AuthenticatorRef{Kind: r.Kind, ID: r.ID})
		}
	}

	switch p.mode {
	case resetReported:
		if len(reported) == 0 {
			return nil, fmt.Errorf("%w: the reported-loss mode needs at least one reported loss", ErrMalformed)
		}

		for _, r := range reported {
			if hasRef(proven, r) {
				return nil, fmt.Errorf("%w: a reported loss was proven in the same recovery", ErrMalformed)
			}

			if !dropUnheld && !hasRef(held, r) {
				return nil, fmt.Errorf("%w: a reported loss is not held", ErrMalformed)
			}
		}

		return keep(held, reported), nil

	case resetCustom:
		chosen, err := p.policy(ctx, ResetInput{
			User:     user,
			Held:     slices.Clone(held),
			Reported: slices.Clone(reported),
			Proven:   slices.Clone(proven),
		})
		if err != nil {
			return nil, diag.Wrap(err, errTextResetPolicy)
		}

		return keep(held, chosen), nil

	default:
		return slices.DeleteFunc(held, func(r AuthenticatorRef) bool { return hasRef(proven, r) }), nil
	}
}

// hasRef reports whether refs holds r, comparing by kind and identifier alone.
// The channel is a display hint, not part of a reference's identity, so a ref a
// consumer's policy or a request returns with one set still names the same
// authenticator.
func hasRef(refs []AuthenticatorRef, r AuthenticatorRef) bool {
	return slices.ContainsFunc(refs, func(o AuthenticatorRef) bool { return o.Kind == r.Kind && o.ID == r.ID })
}

// keep returns the refs of held that are in chosen, in held's order, so a ref
// that is not held is dropped and a ref named twice is removed once.
func keep(held, chosen []AuthenticatorRef) []AuthenticatorRef {
	return slices.DeleteFunc(held, func(r AuthenticatorRef) bool { return !hasRef(chosen, r) })
}

// execute removes the planned authenticators, one Remove per kind in
// registration order, skipping kinds with nothing planned. The first error
// stops it and is returned; removals already done stay done.
func (p planner) execute(ctx context.Context, user identity.UserID, plan []AuthenticatorRef) error {
	for _, k := range p.kinds {
		name := k.Kind()

		var refs []AuthenticatorRef
		for _, r := range plan {
			if r.Kind == name {
				refs = append(refs, r)
			}
		}

		if len(refs) == 0 {
			continue
		}

		if err := k.Remove(ctx, user, refs); err != nil {
			return diag.Wrap(err, errTextResetRemoval)
		}
	}

	return nil
}
