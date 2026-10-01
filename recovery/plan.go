package recovery

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

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
		}

		held = append(held, refs...)
	}

	switch p.mode {
	case resetReported:
		if len(reported) == 0 {
			return nil, fmt.Errorf("%w: the reported-loss mode needs at least one reported loss", ErrMalformed)
		}

		for _, r := range reported {
			if slices.Contains(proven, r) {
				return nil, fmt.Errorf("%w: a reported loss was proven in the same recovery", ErrMalformed)
			}

			if !dropUnheld && !slices.Contains(held, r) {
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
		return slices.DeleteFunc(held, func(r AuthenticatorRef) bool { return slices.Contains(proven, r) }), nil
	}
}

// keep returns the refs of held that are in chosen, in held's order, so a ref
// that is not held is dropped and a ref named twice is removed once.
func keep(held, chosen []AuthenticatorRef) []AuthenticatorRef {
	return slices.DeleteFunc(held, func(r AuthenticatorRef) bool { return !slices.Contains(chosen, r) })
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
