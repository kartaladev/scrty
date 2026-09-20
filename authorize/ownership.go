package authorize

import (
	"context"
	"fmt"
	"strings"

	"github.com/kartaladev/scrty/identity"
)

// OwnershipAuthorizer judges OwnershipAttributes by asking the consumer's own
// functions who owns the record and whether that is the subject.
//
// It holds no state and knows nothing about the consumer's data: what the
// record is, how a request names it and what owning it means all arrive with
// the attributes. That is deliberate — ownership is the one authorization
// question whose answer lives entirely in the consumer's tables, and a library
// that guessed at it would be guessing about their schema.
//
// It declines every other kind of attributes, so it can sit in a Manager beside
// authorizers that judge them.
type OwnershipAuthorizer struct{}

var _ Authorizer = (*OwnershipAuthorizer)(nil)

// NewOwnershipAuthorizer returns an ownership authorizer.
//
// It reports no error because there is nothing to misconfigure: everything this
// authorizer needs comes with each set of attributes, and attributes that are
// missing a piece are refused when they are presented, as ErrInvalidAttributes.
// It is a constructor rather than an exported zero value so that options can be
// added later without changing how consumers build one.
func NewOwnershipAuthorizer() *OwnershipAuthorizer {
	return &OwnershipAuthorizer{}
}

// Authorize reports whether the subject owns the record attrs identify.
//
// The consumer's functions run in order — resolve, then check — and only when
// there is a subject for them to be about. Their errors are wrapped rather than
// turned into denials: neither "the record could not be identified" nor "the
// ownership table could not be read" is a statement about this caller, and a
// caller that logged denials as refused attempts would otherwise record an
// outage as someone trying what they may not do.
func (a *OwnershipAuthorizer) Authorize(ctx context.Context, attrs Attributes) error {
	owned, err := ownershipAttributes(attrs)
	if err != nil {
		return err
	}

	// The subject is read before anything else runs: a consumer's check takes a
	// principal, and handing it a nil one would make every implementation carry
	// a nil guard of its own — the one an implementation forgets.
	subject, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return fmt.Errorf("%w: the request carries no subject to own anything", ErrAccessDenied)
	}

	id, err := owned.ResolveID(ctx)
	if err != nil {
		return fmt.Errorf("authorize: resolve %s/%s identifier: %w", owned.Group, owned.Resource, err)
	}

	// The identifier passes through untouched: it is the consumer's own, and
	// trimming or case-folding it here would look up a different record than
	// the one the request named.
	isOwner, err := owned.OwnedBy(ctx, subject, id)
	if err != nil {
		// The ownership answer is not read when the check failed, however it
		// was returned: a function that reports an error has not judged, and
		// taking its bool anyway would let a zero value decide.
		return fmt.Errorf("authorize: check ownership of %s/%s: %w", owned.Group, owned.Resource, err)
	}

	if !isOwner {
		return fmt.Errorf("%w: the subject does not own the %s/%s in question",
			ErrAccessDenied, owned.Group, owned.Resource)
	}

	return nil
}

// ownershipAttributes narrows attrs to the kind this authorizer judges and
// reports whether their content can be used.
//
// Both the value and the pointer form are accepted, for the same reason
// privilegeAttributes accepts both. A missing resolver or check is refused
// rather than treated as "no ownership constraint": attributes that check
// nothing would allow everyone while reading, at the call site, as an ownership
// check.
func ownershipAttributes(attrs Attributes) (OwnershipAttributes, error) {
	var owned OwnershipAttributes

	switch v := attrs.(type) {
	case OwnershipAttributes:
		owned = v
	case *OwnershipAttributes:
		if v == nil {
			return owned, fmt.Errorf("%w: the ownership attributes are absent", ErrInvalidAttributes)
		}

		owned = *v
	default:
		return owned, fmt.Errorf("%w: %T is not ownership attributes", ErrUnsupportedAttributes, attrs)
	}

	if strings.TrimSpace(owned.Group) == "" {
		return owned, fmt.Errorf("%w: the ownership attributes name no group", ErrInvalidAttributes)
	}

	if strings.TrimSpace(owned.Resource) == "" {
		return owned, fmt.Errorf("%w: the ownership attributes name no resource", ErrInvalidAttributes)
	}

	if owned.ResolveID == nil {
		return owned, fmt.Errorf("%w: the ownership attributes have no identifier resolver",
			ErrInvalidAttributes)
	}

	if owned.OwnedBy == nil {
		return owned, fmt.Errorf("%w: the ownership attributes have no ownership check", ErrInvalidAttributes)
	}

	return owned, nil
}
