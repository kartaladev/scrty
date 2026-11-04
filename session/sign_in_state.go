package session

import (
	"context"
	"errors"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// SignInState is what Sessions.SignInState reads of a sign-in's current
// session. It holds no session identifier and no sealed field.
type SignInState struct {
	// IdleDeadline and AbsoluteDeadline are the current session's own two
	// deadlines. A renewal, a strict rotation or recorded activity can move
	// them, so a holder reads them again rather than trusting an earlier
	// answer.
	IdleDeadline, AbsoluteDeadline time.Time

	// AuthenticatedAt is when the sign-in last proved who it is. A step-up
	// moves it. It is zero for a session that recorded none.
	AuthenticatedAt time.Time

	// ExternalIssuer and ExternalSessionID are the upstream provider's issuer
	// and session, both empty for a sign-in no provider was involved in.
	ExternalIssuer, ExternalSessionID string
}

// errListingAnsweredNotFound stands in for a store's ErrNotFound from a
// listing. See SignInState.
var errListingAnsweredNotFound = errors.New("session: the store answered a listing with not found")

// SignInState reads where one of user's sign-ins stands, from the current
// session of family, at the manager's clock. It is the read for a long-lived
// observer, such as a stream, that names a sign-in and goes on watching it after
// the request that opened it has gone: it holds a user and a family, because an
// identifier it held would stop answering when the sign-in renews.
//
// It is built on Store.ListByUser alone, one query, and that is the whole of its
// effect: it records no presentation, judges nothing, revokes nothing, reports
// nothing and opens no sealed field, so it answers under a sealing store whose
// key was retired. That is what sets it apart from Load. Load is a presentation
// of an identifier: it marks a first use, and past a renewal's grace window it
// revokes the family as reuse, so an observer reloading through Load would sign
// its user out and raise a false theft alarm. For the same reason a family that
// was renewed or rotated strictly answers here with its new current session, and
// the sign-in carries on.
//
// It answers ErrNotFound when family has no live current session: it was ended,
// or its current session reached either deadline. It answers the same for
// another user's family, so a caller learns nothing about other users'
// sign-ins, and for the nil family and an empty user, which name no one and are
// not asked of the store.
//
// The manager does not rely on the store's filtering: a session of another
// user, a superseded one, or one past either deadline at the manager's clock
// does not count, whatever the store answered. A store listing two live sessions
// of one family has the one used last answer, as ListSignIns has it, and of two
// used at the same instant the one with the later idle deadline, so the answer
// does not depend on the listing's order.
//
// A store failure is never ErrNotFound, because a caller closes on that answer
// and an outage says nothing about the sign-in. It is returned as
// ErrListUnavailable, the store's error reachable through errors.Is and errors.As
// behind that fixed text. A failure caused by ctx ending first, a caller that
// hung up or a read that timed out, is returned matching ctx's error instead, and
// not ErrListUnavailable. A listing has no "not found" of its own, since no match
// is an empty result (see Store.ListByUser), so a store failing with ErrNotFound
// is a failure too, and comes back as ErrListUnavailable without it.
//
// Two limits follow from reading only a listing. A listing shows no superseded
// session, so where a successor dies before its predecessor, under a successor
// lifetime shorter than the grace window or idle timeout, the answer is
// ErrNotFound while the predecessor can still load or renew. And a store fails a
// listing it cannot read in full, so one unreadable session of a user makes this
// a failure for all of that user's sign-ins, ended ones included, until the row
// is repaired.
//
// The answer says only that the sign-in is live. It does not say the sign-in has
// finished what it owes, such as a second factor (see ListSignIns), or that its
// user is still active, which the user's own store decides.
func (m *Sessions) SignInState(ctx context.Context, user identity.UserID, family id.ID) (SignInState, error) {
	if user == "" || family.IsZero() {
		return SignInState{}, ErrNotFound
	}

	now := m.clock.Now()
	listed, err := m.store.ListByUser(ctx, user, now)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			err = errListingAnsweredNotFound
		}

		return SignInState{}, listingFailed(ctx, err)
	}

	var current *Session
	for _, s := range listed {
		if s == nil || s.UserID != user || s.FamilyID != family || s.superseded() || s.expired(now) {
			continue
		}
		if current == nil || currentOverride(s, current) {
			current = s
		}
	}
	if current == nil {
		return SignInState{}, ErrNotFound
	}

	return SignInState{
		IdleDeadline:      current.IdleExpiresAt,
		AbsoluteDeadline:  current.AbsoluteExpiresAt,
		AuthenticatedAt:   current.AuthenticatedAt,
		ExternalIssuer:    current.ExternalIssuer,
		ExternalSessionID: current.ExternalSessionID,
	}, nil
}

// currentOverride reports whether s, not held, is the current session of a
// family a store listed twice: it was used later, or at the same instant with
// a later idle deadline.
func currentOverride(s, held *Session) bool {
	if !s.LastAccessedAt.Equal(held.LastAccessedAt) {
		return s.LastAccessedAt.After(held.LastAccessedAt)
	}

	return s.IdleExpiresAt.After(held.IdleExpiresAt)
}
