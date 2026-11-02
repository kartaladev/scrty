package session

import (
	"context"
	"errors"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/pkg/id"
)

// ErrListUnavailable is what Sessions.ListSignIns returns when the store
// could not list the user's sessions. It is a dependency failure, not a
// verdict on the user: the store's own error stays reachable through
// errors.Is and errors.As, behind this package's fixed text.
var ErrListUnavailable = errors.New(textListUnavailable)

// textListUnavailable is ErrListUnavailable's own words, kept as a constant
// so the fixed text of a failed listing is never a dependency's error
// rendered at runtime.
const textListUnavailable = "session: the user's sign-ins could not be listed"

// SignIn is one of a user's live sign-ins: one session family, however often
// it was renewed, as Sessions.ListSignIns reports it.
type SignIn struct {
	// Handle is the family's identifier. It is not a secret and is never a
	// bearer credential: it names the sign-in for ending it, and nothing it
	// carries reaches a session.
	Handle id.ID

	// CreatedAt is when the sign-in happened: the family's start.
	CreatedAt time.Time

	// LastUsedAt is when the sign-in's current session last recorded
	// activity.
	LastUsedAt time.Time

	// FirstFactor is the kind of factor the sign-in's login used.
	FirstFactor factor.Kind

	// Pending is what the sign-in still owes: MFAPending for a second factor,
	// MFAEnrolmentPending for a second-factor enrolment, MFARecoveryPending
	// for a recovery step, and MFANone when it owes nothing.
	Pending MFAState

	// ClientIP and UserAgent are the sign-in metadata the session recorded,
	// returned unchanged; both are empty when none was recorded (see
	// WithSessionMetadata).
	ClientIP, UserAgent string

	// Current reports that the sign-in is the one the caller's own session
	// belongs to.
	Current bool
}

// RecordsMetadata reports whether the manager records sign-in metadata
// (WithSessionMetadata), so a component that needs it, such as a notice
// comparing a sign-in's user agent with the user's other sign-ins, can refuse
// a manager that records none when it is wired rather than finding nothing
// to compare at its first use.
func (m *Sessions) RecordsMetadata() bool { return m.metadata }

// textListEnded is the fixed text of a listing whose caller's own context
// ended before the store answered: a hang-up, not an outage.
const textListEnded = "session: the sign-in listing ended with its caller"

// ListSignIns lists user's live sign-ins, one per session family that has a
// live head at the manager's clock, in one store query (Store.ListByUser).
// Renewals are not extra sign-ins: a family is listed once, with its current
// session's last use, so a sign-in inside its grace window shows the
// successor's activity. A sign-in still owing a second factor, an enrolment
// or a recovery step is listed, and marked (SignIn.Pending), because an
// unknown pending sign-in is exactly what a user needs to see.
//
// current is the caller's own session, whose sign-in is marked
// SignIn.Current; nil marks none. Only its family is read.
//
// No session identifier, and no digest of one, is ever part of the listing:
// a sign-in's handle is its family identifier, which is not a credential.
//
// The manager does not rely on the store's filtering: a session of another
// user, a superseded one, or one past either deadline at the manager's clock
// is never listed, whatever the store answered. The listing's order is
// unspecified.
//
// A store failure is returned as ErrListUnavailable, the store's error
// reachable through errors.Is and errors.As behind that fixed text. A failure
// caused by ctx ending first, a caller that hung up, is returned matching
// ctx's error instead, and not ErrListUnavailable.
func (m *Sessions) ListSignIns(ctx context.Context, user identity.UserID, current *Session) ([]SignIn, error) {
	now := m.clock.Now()
	listed, err := m.store.ListByUser(ctx, user, now)
	if err != nil {
		if hangup.ByCaller(ctx, err) {
			return nil, diag.Wrap(err, textListEnded, ctx.Err())
		}

		return nil, diag.Wrap(err, textListUnavailable, ErrListUnavailable)
	}

	heads := make(map[id.ID]*Session, len(listed))
	for _, s := range listed {
		if s == nil || s.UserID != user || s.superseded() || s.expired(now) || s.FamilyID.IsZero() {
			continue
		}
		if prev, ok := heads[s.FamilyID]; !ok || s.LastAccessedAt.After(prev.LastAccessedAt) {
			heads[s.FamilyID] = s
		}
	}

	signIns := make([]SignIn, 0, len(heads))
	for family, s := range heads {
		signIns = append(signIns, SignIn{
			Handle:      family,
			CreatedAt:   s.FamilyCreatedAt,
			LastUsedAt:  s.LastAccessedAt,
			FirstFactor: s.FirstFactor,
			Pending:     pendingOf(s.MFA),
			ClientIP:    s.ClientIP,
			UserAgent:   s.UserAgent,
			Current:     current != nil && current.FamilyID == family,
		})
	}

	return signIns, nil
}

// pendingOf is what a session in state st still owes: the state itself when
// it is a pending one, MFANone otherwise.
func pendingOf(st MFAState) MFAState {
	switch st {
	case MFAPending, MFAEnrolmentPending, MFARecoveryPending:
		return st
	default:
		return MFANone
	}
}

// EndSignIn ends one of user's sign-ins, the one whose handle (SignIn.Handle)
// is handle, by revoking its whole family, superseded members included, as
// RevokeFamily does.
//
// Only the sign-in's owner ends it. A handle that is malformed, names the nil
// family, names no live sign-in of user at the manager's clock, or names
// another user's sign-in is ErrNotFound, and nothing is revoked: the answer
// to a foreign handle is the answer to an unknown one, so a caller learns
// nothing about other users' sign-ins. Ownership is judged from one listing
// of user's sign-ins (Store.ListByUser); a family never changes owner, so the
// revocation that follows cannot reach another user's family.
//
// The handle of the caller's own current sign-in is accepted, and ends it as
// a logout does: refusing it would only send the client elsewhere to do the
// same.
//
// A store failure is returned behind fixed text, the store's error reachable
// through errors.Is and errors.As; a failure caused by ctx ending first
// matches ctx's error.
func (m *Sessions) EndSignIn(ctx context.Context, user identity.UserID, handle string) error {
	family, err := id.Parse(handle)
	if err != nil || family.IsZero() {
		return ErrNotFound
	}
	if err := ctx.Err(); err != nil {
		return diag.Wrap(err, textEndEnded, err)
	}

	listed, err := m.store.ListByUser(ctx, user, m.clock.Now())
	if err != nil {
		if hangup.ByCaller(ctx, err) {
			return diag.Wrap(err, textEndEnded, ctx.Err())
		}

		return storeFailed(err, "session: the user's sign-ins could not be read to end one")
	}

	owned := false
	for _, s := range listed {
		if s != nil && s.UserID == user && s.FamilyID == family {
			owned = true

			break
		}
	}
	if !owned {
		return ErrNotFound
	}

	if _, err := m.store.DeleteFamily(ctx, family); err != nil {
		return storeFailed(err, "session: the sign-in could not be ended")
	}

	return nil
}

// textEndEnded is the fixed text of an end whose caller's own context ended
// before the store answered: a hang-up, not an outage.
const textEndEnded = "session: ending the sign-in ended with its caller"

// errNoCurrentSignIn and errForeignCurrentSignIn refuse an EndOtherSignIns
// that names no current session of the user: ending "every other" sign-in
// against no current one would end them all.
var (
	errNoCurrentSignIn      = errors.New("session: ending the other sign-ins needs the current session")
	errForeignCurrentSignIn = errors.New("session: the current session is not the user's")
)

// EndOtherSignIns ends every sign-in of user except current's, and reports
// how many sessions went. It is written over Store.DeleteByUserExcept, which
// decides what it keeps and what it deletes in one atomic step, so current's
// family keeps its live members: current itself and, when current is inside
// its renewal window, its successor, including one a renewal racing this call
// inserts. Other users' sessions are untouched.
//
// A nil current, or one belonging to another user, is refused with an error
// and nothing is ended: with no current sign-in of user to keep, the call
// would end every sign-in, which is DeleteByUser's job and never this one's.
//
// A store failure is returned behind fixed text, the store's error reachable
// through errors.Is and errors.As. A failure caused by ctx ending first, a
// caller that hung up, is returned matching ctx's error instead, as
// ListSignIns and EndSignIn answer it.
func (m *Sessions) EndOtherSignIns(ctx context.Context, user identity.UserID, current *Session) (int, error) {
	if current == nil || current.ID == "" {
		return 0, errNoCurrentSignIn
	}
	if current.UserID != user {
		return 0, errForeignCurrentSignIn
	}

	n, err := m.store.DeleteByUserExcept(ctx, user, current.ID)
	if err != nil {
		if hangup.ByCaller(ctx, err) {
			return n, diag.Wrap(err, textEndEnded, ctx.Err())
		}

		return n, storeFailed(err, "session: the user's other sign-ins could not be ended")
	}

	return n, nil
}
