package session

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"slices"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// EndCause says which explicit end a report describes. The zero value is no
// cause, which no report carries.
type EndCause uint8

// The causes of an end. Each names what raised it and what its report says;
// see EndReport for the fields.
const (
	// EndReuse is a family revoked for reuse (see ErrReused). It names the user
	// and the family.
	EndReuse EndCause = iota + 1
	// EndFamilyRevoked is Sessions.RevokeFamily. It names the family, and no
	// user, because the call reads no session.
	EndFamilyRevoked
	// EndDeleted is Sessions.Delete. It names the user and the family the
	// session was read to have, or neither when the read found nothing, as it
	// does for an expired session. A read that fails sends no report, because
	// the deletion does not happen.
	//
	// Delete removes one session and not its family, so a member of the family
	// named, such as the successor of a session deleted inside its renewal
	// window, can still be live.
	EndDeleted
	// EndUserSessions is Sessions.DeleteByUser. It names the user, and no
	// family.
	EndUserSessions
	// EndUserSessionsExcept is Sessions.DeleteByUserExcept. It names the user,
	// no family, and as KeptFamily the family of the session kept. KeptFamily
	// is the nil family when the read did not find the kept session to be the
	// user's: it has gone or expired, or it does not belong to the user. A
	// family may therefore have been spared without the report naming it. A
	// kept session that has expired is already dead, so nothing live was
	// spared then. An observer ending things for a user treats a nil
	// KeptFamily as nothing spared. A read that fails sends no report, because
	// the deletion does not happen.
	EndUserSessionsExcept
	// EndExternalSession is Sessions.DeleteByExternalSession. It names the
	// upstream issuer and session, and neither user nor family.
	EndExternalSession
	// EndUserExternalIssuer is Sessions.DeleteByUserAndExternalIssuer. It names
	// the user and the upstream issuer, and no family.
	EndUserExternalIssuer
	// EndByHandle is Sessions.EndSignIn. It names the user and the family.
	EndByHandle
	// EndOtherSignIns is Sessions.EndOtherSignIns. It names the user, no family,
	// and as KeptFamily the current session's family.
	EndOtherSignIns
)

// EndReport describes one explicit end of sign-ins, for an EndObserver. A bulk
// end is one report, naming what selected the sessions and not each one.
//
// A field is empty when the end did not know it. A report carries no session
// identifier, raw or digested: ExternalSessionID is the upstream provider's
// session and not one this manager issued.
//
// A report says that the store write returned no error, not that a session
// was removed: a write matching nothing is reported too (see WithEndObserver).
type EndReport struct {
	// Cause is which end this is.
	Cause EndCause
	// User is the user whose sign-ins ended, as the consumer referenced them.
	User identity.UserID
	// Family is the family that ended, or, for EndDeleted, the family of the
	// session deleted.
	Family id.ID
	// KeptFamily is the family a bulk end spared. It is the nil family when
	// the read did not find the kept session to be the user's: it has gone or
	// expired, or it does not belong to the user. A family may therefore have
	// been spared without the report naming it. A kept session that has expired
	// is already dead. An observer ending things for a user treats a nil
	// KeptFamily as nothing spared.
	KeptFamily id.ID
	// ExternalIssuer is the upstream issuer that selected the sessions.
	ExternalIssuer string
	// ExternalSessionID is the upstream session that selected the sessions.
	ExternalSessionID string
	// At is when the end was reported, read from the manager's clock (see
	// WithClock) after the store write returned.
	At time.Time
}

// EndObserver is told about each explicit end of sign-ins through a manager.
// See WithEndObserver, which says what is and is not reported, and how an
// observer is called. It must not block, and has no error to return.
type EndObserver interface {
	SignInsEnded(ctx context.Context, r EndReport)
}

// EndObserverFunc adapts a function to an EndObserver. A func cannot be
// compared, so Sessions.ReportsEndsTo never answers yes for one: an observer a
// component must find again implements EndObserver on a pointer instead.
type EndObserverFunc func(ctx context.Context, r EndReport)

// SignInsEnded calls f.
func (f EndObserverFunc) SignInsEnded(ctx context.Context, r EndReport) { f(ctx, r) }

// ReportsEndsTo reports whether the manager was built with observer o (see
// WithEndObserver), comparing by identity. A component that relies on being
// told about ends uses it to refuse, when it is wired, a manager that would
// not tell it.
//
// A value that cannot be compared, such as an EndObserverFunc or a struct
// holding a func, is not the one asked about, even when it is the very value
// the manager was given: the answer is false and nothing panics. A component
// that needs this check implements EndObserver on a pointer. Asking about nil
// is false.
func (m *Sessions) ReportsEndsTo(o EndObserver) bool {
	// The asked value alone needs the check. An interface comparison looks at
	// the dynamic types first, and reaches an incomparable value only when both
	// sides hold one of the same type. Value.Comparable looks inside the value,
	// where a comparable type may still hold a func.
	if o == nil || !reflect.ValueOf(o).Comparable() {
		return false
	}

	return slices.Contains(m.observing(), o)
}

// observing is the observers to tell, in order. A caller ranges over what it
// returned and never writes to it.
func (m *Sessions) observing() []EndObserver { return m.endObservers }

// reportEnd tells the observers about r, with its time read from the manager's
// clock now, once the store write it describes has returned no error. Their
// context keeps ctx's values and not its cancellation, so a client that hangs
// up cannot drop the report.
func (m *Sessions) reportEnd(ctx context.Context, r EndReport) {
	observers := m.observing()
	if len(observers) == 0 {
		return
	}

	r.At = m.clock.Now()
	ctx = context.WithoutCancel(ctx)
	for _, o := range observers {
		m.tellEndObserver(ctx, o, r)
	}
}

// textEndObserverPanicked is all that is logged of an observer's panic. The
// panic's value is left out with the report, because it may quote the report.
const textEndObserverPanicked = "session: an end observer panicked"

// tellEndObserver calls o, and recovers its panic so the next observer still
// runs and the end stands.
func (m *Sessions) tellEndObserver(ctx context.Context, o EndObserver, r EndReport) {
	defer func() {
		if recover() != nil {
			m.logger.LogAttrs(ctx, slog.LevelError, textEndObserverPanicked)
		}
	}()

	o.SignInsEnded(ctx, r)
}

// readForReport reads the session a deletion names, for what its report says,
// straight from the store: Load would judge it, and could revoke its family
// or record a presentation. With no observer it reads nothing.
//
// A session the store does not hold, or holds as expired, is nil and no error:
// the deletion has nothing live to name. Any other failure comes back, and the
// caller writes nothing: a report that named no one would leave the session's
// grants live with nothing left to retry, and one that named no kept family
// would end the sign-in the caller meant to keep.
func (m *Sessions) readForReport(ctx context.Context, id string) (*Session, error) {
	if id == "" || len(m.observing()) == 0 {
		return nil, nil
	}

	s, err := m.loadStored(ctx, id, "session: the session could not be read for its end report")
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) {
		return nil, nil
	}

	return s, err
}
