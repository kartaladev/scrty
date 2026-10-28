package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/id"
)

// ErrReused is what the Sessions returns when a superseded session is
// presented at or after the end of its grace window. By then the Sessions has
// revoked the session's whole family: whoever presents a credential that was
// already replaced is either a client that kept using it too long or someone
// who stole it, and the two cannot be told apart.
//
// It matches ErrExpired through errors.Is, so a caller that only checks
// for an ended session refuses it with no change.
//
// The revocation is a store write, and like every store write it joins a
// transaction the consumer attached to the context. A consumer that rolls
// back its request transaction whenever a call fails also rolls back the
// revocation, and leaves the stolen family alive. Such a consumer must commit
// when errors.Is(err, ErrReused), and anything it writes in that
// transaction from a ReuseObserver it writes inside a savepoint, so a failed
// audit statement does not abort the transaction the revocation is in.
var ErrReused = fmt.Errorf("session: a superseded session was presented after its window: %w", ErrExpired)

// ErrRenewalRequired is what the Sessions returns, with
// WithUnusedSuccessorRecovery on, when an ordinary request presents a
// superseded session after its grace window. Nothing is revoked: the client
// may only have lost a renewal response, and it must renew (see
// LoadForRenewal) before it can use the session again. The renewal, not this
// request, judges whether the identifier is recovered or reused, and it can
// still be ErrExpired: a session whose own idle or absolute deadline
// has passed is never recovered, and its renewal is ErrExpired unless
// its successor was used, which is reuse.
//
// It matches ErrExpired through errors.Is, so a caller that only checks
// for an ended session refuses it with no change. It does not match
// ErrReused.
var ErrRenewalRequired = fmt.Errorf("session: a superseded session must be renewed before use: %w", ErrExpired)

// MaxRenewalGrace is the longest grace window RotateWithGrace accepts,
// inclusive. The window is time in which a stolen identifier works as well as
// the real one, so it is bounded: five minutes covers a retry over a slow
// mobile network several times over.
const MaxRenewalGrace = 5 * time.Minute

// DefaultRenewalGrace is the grace window a renewal endpoint uses when its
// consumer chooses none, and the in-flight window Rotate gives the identifier
// it rotates from: long enough for a request already sent with the old
// identifier to land, short enough that a stolen one is little use.
const DefaultRenewalGrace = 30 * time.Second

// reuseLogReason is the fixed text of the warning written on every detected
// reuse. It names what happened and carries no identifier.
const reuseLogReason = "session: a superseded session was presented after its window; its family was revoked"

// RenewalKind says which kind of renewal RotateWithGrace performed. The zero
// value is no renewal, which is what a failed call returns.
type RenewalKind int

// The kinds of renewal.
const (
	// RenewalFresh is the rotation of a session that had not been superseded.
	RenewalFresh RenewalKind = iota + 1
	// RenewalReRotation is the rotation of a session already superseded and
	// still inside its window, as when a client never received the previous
	// renewal's response and retries it. The previous successor is superseded
	// with a window that has already ended.
	RenewalReRotation
	// RenewalRecovery is the rotation of a session superseded and past its
	// window whose successor had never been presented, which only a manager
	// with WithUnusedSuccessorRecovery performs. The unused successor is
	// superseded with a window that has already ended.
	RenewalRecovery
)

// String returns the kind's name, as "re-rotation" rather than "2". A value
// with no name prints its number.
func (k RenewalKind) String() string {
	switch k {
	case RenewalFresh:
		return "fresh"
	case RenewalReRotation:
		return "re-rotation"
	case RenewalRecovery:
		return "recovery"
	default:
		return "RenewalKind(" + strconv.Itoa(int(k)) + ")"
	}
}

// ReuseObserver is told about each detected reuse, after the family has been
// revoked. See WithReuseObserver.
type ReuseObserver func(ctx context.Context, r ReuseReport)

// ReuseReport describes one detected reuse. It carries no session identifier,
// raw or digested: the family is what was revoked and what an audit record
// names.
type ReuseReport struct {
	// User is the user the revoked family belonged to, as the consumer
	// referenced them.
	User identity.UserID
	// Family is the revoked family.
	Family id.ID
	// SupersededAt is when the presented session was superseded.
	SupersededAt time.Time
	// DetectedAt is when the reuse was detected, read from the manager's
	// clock.
	DetectedAt time.Time
}

// RotateOption configures one RotateWithGrace call. The default, with no
// option, carries the absolute deadline over unchanged.
type RotateOption func(*rotation)

// rotation is what RotateOptions set.
type rotation struct {
	// lifetime is the successor's new absolute lifetime; zero carries the
	// deadline over.
	lifetime    time.Duration
	lifetimeSet bool
}

// WithSuccessorLifetime gives the successor an absolute deadline of now plus
// d, in place of the default, which carries the predecessor's deadline over.
//
// A d of zero or less, or above the manager's lifetime maximum (see
// WithMaxAbsoluteLifetime), is a wiring mistake: RotateWithGrace refuses it
// with ErrConfig and stores nothing. A deadline that would pass the family
// maximum (see WithMaxFamilyLifetime) is not a mistake but the family running
// out, so it is cut to end exactly at the family maximum.
func WithSuccessorLifetime(d time.Duration) RotateOption {
	return func(r *rotation) {
		r.lifetime = d
		r.lifetimeSet = true
	}
}

// RotateWithGrace moves s to a successor in the same family, and keeps s's
// identifier usable for a grace window after it, so a request already in
// flight with the old identifier, or a client that never received the
// response, is not signed out. It returns the successor and the kind of
// renewal performed.
//
// The window ends at now plus grace, or at s's absolute deadline if that is
// earlier. Inside it, loading the old identifier succeeds while its own idle
// and absolute deadlines are unexpired, and records no activity; once either
// has passed it is ErrExpired and nothing is revoked. At or after the
// window's end, presenting the old identifier is reuse (see
// ErrReused), whatever its own deadlines say. The old record keeps its
// own deadlines; the store keeps it for reuse detection until its
// Session.RetainUntil. A grace below 0 or above MaxRenewalGrace is refused
// with ErrConfig and nothing is stored. There is no default grace: a rotation
// with a window is an explicit choice of the caller.
//
// Rotating an identifier that is already superseded and inside its window is
// a re-rotation: a fresh successor is issued, and the previous one is
// superseded with a window that has already ended, so whoever presents it
// next reveals that two parties hold the family. The old identifier's window
// is not extended by a re-rotation. A re-rotation whose previous successor
// has itself been superseded, or is no longer stored, is reuse instead: the
// store refuses it (ErrSuccessorAdvanced), the family is revoked and
// ErrReused returned, so the family never holds two live heads.
//
// Rotating one after its window is reuse, exactly as loading it is, unless
// WithUnusedSuccessorRecovery is on. Then, while its successor has never been
// presented, it is rotated again as inside the window (RenewalRecovery),
// decided atomically by the store (Supersession.RequireUnpresentedSuccessor);
// a successor that was presented, superseded or removed makes it reuse. Its
// own window stays ended. A session whose own idle or absolute deadline has
// passed is never recovered, and no successor is issued: the store is asked
// whether its successor was used (Store.SuccessorPresented), and the renewal
// is reuse when it was, and ErrExpired, revoking nothing, when it was
// not or is no longer stored. A session from LoadForRenewal is what a renewal
// endpoint passes here; only s's identifier is read, the stored session is
// judged.
//
// The successor is built from the stored session, not from s, and keeps
// everything rotation keeps (see Rotate), its family and the family's start
// included. Its absolute deadline is carried over unless WithSuccessorLifetime
// chose another, and its idle deadline starts afresh, capped at the absolute
// one.
//
// Two rotations of one identifier at the same time, through one manager or
// through managers on different replicas sharing one store, produce exactly
// one successor: the store supersedes conditionally on the successor this
// call observed (Store.Supersede), and the loser gets
// ErrRenewalConflict with nothing stored.
func (m *Sessions) RotateWithGrace(ctx context.Context, s *Session, grace time.Duration, opts ...RotateOption) (*Session, RenewalKind, error) {
	if s == nil {
		return nil, 0, errors.New("session: rotate with grace was given no session")
	}
	if grace < 0 || grace > MaxRenewalGrace {
		return nil, 0, fmt.Errorf("%w: renewal grace must be between 0 and %s, got %s", ErrConfig, MaxRenewalGrace, grace)
	}
	var r rotation
	for _, opt := range opts {
		if opt != nil {
			opt(&r)
		}
	}
	if r.lifetimeSet && (r.lifetime <= 0 || r.lifetime > m.maxLifetime) {
		return nil, 0, fmt.Errorf("%w: successor lifetime %s is outside 0 to the maximum %s",
			ErrConfig, r.lifetime, m.maxLifetime)
	}

	old, err := m.loadStored(ctx, s.ID, "session: the session to renew could not be loaded")
	if err != nil {
		return nil, 0, err
	}

	now := m.clock.Now()
	if err := m.judge(ctx, old, now, forRenewal); err != nil {
		return nil, 0, err
	}
	kind := RenewalFresh
	acceptUntil := minTime(now.Add(grace), old.AbsoluteExpiresAt)
	if old.superseded() {
		kind = RenewalReRotation
		if !old.insideWindow(now) {
			// judge let it through: recovery is on and it names a successor.
			kind = RenewalRecovery
		}
		acceptUntil = minTime(acceptUntil, old.AcceptUntil)
	}

	// The family maximum bounds every renewal, so a family already past its
	// end under this manager's maximum cannot be renewed, whatever deadline
	// the record itself still carries.
	familyEnd := m.familyEnd(old)
	if !now.Before(familyEnd) {
		return nil, 0, ErrExpired
	}

	id, err := m.newIdentifier()
	if err != nil {
		return nil, 0, err
	}
	next := successorOf(old, id)
	next.CreatedAt = now
	next.LastAccessedAt = now
	if r.lifetimeSet {
		next.AbsoluteExpiresAt = now.Add(r.lifetime)
	}
	next.AbsoluteExpiresAt = minTime(next.AbsoluteExpiresAt, familyEnd)
	next.IdleExpiresAt = minTime(now.Add(m.idleTimeout), next.AbsoluteExpiresAt)

	err = m.store.Supersede(ctx, Supersession{
		Old:                         old.ID,
		ObservedSuccessor:           old.SuccessorDigest,
		AcceptUntil:                 acceptUntil,
		RetainUntil:                 m.retainUntil(old, acceptUntil),
		Successor:                   next,
		Now:                         now,
		RequireUnpresentedSuccessor: kind == RenewalRecovery,
	})
	if errors.Is(err, ErrSuccessorAdvanced) {
		return nil, 0, m.reuse(ctx, old, now)
	}
	if err != nil {
		return nil, 0, storeFailed(err, "session: the session could not be renewed")
	}

	return next, kind, nil
}

// LoadForRenewal returns the session with this identifier for renewal: it is
// what a renewal endpoint loads before RotateWithGrace, and nothing else
// should call it.
//
// It is Load, with one difference. With WithUnusedSuccessorRecovery on, a
// superseded session past its grace window that still names a successor is
// returned rather than refused with ErrRenewalRequired, so that
// RotateWithGrace can try to recover it, provided its own idle and absolute
// deadlines are unexpired. Once either has passed it is never recovered: it
// is reuse when its successor was used (Store.SuccessorPresented), and
// otherwise ErrExpired, with nothing revoked. Such a session must not
// authenticate anything: its only use is to be rotated. With recovery off it
// behaves exactly like Load.
func (m *Sessions) LoadForRenewal(ctx context.Context, id string) (*Session, error) {
	return m.load(ctx, id, forRenewal)
}

// purpose is what a session is loaded for, which decides the verdict on a
// superseded one past its window under WithUnusedSuccessorRecovery.
type purpose int

const (
	// forRequest is every load but a renewal's.
	forRequest purpose = iota
	// forRenewal is the load of a renewal, which alone may recover.
	forRenewal
)

// judge applies the manager's verdict to a session the store returned.
//
// A superseded one inside its window is then judged by its own deadlines: it
// passes while both are unexpired, and is ErrExpired, revoking
// nothing, once either has passed. The store keeps a superseded record past
// its own deadlines (Session.RetainUntil), so that check is the manager's.
//
// A superseded one at or after the end of its window is reuse, and its
// family is revoked, whatever its own deadlines say: a record kept past them
// exists so a late presentation is detected. The one exception is recovery:
// with it on, one that still names a successor is refused with
// ErrRenewalRequired for a request, and for a renewal is passed, for
// the store to decide, only while its own deadlines are unexpired. Once one
// has passed, recovery never revives it: the renewal is judged by whether its
// successor was used (see ended). One with no successor of its own, knocked
// out by a re-rotation or a recovery, has nothing to recover into and is
// always reuse, whatever now is (see insideWindow). Anything else passes.
func (m *Sessions) judge(ctx context.Context, s *Session, now time.Time, p purpose) error {
	if !s.superseded() {
		return nil
	}
	if s.insideWindow(now) {
		if s.expired(now) {
			return ErrExpired
		}

		return nil
	}
	if m.unusedSuccessorRecovery && len(s.SuccessorDigest) > 0 {
		if p != forRenewal {
			return ErrRenewalRequired
		}
		if s.expired(now) {
			return m.ended(ctx, s, now)
		}

		return nil
	}

	return m.reuse(ctx, s, now)
}

// ended is the verdict on a renewal, under recovery, of s, superseded, past
// its window and past one of its own deadlines: reuse when the store reports
// that s's successor was used, and ErrExpired, revoking nothing,
// otherwise. It never issues a successor.
//
// A store that cannot answer fails the renewal with its error, wrapped as
// every store failure is, and nothing is revoked or issued: the renewal is
// refused either way, and revoking on a failed read would sign out a client
// whose successor may never have been used.
func (m *Sessions) ended(ctx context.Context, s *Session, now time.Time) error {
	// Detached so a client hanging up cannot turn a reuse verdict into a
	// refusal that revokes nothing; values are kept, as in reuse.
	used, err := m.store.SuccessorPresented(context.WithoutCancel(ctx), s.ID)
	if err != nil {
		return storeFailed(err, "session: whether the session's successor was used could not be read")
	}
	if used {
		return m.reuse(ctx, s, now)
	}

	return ErrExpired
}

// reuse revokes s's family, tells the observer, logs the fixed reason with
// the family, and returns ErrReused.
//
// A revocation that fails is returned joined with ErrReused, so the
// request is still refused and the failure is not hidden; the observer is not
// called then, since it is told about a revoked family.
func (m *Sessions) reuse(ctx context.Context, s *Session, now time.Time) error {
	// Detached so a client hanging up cannot abort the revocation;
	// WithoutCancel keeps the context's values, so a consumer's transaction is
	// still joined.
	if _, err := m.store.DeleteFamily(context.WithoutCancel(ctx), s.FamilyID); err != nil {
		m.logger.LogAttrs(ctx, slog.LevelError,
			"session: a superseded session was presented after its window; its family could not be revoked",
			append(diag.Failure("delete_family", err), slog.String("family", s.FamilyID.String()))...)

		return errors.Join(ErrReused, storeFailed(err, "session: the reused session's family could not be revoked"))
	}

	if m.reuseObserver != nil {
		m.reuseObserver(ctx, ReuseReport{
			User:         s.UserID,
			Family:       s.FamilyID,
			SupersededAt: s.SupersededAt,
			DetectedAt:   now,
		})
	}
	m.logger.WarnContext(ctx, reuseLogReason, "family", s.FamilyID.String())

	return ErrReused
}

// successorOf returns the session that from rotates into under identifier
// id: everything carried over, and the supersession and presentation state,
// which belongs to from alone, cleared.
func successorOf(from *Session, id string) *Session {
	next := from.clone()
	next.ID = id
	next.SupersededAt = time.Time{}
	next.AcceptUntil = time.Time{}
	next.RetainUntil = time.Time{}
	next.SuccessorDigest = nil
	next.FirstPresentedAt = time.Time{}

	return next
}

// superseded reports whether a rotation with a grace window replaced s.
func (s *Session) superseded() bool { return !s.SupersededAt.IsZero() }

// insideWindow reports whether s's grace window is still open at now: s names
// a successor and now is before the window's end.
//
// A superseded session with no successor of its own was knocked out by a
// re-rotation or a recovery, which ends its window by definition, so it is
// outside the window whatever now is. Its recorded end is the time of the
// manager that knocked it out, and a reader whose clock is behind that one,
// or whose time was read before the knock-out committed, would otherwise
// still find it open.
func (s *Session) insideWindow(now time.Time) bool {
	return len(s.SuccessorDigest) > 0 && now.Before(s.AcceptUntil)
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}

	return a
}

// WithMaxFamilyLifetime sets how long after a family's start (its first
// session's creation, FamilyCreatedAt) a renewal may carry the family. A
// renewal that chose a new lifetime (WithSuccessorLifetime) whose deadline
// would pass it is cut to end exactly there, so the family maximum is the
// session's overall reauthentication limit: past it, the user signs in
// again, however often the session was renewed.
//
// The default is the lifetime maximum (see WithMaxAbsoluteLifetime), so with
// no option no renewal extends a family past where its first session could
// have ended. A maximum below the lifetime maximum is a configuration error
// from New. There is no unlimited value: a finite family maximum is
// what makes the limit a limit.
//
// A renewal whose family is already past its end under this maximum is
// refused with ErrExpired, and a carried-over deadline later than the
// end is cut to it.
//
// Changing the maximum between deploys is safe to lower and has one limit
// when raised. Lowering it never shortens a superseded record already
// issued: it keeps the retention deadline it holds, and one superseded again
// keeps the later of that deadline and the new one. A record superseded
// before the maximum was raised keeps the retention it was given, so
// presented after that while its family, extended under the new maximum, is
// still live, it is refused as expired and not as reuse: the family is not
// revoked. Rewriting every member on each renewal would restore
// that detection at a per-renewal cost, so the library accepts the limit.
//
// The library does not know the assurance level a consumer targets, so it
// enforces no figure of its own. For reference, NIST SP 800-63B-4 sets the
// overall reauthentication timeout at no more than 30 days at AAL1 and 24
// hours at AAL2.
func WithMaxFamilyLifetime(limit time.Duration) Option {
	return func(m *Sessions) {
		m.maxFamilyLifetime = limit
		m.maxFamilyLifetimeSupplied = true
	}
}

// WithReuseObserver sets a function told about each detected reuse (see
// ErrReused). The default is none: reuse is still refused, the family
// still revoked, and a warning still logged with a fixed reason and the
// family identifier.
//
// The observer runs synchronously, after the family has been revoked, with
// the context of the request that presented the reused session, so it can
// write an audit record in the request's transaction. Its report carries the
// user, the family and the two times, and never a session identifier. It
// returns nothing: it cannot fail the request or undo the revocation. It is
// not called when the revocation itself failed.
//
// The revocation joins a transaction the consumer attached to the context. A
// consumer that does so must commit when errors.Is(err, ErrReused),
// or the rollback takes the revocation with it, and must write the
// observer's audit record inside a savepoint, because a failed statement
// aborts a PostgreSQL transaction and the revocation in it.
//
// A nil observer is a configuration error from New.
func WithReuseObserver(fn ReuseObserver) Option {
	return func(m *Sessions) {
		m.reuseObserver = fn
		m.reuseObserverSupplied = true
	}
}

// WithUnusedSuccessorRecovery lets a renewal recover a superseded identifier
// presented after its grace window, while its current successor has never
// been presented: the identifier is rotated again as inside the window, the
// unused successor is superseded at once and a fresh one is issued
// (RenewalRecovery). It is for clients on poor networks, whose renewal
// response can be lost and retried hours later, when a fresh sign-in may not
// be possible.
//
// The default is off: a superseded identifier presented after its window is
// always reuse, and its family is revoked (see ErrReused).
//
// With it on:
//
//   - Load of such an identifier, for an ordinary request, refuses it with
//     ErrRenewalRequired and revokes nothing, because a client sends
//     its queued requests before it renews.
//   - Only a renewal judges it: LoadForRenewal returns it, and RotateWithGrace
//     recovers it when its successor is still unused, decided atomically by
//     the store (Supersession.RequireUnpresentedSuccessor). A successor that
//     was presented, renewed or removed makes the renewal reuse.
//   - A successor knocked out by a recovery or a re-rotation has no successor
//     of its own to recover into, so presenting it is reuse as before.
//   - A first-use write that fails, other than as a refusal, fails the load
//     (ErrStore) instead of serving the session unmarked.
//
// The trade-off: theft is still detected, but later. A stale identifier
// replayed only on ordinary requests is refused, not detected, until someone
// renews with it. Whoever presents a stale credential second is caught: a
// thief who recovers first is caught by the real client's next use of its
// own successor, and a real client that recovered first catches the thief's.
// The exposure lasts until that second presentation instead of ending with
// the window.
//
// Every manager over one store should agree on this option: the guarantee
// that a first presentation racing a recovery leaves one live head is kept by
// managers that have it on.
func WithUnusedSuccessorRecovery() Option {
	return func(m *Sessions) { m.unusedSuccessorRecovery = true }
}
