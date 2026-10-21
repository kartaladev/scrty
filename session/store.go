package session

import (
	"context"
	"errors"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/id"
)

// ErrSessionNotFound is what a store reports when there is no session to act
// on: none with that identifier, or — for Save — none still there to update.
//
// A caller distinguishes it from ErrSessionExpired because the two mean
// different things to whoever is waiting: an expired session says "log in
// again", a missing one says there is nothing here at all.
var ErrSessionNotFound = errors.New("session: session not found")

// ErrSessionExpired is what a store reports for a session past either of its
// deadlines. Expiry is enforced on every load, so a stale session is never
// served, whether or not anything has got round to deleting it.
var ErrSessionExpired = errors.New("session: session expired")

// ErrSessionUnreadable is what a sealing store reports when a stored value
// will not open: a retired key, a corrupted envelope, or a value moved from
// another session.
//
// It is deliberately not ErrSessionNotFound. A key that has been retired out
// from under live sessions is an operational mistake, and reporting it as a
// missing session would hide it behind a perfectly ordinary-looking login
// prompt.
var ErrSessionUnreadable = errors.New("session: session cannot be read")

// ErrSessionRenewalConflict is what a store reports when a supersession lost
// to another: the session's current successor is no longer the one the caller
// observed, because a concurrent renewal superseded it first. Nothing was
// written. The caller that sees it did not produce a successor, and another
// caller did.
var ErrSessionRenewalConflict = errors.New("session: the session was renewed concurrently")

// ErrSuccessorAdvanced is what a store reports when a supersession names a
// successor that has moved on, and nothing was written. Supersede returns it
// when op.ObservedSuccessor is set and that successor has itself been
// superseded or is no longer stored, or when op.RequireUnpresentedSuccessor
// is set and that successor has been presented (its FirstPresentedAt is
// recorded). It is judged in the same atomic step as the rest of the
// supersession, so a presentation or a rotation of the successor racing it
// either happens first and refuses it, or happens after it.
//
// The Manager reads it as reuse: renewing an identifier whose successor has
// moved on would leave the family with two live heads.
var ErrSuccessorAdvanced = errors.New("session: the session's successor has moved on")

// Supersession is one atomic supersession: Store.Supersede marks Old
// superseded by Successor and inserts Successor, provided Old's current
// successor is still the one the caller observed.
type Supersession struct {
	// Old is the identifier of the session being superseded.
	Old string

	// ObservedSuccessor is the SuccessorDigest the caller read on Old before
	// deciding to supersede it. It is nil for a first rotation, when Old has
	// no successor yet. The supersession happens only while Old's stored
	// successor digest still equals it, byte for byte.
	ObservedSuccessor []byte

	// AcceptUntil is the end of Old's grace window, which the store records
	// on Old unchanged.
	AcceptUntil time.Time

	// Successor is the session inserted in Old's place. It is inserted as
	// given, as Create would insert it.
	Successor *Session

	// Now is the time of the supersession, read from the caller's clock. It
	// is Old's SupersededAt, and both the time a previous successor is
	// superseded at and the end of that previous successor's window.
	Now time.Time

	// RequireUnpresentedSuccessor, when set, makes the supersession also
	// conditional on the observed successor never having been presented: one
	// whose FirstPresentedAt is recorded refuses it with ErrSuccessorAdvanced.
	// The Manager sets it when it recovers an identifier past its window
	// (WithUnusedSuccessorRecovery). It has no effect when ObservedSuccessor
	// is nil.
	RequireUnpresentedSuccessor bool
}

// Store persists sessions.
//
// With no store configured a Manager uses NewMemoryStore, which does not
// survive a restart: every session issued by the previous process is gone. A
// consumer replaces it with any implementation through WithStore, typically
// one backed by a table, and nothing else about the Manager changes.
//
// Creating and saving are separate operations, and saving never inserts. That
// split is the contract's one demand on an implementation beyond doing what
// each method says: a save that could also insert turns the ordinary
// load-then-save of a live request into a way to bring back a session another
// request has just revoked, and it is the revocation that loses that race. In
// SQL, Create is an INSERT and Save is an UPDATE whose row count of zero is
// ErrSessionNotFound.
//
// Every implementation enforces expiry in Load, so no caller can read a stale
// session.
//
// A Session's Data map belongs to the consumer: an implementation stores and
// returns it byte-for-byte and never reads its entries. Records handed over
// and handed back belong to the caller, so an implementation keeping its own
// copy copies in both directions.
//
// An implementation must be safe for concurrent use.
//
//go:generate mockgen -source=store.go -package=session_test -destination=store_mock_test.go -typed
type Store interface {
	// Create inserts s. An identifier that is already stored is an error
	// rather than a replacement: overwriting would silently end the session
	// already holding it.
	Create(ctx context.Context, s *Session) error

	// Save updates the stored session with this identifier, whole except for
	// MFAAtFirstFactor and the family, supersession and presentation fields,
	// and reports ErrSessionNotFound when there is no longer one to update. It
	// never inserts.
	//
	// The family, supersession and presentation fields (FamilyID,
	// FamilyCreatedAt, SupersededAt, AcceptUntil, SuccessorDigest,
	// FirstPresentedAt) are written by Create, Supersede and MarkPresented
	// only: Save keeps the stored values whatever the session handed to it
	// says, so saving a copy loaded before a concurrent supersession cannot
	// undo it.
	//
	// A stored session that is superseded (SupersededAt set) also keeps its
	// IdleExpiresAt and AbsoluteExpiresAt: Supersede set both to the family's
	// absolute deadline, and raises them when a later renewal extends the
	// family. A copy loaded before either would otherwise shorten them and let
	// housekeeping remove the record early.
	// This holds for a previous successor superseded by a re-rotation too.
	//
	// MFAAtFirstFactor is written by Create only: Save keeps the stored value
	// whatever the session handed to it says, so no later save can set or
	// clear the marker. A SQL store leaves its column out of the UPDATE.
	Save(ctx context.Context, s *Session) error

	// Load returns the session with this identifier, ErrSessionNotFound when
	// there is none, and ErrSessionExpired when it is past either deadline.
	//
	// A superseded session is returned like any other, with its supersession
	// state (SupersededAt, AcceptUntil, SuccessorDigest) set, whether or not
	// its grace window has ended: the store enforces the two deadlines only,
	// and the Manager judges the window with its own clock. A consumer calling
	// Load directly therefore sees superseded sessions, and must not treat
	// one as live without that judgement.
	Load(ctx context.Context, id string) (*Session, error)

	// RecordActivity writes lastAccessed and idleExpires to the session with
	// this identifier, and nothing else, provided its stored LastAccessedAt is
	// before olderThan and it is not superseded. A session that is fresher,
	// or superseded, is left unchanged, and that is not an error.
	//
	// It reports ErrSessionNotFound only when there is no session with this
	// identifier, and it never inserts. It never touches any other field, so
	// a change another request saved to the same session in the meantime
	// survives it: a whole-record save in its place would write back the
	// copy this request loaded. In SQL it is one conditional UPDATE of those
	// two columns.
	RecordActivity(ctx context.Context, id string, lastAccessed, idleExpires, olderThan time.Time) error

	// Supersede performs op as one atomic operation. A nil op.Successor is
	// refused with an error and nothing is written:
	//
	//   - it marks op.Old superseded at op.Now, with op.AcceptUntil as its
	//     window end and the digest of op.Successor's identifier as its
	//     successor, and sets both of its deadlines to its absolute deadline;
	//   - it marks Old's previous successor, if it had one, superseded at
	//     op.Now with a window ending at op.Now, and sets both of that
	//     successor's deadlines to its absolute deadline;
	//   - when op.Successor's absolute deadline is later than that of a
	//     superseded session of the same family, Old and the previous
	//     successor included, it raises both of that session's deadlines to
	//     op.Successor's absolute deadline;
	//   - it inserts op.Successor.
	//
	// The raise is what lets a renewal that extends the family (see
	// WithSuccessorLifetime) keep detecting reuse: a superseded identifier
	// presented after its own original deadline, while the family is still
	// live, must load as superseded so the Manager judges it as reuse, not
	// read as an ordinary expiry that leaves the family alive. A superseded
	// session never authenticates past its window, so the raise grants
	// nothing. A deadline is only ever raised, never lowered.
	//
	// It is conditional on op.ObservedSuccessor: it happens only while Old's
	// stored SuccessorDigest equals it byte for byte, nil meaning none. When
	// it does not, Supersede writes nothing and reports
	// ErrSessionRenewalConflict, so concurrent renewals of one session produce
	// exactly one successor. An Old that is not stored, as after its family
	// was revoked, is ErrSessionNotFound, and nothing is inserted.
	//
	// When the observation holds, a non-nil op.ObservedSuccessor must still
	// name a stored successor that is not superseded, and, with
	// op.RequireUnpresentedSuccessor, one never presented. Otherwise
	// Supersede writes nothing and reports ErrSuccessorAdvanced, so a family
	// never holds two live heads. The checks are made in this order: Old
	// missing, then Old's family, then the observation and the rule below
	// for a superseded Old, then the successor.
	//
	// Two rules refuse a supersession whatever it observed. An Old with no
	// family, the nil family, is refused with an error and nothing is written,
	// as DeleteFamily refuses it: every family-less session carries it, so
	// honouring it would touch unrelated sessions. An Old that is superseded
	// already is superseded again only through its observed successor: with
	// none observed, as for a fresh head, it is ErrSessionRenewalConflict,
	// because a superseded session with no successor was knocked out of its
	// chain by a later supersession, and renewing it would give the family a
	// second live head.
	//
	// The condition must hold across processes, not only within one: a lock
	// held by one instance does not stop another replica. In SQL it is one
	// transaction whose conditional UPDATE of Old decides the outcome, joining
	// a caller's transaction when one is attached.
	Supersede(ctx context.Context, op Supersession) error

	// DeleteFamily removes every session of this family, superseded or not,
	// expired or not, and reports how many went. Sessions of other families,
	// the same user's included, are untouched.
	//
	// The nil family, id.Nil, is refused with an error and nothing is
	// deleted: a session written straight to a store with no family carries
	// it, so honouring it would delete unrelated users' sessions.
	DeleteFamily(ctx context.Context, family id.ID) (int, error)

	// MarkPresented records at as the session's FirstPresentedAt, only when
	// none is recorded: a later call leaves the first time unchanged and is
	// not an error. A session that is not stored is ErrSessionNotFound. It
	// never inserts and never touches any other field.
	MarkPresented(ctx context.Context, id string, at time.Time) error

	// Delete removes the session with this identifier. Deleting one that is
	// not there is not an error: the caller asked for it to be gone, and it
	// is.
	Delete(ctx context.Context, id string) error

	// DeleteByUser removes every session of this user, expired ones included.
	// The reference is matched exactly as the consumer supplied it.
	DeleteByUser(ctx context.Context, user identity.UserID) error

	// DeleteByUserExcept removes every session of this user except the one with
	// identifier keep, expired ones included, in one atomic operation, and reports
	// how many it removed. A keep that names another user's session, or none, is
	// left untouched and does not stop the user's sessions from being removed; an
	// empty keep removes them all.
	DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error)

	// CountActiveByUser counts this user's unexpired sessions. Expired ones
	// are excluded whether or not anything has swept them, because a session
	// that will never be served again is not one the user is holding.
	CountActiveByUser(ctx context.Context, user identity.UserID) (int, error)

	// DeleteExpired removes every expired session and reports how many went.
	DeleteExpired(ctx context.Context) (int, error)

	// DeleteByExternalSession removes the sessions matching both issuer and
	// the provider's own session identifier, and reports how many went.
	//
	// An empty issuer, or an empty sessionID, matches nothing and is not an
	// error. An empty issuer that matched everything would let one provider's
	// logout end sessions established at another, and an empty session
	// identifier would match every session that provider issued without one.
	DeleteByExternalSession(ctx context.Context, issuer, sessionID string) (int, error)

	// DeleteByUserAndExternalIssuer removes this user's sessions from this
	// issuer, and reports how many went. An empty issuer matches nothing and
	// is not an error, so a caller with no issuer to hand cannot end that
	// user's password sessions by accident.
	DeleteByUserAndExternalIssuer(ctx context.Context, user identity.UserID, issuer string) (int, error)
}

// storeFailed returns a store's failure with fixed text in place of the
// store's own, which may quote values the library never handed it. The
// store's error stays reachable through errors.Is and errors.As, so a caller
// matching it, or a sentinel it wraps, still does.
//
// A sentinel of this package that the store returned bare — ErrSessionNotFound,
// ErrSessionExpired, ErrSessionUnreadable, ErrSessionRenewalConflict or
// ErrSuccessorAdvanced — carries no store text and comes back as itself, so
// nothing that matches on it changes. The sentinels are not
// passed to diag.Wrap as kinds: a fault matches its kinds, and every other
// store failure would then read as a missing or expired session.
func storeFailed(err error, text string) error {
	//nolint:errorlint // identity: only a bare sentinel is known to carry no store text
	if err == ErrSessionNotFound || err == ErrSessionExpired || err == ErrSessionUnreadable ||
		err == ErrSessionRenewalConflict || err == ErrSuccessorAdvanced {
		return err
	}

	return diag.Wrap(err, text)
}
