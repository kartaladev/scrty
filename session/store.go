package session

import (
	"context"
	"errors"

	"github.com/kartaladev/scrty/identity"
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

	// Save updates the stored session with this identifier, whole, and
	// reports ErrSessionNotFound when there is no longer one to update. It
	// never inserts.
	Save(ctx context.Context, s *Session) error

	// Load returns the session with this identifier, ErrSessionNotFound when
	// there is none, and ErrSessionExpired when it is past either deadline.
	Load(ctx context.Context, id string) (*Session, error)

	// Delete removes the session with this identifier. Deleting one that is
	// not there is not an error: the caller asked for it to be gone, and it
	// is.
	Delete(ctx context.Context, id string) error

	// DeleteByUser removes every session of this user, expired ones included.
	// The reference is matched exactly as the consumer supplied it.
	DeleteByUser(ctx context.Context, user identity.UserID) error

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
