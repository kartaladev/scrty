package onetime

import (
	"context"
	"errors"
	"time"

	"github.com/kartaladev/scrty/pkg/id"
)

// ErrTokenNotFound is what a store reports when there was no record to act on:
// none with that identifier, or — for Consume — none with that identifier still
// unspent.
//
// The two are deliberately the same answer. A consumer of the store cannot
// tell "no such token" from "already spent", so neither can anyone racing a
// redemption, and a manager turns both into ErrInvalidToken regardless.
var ErrTokenNotFound = errors.New("onetime: token not found")

// ErrReapUnsupported is returned by PurgeExpired when the configured store does
// not implement Reaper. It is reported rather than treated as a sweep that
// removed nothing, because in a metric those two look identical and only one of
// them means the store is growing without bound.
var ErrReapUnsupported = errors.New("onetime: store cannot purge expired tokens")

// ErrRetainSinceRequired is returned by a reaper asked to purge with the zero
// time as its cutoff. The zero time is what a caller who forgot to compute a
// cutoff passes, and honouring it literally would delete every expired record,
// including those an issuance count is still resting on.
var ErrRetainSinceRequired = errors.New("onetime: a retain-since cutoff is required")

// Store persists issued tokens.
//
// With no store configured a manager uses NewMemoryStore, which does not
// survive a restart: every link and code issued by the previous process stops
// working. A consumer replaces it with any implementation through WithStore,
// typically one backed by a table, and nothing else about the manager changes.
//
// The records this contract carries hold no secrets. A token's secret exists
// only in the string Issue returned; what is stored is its SHA-256 hash, so an
// implementation may keep these records wherever a hash of a secret may go.
// Subject and Purpose are the consumer's and the manager's own strings, stored
// and returned unchanged.
//
// An implementation must be safe for concurrent use, and Consume in particular
// must be indivisible: see its own contract below, which is what makes a token
// single-use rather than usually-single-use.
//
//go:generate mockgen -source=store.go -package=onetime_test -destination=mocks_test.go -typed
type Store interface {
	// Insert stores tok. An identifier that is already stored is an error
	// rather than a replacement: overwriting would silently invalidate a
	// token already in a holder's hands.
	//
	// The record's byte fields belong to the caller, so an implementation that
	// keeps them past the call copies them.
	Insert(ctx context.Context, tok Token) error

	// FindByID returns the record with this identifier, spent or not, and
	// ErrTokenNotFound when there is none. Expiry and purpose are the
	// manager's to judge, not the store's.
	//
	// The record returned belongs to the caller: an implementation holding its
	// own copy hands back a copy of it, so that a caller writing to what it
	// read cannot change what is stored.
	FindByID(ctx context.Context, tokenID id.ID) (*Token, error)

	// Consume marks the record consumed at, in one indivisible operation that
	// succeeds only while it is still unconsumed, and reports
	// ErrTokenNotFound otherwise.
	//
	// This is the single-use guarantee, and it lives here because only the
	// store can make it: a read followed by a write in the manager would let
	// two callers both read "unspent" and both write. In SQL this is one
	// UPDATE with "consumed_at IS NULL" in its WHERE clause, and a row count
	// of zero is ErrTokenNotFound.
	//
	// The time already recorded is never moved. The first consumption is the
	// one that happened, and a later attempt must not be able to rewrite when
	// the token was spent.
	Consume(ctx context.Context, tokenID id.ID, at time.Time) error

	// CountRecentBySubject counts the records of this purpose belonging to
	// subject that were issued at or after since, spent ones included: what is
	// counted is how often the subject asked, not how many tokens they still
	// hold.
	CountRecentBySubject(ctx context.Context, purpose, subject string, since time.Time) (int, error)
}

// Reaper is the optional half of Store: a store that can delete records it no
// longer needs to hold.
//
// It is separate because purging is a capability, not an obligation. A store
// whose rows are swept by a database job, or which keeps everything for audit,
// implements Store and stops there; a manager over it reports
// ErrReapUnsupported from PurgeExpired rather than pretending to have swept.
// MemoryStore implements both.
type Reaper interface {
	// DeleteExpiredBefore removes the records of this purpose that are both
	// expired and were issued strictly before retainSince, and reports how
	// many went.
	//
	// Both conditions are required. Deleting a record that is expired but
	// still inside the manager's issuance window would hand its holder a fresh
	// allowance to ask for another, so a purge that only looked at expiry
	// would quietly undo the limit the count exists to enforce.
	//
	// A zero retainSince is refused with ErrRetainSinceRequired and nothing is
	// deleted.
	DeleteExpiredBefore(ctx context.Context, purpose string, retainSince time.Time) (int, error)
}
