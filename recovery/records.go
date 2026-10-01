package recovery

import (
	"context"
	"errors"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// Record is one account recovery, kept from the moment it is held until it is
// completed or cancelled, and afterwards as the history the cool-down reads.
//
// A pending record has neither CompletedAt nor CancelledAt set; at most one of
// the two is ever set. NotBefore is the instant it becomes completable.
// Proven and Reported are the authenticators the user proved and reported
// lost, as the library supplied them, so a completion recomputes its reset
// plan from what the user holds then. SavedSpent records whether a saved code
// was spent: the hold voided the rest of the set when it started, a finish
// replaces it, and the notices say so.
type Record struct {
	ID          id.ID
	User        identity.UserID
	StartedAt   time.Time
	NotBefore   time.Time
	CompletedAt time.Time
	CancelledAt time.Time
	Proven      []AuthenticatorRef
	Reported    []AuthenticatorRef
	SavedSpent  bool
}

// ErrRecordNotFound is returned by RecordStore.Find for an identifier the
// store holds no record under.
var ErrRecordNotFound = errors.New("recovery: record not found")

// RecordStore keeps recovery records.
//
// Completion and cancellation are each decided by one conditional write, so of
// a racing completion and cancellation of one record exactly one succeeds, and
// a refused one changes nothing. Completing or cancelling an unknown identifier
// is a refusal, not an error.
//
// The default is NewMemoryRecordStore. Any implementation of this contract may
// be used in its place; the library's durable stores implement it over
// PostgreSQL.
type RecordStore interface {
	// Insert stores r, pending or already completed. An identifier the store
	// already holds is an error.
	Insert(ctx context.Context, r Record) error

	// Find returns the record with this identifier, or ErrRecordNotFound.
	Find(ctx context.Context, id id.ID) (*Record, error)

	// Complete marks the record completed at at, only while it is neither
	// completed nor cancelled and at is not before its NotBefore. It reports
	// whether this call completed it.
	Complete(ctx context.Context, id id.ID, at time.Time) (bool, error)

	// Cancel marks the record cancelled at at, only while it is neither
	// completed nor cancelled. It reports how many records it cancelled: 0 or
	// 1.
	Cancel(ctx context.Context, id id.ID, at time.Time) (int, error)

	// CancelPending marks every record of user that is neither completed nor
	// cancelled as cancelled at at, and reports how many it cancelled.
	CancelPending(ctx context.Context, user identity.UserID, at time.Time) (int, error)

	// LatestCompletion reports the latest completion time among user's
	// records, or false when none is completed.
	LatestCompletion(ctx context.Context, user identity.UserID) (time.Time, bool, error)
}
