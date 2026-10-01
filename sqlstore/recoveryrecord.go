package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
)

// RecoveryRecordStore keeps account recovery records in the
// account_recoveries table the migrate package creates. It implements
// recovery.RecordStore, and is safe for concurrent use.
//
// Complete, Cancel and CancelPending are each one conditional update on
// "neither completed nor cancelled", Complete also on the record's completable
// instant having been reached, so of a completion and a cancellation racing
// on one record, on this process or on another replica, exactly one succeeds,
// and a refused one changes nothing. Completing or cancelling an unknown
// identifier is that refusal, not an error. A database failure is returned
// wrapped with the operation's name, never as a refusal or as
// recovery.ErrRecordNotFound.
//
// The proven and reported authenticators are stored as their "kind:id"
// references, one per line, in order, and read back unchanged.
type RecoveryRecordStore struct{ c *config }

// NewRecoveryRecordStore returns a durable recovery-record store on db.
//
// It honours WithTxResolver, and refuses any other option: records arrive
// with their own identifiers, so WithIDGenerator does not apply, and every
// time it stores comes from the caller, so WithClock does not either.
//
// Limits, stated: PostgreSQL text cannot hold a NUL byte or invalid UTF-8. A
// record whose user reference, or an authenticator reference, holds either,
// or whose authenticator reference would not read back as itself (a newline,
// a colon in its kind, an empty part), is refused with an error that names
// the field, never the value, and nothing is written. Stored times are UTC,
// truncated to the microsecond.
func NewRecoveryRecordStore(db *sql.DB, opts ...Option) (*RecoveryRecordStore, error) {
	c, err := newConfig(db, opts)
	if err != nil {
		return nil, err
	}

	return &RecoveryRecordStore{c: c}, nil
}

// Insert stores r, pending or already completed, refusing an identifier
// already stored. The refusal runs no failing statement, so it leaves a
// caller's transaction usable.
func (s *RecoveryRecordStore) Insert(ctx context.Context, r recovery.Record) error {
	const op = "insert recovery record"

	if err := storekit.CheckID(r.ID, "recovery record"); err != nil {
		return failed(op, err)
	}
	if err := storekit.CheckStorable(storekit.Text("user", string(r.User))); err != nil {
		return failed(op, err)
	}
	proven, err := pgschema.RecoveryRefsText(r.Proven)
	if err != nil {
		return failed(op, fmt.Errorf("the proven list: %w", err))
	}
	reported, err := pgschema.RecoveryRefsText(r.Reported)
	if err != nil {
		return failed(op, fmt.Errorf("the reported list: %w", err))
	}

	n, err := s.c.exec(ctx, op, pgschema.RecoveryRecordInsert, r.ID, string(r.User),
		storekit.Time(r.StartedAt), storekit.Time(r.NotBefore), nullTs(r.CompletedAt), nullTs(r.CancelledAt),
		proven, reported, r.SavedSpent)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("sqlstore: insert recovery record: the identifier is already in use")
	}

	return nil
}

// Find returns the record with this identifier, or recovery.ErrRecordNotFound.
func (s *RecoveryRecordStore) Find(ctx context.Context, rid id.ID) (*recovery.Record, error) {
	const op = "find recovery record"

	var (
		r                  = recovery.Record{ID: rid}
		user               string
		started, notBefore time.Time
		completed, cancel  sql.NullTime
		proven, reported   string
	)
	err := s.c.queryRow(ctx, op, pgschema.RecoveryRecordSelect, []any{rid},
		&user, &started, &notBefore, &completed, &cancel, &proven, &reported, &r.SavedSpent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, recovery.ErrRecordNotFound
	}
	if err != nil {
		return nil, err
	}

	if r.Proven, err = pgschema.ParseRecoveryRefs(proven); err != nil {
		return nil, failed(op, fmt.Errorf("the proven list: %w", err))
	}
	if r.Reported, err = pgschema.ParseRecoveryRefs(reported); err != nil {
		return nil, failed(op, fmt.Errorf("the reported list: %w", err))
	}
	r.User = identity.UserID(user)
	r.StartedAt, r.NotBefore = started.UTC(), notBefore.UTC()
	r.CompletedAt, r.CancelledAt = fromNull(completed), fromNull(cancel)

	return &r, nil
}

// Complete marks the record completed at at, only while it is neither
// completed nor cancelled and at is not before its NotBefore, and reports
// whether this call completed it.
func (s *RecoveryRecordStore) Complete(ctx context.Context, rid id.ID, at time.Time) (bool, error) {
	n, err := s.c.exec(ctx, "complete recovery record", pgschema.RecoveryRecordComplete, rid, storekit.Time(at))

	return n == 1, err
}

// Cancel marks the record cancelled at at, only while it is neither completed
// nor cancelled, and reports how many it cancelled: 0 or 1.
func (s *RecoveryRecordStore) Cancel(ctx context.Context, rid id.ID, at time.Time) (int, error) {
	n, err := s.c.exec(ctx, "cancel recovery record", pgschema.RecoveryRecordCancel, rid, storekit.Time(at))

	return int(n), err
}

// CancelPending marks every record of user that is neither completed nor
// cancelled as cancelled at at, and reports how many it cancelled.
func (s *RecoveryRecordStore) CancelPending(ctx context.Context, user identity.UserID, at time.Time) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	n, err := s.c.exec(ctx, "cancel pending recovery records", pgschema.RecoveryRecordCancelPending,
		string(user), storekit.Time(at))

	return int(n), err
}

// LatestCompletion reports the latest completion time among user's records,
// or false when none is completed.
func (s *RecoveryRecordStore) LatestCompletion(ctx context.Context, user identity.UserID) (time.Time, bool, error) {
	if !storekit.Storable(string(user)) {
		return time.Time{}, false, nil
	}

	var latest sql.NullTime
	if err := s.c.queryRow(ctx, "find latest recovery completion", pgschema.RecoveryRecordLatestCompletion,
		[]any{string(user)}, &latest); err != nil {
		return time.Time{}, false, err
	}

	return fromNull(latest), latest.Valid, nil
}

var _ recovery.RecordStore = (*RecoveryRecordStore)(nil)
