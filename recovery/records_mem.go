package recovery

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

var (
	// errRecordExists refuses an insert under an identifier already held.
	errRecordExists = errors.New("recovery: a record with this identifier already exists")

	// errRecordBothEnded refuses an insert of a record that is both completed
	// and cancelled, which the contract says no record ever is.
	errRecordBothEnded = errors.New("recovery: a record cannot be both completed and cancelled")
)

// MemoryRecordStore keeps recovery records in process memory. It is the
// default RecordStore, and it is safe for concurrent use.
//
// Its limit is stated: it holds this process's records only. A restart
// forgets every record, so a held recovery can no longer be finished or
// cancelled and the cool-down forgets past completions, and behind several
// replicas each keeps its own records, so a recovery held on one is unknown to
// the others. Supply a durable, shared store for anything beyond a single
// process.
//
// It keeps its own copy of every record, and returns copies, so a caller
// changing a record it inserted or found changes nothing stored.
type MemoryRecordStore struct {
	mu      sync.Mutex
	records map[id.ID]*Record
}

// NewMemoryRecordStore returns an empty in-memory store.
func NewMemoryRecordStore() *MemoryRecordStore {
	return &MemoryRecordStore{records: make(map[id.ID]*Record)}
}

// copyRecord returns a copy of r that shares no slice with it.
func copyRecord(r *Record) *Record {
	c := *r
	c.Proven = slices.Clone(r.Proven)
	c.Reported = slices.Clone(r.Reported)

	return &c
}

// pending reports whether r is neither completed nor cancelled.
func pending(r *Record) bool { return r.CompletedAt.IsZero() && r.CancelledAt.IsZero() }

// Insert implements RecordStore. A record with both CompletedAt and
// CancelledAt set is refused, since at most one of the two is ever set.
func (s *MemoryRecordStore) Insert(_ context.Context, r Record) error {
	if !r.CompletedAt.IsZero() && !r.CancelledAt.IsZero() {
		return errRecordBothEnded
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.records[r.ID]; ok {
		return errRecordExists
	}

	s.records[r.ID] = copyRecord(&r)

	return nil
}

// Find implements RecordStore.
func (s *MemoryRecordStore) Find(_ context.Context, rid id.ID) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.records[rid]
	if !ok {
		return nil, ErrRecordNotFound
	}

	return copyRecord(r), nil
}

// Complete implements RecordStore.
func (s *MemoryRecordStore) Complete(_ context.Context, rid id.ID, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.records[rid]
	if !ok || !pending(r) || at.Before(r.NotBefore) {
		return false, nil
	}

	r.CompletedAt = at

	return true, nil
}

// Cancel implements RecordStore.
func (s *MemoryRecordStore) Cancel(_ context.Context, rid id.ID, at time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.records[rid]
	if !ok || !pending(r) {
		return 0, nil
	}

	r.CancelledAt = at

	return 1, nil
}

// CancelPending implements RecordStore.
func (s *MemoryRecordStore) CancelPending(_ context.Context, user identity.UserID, at time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for _, r := range s.records {
		if r.User == user && pending(r) {
			r.CancelledAt = at
			n++
		}
	}

	return n, nil
}

// LatestCompletion implements RecordStore.
func (s *MemoryRecordStore) LatestCompletion(_ context.Context, user identity.UserID) (time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var latest time.Time
	for _, r := range s.records {
		if r.User == user && r.CompletedAt.After(latest) {
			latest = r.CompletedAt
		}
	}

	return latest, !latest.IsZero(), nil
}
