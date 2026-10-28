package oidc

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"
)

// errHandoffTokenIDTaken is returned by MemoryHandoffStore.Insert for a token
// id it already holds.
var errHandoffTokenIDTaken = errors.New("oidc: a handoff record with this token id is already stored")

// MemoryHandoffStore keeps handoff codes in process memory. It is the store a
// consumer passes to NewHandoffManager when it has no shared one, and it is
// safe for concurrent use.
//
// It is not durable and not shared: a code issued by one process cannot be
// redeemed by another, and a restart forgets every code. A deployment of
// several instances, where the callback and the redemption may land on
// different ones, supplies a shared HandoffStore instead.
//
// Nothing purges it on a timer. Expired records stay until DeleteExpired is
// called; an expired record that is still held is never honoured, because
// HandoffManager judges expiry at every redemption.
type MemoryHandoffStore struct {
	mu      sync.Mutex
	records map[string]HandoffRecord
}

// NewMemoryHandoffStore returns an empty in-memory handoff store.
//
// DeleteExpired judges expiry against the cutoff it is given, never against a
// clock of its own, matching HandoffStore's contract, so the store has no
// clock to configure.
func NewMemoryHandoffStore() *MemoryHandoffStore {
	return &MemoryHandoffStore{records: make(map[string]HandoffRecord)}
}

// copyHandoffRecord returns a record that shares no memory with rec, so
// neither a caller wiping the buffer it inserted nor one writing to what it
// read back can change what the store holds.
func copyHandoffRecord(rec HandoffRecord) HandoffRecord {
	rec.SecretHash = slices.Clone(rec.SecretHash)
	rec.AMR = slices.Clone(rec.AMR)
	if rec.ConsumedAt != nil {
		at := *rec.ConsumedAt
		rec.ConsumedAt = &at
	}

	return rec
}

// Insert stores rec. A token id the store already holds is refused rather than
// overwritten: replacing a record would invalidate a code already in a
// holder's hands.
func (s *MemoryHandoffStore) Insert(_ context.Context, rec HandoffRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, taken := s.records[rec.TokenID]; taken {
		return errHandoffTokenIDTaken
	}
	s.records[rec.TokenID] = copyHandoffRecord(rec)

	return nil
}

// FindByTokenID returns a copy of the record, or ErrHandoffNotFound.
func (s *MemoryHandoffStore) FindByTokenID(_ context.Context, tokenID string) (*HandoffRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.records[tokenID]
	if !found {
		return nil, ErrHandoffNotFound
	}
	out := copyHandoffRecord(rec)

	return &out, nil
}

// Consume marks the record consumed at the given time, and succeeds only while
// it is unconsumed.
//
// The test and the write happen under one lock, so of several callers racing
// on one code exactly one succeeds. A missing record and a consumed one are the
// same ErrHandoffNotFound.
func (s *MemoryHandoffStore) Consume(_ context.Context, tokenID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.records[tokenID]
	if !found || rec.ConsumedAt != nil {
		return ErrHandoffNotFound
	}
	rec.ConsumedAt = &at
	s.records[tokenID] = rec

	return nil
}

// DeleteExpired removes the records whose expiry is before the cutoff, and
// returns how many it removed. It judges expiry against the given cutoff
// alone, never the store's own clock, matching HandoffStore's contract.
//
// A zero cutoff is refused with ErrRetainSinceRequired and nothing is removed:
// the zero time is what a caller who forgot to compute a cutoff passes.
func (s *MemoryHandoffStore) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	if before.IsZero() {
		return 0, ErrRetainSinceRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var removed int
	for key, rec := range s.records {
		if !rec.ExpiresAt.Before(before) {
			continue
		}
		delete(s.records, key)
		removed++
	}

	return removed, nil
}

var _ HandoffStore = (*MemoryHandoffStore)(nil)
