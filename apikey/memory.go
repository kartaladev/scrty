package apikey

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// MemoryStore keeps key records in process memory. It is the default store and
// it is safe for concurrent use.
//
// It is not durable, and that is its one stated limit: a new process starts
// with no records, so every key issued by the previous one stops working.
// Supply a durable store through WithStore to survive a restart.
//
// Nothing purges it. A revoked or expired record stays until the process ends;
// neither is ever honoured, because both are judged at every verification.
type MemoryStore struct {
	mu      sync.RWMutex
	records map[id.ID]Key
}

// NewMemoryStore returns the default store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[id.ID]Key)}
}

// Len reports how many records the store currently holds, revoked and expired
// alike. It exists for tests and for a consumer watching the store grow.
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.records)
}

// copyKey returns a record that shares no backing array with rec.
//
// A Key's scopes and digest are slices, so copying the struct copies only their
// headers. Without this the store is a window onto the caller's buffers: a
// consumer editing the scope slice it was handed — or wiping a buffer derived
// from a secret, which is ordinary hygiene — would reach through into what is
// stored. The time pointers are copied for the same reason.
func copyKey(rec Key) Key {
	rec.Scopes = slices.Clone(rec.Scopes)
	rec.SecretDigest = bytes.Clone(rec.SecretDigest)
	rec.ExpiresAt = copyTime(rec.ExpiresAt)
	rec.RevokedAt = copyTime(rec.RevokedAt)
	rec.LastUsedAt = copyTime(rec.LastUsedAt)

	return rec
}

// copyTime copies an optional instant, leaving an absent one absent.
func copyTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}

	out := *t

	return &out
}

// Put stores rec.
func (s *MemoryStore) Put(_ context.Context, rec Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records[rec.ID] = copyKey(rec)

	return nil
}

// Get returns the record with this identifier, or ErrKeyNotFound.
func (s *MemoryStore) Get(_ context.Context, keyID id.ID) (Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, found := s.records[keyID]
	if !found {
		return Key{}, ErrKeyNotFound
	}

	return copyKey(rec), nil
}

// Revoke marks the record revoked at, or reports ErrKeyNotFound.
//
// A record already revoked keeps the time first recorded: the first revocation
// is the one that happened, and a later call must not be able to rewrite when
// the key stopped being accepted.
func (s *MemoryStore) Revoke(_ context.Context, keyID id.ID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.records[keyID]
	if !found {
		return ErrKeyNotFound
	}

	if rec.RevokedAt == nil {
		revoked := at
		rec.RevokedAt = &revoked
		s.records[keyID] = rec
	}

	return nil
}

// TouchLastUsed records that a verification of this key succeeded at, or
// reports ErrKeyNotFound.
func (s *MemoryStore) TouchLastUsed(_ context.Context, keyID id.ID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.records[keyID]
	if !found {
		return ErrKeyNotFound
	}

	used := at
	rec.LastUsedAt = &used
	s.records[keyID] = rec

	return nil
}

// List returns every record belonging to principal, revoked and expired ones
// included. A principal with no keys yields an empty result.
func (s *MemoryStore) List(_ context.Context, principal identity.UserID) ([]Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []Key
	for _, rec := range s.records {
		if rec.Principal == principal {
			out = append(out, copyKey(rec))
		}
	}

	// Map iteration is unordered, so without this a listing's order changes
	// between calls. Sorting by identifier makes it the order the keys were
	// minted in, since the default generator's identifiers sort that way.
	slices.SortFunc(out, func(a, b Key) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})

	return out, nil
}

var _ Store = (*MemoryStore)(nil)
