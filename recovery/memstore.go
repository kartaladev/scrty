package recovery

import (
	"context"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
)

// MemoryCodeStore keeps saved-code hashes in process memory. It is the default
// CodeStore, and it is safe for concurrent use.
//
// Its limit is stated: it holds this process's codes only. A restart forgets
// every set, so every user's saved codes stop working, and behind several
// replicas each keeps its own sets, so a code generated on one is unknown to
// the others. Supply a durable, shared store through WithCodeStore for
// anything beyond a single process.
//
// It keeps its own copies of every hash it is given, so a caller wiping or
// reusing its buffers afterwards changes nothing stored.
type MemoryCodeStore struct {
	mu sync.Mutex
	// sets maps a user to their codes, keyed by hash. A string key is a copy
	// of the hash's bytes, never a view onto the caller's slice.
	sets map[identity.UserID]map[string]*codeEntry
}

// codeEntry is one stored code: when it was stored and, once spent, when.
type codeEntry struct {
	createdAt time.Time
	spentAt   time.Time
}

func (e *codeEntry) spent() bool { return !e.spentAt.IsZero() }

// NewMemoryCodeStore returns an empty in-memory store.
func NewMemoryCodeStore() *MemoryCodeStore {
	return &MemoryCodeStore{sets: make(map[identity.UserID]map[string]*codeEntry)}
}

// ReplaceSet drops user's set and stores hashes in its place, under one lock,
// so no reader sees a mix of the two sets. It cannot fail.
func (s *MemoryCodeStore) ReplaceSet(_ context.Context, user identity.UserID, hashes [][]byte, at time.Time) error {
	set := make(map[string]*codeEntry, len(hashes))
	for _, h := range hashes {
		set[string(h)] = &codeEntry{createdAt: at}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(set) == 0 {
		delete(s.sets, user)

		return nil
	}

	s.sets[user] = set

	return nil
}

// Match reports whether user holds an unspent code whose hash is hash. It
// writes nothing.
func (s *MemoryCodeStore) Match(_ context.Context, user identity.UserID, hash []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.sets[user][string(hash)]

	return ok && !e.spent(), nil
}

// Spend marks user's code whose hash is hash as spent at at, if it is not spent
// already, and reports whether this call spent it. The check and the write
// happen under one lock, so of any number of concurrent spends exactly one
// reports true.
func (s *MemoryCodeStore) Spend(_ context.Context, user identity.UserID, hash []byte, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.sets[user][string(hash)]
	if !ok || e.spent() {
		return false, nil
	}

	e.spentAt = at

	return true, nil
}

// Remaining counts user's unspent codes.
func (s *MemoryCodeStore) Remaining(_ context.Context, user identity.UserID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0

	for _, e := range s.sets[user] {
		if !e.spent() {
			n++
		}
	}

	return n, nil
}

// DeleteUser removes every code of user, spent or not, and reports how many
// were removed.
func (s *MemoryCodeStore) DeleteUser(_ context.Context, user identity.UserID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := len(s.sets[user])
	delete(s.sets, user)

	return n, nil
}
