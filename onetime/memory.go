package onetime

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/kartaladev/scrty/pkg/id"
)

// MemoryStore keeps tokens in process memory. It is the default store, it
// implements Reaper as well as Store, and it is safe for concurrent use.
//
// It is not durable, and that is its one stated limit: a new process starts
// with no tokens, so every link and code issued by the previous one stops
// working. Supply a durable store through WithStore to survive a restart.
//
// Nothing purges it on a timer. Expired records stay until PurgeExpired is
// called, where a consumer decides how often that happens; an expired record
// that is still held is never honoured, because expiry is judged at every
// check.
type MemoryStore struct {
	mu      sync.Mutex
	now     func() time.Time
	records map[id.ID]Token
}

// MemoryStoreOption configures a MemoryStore.
type MemoryStoreOption func(*MemoryStore)

// WithMemoryStoreClock replaces the store's time source. The default is
// time.Now.
//
// The store needs a clock of its own because only it can decide which of its
// records have expired while it sweeps them. A test that moves a manager's
// clock gives the store the same one, so expiry means the same thing on both
// sides. A nil function keeps the default, since a store with no clock could
// not sweep at all.
func WithMemoryStoreClock(now func() time.Time) MemoryStoreOption {
	return func(s *MemoryStore) {
		if now != nil {
			s.now = now
		}
	}
}

// NewMemoryStore returns the default store.
func NewMemoryStore(opts ...MemoryStoreOption) *MemoryStore {
	s := &MemoryStore{now: time.Now, records: make(map[id.ID]Token)}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	return s
}

// Len reports how many records the store currently holds, spent and unspent
// alike. It exists for tests and for a consumer watching the store grow.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.records)
}

// copyToken returns a record that shares no backing array with tok.
//
// A Token's hashes are slices, so copying the struct copies only their headers.
// Without this the store is a window onto the caller's buffers: a consumer
// wiping the buffer it handed over — ordinary hygiene for anything derived from
// a secret — would destroy the stored hash, after which a perfectly good token
// stops matching for a reason nothing points at. An absent binding hash stays
// absent, because slices.Clone of nil is nil, and an empty one would compare
// equal to the hash of a presented nothing.
func copyToken(tok Token) Token {
	tok.SecretHash = slices.Clone(tok.SecretHash)
	tok.BindingHash = slices.Clone(tok.BindingHash)

	return tok
}

// Insert stores tok. A record identifier that is already present is refused
// rather than overwritten: silently replacing a record would invalidate a token
// already in a holder's hands.
func (s *MemoryStore) Insert(_ context.Context, tok Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.records[tok.ID]; exists {
		return fmt.Errorf("onetime: a token with identifier %s is already stored", tok.ID)
	}
	s.records[tok.ID] = copyToken(tok)

	return nil
}

// FindByID returns the record with this identifier, or ErrTokenNotFound.
func (s *MemoryStore) FindByID(_ context.Context, tokenID id.ID) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.records[tokenID]
	if !found {
		return nil, ErrTokenNotFound
	}

	out := copyToken(rec)

	return &out, nil
}

// Consume marks the record consumed at, and succeeds only while it is still
// unconsumed.
//
// The test and the write happen under one lock, so of several callers racing on
// the same token exactly one is told it succeeded. A record that is missing and
// one that is already spent are the same ErrTokenNotFound: the caller learns
// that there was nothing here to spend, and nothing about which of the two it
// was.
func (s *MemoryStore) Consume(_ context.Context, tokenID id.ID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.records[tokenID]
	if !found || !rec.ConsumedAt.IsZero() {
		return ErrTokenNotFound
	}

	rec.ConsumedAt = at
	s.records[tokenID] = rec

	return nil
}

// CountRecentBySubject counts this purpose's records for subject issued at or
// after since, spent ones included: what is being counted is how often the
// subject asked, not how many tokens they still hold.
func (s *MemoryStore) CountRecentBySubject(_ context.Context, purpose, subject string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var n int
	for _, rec := range s.records {
		if rec.Purpose == purpose && rec.Subject == subject && !rec.IssuedAt.Before(since) {
			n++
		}
	}

	return n, nil
}

// DeleteExpiredBefore removes this purpose's records that are both expired by
// the store's clock and were issued strictly before retainSince, and reports
// how many went.
//
// A zero retainSince is refused and nothing is deleted. The zero time is what a
// caller who forgot to compute a cutoff passes, and taken literally it would
// mean "retain nothing issued since the beginning of time" — a sweep that looks
// like a sweep and is in fact a purge of everything expired, including tokens
// an issuance count is still resting on.
func (s *MemoryStore) DeleteExpiredBefore(_ context.Context, purpose string, retainSince time.Time) (int, error) {
	if retainSince.IsZero() {
		return 0, ErrRetainSinceRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()

	var removed int
	for key, rec := range s.records {
		if rec.Purpose != purpose {
			continue
		}
		if now.Before(rec.ExpiresAt) || !rec.IssuedAt.Before(retainSince) {
			continue
		}
		delete(s.records, key)
		removed++
	}

	return removed, nil
}

var (
	_ Store  = (*MemoryStore)(nil)
	_ Reaper = (*MemoryStore)(nil)
)
