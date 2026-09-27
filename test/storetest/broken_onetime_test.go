package storetest_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
)

// oneTimeDefect is one deliberate flaw a oneTimeStore can carry.
type oneTimeDefect string

const (
	oneTimeConforming oneTimeDefect = "conforming"
	// Consume of a spent record succeeds and overwrites when it was spent.
	oneTimeConsumeMovesTime oneTimeDefect = "consume-moves-time"
	// A purge reads a zero cutoff as "no cutoff" and deletes everything expired.
	oneTimeReapAcceptsZero oneTimeDefect = "reap-accepts-zero-cutoff"
	// A purge also deletes a record issued exactly at the cutoff.
	oneTimeReapInclusive oneTimeDefect = "reap-inclusive-cutoff"
	// Insert keeps the caller's hash buffers rather than copies of them.
	oneTimeInsertKeepsSlices oneTimeDefect = "insert-keeps-caller-slices"
	// FindByID refuses a record expired by the system clock, judging what the
	// contract leaves to the manager.
	oneTimeFindRefusesExpiredBySystem oneTimeDefect = "find-refuses-expired-by-system-clock"
	// FindByID refuses a record expired by the store's clock.
	oneTimeFindRefusesExpiredByStore oneTimeDefect = "find-refuses-expired-by-store-clock"
	// FindByID hands back the stored binding hash rather than a copy of it.
	oneTimeFindSharesBinding oneTimeDefect = "find-shares-binding"
	// The recent-issue count leaves out records expired by the store's clock,
	// so a subject waiting out their tokens' expiry asks again unlimited.
	oneTimeCountSkipsExpiredByStore oneTimeDefect = "count-skips-expired-by-store-clock"
	// The recent-issue count leaves out records expired by the system clock.
	oneTimeCountSkipsExpiredBySystem oneTimeDefect = "count-skips-expired-by-system-clock"
	// Consume refuses a record expired by the system clock, judging what the
	// contract leaves to the manager.
	oneTimeConsumeRefusesExpiredBySystem oneTimeDefect = "consume-refuses-expired-by-system-clock"
	// Consume refuses a record expired by the store's clock.
	oneTimeConsumeRefusesExpiredByStore oneTimeDefect = "consume-refuses-expired-by-store-clock"
)

// oneTimeStore is a one-time token store and reaper over process memory,
// written apart from the shipped store so a defect can reach state the
// shipped store never exposes. Without a defect it conforms.
type oneTimeStore struct {
	defect oneTimeDefect
	now    func() time.Time

	mu      sync.Mutex
	records map[id.ID]onetime.Token
}

var (
	_ onetime.Store  = (*oneTimeStore)(nil)
	_ onetime.Reaper = (*oneTimeStore)(nil)
)

func newOneTimeStore(defect oneTimeDefect, now func() time.Time) *oneTimeStore {
	return &oneTimeStore{defect: defect, now: now, records: make(map[id.ID]onetime.Token)}
}

func cloneToken(tok onetime.Token) onetime.Token {
	tok.SecretHash = bytes.Clone(tok.SecretHash)
	tok.BindingHash = bytes.Clone(tok.BindingHash)
	return tok
}

func (s *oneTimeStore) Insert(_ context.Context, tok onetime.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.records[tok.ID]; exists {
		return errors.New("identifier already stored")
	}
	if s.defect != oneTimeInsertKeepsSlices {
		tok = cloneToken(tok)
	}
	s.records[tok.ID] = tok
	return nil
}

func (s *oneTimeStore) FindByID(_ context.Context, tokenID id.ID) (*onetime.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tok, ok := s.records[tokenID]
	switch {
	case !ok,
		s.defect == oneTimeFindRefusesExpiredBySystem && !time.Now().Before(tok.ExpiresAt),
		s.defect == oneTimeFindRefusesExpiredByStore && !s.now().Before(tok.ExpiresAt):
		return nil, onetime.ErrTokenNotFound
	}
	out := cloneToken(tok)
	if s.defect == oneTimeFindSharesBinding {
		out.BindingHash = tok.BindingHash
	}
	return &out, nil
}

func (s *oneTimeStore) Consume(_ context.Context, tokenID id.ID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tok, ok := s.records[tokenID]
	switch {
	case !ok,
		!tok.ConsumedAt.IsZero() && s.defect != oneTimeConsumeMovesTime,
		s.defect == oneTimeConsumeRefusesExpiredBySystem && !time.Now().Before(tok.ExpiresAt),
		s.defect == oneTimeConsumeRefusesExpiredByStore && !s.now().Before(tok.ExpiresAt):
		return onetime.ErrTokenNotFound
	}
	tok.ConsumedAt = at
	s.records[tokenID] = tok
	return nil
}

func (s *oneTimeStore) CountRecentBySubject(_ context.Context, purpose, subject string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	n := 0
	for _, tok := range s.records {
		switch {
		case tok.Purpose != purpose, tok.Subject != subject, tok.IssuedAt.Before(since),
			s.defect == oneTimeCountSkipsExpiredByStore && !now.Before(tok.ExpiresAt),
			s.defect == oneTimeCountSkipsExpiredBySystem && !time.Now().Before(tok.ExpiresAt):
		default:
			n++
		}
	}
	return n, nil
}

func (s *oneTimeStore) DeleteExpiredBefore(_ context.Context, purpose string, retainSince time.Time) (int, error) {
	if retainSince.IsZero() && s.defect != oneTimeReapAcceptsZero {
		return 0, onetime.ErrRetainSinceRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	n := 0
	for key, tok := range s.records {
		before := tok.IssuedAt.Before(retainSince) || retainSince.IsZero() ||
			(s.defect == oneTimeReapInclusive && tok.IssuedAt.Equal(retainSince))
		if tok.Purpose == purpose && !now.Before(tok.ExpiresAt) && before {
			delete(s.records, key)
			n++
		}
	}
	return n, nil
}
