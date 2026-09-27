package storetest_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/kartaladev/scrty/policy"
)

// attemptDefect is one deliberate flaw an attemptStore can carry.
type attemptDefect string

const (
	attemptConforming attemptDefect = "conforming"
	// FailureCount also counts a failure recorded exactly at since.
	attemptCountInclusive attemptDefect = "count-inclusive"
	// A purge also deletes a failure recorded exactly at the cutoff.
	attemptReapInclusive attemptDefect = "reap-inclusive-cutoff"
	// RecordFailure and FailureCount strip NUL bytes from the username, so
	// two submitted identifiers count as one.
	attemptStripsNUL attemptDefect = "strips-nul"
	// RecordFailure and FailureCount refuse a username holding a NUL byte,
	// without echoing it. The contract allows it, so this conforms.
	attemptRefusesNUL attemptDefect = "refuses-nul"
)

// username applies the defect's handling of a NUL byte to username.
func (s *attemptStore) username(username string) (string, error) {
	switch {
	case !strings.ContainsRune(username, 0):
		return username, nil
	case s.defect == attemptStripsNUL:
		return strings.ReplaceAll(username, "\x00", ""), nil
	case s.defect == attemptRefusesNUL:
		return "", errors.New("the username holds text the store cannot keep")
	default:
		return username, nil
	}
}

// attemptStore is a login-attempt store and reaper over process memory. The
// shipped in-memory store has no reaper, so without a defect this is the
// conforming store the suite's purge cases are seen passing on.
type attemptStore struct {
	defect attemptDefect

	mu       sync.Mutex
	failures map[string][]time.Time
}

var (
	_ policy.AttemptStore  = (*attemptStore)(nil)
	_ policy.AttemptReaper = (*attemptStore)(nil)
)

func newAttemptStore(defect attemptDefect) *attemptStore {
	return &attemptStore{defect: defect, failures: make(map[string][]time.Time)}
}

func (s *attemptStore) RecordFailure(_ context.Context, username string, at time.Time) error {
	username, err := s.username(username)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.failures[username] = append(s.failures[username], at)
	return nil
}

func (s *attemptStore) Reset(_ context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.failures, username)
	return nil
}

func (s *attemptStore) FailureCount(_ context.Context, username string, since time.Time) (int, error) {
	username, err := s.username(username)
	if err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for _, at := range s.failures[username] {
		if at.After(since) || (s.defect == attemptCountInclusive && at.Equal(since)) {
			n++
		}
	}
	return n, nil
}

func (s *attemptStore) DeleteAttemptsBefore(_ context.Context, retainSince time.Time) (int, error) {
	if retainSince.IsZero() {
		return 0, policy.ErrRetainSinceRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for username, times := range s.failures {
		kept := times[:0]
		for _, at := range times {
			if at.Before(retainSince) || (s.defect == attemptReapInclusive && at.Equal(retainSince)) {
				n++
				continue
			}
			kept = append(kept, at)
		}
		s.failures[username] = kept
	}
	return n, nil
}
