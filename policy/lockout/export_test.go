package lockout

import "github.com/kartaladev/scrty/policy"

// This file exposes what the package's tests need and consumers must not have.
// It is a test file, so nothing here reaches a production build.

// IdentifiersForTest reports how many distinct identifiers the store holds,
// so a test can show what a sweep released.
func (s *MemoryAttemptStore) IdentifiersForTest() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.entries)
}

// StoreForTest exposes the store a policy counts in, so a test of the default
// store can reach the one the policy built for itself.
func (p *Policy) StoreForTest() policy.AttemptStore { return p.store }
