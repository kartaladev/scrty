package policy

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrReapUnsupported is returned by AccountLockoutPolicy.PurgeExpired when the
// configured attempt store cannot delete anything.
//
// It is reported rather than treated as a sweep that removed nothing, because
// in a metric the two are indistinguishable and only one of them means the
// store is growing without bound.
var ErrReapUnsupported = errors.New("policy: attempt store cannot purge attempts")

// ErrRetainSinceRequired is returned by an AttemptReaper asked to purge with
// the zero time as its cutoff, and nothing is deleted.
//
// The zero time is what a caller who forgot to compute a cutoff passes. Taken
// literally it means "retain nothing recorded since the beginning of time",
// which would delete every failure an account is currently locked by, and so
// would turn a routine sweep into a way to unlock accounts.
var ErrRetainSinceRequired = errors.New("policy: a retain-since cutoff is required")

// AttemptStore records and counts failed authentication attempts per submitted
// identifier. It is what the account lockout policy keys its decision on.
//
// With no store configured the policy uses NewMemoryAttemptStore, which counts
// within one replica only and does not survive a restart. A consumer replaces
// it through WithAttemptStore with any implementation — typically one row per
// failure in their own database, so that every replica locks the same account
// at the same time.
//
// The identifier is the string the caller submitted, stored and matched
// exactly as given: this package attaches no meaning to it and never folds its
// case, because an implementation that did would decide, on the library's
// behalf, that two logins are the same account.
//
// An implementation is called on the request path, once per login attempt, so
// it must be safe for concurrent use.
//
//go:generate mockgen -source=attempts.go -package=policy_test -destination=attempts_mock_test.go -typed
type AttemptStore interface {
	// RecordFailure records one failed attempt for username at the instant at,
	// which is the caller's clock rather than the store's: the same instant the
	// policy judges the window against.
	RecordFailure(ctx context.Context, username string, at time.Time) error

	// Reset clears username's recorded failures, which is what a successful
	// authentication does. Clearing an identifier that has no failures is not
	// an error: a login succeeding is the ordinary case, and it must not have
	// to ask first.
	Reset(ctx context.Context, username string) error

	// FailureCount reports how many of username's failures were recorded
	// strictly after since.
	//
	// Strictly is the contract, not an implementation detail. The policy passes
	// now minus its window, so a failure exactly as old as the window has just
	// fallen out of it; counting it would make the window one instant longer
	// than the one the deployment configured, and would keep an account locked
	// for that instant after its lockout expired.
	FailureCount(ctx context.Context, username string, since time.Time) (int, error)
}

// AttemptReaper is the optional half of AttemptStore: a store that can delete
// the failures it no longer needs to hold.
//
// It is separate because purging is a capability, not an obligation. A store
// whose rows are swept by a database job, or which keeps every failure for
// audit, implements AttemptStore and stops there; PurgeExpired over it reports
// ErrReapUnsupported rather than pretending to have swept. MemoryAttemptStore
// is such a store.
type AttemptReaper interface {
	// DeleteAttemptsBefore removes the failures recorded strictly before
	// retainSince, whatever identifier they belong to, and reports how many
	// went.
	//
	// Strictly before is what makes a sweep safe to run at any moment: the
	// policy derives retainSince from its own window, so every failure the
	// window still counts is left exactly where it is and no sweep can shorten
	// a lockout.
	//
	// A zero retainSince is refused with ErrRetainSinceRequired and nothing is
	// deleted.
	DeleteAttemptsBefore(ctx context.Context, retainSince time.Time) (int, error)
}

// MemoryAttemptStore keeps failed attempts in process memory. It is the
// default store and it is safe for concurrent use.
//
// Its limits are stated rather than worked around:
//
//   - It is per replica. Two processes behind a load balancer count their own
//     failures, so an attacker spread across replicas needs the threshold on
//     each of them before any one locks the account.
//   - It does not survive a restart. A deploy clears every count, and every
//     account locked at that moment is unlocked.
//   - It cannot purge: it does not implement AttemptReaper, so PurgeExpired
//     over it reports ErrReapUnsupported instead of a silent zero. A failure
//     older than the window stops being counted but is still held, and is
//     released only when a successful authentication resets that identifier,
//     so what the store holds grows with the number of distinct identifiers
//     that have ever failed against this replica.
//
// A deployment that needs any of those supplies its own store through
// WithAttemptStore.
type MemoryAttemptStore struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

// NewMemoryAttemptStore returns the default attempt store, holding nothing.
func NewMemoryAttemptStore() *MemoryAttemptStore {
	return &MemoryAttemptStore{failures: make(map[string][]time.Time)}
}

// RecordFailure records one failed attempt for username at the instant at.
//
// The instant is the caller's, not the store's: the policy counting the window
// and the store holding the failures must agree about when it happened, and
// only the caller knows which clock the deployment judges time by.
func (s *MemoryAttemptStore) RecordFailure(_ context.Context, username string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.failures[username] = append(s.failures[username], at)

	return nil
}

// Reset clears username's recorded failures, and is not an error for an
// identifier that has none.
func (s *MemoryAttemptStore) Reset(_ context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.failures, username)

	return nil
}

// FailureCount reports how many of username's failures were recorded strictly
// after since.
//
// Nothing the store holds leaves it: the count is a number, and the instants
// it was computed from stay behind the lock, so a caller cannot reach into the
// record of what an account has been locked for.
func (s *MemoryAttemptStore) FailureCount(_ context.Context, username string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int
	for _, at := range s.failures[username] {
		if at.After(since) {
			count++
		}
	}

	return count, nil
}

var _ AttemptStore = (*MemoryAttemptStore)(nil)
