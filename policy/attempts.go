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

// FailureStreakStore is the optional half of AttemptStore that keeps each
// identifier's consecutive failures, for a policy configured with
// WithLockoutCap.
//
// A store that implements it must clear the streak, hold included, in Reset,
// atomically with the failures Reset already clears: one transaction for a SQL
// store. No reader may ever see the failure log cleared and the hold kept, or
// the reverse, so that every path that clears an identifier's failures also
// lifts its hold.
//
// Identifiers are matched exactly, as AttemptStore matches them. Every instant
// is the caller's, never the store's clock.
//
// An identifier the store cannot hold, such as one with a NUL byte in a
// PostgreSQL text column, is refused by AddStreakFailure with an error whose
// text does not contain the identifier, and reads from FailureStreak as the
// zero FailureStreak with a nil error. The policy denies on a read error, so
// an unstorable identifier must read as no streak rather than fail the read,
// exactly as FailureCount treats it.
//
// The lockout policy always passes a non-zero since that is before the instant
// of the failure, and a limit of at least 2. A store need not validate them,
// and its behaviour outside them is unspecified.
//
// An implementation is called on the request path, once per failed login, so
// it must be safe for concurrent use.
type FailureStreakStore interface {
	// AddStreakFailure adds one failure at at to username's streak, in one
	// atomic write, and returns the streak after it.
	//
	// A streak that is not held and whose newest failure is at or before since
	// restarts: the cutoff is inclusive, so a newest failure exactly at since
	// is inactive. A restarted streak is {Failures: 1, Newest: at}. The write
	// that brings the count to limit or above, on a streak not yet held, sets
	// HeldAt to at and reports setHold true; no later write moves HeldAt, and
	// no other write reports setHold. A limit lowered below a streak's count is
	// therefore reached by that streak's next write.
	//
	// On a streak that continues, Newest never moves backwards: an at earlier
	// than the stored newest failure still counts, but leaves Newest where it
	// is. The restart is judged against the stored newest failure, never
	// against at.
	//
	// The caller passes a non-zero since that is before at, and a limit of at
	// least 2. A store need not validate them, and its behaviour outside them
	// is unspecified.
	//
	// An identifier the store cannot hold is refused with an error whose text
	// does not contain it.
	AddStreakFailure(
		ctx context.Context, username string, at, since time.Time, limit int,
	) (streak FailureStreak, setHold bool, err error)

	// FailureStreak reads username's streak. One that is not held and whose
	// newest failure is at or before since reads as the zero FailureStreak.
	// An identifier with no streak reads as the zero FailureStreak, and is
	// not an error. So is an identifier the store cannot hold: it reads as the
	// zero FailureStreak with a nil error.
	//
	// The caller passes a non-zero since. A store need not validate it, and its
	// behaviour for a zero since is unspecified.
	FailureStreak(ctx context.Context, username string, since time.Time) (FailureStreak, error)

	// DeleteStreaksBefore removes every streak that is not held and whose
	// newest failure is strictly before retainSince, and reports how many
	// went. A held streak is never removed.
	//
	// A zero retainSince is refused with ErrRetainSinceRequired and nothing is
	// deleted.
	DeleteStreaksBefore(ctx context.Context, retainSince time.Time) (int, error)
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
//   - It keeps consecutive-failure streaks (FailureStreakStore) and can delete
//     the inactive ones through DeleteStreaksBefore, but that does not make it
//     an AttemptReaper: the failures above are still never purged.
//
// A deployment that needs any of those supplies its own store through
// WithAttemptStore.
type MemoryAttemptStore struct {
	mu       sync.Mutex
	failures map[string][]time.Time
	streaks  map[string]FailureStreak
}

// NewMemoryAttemptStore returns the default attempt store, holding nothing.
func NewMemoryAttemptStore() *MemoryAttemptStore {
	return &MemoryAttemptStore{
		failures: make(map[string][]time.Time),
		streaks:  make(map[string]FailureStreak),
	}
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

// Reset clears username's recorded failures and its consecutive-failure
// streak, hold included, and is not an error for an identifier that has
// neither.
func (s *MemoryAttemptStore) Reset(_ context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.failures, username)
	delete(s.streaks, username)

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

// AddStreakFailure adds one failure at at to username's streak and returns
// the streak after it, under the store's lock, so concurrent adds each see the
// previous one's result. It follows FailureStreakStore's contract: an inactive
// streak that is not held restarts at one with Newest at at, the add that
// brings the count to limit or above sets the hold and is the only one to
// report it, and on a continuing streak Newest never moves backwards. It holds
// any identifier, so it never refuses one.
func (s *MemoryAttemptStore) AddStreakFailure(
	_ context.Context, username string, at, since time.Time, limit int,
) (FailureStreak, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur := s.streaks[username]
	if !cur.Held() && !cur.Newest.After(since) {
		cur = FailureStreak{}
	}
	cur.Failures++
	if at.After(cur.Newest) {
		cur.Newest = at
	}
	setHold := false
	if !cur.Held() && cur.Failures >= limit {
		cur.HeldAt, setHold = at, true
	}
	s.streaks[username] = cur

	return cur, setHold, nil
}

// FailureStreak reads username's streak. One that is not held and whose
// newest failure is at or before since reads as the zero FailureStreak, as
// does an identifier with no streak.
func (s *MemoryAttemptStore) FailureStreak(_ context.Context, username string, since time.Time) (FailureStreak, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur := s.streaks[username]
	if !cur.Held() && !cur.Newest.After(since) {
		return FailureStreak{}, nil
	}

	return cur, nil
}

// DeleteStreaksBefore removes every streak that is not held and whose newest
// failure is strictly before retainSince, and reports how many went. A held
// streak is kept whatever its age. A zero retainSince is refused with
// ErrRetainSinceRequired and nothing is deleted.
func (s *MemoryAttemptStore) DeleteStreaksBefore(_ context.Context, retainSince time.Time) (int, error) {
	if retainSince.IsZero() {
		return 0, ErrRetainSinceRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var n int
	for username, cur := range s.streaks {
		if !cur.Held() && cur.Newest.Before(retainSince) {
			delete(s.streaks, username)
			n++
		}
	}

	return n, nil
}

var _ FailureStreakStore = (*MemoryAttemptStore)(nil)
