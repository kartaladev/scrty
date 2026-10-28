package lockout

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/policy"
)

// ErrReapUnsupported is returned by Policy.PurgeExpired when the
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

// ErrAttemptStoreFull is returned by MemoryAttemptStore when it already holds
// as many identifiers as its capacity allows, a sweep has released none, and
// it is asked to record a failure for an identifier it does not hold, or to
// count the failures of one.
//
// The lockout policy treats it as it treats any store error: the login is
// denied. A full store that let a new identifier through would let it guess
// without being counted, which is the one thing a lockout store must never do.
var ErrAttemptStoreFull = errors.New("policy: the attempt store is full")

// AttemptReaper is the optional half of policy.AttemptStore: a store that can delete
// the failures it no longer needs to hold.
//
// It is separate because purging is a capability, not an obligation. A store
// whose rows are swept by a database job, or which keeps every failure for
// audit, implements policy.AttemptStore and stops there; PurgeExpired over it reports
// ErrReapUnsupported rather than pretending to have swept. MemoryAttemptStore
// implements it.
//
//go:generate mockgen -source=attempts.go -package=lockout_test -destination=attempts_mock_test.go -typed
//go:generate mockgen -source=../attempt_views.go -package=lockout_test -destination=attemptstore_mock_test.go -typed -exclude_interfaces=AttemptViewRequirer
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

// FailureStreakStore is the optional half of policy.AttemptStore that keeps each
// identifier's consecutive failures, for a policy configured with
// WithCap.
//
// A store that implements it must clear the streak, hold included, in Reset,
// atomically with the failures Reset already clears: one transaction for a SQL
// store. No reader may ever see the failure log cleared and the hold kept, or
// the reverse, so that every path that clears an identifier's failures also
// lifts its hold.
//
// Identifiers are matched exactly, as policy.AttemptStore matches them. Every instant
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

// defaultAttemptStoreCapacity is how many identifiers MemoryAttemptStore holds
// unless WithAttemptStoreCapacity replaces it.
const defaultAttemptStoreCapacity = 100_000

// maxPlainIdentifierLen is the longest identifier MemoryAttemptStore keeps as
// given. A longer one is kept by its SHA-256 digest, so the bytes an attacker
// can make the store hold per identifier are bounded, whatever they submit.
const maxPlainIdentifierLen = 256

// fullSweepInterval is the most often a full store sweeps again to make room.
// A full store is swept on demand rather than once per retention, so it frees
// space as soon as failures age out; the interval keeps that sweep from being
// something an attacker can make run on every request.
const fullSweepInterval = time.Minute

// compactMinIdentifiers is the high-water mark below which the store's map is
// never replaced: below it, the buckets a sweep leaves behind are not worth a
// copy.
const compactMinIdentifiers = 1024

// attemptKey is how MemoryAttemptStore holds an identifier: as given when it
// is at most maxPlainIdentifierLen bytes, and by digest otherwise. The flag
// keeps the two apart, so no identifier as given can collide with another's
// digest.
type attemptKey struct {
	id       string
	digested bool
}

// keyFor returns the key username is held under.
func keyFor(username string) attemptKey {
	if len(username) <= maxPlainIdentifierLen {
		return attemptKey{id: username}
	}
	sum := sha256.Sum256([]byte(username))

	return attemptKey{id: string(sum[:]), digested: true}
}

// attemptEntry is everything MemoryAttemptStore holds for one identifier.
type attemptEntry struct {
	failures []time.Time
	streak   FailureStreak
}

// empty reports whether the entry holds nothing the policy needs: no failure
// and no streak.
func (e *attemptEntry) empty() bool {
	return len(e.failures) == 0 && e.streak.Failures == 0 && !e.streak.Held()
}

// MemoryAttemptOption configures a MemoryAttemptStore.
type MemoryAttemptOption func(*MemoryAttemptStore)

// WithAttemptStoreCapacity replaces how many identifiers the store holds at
// once. The default is 100,000.
//
// A capacity of zero or less holds nothing, so every login would be refused;
// it is a wiring mistake, and NewMemoryAttemptStore panics on it, since it
// returns no error.
func WithAttemptStoreCapacity(n int) MemoryAttemptOption {
	return func(s *MemoryAttemptStore) { s.capacity = n }
}

// MemoryAttemptStore keeps failed attempts in process memory. It is the
// default store and it is safe for concurrent use.
//
// It stays bounded. A lockout policy built over it tells it the longest it
// needs a failure kept: the window, or the cap's retention (WithCap)
// when that is longer. The store then forgets what is older than that as it is
// written to: each write drops the written identifier's expired failures, and
// once per retention a write sweeps every identifier. A hold is never
// forgotten before it lifts. A store shared by several policies keeps what the
// longest-retaining of them needs. A store no policy has been built over does
// not know how long a failure matters, and forgets nothing by age.
//
// It holds at most 100,000 identifiers (WithAttemptStoreCapacity). An
// identifier longer than 256 bytes is held by its SHA-256 digest, so a long
// one costs no more than a short one. When the store is full and a sweep frees
// nothing, a failure for an identifier it does not hold is refused with
// ErrAttemptStoreFull, and so is counting that identifier's failures, so the
// lockout policy denies its login. That is the trade-off: a flood of distinct
// identifiers can stop new identifiers from logging in on this replica until
// the flood's failures age out, rather than let any of them guess uncounted.
// Identifiers the store already holds are counted and judged as before.
// Forgetting counts to make room was rejected, because a way to make the store
// forget is a way to disarm lockout.
//
// Its other limits are stated rather than worked around:
//
//   - It is per replica. Two processes behind a load balancer count their own
//     failures, so an attacker spread across replicas needs the threshold on
//     each of them before any one locks the account.
//   - It does not survive a restart. A deploy clears every count, and every
//     account locked at that moment is unlocked.
//
// A lockout policy tells the store its retention only when the store passed to
// WithAttemptStore is a *MemoryAttemptStore itself. A consumer type that wraps
// one never learns the retention, so it never sweeps, and once full it refuses
// every new identifier until it is reset. Build such a wrapper over a store the
// consumer sweeps itself, or pass the inner *MemoryAttemptStore to the policy
// and have the wrapper forward to it.
//
// A deployment that needs any of those, or a capacity a single process cannot
// give, supplies its own store through WithAttemptStore: a durable or shared
// store is the override for the full-store trade-off.
type MemoryAttemptStore struct {
	mu       sync.Mutex
	entries  map[attemptKey]*attemptEntry
	capacity int

	// retention is how long a failure matters to the longest-retaining policy
	// built over the store, and zero while no policy has been. clk is the
	// first such policy's clock, used to sweep a full store on a read, which
	// carries no instant of its own.
	retention time.Duration
	clk       clock.Clock

	// sweptAt paces the regular sweep, once per retention; fullSweptAt paces
	// the sweep a full store runs to make room, once per fullSweepInterval.
	sweptAt, fullSweptAt time.Time

	// highWater is the most identifiers held since the map was last replaced,
	// which tells a map emptied by a sweep from one that was always small.
	highWater int
}

// NewMemoryAttemptStore returns the default attempt store, holding nothing,
// with a capacity of 100,000 identifiers unless WithAttemptStoreCapacity
// replaces it. It panics on a capacity of zero or less.
func NewMemoryAttemptStore(opts ...MemoryAttemptOption) *MemoryAttemptStore {
	s := &MemoryAttemptStore{
		entries:  make(map[attemptKey]*attemptEntry),
		capacity: defaultAttemptStoreCapacity,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if s.capacity <= 0 {
		panic(fmt.Sprintf("policy: WithAttemptStoreCapacity must be positive, got %d: "+
			"a store that holds nothing refuses every login", s.capacity))
	}

	return s
}

// retainFor tells the store a policy built over it needs failures kept for
// retention, judged by clk. The store keeps the longest retention it has been
// told, so no policy sharing it loses a failure it still counts.
func (s *MemoryAttemptStore) retainFor(retention time.Duration, clk clock.Clock) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.retention = max(s.retention, retention)
	if s.clk == nil {
		s.clk = clk
	}
}

// entryForWriteLocked returns key's entry, creating it if there is room, after
// the sweep the write at now is due.
func (s *MemoryAttemptStore) entryForWriteLocked(key attemptKey, now time.Time) (*attemptEntry, error) {
	s.sweepLocked(now)

	if e, ok := s.entries[key]; ok {
		return e, nil
	}
	if !s.roomLocked(now) {
		return nil, ErrAttemptStoreFull
	}

	e := &attemptEntry{}
	s.entries[key] = e
	s.highWater = max(s.highWater, len(s.entries))

	return e, nil
}

// roomLocked reports whether the store can take one more identifier, sweeping
// a full store first when that sweep is due.
func (s *MemoryAttemptStore) roomLocked(now time.Time) bool {
	if len(s.entries) < s.capacity {
		return true
	}
	if s.retention <= 0 {
		return false
	}

	// A clock stepped backwards would otherwise stop the sweep until it caught
	// up; re-arming from now resumes it one interval later.
	if now.Before(s.fullSweptAt) {
		s.fullSweptAt = now
	}
	if s.fullSweptAt.IsZero() || now.Sub(s.fullSweptAt) >= min(fullSweepInterval, s.retention) {
		s.pruneLocked(now)
		s.fullSweptAt = now
	}

	return len(s.entries) < s.capacity
}

// sweepLocked sweeps the store at most once per retention, from the writes
// themselves, so there is no goroutine to start, stop or leak, and an attacker
// cannot make it run more often by sending more requests.
func (s *MemoryAttemptStore) sweepLocked(now time.Time) {
	if s.retention <= 0 {
		return
	}
	if now.Before(s.sweptAt) {
		s.sweptAt = now

		return
	}
	if !s.sweptAt.IsZero() && now.Sub(s.sweptAt) < s.retention {
		return
	}

	s.pruneLocked(now)
	s.sweptAt = now
}

// pruneLocked forgets, for every identifier, the failures recorded strictly
// before now minus the retention, and the identifiers left with nothing the
// policy needs. A streak whose newest failure is that old is inactive and goes
// too; a held one never does.
func (s *MemoryAttemptStore) pruneLocked(now time.Time) {
	cutoff := now.Add(-s.retention)
	for key, e := range s.entries {
		e.failures = dropBefore(e.failures, cutoff)
		if !e.streak.Held() && !e.streak.Newest.After(cutoff) {
			e.streak = FailureStreak{}
		}
		if e.empty() {
			delete(s.entries, key)
		}
	}
	s.compactLocked()
}

// compactLocked replaces the map once a sweep has left it under a quarter of
// its high-water mark. Go maps keep their buckets after their entries are
// deleted, so without it a flood's memory would stay held after its
// identifiers had gone.
func (s *MemoryAttemptStore) compactLocked() {
	n := len(s.entries)
	if s.highWater < compactMinIdentifiers || 4*n >= s.highWater {
		return
	}

	fresh := make(map[attemptKey]*attemptEntry, n)
	maps.Copy(fresh, s.entries)
	s.entries, s.highWater = fresh, n
}

// dropBefore removes, in place, the instants strictly before cutoff, and
// returns the ones kept.
func dropBefore(at []time.Time, cutoff time.Time) []time.Time {
	kept := at[:0]
	for _, t := range at {
		if !t.Before(cutoff) {
			kept = append(kept, t)
		}
	}
	clear(at[len(kept):])

	return kept
}

// RecordFailure records one failed attempt for username at the instant at.
//
// The instant is the caller's, not the store's: the policy counting the window
// and the store holding the failures must agree about when it happened, and
// only the caller knows which clock the deployment judges time by.
//
// A full store refuses an identifier it does not hold with
// ErrAttemptStoreFull; see MemoryAttemptStore.
func (s *MemoryAttemptStore) RecordFailure(_ context.Context, username string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, err := s.entryForWriteLocked(keyFor(username), at)
	if err != nil {
		return err
	}
	if s.retention > 0 {
		e.failures = dropBefore(e.failures, at.Add(-s.retention))
	}
	e.failures = append(e.failures, at)

	return nil
}

// Reset clears username's recorded failures and its consecutive-failure
// streak, hold included, and is not an error for an identifier that has
// neither.
func (s *MemoryAttemptStore) Reset(_ context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, keyFor(username))

	return nil
}

// FailureCount reports how many of username's failures were recorded strictly
// after since.
//
// Nothing the store holds leaves it: the count is a number, and the instants
// it was computed from stay behind the lock, so a caller cannot reach into the
// record of what an account has been locked for.
//
// A full store that does not hold username, and cannot make room for it,
// answers ErrAttemptStoreFull rather than zero: the failure that login would
// go on to record could not be counted, so it must not be let through to make
// it.
func (s *MemoryAttemptStore) FailureCount(_ context.Context, username string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[keyFor(username)]
	if !ok {
		if s.fullLocked() {
			return 0, ErrAttemptStoreFull
		}

		return 0, nil
	}

	var count int
	for _, at := range e.failures {
		if at.After(since) {
			count++
		}
	}

	return count, nil
}

// fullLocked reports whether the store has no room for one more identifier,
// sweeping it first, by the owning policy's clock, when that sweep is due.
func (s *MemoryAttemptStore) fullLocked() bool {
	if len(s.entries) < s.capacity {
		return false
	}
	if s.clk == nil {
		return true
	}

	return !s.roomLocked(s.clk.Now())
}

var _ policy.AttemptStore = (*MemoryAttemptStore)(nil)

// clampCutoffLocked returns cutoff, or now minus the store's longest retention
// when that is earlier. Without a retention, which no policy has set yet, or
// without a clock, the cutoff stands. The caller holds s.mu.
func (s *MemoryAttemptStore) clampCutoffLocked(cutoff time.Time) time.Time {
	if s.retention <= 0 || s.clk == nil {
		return cutoff
	}

	floor := s.clk.Now().Add(-s.retention)
	if floor.Before(cutoff) {
		return floor
	}

	return cutoff
}

// DeleteAttemptsBefore removes the failures recorded strictly before
// retainSince, whatever identifier they belong to, and reports how many went.
// An identifier left with no failures and no streak is forgotten. A zero
// retainSince is refused with ErrRetainSinceRequired and nothing is deleted.
//
// The cutoff is clamped to no later than now minus the longest retention any
// policy built over the store has asked for, so a store shared by policies
// with different windows keeps what the longest-retaining of them still counts,
// whichever policy purges.
func (s *MemoryAttemptStore) DeleteAttemptsBefore(_ context.Context, retainSince time.Time) (int, error) {
	if retainSince.IsZero() {
		return 0, ErrRetainSinceRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	retainSince = s.clampCutoffLocked(retainSince)

	var n int
	for key, e := range s.entries {
		before := len(e.failures)
		e.failures = dropBefore(e.failures, retainSince)
		n += before - len(e.failures)
		if e.empty() {
			delete(s.entries, key)
		}
	}
	s.compactLocked()

	return n, nil
}

var _ AttemptReaper = (*MemoryAttemptStore)(nil)

// AddStreakFailure adds one failure at at to username's streak and returns
// the streak after it, under the store's lock, so concurrent adds each see the
// previous one's result. It follows FailureStreakStore's contract: an inactive
// streak that is not held restarts at one with Newest at at, the add that
// brings the count to limit or above sets the hold and is the only one to
// report it, and on a continuing streak Newest never moves backwards.
//
// It holds any identifier, long ones by digest, but a full store refuses one
// it does not hold with ErrAttemptStoreFull; see MemoryAttemptStore.
func (s *MemoryAttemptStore) AddStreakFailure(
	_ context.Context, username string, at, since time.Time, limit int,
) (FailureStreak, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, err := s.entryForWriteLocked(keyFor(username), at)
	if err != nil {
		return FailureStreak{}, false, err
	}

	cur := e.streak
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
	e.streak = cur

	return cur, setHold, nil
}

// FailureStreak reads username's streak. One that is not held and whose
// newest failure is at or before since reads as the zero FailureStreak, as
// does an identifier with no streak.
func (s *MemoryAttemptStore) FailureStreak(_ context.Context, username string, since time.Time) (FailureStreak, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[keyFor(username)]
	if !ok {
		return FailureStreak{}, nil
	}
	cur := e.streak
	if !cur.Held() && !cur.Newest.After(since) {
		return FailureStreak{}, nil
	}

	return cur, nil
}

// DeleteStreaksBefore removes every streak that is not held and whose newest
// failure is strictly before retainSince, and reports how many went. A held
// streak is kept whatever its age. A zero retainSince is refused with
// ErrRetainSinceRequired and nothing is deleted.
//
// The cutoff is clamped as DeleteAttemptsBefore's is: to no later than now
// minus the longest retention any policy built over the store has asked for,
// so a policy with a shorter cap retention cannot drop a count another policy
// on the same store still holds.
func (s *MemoryAttemptStore) DeleteStreaksBefore(_ context.Context, retainSince time.Time) (int, error) {
	if retainSince.IsZero() {
		return 0, ErrRetainSinceRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	retainSince = s.clampCutoffLocked(retainSince)

	var n int
	for key, e := range s.entries {
		if e.streak.Failures == 0 || e.streak.Held() || !e.streak.Newest.Before(retainSince) {
			continue
		}
		e.streak = FailureStreak{}
		n++
		if len(e.failures) == 0 {
			delete(s.entries, key)
		}
	}
	s.compactLocked()

	return n, nil
}

var _ FailureStreakStore = (*MemoryAttemptStore)(nil)
