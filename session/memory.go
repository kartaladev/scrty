package session

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

// MemoryStore keeps sessions in process memory. It is the default store, and
// it is safe for concurrent use.
//
// It holds its own copies of records, on the way in and on the way out, so a
// caller writing to a session it stored or loaded cannot change stored state,
// and two callers holding "the same" session hold two records.
//
// Start launches housekeeping, which sweeps expired sessions one
// WithHousekeepingInterval after the previous sweep finished, waiting on the
// store's clock (WithMemoryStoreClock). The interval defaults to one minute.
// Stop ends it. Both are idempotent, and housekeeping also ends when the
// context given to Start does.
//
// # Limits, stated
//
// It is per process and not durable. A new process starts with no sessions, so
// every session issued by the previous one stops working, and two replicas do
// not see each other's. A consumer that needs either supplies a durable store
// through WithStore, and nothing else about the manager changes.
//
// Without Start, expired sessions stay in memory until something deletes
// them — DeleteExpired, DeleteByUser, or a later Start. They are never served:
// Load judges expiry on every read, so a record that is still held is already
// unreachable. What is lost is the memory it occupies, not safety. Loading
// does not delete what it refuses, deliberately: a read that deleted other
// records would make every caller a sweeper and every read a write.
type MemoryStore struct {
	mu       sync.RWMutex
	clock    clock.Timed
	interval time.Duration
	records  map[string]*Session

	// byDigest maps the digest of each stored identifier to that identifier,
	// so finding the record a successor digest names is a lookup rather than
	// a scan that hashes every key. It holds exactly the keys of records, and
	// is written wherever records is.
	byDigest map[string]string

	// byFamily maps each family to the identifiers of its stored records, so
	// revoking a family touches its own records rather than scanning the
	// store. Like byDigest it is written wherever records is.
	byFamily map[id.ID]map[string]struct{}

	// lifecycle guards the housekeeping run below. It is separate from mu so
	// that Stop can wait for a sweep to finish while that sweep takes mu.
	lifecycle sync.Mutex
	cancel    context.CancelFunc
	runDone   <-chan struct{}
	wg        sync.WaitGroup
}

// NewMemoryStore returns the default store.
func NewMemoryStore(opts ...MemoryStoreOption) *MemoryStore {
	s := &MemoryStore{
		clock:    clock.System(),
		interval: defaultHousekeepingInterval,
		records:  make(map[string]*Session),
		byDigest: make(map[string]string),
		byFamily: make(map[id.ID]map[string]struct{}),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	return s
}

// Len reports how many records the store currently holds, expired ones
// included.
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.records)
}

// Start launches housekeeping, which calls DeleteExpired one interval after the
// previous call finished until Stop is called or ctx ends.
//
// It is idempotent: starting a store whose housekeeping is running launches
// nothing and returns nil. Starting again after the context of a previous run
// ended launches fresh housekeeping, which is how a consumer whose request-scoped
// context ended by mistake gets housekeeping back without a new store.
//
// Housekeeping is optional. Without it nothing is ever served that has
// expired, because Load judges expiry on every read; what is lost is the
// memory those records occupy. See the type's documentation.
//
// Start returns before housekeeping has begun waiting on the clock: the loop
// calls the clock's After from its own goroutine. A caller driving a controlled
// clock (WithMemoryStoreClock) waits for that one waiter before advancing it —
// with clockwork's fake, BlockUntilContext(ctx, 1) — or its advance may land
// before the loop starts counting and never trigger a sweep.
func (s *MemoryStore) Start(ctx context.Context) error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()

	if s.runningLocked() {
		return nil
	}
	// A previous run whose context was cancelled is over, or is ending.
	// Reaping it leaves the WaitGroup at zero, so the loop launched below is
	// the only one a later Stop waits for.
	s.reapLocked()

	loopCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.runDone = loopCtx.Done()

	s.wg.Add(1)
	go s.housekeep(loopCtx)

	return nil
}

// runningLocked reports whether the loop last launched is still live, which is
// true until that run's context is cancelled. Callers hold s.lifecycle.
func (s *MemoryStore) runningLocked() bool {
	if s.runDone == nil {
		return false
	}
	select {
	case <-s.runDone:
		return false
	default:
		return true
	}
}

// reapLocked ends the run last launched, if there is one, and returns only
// once its loop has ended. Callers hold s.lifecycle.
//
// Waiting under the lifecycle lock is safe, and is what makes concurrent Start
// and Stop race-free: the loop never takes this lock, so it cannot be blocked
// on it while the wait is in progress.
func (s *MemoryStore) reapLocked() {
	if s.cancel == nil {
		return
	}

	s.cancel()
	s.wg.Wait()
	s.cancel, s.runDone = nil, nil
}

// housekeep sweeps expired sessions one interval after the previous sweep
// finished, waiting on the store's clock, until ctx ends.
//
// It ends with return, never with break: a break inside the select would leave
// the select but not the for.
func (s *MemoryStore) housekeep(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.clock.After(s.interval):
			// The only error this store returns is none, and there is no
			// caller to hand one to from a background loop.
			_, _ = s.DeleteExpired(ctx)
		}
	}
}

// Stop ends housekeeping and returns only once it has ended, so no sweep is in
// progress when Stop returns.
//
// It is idempotent, and returns at once for a store that was never started.
// Unlike a cancelled context, Stop is not terminal: a later Start launches
// housekeeping again.
func (s *MemoryStore) Stop() error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()

	s.reapLocked()

	return nil
}

// Create inserts sess. An identifier that is already stored is refused rather
// than overwritten: replacing it would silently end the session already
// holding that identifier. A session with no family, the nil family, is
// refused with an error before anything is written.
func (s *MemoryStore) Create(_ context.Context, sess *Session) error {
	if sess.FamilyID.IsZero() {
		return errors.New("session: a session with no family cannot be stored")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.records[sess.ID]; exists {
		return errors.New("session: a session with this identifier is already stored")
	}
	s.putLocked(sess.clone())

	return nil
}

// putLocked stores rec, a record not stored yet, under its identifier and
// indexes its digest and family. Callers hold s.mu.
func (s *MemoryStore) putLocked(rec *Session) {
	s.records[rec.ID] = rec
	s.byDigest[string(sessionDigest(rec.ID))] = rec.ID
	members, ok := s.byFamily[rec.FamilyID]
	if !ok {
		members = make(map[string]struct{})
		s.byFamily[rec.FamilyID] = members
	}
	members[rec.ID] = struct{}{}
}

// deleteLocked removes the record with this identifier and its index
// entries. Callers hold s.mu.
func (s *MemoryStore) deleteLocked(sessionID string) {
	rec, found := s.records[sessionID]
	if !found {
		return
	}
	delete(s.records, sessionID)
	delete(s.byDigest, string(sessionDigest(sessionID)))
	if members := s.byFamily[rec.FamilyID]; members != nil {
		delete(members, sessionID)
		if len(members) == 0 {
			delete(s.byFamily, rec.FamilyID)
		}
	}
}

// Save updates the stored session, whole except for MFAAtFirstFactor,
// AuthenticatedAt and the family, supersession and presentation fields, and
// never inserts. Those are
// kept as Create, Supersede and MarkPresented wrote them, whatever the saved
// session says. A superseded record also keeps both of its deadlines.
//
// A session that is no longer stored is ErrSessionNotFound. That is the whole
// point of the split: a request that loaded a session, raced a logout and then
// recorded activity would otherwise write the revoked session back, and the
// revocation would lose.
func (s *MemoryStore) Save(_ context.Context, sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.records[sess.ID]
	if !exists {
		return ErrSessionNotFound
	}
	rec := sess.clone()
	rec.MFAAtFirstFactor = stored.MFAAtFirstFactor
	rec.AuthenticatedAt = stored.AuthenticatedAt
	rec.FamilyID = stored.FamilyID
	rec.FamilyCreatedAt = stored.FamilyCreatedAt
	rec.SupersededAt = stored.SupersededAt
	rec.AcceptUntil = stored.AcceptUntil
	rec.SuccessorDigest = stored.SuccessorDigest
	rec.FirstPresentedAt = stored.FirstPresentedAt
	if !stored.SupersededAt.IsZero() {
		rec.IdleExpiresAt = stored.IdleExpiresAt
		rec.AbsoluteExpiresAt = stored.AbsoluteExpiresAt
	}
	s.records[sess.ID] = rec

	return nil
}

// Load returns the session with this identifier.
func (s *MemoryStore) Load(_ context.Context, id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, found := s.records[id]
	if !found {
		return nil, ErrSessionNotFound
	}
	if rec.expired(s.clock.Now()) {
		return nil, ErrSessionExpired
	}

	return rec.clone(), nil
}

// removeWhere deletes every record matching keep and reports how many went.
func (s *MemoryStore) removeWhere(match func(*Session) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	var removed int
	for id, rec := range s.records {
		if !match(rec) {
			continue
		}
		s.deleteLocked(id)
		removed++
	}

	return removed
}

// DeleteByUser removes every session of this user, expired ones included.
//
// The reference is compared byte-for-byte, because identity states a user
// reference is opaque: two references differing only in case are two different
// users, and folding them here would let one user's logout end another's
// session.
func (s *MemoryStore) DeleteByUser(_ context.Context, user identity.UserID) error {
	s.removeWhere(func(rec *Session) bool { return rec.UserID == user })

	return nil
}

// DeleteByUserExcept removes every session of this user except the one with
// identifier keep, expired ones included, and reports how many went. It runs
// under the store's lock, so a session created concurrently is either removed
// or created after the call.
//
// A keep naming another user's session, or none, leaves it untouched and
// removes every session of this user; an empty keep names none. The reference
// is compared byte-for-byte, as DeleteByUser compares it.
func (s *MemoryStore) DeleteByUserExcept(_ context.Context, user identity.UserID, keep string) (int, error) {
	return s.removeWhere(func(rec *Session) bool { return rec.UserID == user && rec.ID != keep }), nil
}

// CountActiveByUser counts this user's unexpired sessions that are not
// superseded: a renewed sign-in counts once, however often it was renewed.
//
// Expired records are excluded whether or not housekeeping has reached them,
// so a concurrent-session limit written against this count does not depend on
// how recently the store was swept.
func (s *MemoryStore) CountActiveByUser(_ context.Context, user identity.UserID) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := s.clock.Now()

	var n int
	for _, rec := range s.records {
		if rec.UserID == user && rec.SupersededAt.IsZero() && !rec.expired(now) {
			n++
		}
	}

	return n, nil
}

// DeleteExpired removes every expired session and reports how many went.
func (s *MemoryStore) DeleteExpired(_ context.Context) (int, error) {
	now := s.clock.Now()

	return s.removeWhere(func(rec *Session) bool { return rec.expired(now) }), nil
}

// DeleteByExternalSession removes the sessions matching both issuer and the
// provider's own session identifier, and reports how many went.
//
// An empty issuer or an empty session identifier matches nothing. Matching
// everything instead would let one provider's back-channel logout end sessions
// established at another, and an empty session identifier would sweep every
// session that provider issued without one.
func (s *MemoryStore) DeleteByExternalSession(_ context.Context, issuer, sessionID string) (int, error) {
	if issuer == "" || sessionID == "" {
		return 0, nil
	}

	return s.removeWhere(func(rec *Session) bool {
		return rec.ExternalIssuer == issuer && rec.ExternalSessionID == sessionID
	}), nil
}

// DeleteByUserAndExternalIssuer removes this user's sessions from this issuer,
// and reports how many went. An empty issuer matches nothing, so a caller with
// no issuer to hand cannot end that user's password sessions by accident.
func (s *MemoryStore) DeleteByUserAndExternalIssuer(_ context.Context, user identity.UserID, issuer string) (int, error) {
	if issuer == "" {
		return 0, nil
	}

	return s.removeWhere(func(rec *Session) bool {
		return rec.UserID == user && rec.ExternalIssuer == issuer
	}), nil
}

// Delete removes the session with this identifier.
func (s *MemoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deleteLocked(id)

	return nil
}

// RecordActivity writes lastAccessed and idleExpires to the stored session,
// and nothing else, idleExpires capped at the stored absolute deadline, when
// its stored last access is not later than olderThan and it is not superseded. A fresher or superseded session is left unchanged.
// A session that is not stored is ErrSessionNotFound, and nothing is
// inserted.
//
// It changes the stored record in place under the store's lock, so a change
// another caller saved in the meantime survives it.
func (s *MemoryStore) RecordActivity(_ context.Context, id string, lastAccessed, idleExpires, olderThan time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.records[id]
	if !found {
		return ErrSessionNotFound
	}
	if !rec.SupersededAt.IsZero() || rec.LastAccessedAt.After(olderThan) {
		return nil
	}
	rec.LastAccessedAt = lastAccessed
	if idleExpires.After(rec.AbsoluteExpiresAt) {
		idleExpires = rec.AbsoluteExpiresAt
	}
	rec.IdleExpiresAt = idleExpires

	return nil
}

// Supersede marks op.Old superseded by op.Successor, supersedes Old's previous
// successor with a window ending at op.Now, and inserts op.Successor, all
// under the store's lock, provided Old's successor is still
// op.ObservedSuccessor. A stale observation writes nothing and is
// ErrSessionRenewalConflict; an Old that is not stored is ErrSessionNotFound;
// a nil Successor is an error, and so is an Old with no family (the nil
// family), which is refused before anything is written. An Old that is
// superseded already is superseded again only through its observed successor:
// observing none, as for a fresh head, is ErrSessionRenewalConflict, since the
// session was knocked out of the chain and renewing it would give the family a
// second live head. An observed successor that is superseded or no
// longer stored, or presented when op.RequireUnpresentedSuccessor is set,
// writes nothing and is ErrSuccessorAdvanced.
//
// A successor with no family, or a RetainUntil before AcceptUntil, is
// refused with an error before anything is written. Old and its previous
// successor take the later of each current deadline and op.RetainUntil, so
// housekeeping removes them only when their family could no longer be live,
// and no supersession lowers a deadline.
//
// Nothing else is written: no other record of the family is touched, however
// many renewals came before.
func (s *MemoryStore) Supersede(_ context.Context, op Supersession) error {
	if op.Successor == nil {
		return errors.New("session: a supersession needs a successor")
	}
	if op.Successor.FamilyID.IsZero() {
		return errors.New("session: a supersession's successor needs a family")
	}
	if op.RetainUntil.Before(op.AcceptUntil) {
		return errors.New("session: a supersession's retention deadline is before the end of its window")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	old, found := s.records[op.Old]
	if !found {
		return ErrSessionNotFound
	}
	if old.FamilyID.IsZero() {
		return errors.New("session: a session with no family cannot be superseded")
	}
	if !bytes.Equal(old.SuccessorDigest, op.ObservedSuccessor) ||
		len(op.ObservedSuccessor) == 0 && !old.SupersededAt.IsZero() {
		return ErrSessionRenewalConflict
	}
	previous := s.successorLocked(old)
	if len(op.ObservedSuccessor) > 0 && (previous == nil || !previous.SupersededAt.IsZero() ||
		op.RequireUnpresentedSuccessor && !previous.FirstPresentedAt.IsZero()) {
		return ErrSuccessorAdvanced
	}
	if _, exists := s.records[op.Successor.ID]; exists {
		return errors.New("session: a session with this identifier is already stored")
	}

	if previous != nil {
		previous.SupersededAt = op.Now
		previous.AcceptUntil = op.Now
		retain(previous, op.RetainUntil)
	}
	old.SupersededAt = op.Now
	old.AcceptUntil = op.AcceptUntil
	old.SuccessorDigest = sessionDigest(op.Successor.ID)
	retain(old, op.RetainUntil)
	s.putLocked(op.Successor.clone())

	return nil
}

// retain holds a superseded record to one deadline: the later of its absolute
// deadline and until, as both of its deadlines. It never lowers one: a record
// that already outlives the retention keeps its own absolute deadline.
func retain(rec *Session, until time.Time) {
	rec.AbsoluteExpiresAt = laterTime(rec.AbsoluteExpiresAt, until)
	rec.IdleExpiresAt = rec.AbsoluteExpiresAt
}

// successorLocked returns the stored record whose identifier old's successor
// digest names, or nil when old has no successor or it is no longer stored.
// Callers hold s.mu.
func (s *MemoryStore) successorLocked(old *Session) *Session {
	if len(old.SuccessorDigest) == 0 {
		return nil
	}

	id, ok := s.byDigest[string(old.SuccessorDigest)]
	if !ok {
		return nil
	}

	return s.records[id]
}

// DeleteFamily removes every session of this family, superseded or not and
// expired or not, and reports how many went. It reads the family's records
// from an index, so its cost is the family's size, not the store's.
//
// The nil family is refused with an error and nothing is deleted: it names no
// family, as Create refuses to store a session in it.
func (s *MemoryStore) DeleteFamily(_ context.Context, family id.ID) (int, error) {
	if family.IsZero() {
		return 0, errors.New("session: the nil family names no family")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	members := s.byFamily[family]
	n := len(members)
	for sessionID := range members {
		s.deleteLocked(sessionID)
	}

	return n, nil
}

// MarkPresented records at as the session's first presentation, only when
// none is recorded and the session is not superseded, under the store's lock,
// so a supersession either happens first and refuses the mark, or after it. A
// session that is not stored is ErrSessionNotFound; a superseded one is
// ErrSessionSuperseded, whether presented or not, and nothing is written; an
// unsuperseded one already presented is not an error.
func (s *MemoryStore) MarkPresented(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.records[id]
	switch {
	case !found:
		return ErrSessionNotFound
	case !rec.SupersededAt.IsZero():
		return ErrSessionSuperseded
	case !rec.FirstPresentedAt.IsZero():
		return nil
	}
	rec.FirstPresentedAt = at

	return nil
}

var _ Store = (*MemoryStore)(nil)
