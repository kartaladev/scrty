package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/lifecycle"
	"github.com/kartaladev/scrty/internal/nilcheck"
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
// WithMemoryStoreHousekeepingInterval after the previous sweep finished, waiting on the
// store's clock (WithMemoryStoreClock). The interval defaults to one minute.
// Only Shutdown ends it, and Shutdown is terminal for housekeeping alone: a
// shut-down store keeps saving, loading and deleting sessions.
//
// # Limits, stated
//
// It is per process and not durable. A new process starts with no sessions, so
// every session issued by the previous one stops working, and two replicas do
// not see each other's. A consumer that needs either supplies a durable store
// through WithStore, and nothing else about the manager changes.
//
// Without Start, or after Shutdown, expired sessions stay in memory until
// something deletes them — DeleteExpired or DeleteByUser. They are never served:
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

	// lifecycleMu guards the housekeeping state below. It is separate from mu,
	// and never held while waiting, so that Shutdown can wait for a sweep that
	// takes mu, and Start and Shutdown never wait on each other.
	lifecycleMu sync.Mutex
	shutdown    bool
	// cancel ends the housekeeping run, and done is closed once it has
	// ended. Both stay set after Shutdown, so a later Shutdown waits again.
	// They are nil until Start.
	cancel context.CancelFunc
	done   chan struct{}
}

// NewMemoryStore returns the default store: housekeeping every minute
// (WithMemoryStoreHousekeepingInterval) on the system clock
// (WithMemoryStoreClock).
//
// It refuses a housekeeping interval of zero or less, and a nil clock, typed
// nil included, with an error wrapping ErrConfig, and returns no store.
func NewMemoryStore(opts ...MemoryStoreOption) (*MemoryStore, error) {
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

	if s.interval <= 0 {
		return nil, fmt.Errorf("%w: the housekeeping interval must be positive, got %s", ErrConfig, s.interval)
	}
	if nilcheck.IsNil(s.clock) {
		return nil, fmt.Errorf("%w: the memory store's clock must not be nil", ErrConfig)
	}

	return s, nil
}

// Len reports how many records the store currently holds, expired ones
// included.
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.records)
}

// ErrAlreadyStarted is what Start returns for a store whose housekeeping is
// already running.
var ErrAlreadyStarted = errors.New("session: already started")

// ErrAlreadyShutdown is what Start returns for a store that has been shut
// down.
var ErrAlreadyShutdown = errors.New("session: already shut down")

// Start launches housekeeping, which calls DeleteExpired one interval after
// the previous call finished until Shutdown is called.
//
// Housekeeping carries the values of ctx, such as trace and log fields, but
// not its cancellation or deadline: only Shutdown stops it, so a
// request-scoped context passed here, or one already cancelled, does not end
// it. A second Start returns ErrAlreadyStarted, and a Start after Shutdown
// returns ErrAlreadyShutdown; neither launches anything.
//
// A nil ctx is refused with an error wrapping ErrConfig, and nothing is
// launched or changed: a later Start with a real context still works.
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
	if ctx == nil {
		return fmt.Errorf("%w: Start needs a non-nil context", ErrConfig)
	}

	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	switch {
	case s.shutdown:
		return ErrAlreadyShutdown
	case s.cancel != nil:
		return ErrAlreadyStarted
	}

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})
	s.cancel, s.done = cancel, done

	go s.housekeep(runCtx, done)

	return nil
}

// housekeep sweeps expired sessions one interval after the previous sweep
// finished, waiting on the store's clock, until ctx ends, and closes done
// once it has returned.
//
// It ends with return, never with break: a break inside the select would leave
// the select but not the for.
func (s *MemoryStore) housekeep(ctx context.Context, done chan<- struct{}) {
	defer close(done)

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

// Shutdown ends housekeeping and waits for it to end, so no sweep is in
// progress when it returns nil. It waits no longer than ctx allows: if ctx is
// done first, it returns ctx's error, and the sweep in progress finishes on
// its own. When housekeeping has already ended, it returns nil even for a ctx
// that is already done.
//
// A nil ctx is refused with an error wrapping ErrConfig, and nothing is
// changed: the store is not marked shut down and housekeeping keeps running.
//
// It is terminal for housekeeping only. Housekeeping never runs again, and a
// later Start returns ErrAlreadyShutdown, but the store keeps saving, loading
// and deleting sessions, so requests still being drained are served.
//
// It is idempotent. A later Shutdown waits again under its own context, and
// returns nil once housekeeping has ended. Shutting down a store that was
// never started marks it shut down and returns nil.
//
// Call it from outside housekeeping. Shutdown called from within a sweep, by
// a clock or a wrapper the sweep calls into, cannot wait for itself: it waits
// until its own ctx ends and returns that ctx's error.
func (s *MemoryStore) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: Shutdown needs a non-nil context", ErrConfig)
	}

	s.lifecycleMu.Lock()
	s.shutdown = true
	cancel, done := s.cancel, s.done
	s.lifecycleMu.Unlock()

	if cancel == nil {
		return nil
	}
	cancel()

	// A run that has ended wins over a ctx that is already done.
	return lifecycle.Await(ctx, done)
}

// Create inserts sess. An identifier that is already stored is refused rather
// than overwritten: replacing it would silently end the session already
// holding that identifier. A session with no family, the nil family, is
// refused with an error before anything is written.
func (s *MemoryStore) Create(_ context.Context, sess *Session) error {
	if sess.FamilyID.IsZero() {
		return errors.New("session: a session with no family cannot be stored")
	}
	if sess.FamilyCreatedAt.IsZero() {
		return errors.New("session: a session with no family start time cannot be stored")
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
// AuthenticatedAt and the family, supersession (RetainUntil included) and
// presentation fields, and never inserts. Those are kept as Create, Supersede
// and MarkPresented wrote them, whatever the saved session says. A superseded
// record also keeps both of its own deadlines, so a stale copy can change
// neither them nor its retention.
//
// A session that is no longer stored is ErrNotFound. That is the whole
// point of the split: a request that loaded a session, raced a logout and then
// recorded activity would otherwise write the revoked session back, and the
// revocation would lose.
func (s *MemoryStore) Save(_ context.Context, sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.records[sess.ID]
	if !exists {
		return ErrNotFound
	}
	rec := sess.clone()
	rec.MFAAtFirstFactor = stored.MFAAtFirstFactor
	rec.AuthenticatedAt = stored.AuthenticatedAt
	rec.FamilyID = stored.FamilyID
	rec.FamilyCreatedAt = stored.FamilyCreatedAt
	rec.SupersededAt = stored.SupersededAt
	rec.AcceptUntil = stored.AcceptUntil
	rec.SuccessorDigest = stored.SuccessorDigest
	rec.RetainUntil = stored.RetainUntil
	rec.FirstPresentedAt = stored.FirstPresentedAt
	if !stored.SupersededAt.IsZero() {
		rec.IdleExpiresAt = stored.IdleExpiresAt
		rec.AbsoluteExpiresAt = stored.AbsoluteExpiresAt
	}
	s.records[sess.ID] = rec

	return nil
}

// Load returns the session with this identifier. A live session past either
// deadline is ErrExpired. A superseded one is returned until its
// RetainUntil passes, whatever its own deadlines say and with them intact, so
// a [Sessions] can tell a late presentation (reuse) from an expiry; one with no
// RetainUntil is judged by its own deadlines.
func (s *MemoryStore) Load(_ context.Context, id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, found := s.records[id]
	if !found {
		return nil, ErrNotFound
	}
	if stale(rec, s.clock.Now()) {
		return nil, ErrExpired
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
// identifier keep and its family's current session, the member not
// superseded, expired ones included, and reports how many went. Every other
// member of keep's family goes, superseded ones included. It runs under the
// store's lock, so a session created or superseded concurrently is either
// judged by this rule or written after the call.
//
// A keep naming another user's session, or none, leaves it untouched and
// removes every session of this user; an empty keep names none. The reference
// is compared byte-for-byte, as DeleteByUser compares it.
func (s *MemoryStore) DeleteByUserExcept(_ context.Context, user identity.UserID, keep string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	kept := map[string]struct{}{keep: {}}
	if rec, found := s.records[keep]; found && rec.UserID == user && !rec.FamilyID.IsZero() {
		for member := range s.byFamily[rec.FamilyID] {
			if s.records[member].SupersededAt.IsZero() {
				kept[member] = struct{}{}
			}
		}
	}

	var removed int
	for sessionID, rec := range s.records {
		if _, keepIt := kept[sessionID]; keepIt || rec.UserID != user {
			continue
		}
		s.deleteLocked(sessionID)
		removed++
	}

	return removed, nil
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

// DeleteExpired removes every expired session and reports how many went: a
// live one once either of its deadlines passes, and a superseded one once its
// RetainUntil passes, or its own deadlines when it has none.
func (s *MemoryStore) DeleteExpired(_ context.Context) (int, error) {
	now := s.clock.Now()

	return s.removeWhere(func(rec *Session) bool { return stale(rec, now) }), nil
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
// A session that is not stored is ErrNotFound, and nothing is
// inserted.
//
// It changes the stored record in place under the store's lock, so a change
// another caller saved in the meantime survives it.
func (s *MemoryStore) RecordActivity(_ context.Context, id string, lastAccessed, idleExpires, olderThan time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.records[id]
	if !found {
		return ErrNotFound
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
// ErrRenewalConflict; an Old that is not stored is ErrNotFound;
// a nil Successor is an error, and so is an Old with no family (the nil
// family), which is refused before anything is written. An Old that is
// superseded already is superseded again only through its observed successor:
// observing none, as for a fresh head, is ErrRenewalConflict, since the
// session was knocked out of the chain and renewing it would give the family a
// second live head. An observed successor that is superseded or no
// longer stored, or presented when op.RequireUnpresentedSuccessor is set,
// writes nothing and is ErrSuccessorAdvanced.
//
// A successor with no family, or a RetainUntil before AcceptUntil, is
// refused with an error before anything is written. Old and its previous
// successor take the later of their stored RetainUntil and op.RetainUntil as
// their RetainUntil, so housekeeping removes them only when their family
// could no longer be live, and no supersession lowers a retention deadline.
// Neither record's own deadlines change.
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
	if op.Successor.FamilyCreatedAt.IsZero() {
		return errors.New("session: a supersession's successor needs a family start time")
	}
	if op.RetainUntil.Before(op.AcceptUntil) {
		return errors.New("session: a supersession's retention deadline is before the end of its window")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	old, found := s.records[op.Old]
	if !found {
		return ErrNotFound
	}
	if old.FamilyID.IsZero() {
		return errors.New("session: a session with no family cannot be superseded")
	}
	if !bytes.Equal(old.SuccessorDigest, op.ObservedSuccessor) ||
		len(op.ObservedSuccessor) == 0 && !old.SupersededAt.IsZero() {
		return ErrRenewalConflict
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

// retain keeps a superseded record for reuse detection until the later of its
// retention deadline and until, never lowering it. Its own deadlines are left
// alone: renewal, recovery and a load inside the window still read them.
func retain(rec *Session, until time.Time) {
	rec.RetainUntil = laterTime(rec.RetainUntil, until)
}

// stale reports whether the store may forget rec at now: a superseded record
// once its retention deadline passes, any other, and a superseded one with no
// retention deadline, once one of its own deadlines does.
func stale(rec *Session, now time.Time) bool {
	if rec.superseded() && !rec.RetainUntil.IsZero() {
		return !now.Before(rec.RetainUntil)
	}

	return rec.expired(now)
}

// successorLocked returns the stored record whose identifier old's successor
// digest names, or nil when old has no successor or it is no longer stored.
// Callers hold s.mu, for reading at least.
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
// session that is not stored is ErrNotFound; a superseded one is
// ErrSuperseded, whether presented or not, and nothing is written; an
// unsuperseded one already presented is not an error.
func (s *MemoryStore) MarkPresented(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.records[id]
	switch {
	case !found:
		return ErrNotFound
	case !rec.SupersededAt.IsZero():
		return ErrSuperseded
	case !rec.FirstPresentedAt.IsZero():
		return nil
	}
	rec.FirstPresentedAt = at

	return nil
}

// SuccessorPresented reports whether the current successor of the session
// with this identifier was used, under the store's read lock, writing
// nothing: true when that successor is stored and was presented or has been
// superseded, false when it is stored unused, is no longer stored, or the
// session has none. A session that is not stored is ErrNotFound.
// "Stored" is judged as Load judges it, at the store's clock: a record Load
// would not return, swept or not, is not stored, for the session and for its
// successor alike.
func (s *MemoryStore) SuccessorPresented(_ context.Context, id string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := s.clock.Now()
	rec, found := s.records[id]
	if !found || stale(rec, now) {
		return false, ErrNotFound
	}
	successor := s.successorLocked(rec)
	if successor == nil || stale(successor, now) {
		return false, nil
	}

	return !successor.FirstPresentedAt.IsZero() || successor.superseded(), nil
}

var _ Store = (*MemoryStore)(nil)

// MemoryStoreOption configures a MemoryStore.
type MemoryStoreOption func(*MemoryStore)

// WithMemoryStoreHousekeepingInterval replaces how often a started store sweeps expired
// sessions. The default is one minute. Each sweep starts one interval after
// the previous one finished.
//
// Zero or less is refused by NewMemoryStore with an error wrapping ErrConfig:
// a non-positive interval would make housekeeping spin, which is not what a
// caller asking for it wants.
func WithMemoryStoreHousekeepingInterval(d time.Duration) MemoryStoreOption {
	return func(s *MemoryStore) { s.interval = d }
}

// WithMemoryStoreClock replaces the store's time source. The default is
// clock.System().
//
// The store needs a clock of its own because only it can decide which of its
// records are expired, both when it refuses to serve one and when it sweeps,
// and it waits on the same clock between housekeeping sweeps, so a controlled
// clock runs housekeeping without real waiting. A test that moves a manager's
// clock gives the store the same one, so expiry means the same thing on both
// sides.
//
// The housekeeping loop calls After from its own goroutine, after Start has
// returned, and again only once the previous sweep has finished. A caller
// driving a controlled clock therefore waits for the loop to be waiting on it
// before advancing it, both after Start and after each advance that triggers a
// sweep: with clockwork's fake, BlockUntilContext(ctx, 1), counting only this
// store's waiter, so a clock shared with other waiters needs their count added.
// An advance made earlier is not seen by a loop that has not yet called After.
//
// A nil clock, typed nil included, is refused by NewMemoryStore with an error
// wrapping ErrConfig, since a store with no clock could not judge expiry at
// all.
func WithMemoryStoreClock(clk clock.Timed) MemoryStoreOption {
	return func(s *MemoryStore) { s.clock = clk }
}
