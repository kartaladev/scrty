package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

// Sessions mints sessions, holds them in a Store and enforces their two
// deadlines: an idle one that activity extends and an absolute one that
// nothing extends.
//
// Every default is replaceable. With no options a manager keeps its sessions
// in process memory, mints their identifiers from crypto/rand, expires them
// after 30 minutes of inactivity and ends them 12 hours after they began. A
// consumer supplies a durable store through WithStore, different deadlines
// through WithIdleTimeout and WithAbsoluteTimeout, and a test moves time
// through WithClock without waiting for it.
//
// A store's failure is returned behind fixed text of this package, because
// the store's own text may quote values the library never handed it; the
// store's error still matches through errors.Is and errors.As. A store that
// answers with one of this package's sentinels — ErrNotFound,
// ErrExpired, ErrUnreadable — bare gets that same value back. A
// consumer who wants the store's full error logs it inside their own Store.
//
// A Sessions value is safe for concurrent use as far as its store is: after
// construction it holds no mutable state of its own beyond the lock that
// serialises Rotate.
type Sessions struct {
	store           Store
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	clock           clock.Clock
	logger          *slog.Logger
	random          io.Reader

	// families generates the family identifier every Create starts. It is the
	// pkg/id default generator on the manager's clock: a family identifier is
	// not a secret, so it needs ordering and uniqueness, not the entropy a
	// session identifier draws from random.
	families id.Generator

	// touchInterval is how stale recorded activity may be before Touch writes
	// it again; 0 writes every time.
	touchInterval time.Duration

	// maxLifetime is the longest absolute lifetime a Create may ask for. It
	// is the absolute timeout unless WithMaxAbsoluteLifetime said otherwise.
	maxLifetime         time.Duration
	maxLifetimeSupplied bool

	// maxFamilyLifetime bounds how far a renewal with a new lifetime may
	// carry a family past its start. It is maxLifetime unless
	// WithMaxFamilyLifetime said otherwise.
	maxFamilyLifetime         time.Duration
	maxFamilyLifetimeSupplied bool

	// reuseObserver is told about each detected reuse; nil tells no one.
	reuseObserver         ReuseObserver
	reuseObserverSupplied bool

	// unusedSuccessorRecovery is WithUnusedSuccessorRecovery: a superseded
	// identifier past its window may be renewed while its successor is
	// unused, and an ordinary request with it is refused without revoking.
	unusedSuccessorRecovery bool

	// familiesSupplied records that WithFamilyIDGenerator was given, so a nil
	// generator is told apart from the default.
	familiesSupplied bool

	// storeSupplied records that WithStore replaced the default, so the
	// per-process warning below is written only where it is true.
	storeSupplied bool

	// rotating serialises Rotate, one identifier at a time. The store's
	// conditional Supersede is what keeps a family to one successor, across
	// replicas too; the lock settles two strict rotations of one session in
	// this process more gently. Without it the second could read the old
	// record between the first's supersession and its delete, find a window
	// that has already ended, and revoke the family as reuse; with it, the
	// second finds the record deleted and is refused with
	// ErrNotFound. The lock follows the session rather than the
	// manager, so two users completing a second factor at the same moment do
	// not take turns.
	rotating keyedMutex
}

// keyedMutex hands out one mutex per key and keeps none it is not using.
//
// The zero value is ready to use. It exists because the resource a rotation
// contends for is one session, not the whole manager: locking per key lets
// unrelated sessions rotate at the same time while two rotations of one
// identifier still take turns.
type keyedMutex struct {
	mu   sync.Mutex
	held map[string]*keyedLock
}

// keyedLock is one key's mutex and a count of who is using or waiting for it.
// The count is what lets the last one out remove the entry, so the map does
// not grow by one dead mutex per session ever rotated.
type keyedLock struct {
	mu       sync.Mutex
	inFlight int
}

// lock takes the mutex for key and returns the function that releases it.
//
// Registering under k.mu and then taking the key's own mutex outside it is
// what keeps unrelated keys concurrent: k.mu is held only for the map lookup,
// never for the work the caller does under the key.
func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	if k.held == nil {
		k.held = make(map[string]*keyedLock)
	}
	l, found := k.held[key]
	if !found {
		l = &keyedLock{}
		k.held[key] = l
	}
	l.inFlight++
	k.mu.Unlock()

	l.mu.Lock()

	return func() {
		l.mu.Unlock()

		k.mu.Lock()
		l.inFlight--
		if l.inFlight == 0 {
			delete(k.held, key)
		}
		k.mu.Unlock()
	}
}

// perProcessWarning is written once per manager left on the default store.
//
// It names the consequence rather than merely saying "in memory", because the
// mistake it prevents is deploying a second replica and discovering that every
// other request looks logged out, or that a rolling restart signs everyone
// out at once.
const perProcessWarning = "session: the default in-memory store keeps sessions in this process only, " +
	"so a restart ends every session and a second replica does not see this one's"

// New returns a session manager.
//
// A non-positive idle or absolute timeout is refused here rather than left to
// be noticed at the first login: a zero idle timeout expires every session at
// the instant it is created, so the manager would look like it worked and
// nobody would stay logged in.
//
// Every port and function this takes is refused when nil, with one exception:
// a nil logger is ignored, because "do not log from this component" is a
// reading a nil logger plainly has, while a nil clock has no reading other
// than a mistake.
func New(opts ...Option) (*Sessions, error) {
	m := &Sessions{
		idleTimeout:     defaultIdleTimeout,
		absoluteTimeout: defaultAbsoluteTimeout,
		clock:           clock.System(),
		logger:          slog.Default(),
		random:          rand.Reader,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}

	if m.idleTimeout <= 0 {
		return nil, fmt.Errorf("%w: idle timeout must be positive, got %s", ErrConfig, m.idleTimeout)
	}
	if m.absoluteTimeout <= 0 {
		return nil, fmt.Errorf("%w: absolute timeout must be positive, got %s", ErrConfig, m.absoluteTimeout)
	}
	if m.touchInterval < 0 || m.touchInterval >= m.idleTimeout {
		return nil, fmt.Errorf("%w: touch interval must be at least 0 and less than the idle timeout %s, got %s",
			ErrConfig, m.idleTimeout, m.touchInterval)
	}
	if !m.maxLifetimeSupplied {
		m.maxLifetime = m.absoluteTimeout
	}
	if m.maxLifetime < m.absoluteTimeout {
		return nil, fmt.Errorf("%w: maximum absolute lifetime %s is below the absolute timeout %s",
			ErrConfig, m.maxLifetime, m.absoluteTimeout)
	}
	if !m.maxFamilyLifetimeSupplied {
		m.maxFamilyLifetime = m.maxLifetime
	}
	if m.maxFamilyLifetime < m.maxLifetime {
		return nil, fmt.Errorf("%w: maximum family lifetime %s is below the maximum absolute lifetime %s",
			ErrConfig, m.maxFamilyLifetime, m.maxLifetime)
	}
	if m.reuseObserverSupplied && m.reuseObserver == nil {
		return nil, fmt.Errorf("%w: reuse observer must not be nil", ErrConfig)
	}
	if m.storeSupplied && nilcheck.IsNil(m.store) {
		return nil, fmt.Errorf("%w: store must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(m.clock) {
		return nil, fmt.Errorf("%w: clock must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(m.random) {
		return nil, fmt.Errorf("%w: random source must not be nil", ErrConfig)
	}

	if m.familiesSupplied && nilcheck.IsNil(m.families) {
		return nil, fmt.Errorf("%w: family identifier generator must not be nil", ErrConfig)
	}
	if !m.familiesSupplied {
		m.families = id.NewV7Generator(id.WithClock(m.clock))
	}

	if !m.storeSupplied {
		// The default store judges expiry itself, so it reads the manager's
		// clock: otherwise a manager on a fake or shifted clock would sweep
		// and refuse sessions by a different time than it created them by.
		store, err := NewMemoryStore(WithMemoryStoreClock(timedClock(m.clock)))
		if err != nil {
			return nil, err
		}
		m.store = store
		m.logger.Warn(perProcessWarning)
	}

	return m, nil
}

// identifierBytes is how much entropy a session identifier carries. Thirty-two
// bytes put a bearer identifier out of reach of guessing, and leave no reason
// to make it longer.
const identifierBytes = 32

// newIdentifier reads identifierBytes from the configured source and encodes
// them URL-safe without padding, so the result is 43 characters that travel in
// a cookie, a header or a path segment untouched.
//
// A failing source is an error and nothing else. Falling back to any other
// source — a counter, the clock, a shorter read — would hand out an identifier
// that looks exactly like a good one and can be guessed, and nothing later in
// the request would notice.
func (m *Sessions) newIdentifier() (string, error) {
	raw := make([]byte, identifierBytes)
	if _, err := io.ReadFull(m.random, raw); err != nil {
		return "", fmt.Errorf("session: reading %d random bytes for a session identifier: %w", identifierBytes, err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Create mints a session for user and stores it. The session starts a family
// of its own: a new FamilyID, with FamilyCreatedAt its creation time.
//
// The absolute deadline is CreatedAt plus the manager's absolute timeout
// unless WithAbsoluteLifetime chose another; a lifetime that is not positive
// or exceeds the manager's maximum (WithMaxAbsoluteLifetime) is refused with
// ErrConfig and nothing is stored. The idle deadline is capped at the
// absolute one.
//
// The session records the sign-in as its authentication time
// (AuthenticatedAt is CreatedAt), before the options run.
//
// Every create option is applied before the one store write, so a crash cannot
// leave a live session that has forgotten which factor established it or which
// provider it came from. Options run after the creation time and deadlines are
// set, so an option may read them, as WithSecondFactorAtLogin does.
func (m *Sessions) Create(ctx context.Context, user identity.UserID, opts ...CreateOption) (*Session, error) {
	id, err := m.newIdentifier()
	if err != nil {
		return nil, err
	}

	family, err := m.families.NewID()
	if err != nil {
		return nil, fmt.Errorf("session: generating a family identifier: %w", err)
	}
	if family.IsZero() {
		return nil, fmt.Errorf("%w: the family identifier generator returned the nil identifier", ErrConfig)
	}

	now := m.clock.Now()
	s := &Session{
		ID:                id,
		UserID:            user,
		CreatedAt:         now,
		LastAccessedAt:    now,
		IdleExpiresAt:     now.Add(m.idleTimeout),
		AbsoluteExpiresAt: now.Add(m.absoluteTimeout),
		FamilyID:          family,
		FamilyCreatedAt:   now,
		// A sign-in is an authentication. Set before the options, so a
		// consumer's option may still choose another time.
		AuthenticatedAt: now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	// The lifetime is read back from the deadline the options left, so a
	// WithAbsoluteLifetime and any consumer option that sets the deadline are
	// judged the same way, before anything is stored.
	if lifetime := s.AbsoluteExpiresAt.Sub(s.CreatedAt); lifetime <= 0 || lifetime > m.maxLifetime {
		return nil, fmt.Errorf("%w: absolute lifetime %s is outside 0 to the maximum %s",
			ErrConfig, lifetime, m.maxLifetime)
	}
	if s.IdleExpiresAt.After(s.AbsoluteExpiresAt) {
		s.IdleExpiresAt = s.AbsoluteExpiresAt
	}

	if err := m.store.Create(ctx, s); err != nil {
		return nil, storeFailed(err, "session: the session could not be created")
	}

	return s, nil
}

// Load returns the session with this identifier.
//
// A session superseded by RotateWithGrace loads until its grace window ends,
// while its own deadlines are unexpired; inside the window, one past either
// of them is ErrExpired and nothing is revoked. Presenting it at or
// after the window's end is reuse, whatever its own deadlines say: Load
// revokes its whole family and returns ErrReused (see there for what a
// consumer's transaction must do with it). Every endpoint that reaches a
// session through Load — logout included — therefore gives the same verdict.
//
// With WithUnusedSuccessorRecovery on, a superseded session past its window
// that names a successor is refused with ErrRenewalRequired instead,
// and nothing is revoked: only a renewal (LoadForRenewal, then
// RotateWithGrace) judges it. A superseded session with no successor of its
// own, knocked out by a re-rotation or a recovery, is reuse either way, and
// whatever this manager's clock says: the knock-out ended its window, even
// when the manager that wrote it reads a later time than this one.
//
// The first time a session that is not superseded loads, Load records it as
// presented (Store.MarkPresented), which is what tells an unused successor
// from a used one. The store refuses the mark of a session superseded since
// it was read (ErrSuperseded), and only then does Load read it again
// and judge it at a time read after the re-read: a recovery that superseded
// it between the read and the mark makes this load reuse, rather than
// leaving two live sessions in the family. A live session's first
// presentation therefore costs one read and one write. A session gone by the
// time of the mark is ErrNotFound. Any other failure to record the
// mark is logged at debug and the session is read again and judged the same
// way, since the mark may have lost the race before the failure was
// reported; if that read fails too, the load fails. With
// WithUnusedSuccessorRecovery such a failure fails the load at once (it is
// still logged at debug), because a session served with its first use
// unrecorded could later be judged an unused successor and recovered; leave
// recovery off to serve it.
func (m *Sessions) Load(ctx context.Context, id string) (*Session, error) {
	return m.load(ctx, id, forRequest)
}

// load is Load and LoadForRenewal, which differ only in p.
func (m *Sessions) load(ctx context.Context, id string, p purpose) (*Session, error) {
	s, err := m.loadStored(ctx, id, "session: the session could not be loaded")
	if err != nil {
		return nil, err
	}

	now := m.clock.Now()
	if err := m.judge(ctx, s, now, p); err != nil {
		return nil, err
	}
	if !s.superseded() && s.FirstPresentedAt.IsZero() {
		if err := m.markPresented(ctx, s, now); err != nil {
			if m.unusedSuccessorRecovery && !errors.Is(err, ErrSuperseded) &&
				!errors.Is(err, ErrNotFound) {
				return nil, storeFailed(err, "session: the session's first presentation could not be recorded")
			}

			return m.reloadSuperseded(ctx, id, p, err)
		}
	}

	return s, nil
}

// loadStored reads the session with this identifier from the store. A store
// that answers with neither a session nor an error is read as ErrNotFound,
// so no caller dereferences it; any other failure is a store failure carrying
// text.
func (m *Sessions) loadStored(ctx context.Context, id, text string) (*Session, error) {
	s, err := m.store.Load(ctx, id)
	if err != nil {
		return nil, storeFailed(err, text)
	}
	if s == nil {
		return nil, ErrNotFound
	}

	return s, nil
}

// reloadSuperseded answers a load whose mark failed with err:
// ErrNotFound when the session is gone, and for any other failure,
// ErrSuperseded included, the verdict on the session read again. A
// failure that is not a refusal is read again too when recovery is off (with
// it on, load fails on such a failure before calling this), because the mark may have
// reached the store and lost the race to a recovery before the failure was
// reported; serving the session unmarked would leave this request
// authenticated by a successor the recovery just superseded. If the read
// again fails, so does the load (ErrStore, as for the first read): the
// session cannot be shown to be live, and the load fails closed.
//
// A recovery supersedes a successor only while it is unpresented, so a
// recovery committed between this load's read and its mark would otherwise
// leave this request authenticated by the successor it just superseded, and
// the family with two live heads. Read again, the session is judged as it now
// stands: one knocked out by the recovery names no successor of its own and
// is reuse; one superseded by an ordinary renewal inside its window is
// returned, unmarked.
//
// The re-read is judged at a time read after it, not at the time the first
// read was judged: a recovery committed in between supersedes with a window
// ending at its own, later, time, which the earlier time would read as still
// open.
func (m *Sessions) reloadSuperseded(ctx context.Context, id string, p purpose, err error) (*Session, error) {
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}

	again, err := m.loadStored(ctx, id, "session: the session could not be loaded")
	if err != nil {
		return nil, err
	}
	if err := m.judge(ctx, again, m.clock.Now(), p); err != nil {
		return nil, err
	}

	return again, nil
}

// markPresented records s's first presentation at now, and on success sets it
// on s too. It returns the store's failure, which the load answers by reading
// the session again (reloadSuperseded). A failure other than
// ErrSuperseded and ErrNotFound is logged first at debug, with
// the store's text left out.
func (m *Sessions) markPresented(ctx context.Context, s *Session, now time.Time) error {
	err := m.store.MarkPresented(ctx, s.ID, now)
	switch {
	case err == nil:
		s.FirstPresentedAt = now
	case errors.Is(err, ErrSuperseded), errors.Is(err, ErrNotFound):
		return err
	default:
		m.logger.LogAttrs(ctx, slog.LevelDebug, "session: the session's first presentation could not be recorded",
			diag.Failure("mark_presented", err)...)
		return err
	}

	return nil
}

// Touch records activity on s: it moves the last-access time to now and the
// idle deadline to now plus the idle timeout, capped at the absolute deadline,
// and persists both through Store.RecordActivity, which writes those two
// fields and nothing else, so a change another request saved to the same
// session is not undone. s is updated in memory only once the store has
// accepted the write.
//
// Recording activity persists only the last-access time and the idle
// deadline. A change to any other field of s, such as its Data, is persisted
// by Save, never by Touch.
//
// With WithTouchInterval set, a Touch that finds the last recorded activity
// younger than the interval writes nothing and leaves s as it is. The default
// interval is 0: every Touch writes. A session that has been superseded
// takes no activity and Touch writes nothing for it, so a grace window is
// never extended by use.
//
// The cap is what keeps the absolute deadline absolute. Without it a session
// in constant use pushes its idle deadline past the hour it was always going
// to end at, and the second deadline stops meaning anything.
//
// Activity on a session that is already past either deadline is refused with
// ErrExpired and nothing is written: an expired session is not one a
// request can revive by being made.
func (m *Sessions) Touch(ctx context.Context, s *Session) error {
	now := m.clock.Now()
	if s.expired(now) {
		return ErrExpired
	}

	if s.superseded() || m.touchInterval > 0 && now.Sub(s.LastAccessedAt) < m.touchInterval {
		return nil
	}

	idle := now.Add(m.idleTimeout)
	if idle.After(s.AbsoluteExpiresAt) {
		idle = s.AbsoluteExpiresAt
	}
	if err := m.store.RecordActivity(ctx, s.ID, now, idle, now.Add(-m.touchInterval)); err != nil {
		return storeFailed(err, "session: the session's activity could not be saved")
	}
	s.LastAccessedAt = now
	s.IdleExpiresAt = idle

	return nil
}

// Save persists changes made to s, and never re-creates a session that has
// been deleted: a session that is no longer stored is ErrNotFound.
func (m *Sessions) Save(ctx context.Context, s *Session) error {
	return storeFailed(m.store.Save(ctx, s), "session: the session could not be saved")
}

// Delete removes the session with this identifier.
func (m *Sessions) Delete(ctx context.Context, id string) error {
	return storeFailed(m.store.Delete(ctx, id), "session: the session could not be deleted")
}

// DeleteByUser removes every session of this user, expired ones included: a
// caller ending a user's sessions wants them gone, not filtered.
func (m *Sessions) DeleteByUser(ctx context.Context, user identity.UserID) error {
	return storeFailed(m.store.DeleteByUser(ctx, user), "session: the user's sessions could not be deleted")
}

// DeleteByUserExcept removes every session of this user except the one with
// identifier keep and, when keep belongs to a family, that family's current
// session (the member not superseded), expired ones included, in one atomic
// operation, and reports how many went. It is what ending a user's other
// sessions, after a change to how they sign in, is written against: the
// caller's sign-in survives even when keep was renewed inside its window.
//
// A keep naming another user's session, or none, is left untouched and every
// session of this user goes; an empty keep ends them all.
func (m *Sessions) DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error) {
	n, err := m.store.DeleteByUserExcept(ctx, user, keep)
	if err != nil {
		return n, storeFailed(err, "session: the user's other sessions could not be deleted")
	}

	return n, nil
}

// CountActiveByUser counts this user's unexpired sessions, which is what a
// concurrent-session limit is written against. A superseded session is not
// counted, so a renewed sign-in counts once however often it is renewed.
func (m *Sessions) CountActiveByUser(ctx context.Context, user identity.UserID) (int, error) {
	n, err := m.store.CountActiveByUser(ctx, user)
	if err != nil {
		return n, storeFailed(err, "session: the user's active sessions could not be counted")
	}

	return n, nil
}

// DeleteExpired removes every expired session and reports how many went.
func (m *Sessions) DeleteExpired(ctx context.Context) (int, error) {
	n, err := m.store.DeleteExpired(ctx)
	if err != nil {
		return n, storeFailed(err, "session: expired sessions could not be deleted")
	}

	return n, nil
}

// DeleteByExternalSession ends the sessions a provider established under this
// issuer and provider session identifier, and reports how many went. It is
// what a back-channel logout from that provider calls.
//
// An empty issuer or an empty session identifier ends nothing and is not an
// error.
func (m *Sessions) DeleteByExternalSession(ctx context.Context, issuer, sessionID string) (int, error) {
	n, err := m.store.DeleteByExternalSession(ctx, issuer, sessionID)
	if err != nil {
		return n, storeFailed(err, "session: the provider session's sessions could not be deleted")
	}

	return n, nil
}

// DeleteByUserAndExternalIssuer ends this user's sessions from this issuer,
// and reports how many went. An empty issuer ends nothing and is not an error.
func (m *Sessions) DeleteByUserAndExternalIssuer(ctx context.Context, user identity.UserID, issuer string) (int, error) {
	n, err := m.store.DeleteByUserAndExternalIssuer(ctx, user, issuer)
	if err != nil {
		return n, storeFailed(err, "session: the user's sessions from the issuer could not be deleted")
	}

	return n, nil
}

// RevokeFamily ends every session of one family, superseded ones included,
// and reports how many went. A family is the sessions one sign-in went on to
// issue through rotation and renewal, so this ends that sign-in without
// touching the user's sessions from other sign-ins. An unknown family ends
// nothing and is not an error.
func (m *Sessions) RevokeFamily(ctx context.Context, family id.ID) (int, error) {
	if family.IsZero() {
		return 0, errors.New("session: the nil family names no sessions to revoke")
	}

	n, err := m.store.DeleteFamily(ctx, family)
	if err != nil {
		return n, storeFailed(err, "session: the family's sessions could not be deleted")
	}

	return n, nil
}

// familyEnd is the latest time s's family could still be live under this
// manager: its start plus the family maximum.
func (m *Sessions) familyEnd(s *Session) time.Time {
	return s.FamilyCreatedAt.Add(m.maxFamilyLifetime)
}

// retainUntil is the retention deadline of a supersession of s whose window
// ends at acceptUntil: the latest of the family's end, s's own absolute
// deadline and the window's end. The family's end is the point no renewal
// extends the family past, so every superseded record kept until then is
// still judged as superseded, not expired, while the family lives. The other
// two keep a family maximum lowered by a deploy from shortening a record
// issued under the old one, inside its own window included.
func (m *Sessions) retainUntil(s *Session, acceptUntil time.Time) time.Time {
	return laterTime(laterTime(m.familyEnd(s), s.AbsoluteExpiresAt), acceptUntil)
}

// laterTime returns the later of a and b.
func laterTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}

	return a
}

// IdleTimeout reports how long a session survives with no activity, which is
// what WithIdleTimeout configured.
func (m *Sessions) IdleTimeout() time.Duration { return m.idleTimeout }

// AbsoluteTimeout reports the deadline nothing extends, which is what
// WithAbsoluteTimeout configured.
func (m *Sessions) AbsoluteTimeout() time.Duration { return m.absoluteTimeout }

// Rotate moves s to a new identifier and returns it under that identifier.
//
// It exists for the moment a session's privilege changes — a second factor
// accepted, a step-up completed — because a handle someone obtained before
// that change must not still answer requests after it. Everything except the
// identifier is carried over: the user, the first factor, both deadlines, the
// challenge state (including MFAAtFirstFactor), the family (FamilyID and
// FamilyCreatedAt), the federated assurance and
// the consumer's own data.
//
// The old entry is superseded by the new one, through the store's
// conditional Store.Supersede with a short in-flight window
// (DefaultRenewalGrace, never past the absolute deadline), and then deleted,
// so the old identifier is not found afterwards. A request that loads the old
// identifier between the two writes gets the old session as it was — still
// owing the second factor, which every gate confines — and is not judged as
// reuse. A failure of the supersession writes nothing and leaves the old
// handle working, so a caller that refuses on the error has lost nothing. A
// failure of the delete does not fail the rotation: the successor is stored,
// so it is returned, and the failure is logged at error with the family and
// never an identifier. The old entry is then left superseded; it loads until
// its in-flight window ends, and presenting it after that is reuse (see
// ErrReused).
//
// A session the store no longer holds, or that is past either deadline, is
// refused with the store's sentinel, as itself, and nothing is written:
// rotation is a move, not a way to bring a revoked session back under a fresh
// handle. Two rotations of one handle through one manager are serialised on
// that identifier, so the second finds the old entry already gone and is
// refused with ErrNotFound. Rotations of different sessions do not
// wait for each other.
//
// Racing rotations that the lock does not see — a RotateWithGrace of the
// same session, or a Rotate on another manager over the same store — are
// settled by the store's condition: exactly one produces a successor, and the
// one that supersedes second is refused with ErrRenewalConflict and
// stores nothing. A grace rotation that reads the old entry only after this
// rotation superseded it finds it inside the in-flight window, and is a
// re-rotation (see RotateWithGrace): this rotation's successor is knocked out,
// so the family still has one live head.
//
// Rotate never extends the session: the absolute deadline is carried over
// whatever WithMaxFamilyLifetime allows, because a privilege change must not
// lengthen it. The successor's deadlines, absolute and idle, are those of the
// session it is given, because the caller may have restored them (see
// RestoreEnrolmentDeadlines); only the family fields come from storage. The
// successor stays in s's family, and none of s's supersession or presentation
// state is carried over: the successor is recorded as presented at the
// rotation (FirstPresentedAt), since it goes straight to the caller using it,
// so WithUnusedSuccessorRecovery can never renew the old identifier into a
// second successor.
//
// A session superseded by RotateWithGrace is refused. Inside its window the
// refusal is ErrRenewalConflict and nothing is written, so the client
// retries with its current credential and the family keeps one live head.
// Past its window it is judged as Load judges it: reuse (see
// ErrReused), or ErrRenewalRequired with
// WithUnusedSuccessorRecovery on. A successor knocked out by a re-rotation or
// a recovery has no window left, whatever this manager's clock says, and is
// reuse.
//
// s is not modified. The returned session is the one to use.
func (m *Sessions) Rotate(ctx context.Context, s *Session) (*Session, error) {
	if s == nil {
		return nil, fmt.Errorf("session: rotate was given no session")
	}

	unlock := m.rotating.lock(s.ID)
	defer unlock()

	stored, err := m.loadStored(ctx, s.ID, "session: the session to rotate could not be loaded")
	if err != nil {
		return nil, err
	}
	now := m.clock.Now()
	if stored.superseded() && stored.insideWindow(now) {
		return nil, ErrRenewalConflict
	}
	if err := m.judge(ctx, stored, now, forRequest); err != nil {
		return nil, err
	}

	id, err := m.newIdentifier()
	if err != nil {
		return nil, err
	}

	rotated := successorOf(s, id)
	// The family is the stored record's, never the caller's copy's: a copy
	// with the family cleared or altered must not move the successor out of
	// the family the store holds.
	rotated.FamilyID, rotated.FamilyCreatedAt = stored.FamilyID, stored.FamilyCreatedAt
	// The successor is a record written now, so its creation time is now.
	// AuthenticatedAt stays as s carries it: that is the sign-in's, or the
	// refresh second-factor verification wrote onto s before rotating.
	rotated.CreatedAt = now
	// The successor goes straight back to the caller that is using it, so it
	// is recorded as presented now. That is also what keeps a recovery
	// (WithUnusedSuccessorRecovery) from renewing the old identifier into a
	// second successor if the delete below fails and leaves it superseded.
	rotated.FirstPresentedAt = now

	// The store's conditional supersession, not the lock above, is what
	// stops a grace rotation of the same session — through this manager or
	// another sharing the store — from producing a second successor beside
	// this one. The short in-flight window lets a request already sent with
	// the old identifier land as the session it was, still owing whatever
	// the rotation changed, rather than as reuse.
	acceptUntil := minTime(now.Add(DefaultRenewalGrace), stored.AbsoluteExpiresAt)
	err = m.store.Supersede(ctx, Supersession{
		Old:               stored.ID,
		ObservedSuccessor: stored.SuccessorDigest,
		AcceptUntil:       acceptUntil,
		RetainUntil:       m.retainUntil(stored, acceptUntil),
		Successor:         rotated,
		Now:               now,
	})
	if err != nil {
		return nil, storeFailed(err, "session: the rotated session could not be created")
	}

	// The successor is stored, so the rotation has happened: failing it now
	// would leave the caller holding the old identifier, whose next request
	// after the window would be reuse. The old record stays superseded and
	// stops answering when its window ends.
	if err := m.store.Delete(ctx, s.ID); err != nil {
		m.logger.LogAttrs(ctx, slog.LevelError, rotateDeleteLogReason,
			append(diag.Failure("delete", err), slog.String("family", stored.FamilyID.String()))...)
	}

	return rotated, nil
}

// rotateDeleteLogReason is the fixed text logged when the delete after a
// strict rotation fails. It carries no identifier.
const rotateDeleteLogReason = "session: the session rotated from could not be deleted; it stops answering when its in-flight window ends"

// timedClock adapts the manager's clock to the clock.Timed that
// NewMemoryStore takes, so the default store's time checks follow the
// manager. A clock that can already wait is used as it is. For one that
// cannot, After exists only to satisfy the type: the manager never starts its
// default store, so no housekeeping loop ever waits on it.
func timedClock(c clock.Clock) clock.Timed {
	if t, ok := c.(clock.Timed); ok {
		return t
	}

	return nowOnly{Clock: c, waiter: clock.System()}
}

type nowOnly struct {
	clock.Clock
	waiter clock.Timed
}

func (c nowOnly) After(d time.Duration) <-chan time.Time { return c.waiter.After(d) }

// identifierEncoding is how a session identifier's random bytes are written:
// URL-safe base64 without padding, decoded strictly, so a value whose final
// character carries set spare bits is not a second spelling of one
// identifier.
var identifierEncoding = base64.RawURLEncoding.Strict()

// ValidIdentifier reports whether v has the exact shape of an identifier the
// Sessions issues: identifierBytes of entropy, encoded URL-safe without
// padding, which is 43 characters of the alphabet A–Z, a–z, 0–9, "-" and "_".
//
// It says nothing about whether such a session exists. It is for a caller that
// receives a presented identifier from outside, such as an HTTP bearer, and
// wants to refuse a value that cannot be one before it costs a store lookup.
// An identifier minted by a consumer's own store is not one a [Sessions]
// issues, and is reported invalid.
func ValidIdentifier(v string) bool {
	if len(v) != identifierEncoding.EncodedLen(identifierBytes) {
		return false
	}

	// The decoder skips carriage returns and line feeds, so the decoded length
	// is checked as well as the encoded one.
	raw, err := identifierEncoding.DecodeString(v)

	return err == nil && len(raw) == identifierBytes
}

// TouchInterval reports how stale recorded activity may be before Touch writes
// it again, which is what WithTouchInterval configured. Zero, the default,
// means every Touch writes.
func (m *Sessions) TouchInterval() time.Duration { return m.touchInterval }
