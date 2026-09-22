package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// Manager mints sessions, holds them in a Store and enforces their two
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
// A Manager is safe for concurrent use as far as its store is: it holds no
// mutable state of its own after construction.
type Manager struct {
	store           Store
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	now             func() time.Time
	logger          *slog.Logger
	random          io.Reader

	// storeSupplied records that WithStore replaced the default, so the
	// per-process warning below is written only where it is true.
	storeSupplied bool
}

// perProcessWarning is written once per manager left on the default store.
//
// It names the consequence rather than merely saying "in memory", because the
// mistake it prevents is deploying a second replica and discovering that every
// other request looks logged out, or that a rolling restart signs everyone
// out at once.
const perProcessWarning = "session: the default in-memory store keeps sessions in this process only, " +
	"so a restart ends every session and a second replica does not see this one's"

// NewManager returns a session manager.
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
func NewManager(opts ...ManagerOption) (*Manager, error) {
	m := &Manager{
		store:           NewMemoryStore(),
		idleTimeout:     defaultIdleTimeout,
		absoluteTimeout: defaultAbsoluteTimeout,
		now:             time.Now,
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
	if nilcheck.IsNil(m.store) {
		return nil, fmt.Errorf("%w: store must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(m.now) {
		return nil, fmt.Errorf("%w: clock must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(m.random) {
		return nil, fmt.Errorf("%w: random source must not be nil", ErrConfig)
	}

	if !m.storeSupplied {
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
func (m *Manager) newIdentifier() (string, error) {
	raw := make([]byte, identifierBytes)
	if _, err := io.ReadFull(m.random, raw); err != nil {
		return "", fmt.Errorf("session: reading %d random bytes for a session identifier: %w", identifierBytes, err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Create mints a session for user and stores it.
//
// Every create option is applied before the one store write, so a crash cannot
// leave a live session that has forgotten which factor established it or which
// provider it came from.
func (m *Manager) Create(ctx context.Context, user identity.UserID, opts ...CreateOption) (*Session, error) {
	id, err := m.newIdentifier()
	if err != nil {
		return nil, err
	}

	now := m.now()
	s := &Session{
		ID:                id,
		UserID:            user,
		CreatedAt:         now,
		LastAccessedAt:    now,
		IdleExpiresAt:     now.Add(m.idleTimeout),
		AbsoluteExpiresAt: now.Add(m.absoluteTimeout),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	if err := m.store.Create(ctx, s); err != nil {
		return nil, err
	}

	return s, nil
}

// Load returns the session with this identifier.
func (m *Manager) Load(ctx context.Context, id string) (*Session, error) {
	return m.store.Load(ctx, id)
}

// Touch records activity on s: it moves the last-access time to now and the
// idle deadline to now plus the idle timeout, capped at the absolute deadline,
// and persists both.
//
// The cap is what keeps the absolute deadline absolute. Without it a session
// in constant use pushes its idle deadline past the hour it was always going
// to end at, and the second deadline stops meaning anything.
//
// Activity on a session that is already past either deadline is refused with
// ErrSessionExpired and nothing is written: an expired session is not one a
// request can revive by being made.
func (m *Manager) Touch(ctx context.Context, s *Session) error {
	now := m.now()
	if s.expired(now) {
		return ErrSessionExpired
	}

	idle := now.Add(m.idleTimeout)
	if idle.After(s.AbsoluteExpiresAt) {
		idle = s.AbsoluteExpiresAt
	}
	s.LastAccessedAt = now
	s.IdleExpiresAt = idle

	return m.store.Save(ctx, s)
}

// Save persists changes made to s, and never re-creates a session that has
// been deleted: a session that is no longer stored is ErrSessionNotFound.
func (m *Manager) Save(ctx context.Context, s *Session) error {
	return m.store.Save(ctx, s)
}

// Delete removes the session with this identifier.
func (m *Manager) Delete(ctx context.Context, id string) error {
	return m.store.Delete(ctx, id)
}

// DeleteByUser removes every session of this user, expired ones included: a
// caller ending a user's sessions wants them gone, not filtered.
func (m *Manager) DeleteByUser(ctx context.Context, user identity.UserID) error {
	return m.store.DeleteByUser(ctx, user)
}

// CountActiveByUser counts this user's unexpired sessions, which is what a
// concurrent-session limit is written against.
func (m *Manager) CountActiveByUser(ctx context.Context, user identity.UserID) (int, error) {
	return m.store.CountActiveByUser(ctx, user)
}

// DeleteExpired removes every expired session and reports how many went.
func (m *Manager) DeleteExpired(ctx context.Context) (int, error) {
	return m.store.DeleteExpired(ctx)
}

// DeleteByExternalSession ends the sessions a provider established under this
// issuer and provider session identifier, and reports how many went. It is
// what a back-channel logout from that provider calls.
//
// An empty issuer or an empty session identifier ends nothing and is not an
// error.
func (m *Manager) DeleteByExternalSession(ctx context.Context, issuer, sessionID string) (int, error) {
	return m.store.DeleteByExternalSession(ctx, issuer, sessionID)
}

// DeleteByUserAndExternalIssuer ends this user's sessions from this issuer,
// and reports how many went. An empty issuer ends nothing and is not an error.
func (m *Manager) DeleteByUserAndExternalIssuer(ctx context.Context, user identity.UserID, issuer string) (int, error) {
	return m.store.DeleteByUserAndExternalIssuer(ctx, user, issuer)
}

// IdleTimeout reports how long a session survives with no activity, which is
// what WithIdleTimeout configured.
func (m *Manager) IdleTimeout() time.Duration { return m.idleTimeout }

// AbsoluteTimeout reports the deadline nothing extends, which is what
// WithAbsoluteTimeout configured.
func (m *Manager) AbsoluteTimeout() time.Duration { return m.absoluteTimeout }
