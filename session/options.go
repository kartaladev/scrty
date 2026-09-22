package session

import (
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/factor"
)

// ErrConfig is wrapped by every error NewManager and NewEncryptedStore return
// for a wiring mistake, so a consumer can tell a contradictory configuration
// from a failure at request time without matching on message text.
var ErrConfig = errors.New("session: invalid configuration")

const (
	// defaultIdleTimeout is how long a session survives with no activity when
	// nothing is configured. Half an hour is long enough not to interrupt
	// someone reading a page and short enough that an unattended browser is
	// not an open session by the time anyone walks past it.
	defaultIdleTimeout = 30 * time.Minute

	// defaultAbsoluteTimeout is the deadline nothing extends when nothing is
	// configured. Half a day makes a working day end with a fresh login rather
	// than with a session that has been alive since some morning nobody
	// remembers.
	defaultAbsoluteTimeout = 12 * time.Hour

	// defaultHousekeepingInterval is how often a started MemoryStore sweeps
	// expired sessions when nothing is configured. A minute keeps the memory a
	// burst of logins leaves behind from outliving the burst by much, at a
	// cost of one pass over the map a minute.
	defaultHousekeepingInterval = time.Minute
)

// ManagerOption configures a Manager. Every option names the default it
// replaces, and every default works with no configuration at all.
type ManagerOption func(*Manager)

// WithStore replaces where sessions are kept. The default is NewMemoryStore,
// which does not survive a restart.
//
// A nil store is a configuration error rather than a silent fallback to
// memory: a consumer who passed one meant to supply their own, and quietly
// keeping their users' sessions in process memory is not a failure they would
// find out about until a deploy.
func WithStore(s Store) ManagerOption {
	return func(m *Manager) {
		m.store = s
		m.storeSupplied = true
	}
}

// WithIdleTimeout replaces how long a session survives with no activity. The
// default is 30 minutes.
//
// Zero or less is a configuration error: it would expire every session at the
// instant it was created, which no caller can have meant.
func WithIdleTimeout(d time.Duration) ManagerOption {
	return func(m *Manager) { m.idleTimeout = d }
}

// WithAbsoluteTimeout replaces the deadline nothing extends. The default is 12
// hours. Zero or less is a configuration error, for the same reason a zero
// idle timeout is.
func WithAbsoluteTimeout(d time.Duration) ManagerOption {
	return func(m *Manager) { m.absoluteTimeout = d }
}

// WithClock replaces the time source. The default is time.Now.
//
// A nil clock is a configuration error rather than a silent fallback: a caller
// passing one meant to inject a clock, and falling back to the wall clock
// would make a test whose clock never advances look like one that does.
func WithClock(now func() time.Time) ManagerOption { return func(m *Manager) { m.now = now } }

// WithSessionLogger replaces the logger. The default is slog.Default().
//
// A nil logger is ignored rather than refused: unlike a clock, a nil logger
// has an obvious safe reading — the caller does not want this component's logs
// — and refusing it would make logging mandatory.
func WithSessionLogger(l *slog.Logger) ManagerOption {
	return func(m *Manager) {
		if l != nil {
			m.logger = l
		}
	}
}

// WithRandom replaces the source session identifiers are drawn from. The
// default is crypto/rand.Reader.
//
// It exists so a test can make the entropy source fail, and so a consumer
// whose platform supplies its own cryptographic source can use it. A nil
// reader is a configuration error: falling back would override a deliberate
// choice about where this deployment's randomness comes from.
func WithRandom(r io.Reader) ManagerOption { return func(m *Manager) { m.random = r } }

// CreateOption configures one session as it is created, rather than the
// Manager behind it.
//
// Everything a create option sets is applied before the single store write
// that creates the session, so a crash between two writes cannot leave a live
// session that has forgotten how it was established.
type CreateOption func(*Session)

// WithFirstFactor records the kind of factor the login used. The default is
// the empty kind, meaning none was recorded.
//
// There is no default kind on purpose. What an unrecorded first factor means
// for access — whether it is challenged, refused or waved through — belongs to
// the security-policy capability and its own options, not to a guess made
// here.
func WithFirstFactor(kind factor.Kind) CreateOption {
	return func(s *Session) { s.FirstFactor = kind }
}

// WithExternalSession records the identity provider a federated login came
// from: the provider name as the consumer configured it, the issuer the token
// was verified against, the provider's own session identifier (which may be
// empty, since not every provider issues one) and the raw ID token.
//
// The default is no external session at all, which is what a password login
// records. The ID token is a credential in its own right: wrap the store in
// NewEncryptedStore to seal it before it reaches durable storage.
func WithExternalSession(provider, issuer, sessionID, idToken string) CreateOption {
	return func(s *Session) {
		s.ExternalProvider = provider
		s.ExternalIssuer = issuer
		s.ExternalSessionID = sessionID
		s.ExternalIDToken = idToken
	}
}

// MemoryStoreOption configures a MemoryStore.
type MemoryStoreOption func(*MemoryStore)

// WithHousekeepingInterval replaces how often a started store sweeps expired
// sessions. The default is one minute.
//
// Zero or less is ignored and the default is kept: a non-positive interval
// would make the ticker either refuse to be created or spin, and neither is
// what a caller asking for housekeeping wants.
func WithHousekeepingInterval(d time.Duration) MemoryStoreOption {
	return func(s *MemoryStore) {
		if d > 0 {
			s.interval = d
		}
	}
}

// WithMemoryStoreClock replaces the store's time source. The default is
// time.Now.
//
// The store needs a clock of its own because only it can decide which of its
// records are expired, both when it refuses to serve one and when it sweeps.
// A test that moves a manager's clock gives the store the same one, so expiry
// means the same thing on both sides. A nil function keeps the default, since
// a store with no clock could not judge expiry at all.
func WithMemoryStoreClock(now func() time.Time) MemoryStoreOption {
	return func(s *MemoryStore) {
		if now != nil {
			s.now = now
		}
	}
}
