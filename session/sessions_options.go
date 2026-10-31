package session

import (
	"errors"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

// ErrConfig is wrapped by every error New, NewEncryptedStore and
// NewMemoryStore return for a wiring mistake, and by the error
// MemoryStore.Start and MemoryStore.Shutdown return when given a nil context,
// so a consumer can tell a contradictory configuration from a failure at
// request time without matching on message text.
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

// Option configures a [Sessions]. Every option names the default it
// replaces, and every default works with no configuration at all.
type Option func(*Sessions)

// WithStore replaces where sessions are kept. The default is NewMemoryStore,
// which does not survive a restart, and which reads the manager's own clock
// (see WithClock). A store given here keeps its own clock; the manager never
// replaces it.
//
// A nil store is a configuration error rather than a silent fallback to
// memory: a consumer who passed one meant to supply their own, and quietly
// keeping their users' sessions in process memory is not a failure they would
// find out about until a deploy.
func WithStore(s Store) Option {
	return func(m *Sessions) {
		m.store = s
		m.storeSupplied = true
	}
}

// WithIdleTimeout replaces how long a session survives with no activity. The
// default is 30 minutes.
//
// Zero or less is a configuration error: it would expire every session at the
// instant it was created, which no caller can have meant.
func WithIdleTimeout(d time.Duration) Option {
	return func(m *Sessions) { m.idleTimeout = d }
}

// WithAbsoluteTimeout replaces the deadline nothing extends. The default is 12
// hours. Zero or less is a configuration error, for the same reason a zero
// idle timeout is.
func WithAbsoluteTimeout(d time.Duration) Option {
	return func(m *Sessions) { m.absoluteTimeout = d }
}

// WithTouchInterval sets how stale a session's recorded activity may be
// before Touch writes it again. The default is 0: every Touch writes.
//
// With an interval d, a Touch that finds the last recorded activity less
// than d old writes nothing, so a busy session costs one store write per
// interval rather than one per request. The cost is that a skipped touch
// leaves the stored idle deadline up to d earlier than it would have been:
// expiry can only come sooner, never later, and a session is never kept
// alive by a write that did not happen.
//
// d must be at least 0 and less than the idle timeout; anything else is a
// configuration error from New, because an interval as long as the
// idle timeout would let a session expire while in constant use.
//
// Deployments with busy clients should set one, for example a minute. The
// bound it costs is the one above: idle expiry up to one interval early.
//
// An httpsec chain refuses, with a configuration error from httpsec.New, a
// touch interval at least as long as any idle timeout its policy engine
// enforces (policy.IdleTimeout), because the stored last access can be
// up to one interval stale.
func WithTouchInterval(d time.Duration) Option {
	return func(m *Sessions) { m.touchInterval = d }
}

// WithMaxAbsoluteLifetime sets the longest absolute lifetime a Create may
// ask for through WithAbsoluteLifetime. The default is the absolute timeout
// (see WithAbsoluteTimeout), so with no option no session can outlive it.
//
// A maximum below the absolute timeout is a configuration error from
// New: the default lifetime would already exceed it. The same maximum
// bounds a renewal's new lifetime (see WithSuccessorLifetime).
//
// A renewal whose family is already past its end under this maximum is
// refused with ErrExpired, and a carried-over deadline later than the
// end is cut to it.
//
// Changing the maximum between deploys is safe to lower and has one limit
// when raised. Lowering it never shortens a superseded record already
// issued: it keeps the retention deadline it holds, and one superseded again
// keeps the later of that deadline and the new one. A record superseded
// before the maximum was raised keeps the retention it was given, so
// presented after that while its family, extended under the new maximum, is
// still live, it is refused as expired and not as reuse: the family is not
// revoked. Rewriting every member on each renewal would restore
// that detection at a per-renewal cost, so the library accepts the limit.
//
// The library does not know the assurance level a consumer targets, so it
// enforces no figure of its own. For reference, NIST SP 800-63B-4 sets the
// overall reauthentication timeout at no more than 30 days at AAL1 and 24
// hours at AAL2; see WithMaxFamilyLifetime for the limit renewals keep.
func WithMaxAbsoluteLifetime(limit time.Duration) Option {
	return func(m *Sessions) { m.maxLifetime = limit; m.maxLifetimeSupplied = true }
}

// WithAbsoluteLifetime gives the session being created an absolute lifetime
// of d in place of the manager's absolute timeout. The default, with no
// option, is that timeout. The idle deadline is capped at the result.
//
// Create refuses a d of zero or less, or one above the manager's maximum
// (see WithMaxAbsoluteLifetime), with ErrConfig and stores nothing: a
// requested lifetime is never silently shortened.
func WithAbsoluteLifetime(d time.Duration) CreateOption {
	return func(s *Session) { s.AbsoluteExpiresAt = s.CreatedAt.Add(d) }
}

// WithClock replaces the time source. The default is clock.System().
//
// The default in-memory store reads this same clock, so a manager given a fake
// clock and no store creates, refuses and sweeps sessions by one time. A store
// given through WithStore keeps its own.
//
// A nil clock, typed nil included, is a configuration error rather than a
// silent fallback: a caller passing one meant to inject a clock, and falling
// back to the wall clock would make a test whose clock never advances look
// like one that does.
func WithClock(clk clock.Clock) Option { return func(m *Sessions) { m.clock = clk } }

// WithFamilyIDGenerator replaces the generator of the family identifier each
// Create starts. The default is id.NewV7Generator on the manager's clock (see
// WithClock), whichever order the two options are given in.
//
// A family identifier is not a secret: it groups the sessions one sign-in
// goes on to issue, and needs uniqueness, not the entropy a session
// identifier draws from WithRandom. A consumer replaces it to mint
// identifiers their own records can be correlated with. A generator should
// not return id.Nil, which names no family. A nil generator, typed nil
// included, is a configuration error.
func WithFamilyIDGenerator(g id.Generator) Option {
	return func(m *Sessions) {
		m.families = g
		m.familiesSupplied = true
	}
}

// WithLogger replaces the logger. The default is slog.Default().
//
// A nil logger is ignored rather than refused: unlike a clock, a nil logger
// has an obvious safe reading — the caller does not want this component's logs
// — and refusing it would make logging mandatory.
func WithLogger(l *slog.Logger) Option {
	return func(m *Sessions) {
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
func WithRandom(r io.Reader) Option { return func(m *Sessions) { m.random = r } }

// CreateOption configures one session as it is created, rather than the
// Sessions behind it.
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

// WithSecondFactorAtLogin records that the login creating the session met its
// second factor at its first, as a user-verified passkey login does.
//
// The session is created with MFA set to MFASatisfied, MFASatisfiedAt set to
// its creation time and MFAAtFirstFactor set, all in the one creating write,
// so there is no moment at which the session exists unsatisfied. The default
// is a session with no second factor recorded (MFANone).
//
// It is meant for the library's own login tail, which adds it only when the
// login carried the library's proof (policy.Input.SecondFactorAtLogin). A
// consumer that adds it to a session of their own creates a satisfied session
// on their own word.
func WithSecondFactorAtLogin() CreateOption {
	return func(s *Session) {
		s.MFA = MFASatisfied
		s.MFASatisfiedAt = s.CreatedAt
		s.MFAAtFirstFactor = true
	}
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

// WithFederatedAssurance records the authentication methods references (amr)
// and the authentication context class reference (acr) the identity provider
// asserted for the login creating the session. The default is none recorded.
//
// They are written in the creating write, with the first factor and the
// provider, and Rotate carries them over. The slice is copied, so the caller
// keeping or changing amr afterwards does not reach the session. They are
// library-owned fields, never stored in or read from Data, and recording them
// changes neither MFA nor MFAAtFirstFactor.
//
// It is meant for the library's own OIDC completion, which passes what the
// validated ID token asserted. A consumer that adds it to a session of their
// own records assurance on their own word.
func WithFederatedAssurance(amr []string, acr string) CreateOption {
	return func(s *Session) {
		s.FederatedAMR = slices.Clone(amr)
		s.FederatedACR = acr
	}
}
