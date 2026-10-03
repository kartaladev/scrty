package passkey

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/ratelimit"
)

// Option configures a Manager. Every option names the default it replaces.
// A nil option is ignored.
type Option func(*Manager)

// NameResolver returns the user name and display name a registration's
// creation options carry for the user d describes. An authenticator shows
// them when the user picks a passkey; neither is the user handle.
type NameResolver func(ctx context.Context, d *identity.Details) (name, display string, err error)

// RegistrationFacts is what a consumer's registration check is given about a
// verified registration, before anything is stored.
type RegistrationFacts struct {
	// User is the session's user, who is registering.
	User identity.UserID
	// AAGUID identifies the authenticator model: 16 bytes, or nil.
	AAGUID []byte
	// BackupEligible and BackupState are the authenticator's backup flags. A
	// synced passkey is backup-eligible.
	BackupEligible bool
	BackupState    bool
	// AttestationFormat is the attestation statement's format, "none" or empty
	// when none was conveyed.
	AttestationFormat string
	// AttestationTrusted reports whether the attestation verified as trusted
	// under the verifier's attestation policy.
	AttestationTrusted bool
}

// WithConfirmLimiterFactory builds the limiter that counts failed emailed-code
// confirmations per user (ConfirmEmailCode) through f, under the namespace
// "passkey-email-confirm" with this flow's own limit and window: 5 failures per
// 15 minutes.
//
// Default: ratelimit.MemoryLimiterFactory, logging through the Manager's logger
// and clock, so the limit holds in this process alone. Precedence: a limiter
// given for one confirmation (RegistrationContext.ConfirmLimiter) wins for that
// call; then the limiter f built; then the in-memory default. Because the
// explicit limiter is given per call, f is asked once, when New runs.
//
// For this second-factor flow, a shared limiter in
// ratelimit.UnavailableFallBackToLocal mode is the recommended choice: during an
// outage of the shared store each replica still bounds guessing on its own, and
// users are not locked out of sign-in.
//
// A nil factory, typed nil included, is an error wrapping ErrConfig, as is an
// error from f, which names the namespace.
func WithConfirmLimiterFactory(f ratelimit.LimiterFactory) Option {
	return func(m *Manager) {
		m.confirmFactory = f
		m.factorySet = true
	}
}

// WithChallengeTTL replaces how long a ceremony challenge is honoured after it
// is issued. The default is 5 minutes, and it is also the timeout the creation
// options carry. Zero or less is a configuration error.
func WithChallengeTTL(d time.Duration) Option {
	return func(m *Manager) { m.ttl = d }
}

// WithRegistrationChallengeLimit replaces how many registration challenges one
// user may be issued within the issuance window of one hour. The default is
// 10; the next begin is refused with ErrRegistrationThrottled. Zero or less is
// a configuration error.
func WithRegistrationChallengeLimit(n int) Option {
	return func(m *Manager) { m.issueLimit = n }
}

// WithPasskeyLimit replaces how many passkeys one user may hold, counting
// every state. The default is 25; a registration beyond it is refused with
// ErrLimitReached. Zero or less is a configuration error.
func WithPasskeyLimit(n int) Option {
	return func(m *Manager) { m.passkeyLimit = n }
}

// WithManagementFreshness replaces how recent a full session's latest
// authentication must be — the later of its creation and its second factor —
// for it to register or remove a passkey. The default is 15 minutes; an older
// session is refused with ErrReauthenticationRequired. Zero or less is a
// configuration error.
func WithManagementFreshness(d time.Duration) Option {
	return func(m *Manager) { m.freshness = d }
}

// WithUserVerification replaces the user-verification requirement of every
// ceremony. The default is UVRequired, which refuses a response without the
// user-verified flag. UVPreferred admits security keys without a PIN: an
// assertion without user verification then proves possession only, so a
// passwordless login made with one is single-factor and records no second
// factor. Any other value is a configuration error.
func WithUserVerification(uv UserVerification) Option {
	return func(m *Manager) { m.uv = uv }
}

// WithResidentKey replaces the discoverable-credential requirement of a
// registration. The default is ResidentKeyRequired. ResidentKeyPreferred
// admits credentials that cannot sign in without a username: they serve only
// as a second factor, never for passwordless login. Any other value is a
// configuration error.
func WithResidentKey(rk ResidentKey) Option {
	return func(m *Manager) { m.residentKey = rk }
}

// WithNameResolver replaces how the user name and display name of the
// creation options are taken from the user's loaded details. The default uses
// the username for both. A nil resolver is a configuration error.
func WithNameResolver(fn NameResolver) Option {
	return func(m *Manager) {
		m.names = fn
		m.namesSet = true
	}
}

// WithRepudiationContact sets where a user who did not make a change to their
// passkeys is told to turn, such as a support address. It has no default and
// is required: a notice that a passkey was bound is only useful when it says
// what to do if it was not the recipient.
func WithRepudiationContact(s string) Option {
	return func(m *Manager) { m.repudiation = s }
}

// WithSynchronousDelivery accepts a sender that does not report
// notify.NonBlocking. By default such a sender is a configuration error,
// because a registration finish would then wait on a mail server.
func WithSynchronousDelivery() Option {
	return func(m *Manager) { m.syncDelivery = true }
}

// WithRegistrationCheck adds a consumer check that runs on every verified
// registration, after verification and before anything is stored. There is
// none by default. An error it returns refuses the registration and is
// returned unchanged, and nothing is stored. A consumer can use it to apply a
// stricter policy to some users only, such as refusing backup-eligible
// passkeys for administrators. A nil check is a configuration error.
func WithRegistrationCheck(fn func(ctx context.Context, f RegistrationFacts) error) Option {
	return func(m *Manager) {
		m.regCheck = fn
		m.regCheckSet = true
	}
}

// WithOptionalRecoveryCodes stores a passkey active at once even when its user
// has no other way back in, and reports in the registration result that
// recovery is not set up, for the consumer's interface to prompt. By default,
// when Deps.Recovery is wired, such a passkey waits pending until the user
// confirms a new set of saved recovery codes. The optional mode allows
// accounts that only the operator can recover.
func WithOptionalRecoveryCodes() Option {
	return func(m *Manager) { m.optionalCodes = true }
}

// WithClock replaces the time source. The default is clock.System(). A nil
// clock is a configuration error.
func WithClock(clk clock.Clock) Option {
	return func(m *Manager) {
		m.clock = clk
		m.clockSet = true
	}
}

// WithRandom replaces the source user handles, emailed codes and challenge
// secrets are drawn from. The default is crypto/rand.Reader. A nil reader is a
// configuration error.
func WithRandom(r io.Reader) Option {
	return func(m *Manager) {
		m.random = r
		m.randomSet = true
	}
}

// WithIDGenerator replaces the generator of credential and challenge
// identifiers. The default is id.NewV7Generator. A nil generator is a
// configuration error.
func WithIDGenerator(g id.Generator) Option {
	return func(m *Manager) {
		m.ids = g
		m.idsSet = true
	}
}

// WithLogger replaces the logger. The default is slog.Default(). A nil logger
// is ignored.
func WithLogger(l *slog.Logger) Option {
	return func(m *Manager) {
		if l != nil {
			m.logger = l
		}
	}
}
