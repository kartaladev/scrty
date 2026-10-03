package passkey

//go:generate mockgen -source=verifier.go -destination=verifier_mock_test.go -package=passkey_test -typed
//go:generate mockgen -source=sessions.go -destination=sessions_mock_test.go -package=passkey_test -typed
//go:generate mockgen -destination=sender_mock_test.go -package=passkey_test -typed github.com/kartaladev/scrty/notify Sender
//go:generate mockgen -destination=userloader_mock_test.go -package=passkey_test -typed github.com/kartaladev/scrty/identity UserLoader
//go:generate mockgen -destination=lookup_mock_test.go -package=passkey_test -typed github.com/kartaladev/scrty/policy MFAMethodLookup
//go:generate mockgen -destination=limiter_mock_test.go -package=passkey_test -typed github.com/kartaladev/scrty/ratelimit Limiter,LimiterFactory

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// RecoveryDeps wire saved recovery codes to registration.
type RecoveryDeps struct {
	// Codes generates and confirms a user's saved codes. Required.
	Codes *recovery.Codes
	// WayBack reports whether a user has another way back in. Required.
	WayBack *recovery.WayBackCheck
}

// Deps are the ports a Manager works over.
type Deps struct {
	// Verifier parses and verifies WebAuthn responses. Required: the core
	// package has no WebAuthn dependency and so no default.
	Verifier Verifier
	// Credentials keeps passkeys. The default is NewMemoryCredentialStore,
	// which holds this process's passkeys only.
	Credentials CredentialStore
	// Handles keeps user handles. The default is NewMemoryHandleStore, which
	// holds this process's handles only.
	Handles HandleStore
	// Challenges keeps ceremony challenges. The default is
	// onetime.NewMemoryStore, which holds this process's challenges only:
	// behind several replicas a finish must reach the replica that began it.
	Challenges onetime.Store
	// Users loads the user, for the name resolver and the contact address.
	// Required.
	Users identity.UserLoader
	// MFAMethods are the configured second-factor methods, which decide
	// whether a full session must have met its second factor to register or
	// remove a passkey. They are used by a direct caller of the manager, and
	// whenever the RegistrationContext carries no MFAMethods of its own; a
	// chain passes its MFA slot's methods there instead. May be empty.
	MFAMethods []policy.MFAMethodLookup
	// Sender delivers the emailed code and the notices. Required, and it must
	// report notify.NonBlocking unless WithSynchronousDelivery is given.
	Sender notify.Sender
	// Recovery wires saved recovery codes to registration. Optional: with
	// none, a registration never waits for saved codes.
	Recovery *RecoveryDeps
	// Sessions ends sessions when a passkey is removed or suspended as a
	// suspected clone. *session.Manager satisfies it; wire the same manager
	// the chain uses, the one given to httpsec.PasskeyDeps.Sessions. Required
	// unless both WithoutSessionRevocationOnRemoval and
	// WithoutSessionRevocationOnClone are given.
	Sessions SessionRevoker
}

// Manager runs the passkey ceremonies. It is safe for concurrent use.
type Manager struct {
	verifier    Verifier
	credentials CredentialStore
	handles     HandleStore
	users       identity.UserLoader
	methods     []policy.MFAMethodLookup
	sender      notify.Sender
	recovery    *RecoveryDeps
	sessions    SessionRevoker

	keepOnRemoval bool
	keepOnClone   bool

	registration   *onetime.Manager
	login          *onetime.Manager
	purgeMu        sync.Mutex
	lastPurge      time.Time
	loginCheck     func(ctx context.Context, f LoginFacts) error
	loginCheckSet  bool
	noProofAtLogin bool
	cloneResponse  CloneResponse
	clonePolicy    func(ctx context.Context, s CloneSignal) CloneAction
	clonePolicySet bool
	confirmLimiter ratelimit.Limiter
	confirmFactory ratelimit.LimiterFactory
	factorySet     bool
	contact        mfa.ContactResolver
	contactSet     bool
	messages       Messages
	messagesSet    bool

	ttl           time.Duration
	issueLimit    int
	passkeyLimit  int
	freshness     time.Duration
	uv            UserVerification
	residentKey   ResidentKey
	names         NameResolver
	namesSet      bool
	repudiation   string
	syncDelivery  bool
	regCheck      func(ctx context.Context, f RegistrationFacts) error
	regCheckSet   bool
	optionalCodes bool
	clock         clock.Clock
	clockSet      bool
	random        io.Reader
	randomSet     bool
	ids           id.Generator
	idsSet        bool
	logger        *slog.Logger
	sampler       *logsample.Sampler
	logInterval   time.Duration
	compare       func(stored, presented string) bool
}

// The defaults the options replace.
const (
	defaultChallengeTTL  = 5 * time.Minute
	defaultIssueLimit    = 10
	issuanceWindow       = time.Hour
	defaultPasskeyLimit  = 25
	defaultFreshness     = 15 * time.Minute
	registrationPurpose  = "passkey-registration"
	defaultConfirmLimit  = 5
	defaultConfirmWindow = 15 * time.Minute
	// namespaceEmailConfirm names the emailed-code limit to a limiter factory.
	namespaceEmailConfirm = "passkey-email-confirm"
	defaultLogInterval    = time.Minute
)

// New returns a Manager over deps, with the defaults every Option names.
//
// Every wiring mistake is an error wrapping ErrConfig, before any ceremony
// runs: a nil verifier, user loader or sender (typed nil included); a relying
// party the verifier reports that does not validate; a sender that does not
// report notify.NonBlocking without WithSynchronousDelivery; no repudiation
// contact; a nil MFA method entry; Deps.Recovery without both its codes and
// its way-back check; a challenge lifetime, freshness window, issuance limit
// or passkey limit of zero or less; an unknown user-verification or
// resident-key value; and a nil name resolver, registration check, clock,
// random source or identifier generator; and no session revoker (typed nil
// included) while either WithoutSessionRevocationOnRemoval or
// WithoutSessionRevocationOnClone is left off.
func New(deps Deps, opts ...Option) (*Manager, error) {
	m := &Manager{
		verifier:    deps.Verifier,
		credentials: deps.Credentials,
		handles:     deps.Handles,
		users:       deps.Users,
		methods:     deps.MFAMethods,
		sender:      deps.Sender,
		recovery:    deps.Recovery,
		sessions:    deps.Sessions,

		contact:       mfa.UsernameAsAddress,
		ttl:           defaultChallengeTTL,
		issueLimit:    defaultIssueLimit,
		passkeyLimit:  defaultPasskeyLimit,
		freshness:     defaultFreshness,
		uv:            UVRequired,
		residentKey:   ResidentKeyRequired,
		cloneResponse: CloneSuspend,
		names:         usernameAsNames,
		clock:         clock.System(),
		random:        rand.Reader,
		ids:           id.NewV7Generator(),
		logger:        slog.Default(),
		logInterval:   defaultLogInterval,
		compare:       constantTimeEqual,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}

	if err := m.validate(); err != nil {
		return nil, err
	}

	if !m.messagesSet {
		m.messages = defaultMessages{repudiation: m.repudiation}
	}

	m.sampler = logsample.New(m.logInterval, logsample.WithReporter(m.reportSuppressed))

	if nilcheck.IsNil(m.credentials) {
		m.credentials = NewMemoryCredentialStore()
	}

	if nilcheck.IsNil(m.handles) {
		m.handles = NewMemoryHandleStore()
	}

	challenges := deps.Challenges
	if nilcheck.IsNil(challenges) {
		challenges = onetime.NewMemoryStore(onetime.WithMemoryStoreClock(m.clock))
	}

	reg, err := onetime.NewManager(registrationPurpose,
		onetime.WithStore(challenges),
		onetime.WithTTL(m.ttl),
		onetime.WithIssuanceWindow(issuanceWindow),
		onetime.WithClock(m.clock),
		onetime.WithRandom(m.random),
		onetime.WithIDGenerator(m.ids),
		onetime.WithLogger(m.logger),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: registration challenges: %w", ErrConfig, err)
	}

	m.registration = reg

	login, err := onetime.NewManager(loginPurpose,
		onetime.WithStore(challenges),
		onetime.WithTTL(m.ttl),
		onetime.WithIssuanceWindow(m.ttl),
		onetime.WithClock(m.clock),
		onetime.WithRandom(m.random),
		onetime.WithIDGenerator(m.ids),
		onetime.WithLogger(m.logger),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: login challenges: %w", ErrConfig, err)
	}

	m.login = login

	if err := m.resolveConfirmLimiter(); err != nil {
		return nil, err
	}

	return m, nil
}

// resolveConfirmLimiter builds the emailed-code confirm limiter from the
// factory WithConfirmLimiterFactory gave, or else the in-memory default logging
// through the Manager's logger and clock. A factory replaced with nothing is
// refused.
func (m *Manager) resolveConfirmLimiter() error {
	factory := m.confirmFactory

	switch {
	case m.factorySet && nilcheck.IsNil(factory):
		return fmt.Errorf("%w: WithConfirmLimiterFactory was given no factory", ErrConfig)
	case !m.factorySet:
		factory = ratelimit.MemoryLimiterFactory(
			ratelimit.WithMemoryLimiterClock(m.clock), ratelimit.WithMemoryLimiterLogger(m.logger))
	}

	limiter, err := factory.NewLimiter(namespaceEmailConfirm, defaultConfirmLimit, defaultConfirmWindow)
	if err != nil {
		return fmt.Errorf("%w: limiter for namespace %q: %w", ErrConfig, namespaceEmailConfirm, err)
	}

	m.confirmLimiter = limiter

	return nil
}

// validate refuses every meaningless configuration with ErrConfig.
func (m *Manager) validate() error {
	var missing string

	switch {
	case nilcheck.IsNil(m.verifier):
		missing = "a verifier is required"
	case nilcheck.IsNil(m.users):
		missing = "a user loader is required"
	case nilcheck.IsNil(m.sender):
		missing = "a sender is required"
	case strings.TrimSpace(m.repudiation) == "":
		missing = "a repudiation contact is required"
	case m.ttl <= 0:
		missing = "the challenge lifetime must be positive"
	case m.freshness <= 0:
		missing = "the freshness window must be positive"
	case m.issueLimit <= 0:
		missing = "the registration challenge limit must be positive"
	case m.passkeyLimit <= 0:
		missing = "the passkey limit must be positive"
	case m.uv != UVRequired && m.uv != UVPreferred:
		missing = "unknown user-verification requirement"
	case m.residentKey != ResidentKeyRequired && m.residentKey != ResidentKeyPreferred:
		missing = "unknown resident-key requirement"
	case m.namesSet && m.names == nil:
		missing = "the name resolver must not be nil"
	case m.regCheckSet && m.regCheck == nil:
		missing = "the registration check must not be nil"
	case m.loginCheckSet && m.loginCheck == nil:
		missing = "the login check must not be nil"
	case m.cloneResponse != CloneSuspend && m.cloneResponse != CloneSignalOnly:
		missing = "unknown clone response"
	case m.clonePolicySet && m.clonePolicy == nil:
		missing = "the clone policy must not be nil"
	case m.clockSet && nilcheck.IsNil(m.clock):
		missing = "the clock must not be nil"
	case m.randomSet && nilcheck.IsNil(m.random):
		missing = "the random source must not be nil"
	case m.idsSet && nilcheck.IsNil(m.ids):
		missing = "the identifier generator must not be nil"
	case m.messagesSet && nilcheck.IsNil(m.messages):
		missing = "the messages must not be nil"
	case m.contactSet && m.contact == nil:
		missing = "the contact resolver must not be nil"
	case (!m.keepOnRemoval || !m.keepOnClone) && nilcheck.IsNil(m.sessions):
		missing = "a session revoker is required while session revocation is on"
	case m.recovery != nil && (m.recovery.Codes == nil || m.recovery.WayBack == nil):
		missing = "recovery needs both saved codes and a way-back check"
	}

	if missing != "" {
		return fmt.Errorf("%w: %s", ErrConfig, missing)
	}

	for _, lk := range m.methods {
		if nilcheck.IsNil(lk) {
			return fmt.Errorf("%w: an MFA method entry is nil", ErrConfig)
		}
	}

	if nb, ok := m.sender.(notify.NonBlocking); (!ok || !nb.NonBlocking()) && !m.syncDelivery {
		return fmt.Errorf("%w: the sender is synchronous; accept it with WithSynchronousDelivery", ErrConfig)
	}

	return m.verifier.RelyingParty().Validate()
}

// ChallengeTTL reports how long a ceremony challenge m issues stays valid:
// the default of 5 minutes, or what WithChallengeTTL set. A caller that binds
// a passwordless challenge to a cookie gives the cookie this lifetime.
func (m *Manager) ChallengeTTL() time.Duration {
	return m.ttl
}

// RequiresRecoveryCodes reports whether a passwordless login over m would
// still need saved recovery codes wired: true when Deps.Recovery is not set
// and WithOptionalRecoveryCodes is not given. A user signing in with passkeys
// alone has no password to fall back on, so a caller that serves passwordless
// login refuses such a manager at construction rather than strand the user
// with no way back in.
func (m *Manager) RequiresRecoveryCodes() bool {
	return m.recovery == nil && !m.optionalCodes
}

// usernameAsNames is the default NameResolver: the username, for both names.
func usernameAsNames(_ context.Context, d *identity.Details) (string, string, error) {
	return d.Username, d.Username, nil
}

// constantTimeEqual compares a stored and a presented code in constant time.
func constantTimeEqual(stored, presented string) bool {
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1
}

// admit decides whether s may change the user's authenticators: register a
// passkey, or remove one.
//
// A session with no user, or owing a password change, is refused, and a nil
// entry in rc.MFAMethods is then ErrConfig, whatever the session's MFA state. A
// recovery-pending or enrolment-only session is then admitted without further
// checks: the recovery is its authentication, its user has no usable second
// factor, and its life is short by construction. A full session — no pending
// challenge, never confined — must have met its second factor when its
// account has one (owesSecondFactor): a configured MFA method its user can
// use, or the user's own active passkeys while a passkey route can meet the
// second factor. Its latest authentication, the later of its creation and its
// second factor, must also be within the freshness window. The configured
// methods are rc.MFAMethods, or Deps.MFAMethods when rc lists none. Anything
// else, such as a session with a pending MFA challenge, is refused. Every
// refusal is ErrReauthenticationRequired, except that a failed MFA or passkey
// lookup refuses with fixed text, and a nil entry in rc.MFAMethods with
// ErrConfig.
func (m *Manager) admit(ctx context.Context, s *session.Session, rc RegistrationContext) error {
	if s == nil || s.UserID == "" || s.PasswordChangePending {
		return ErrReauthenticationRequired
	}

	// A nil entry is a wiring mistake whatever the session, so it is checked
	// before any session is admitted.
	for _, lk := range rc.MFAMethods {
		if nilcheck.IsNil(lk) {
			return fmt.Errorf("%w: an MFA method entry of the registration context is nil", ErrConfig)
		}
	}

	switch s.MFA {
	case session.MFARecoveryPending, session.MFAEnrolmentPending:
		return nil
	case session.MFANone, session.MFASatisfied:
		if !s.EnrolmentOriginDeadline.IsZero() {
			return ErrReauthenticationRequired
		}
	default:
		return ErrReauthenticationRequired
	}

	methods := rc.MFAMethods
	if len(methods) == 0 {
		methods = m.methods
	}

	if s.MFA != session.MFASatisfied {
		owed, err := m.owesSecondFactor(ctx, s, methods, rc.PasswordlessLogin)
		if err != nil {
			return err
		}

		if owed {
			return ErrReauthenticationRequired
		}
	}

	latest := s.CreatedAt
	if s.MFASatisfiedAt.After(latest) {
		latest = s.MFASatisfiedAt
	}

	if m.clock.Now().Sub(latest) > m.freshness {
		return ErrReauthenticationRequired
	}

	return nil
}

// owesSecondFactor reports whether the account of s's user has a second
// factor s has not met: a configured method usable against s's first factor,
// or the user's own active passkeys while a passkey route can meet the second
// factor. The routes are this manager's passkey MFA method among methods, and
// passwordless login on the caller's chain, which meets the second factor
// unless WithoutSecondFactorAtLogin is set. The passkeys count whatever s's
// first factor, since the account's assurance does not depend on how s was
// established; with no route they meet no second factor, and counting them
// would leave their holder unable ever to manage passkeys. A failed lookup is
// an error with fixed text.
func (m *Manager) owesSecondFactor(
	ctx context.Context, s *session.Session, methods []policy.MFAMethodLookup, passwordless bool,
) (bool, error) {
	usable, err := policy.UsableMFAMethods(ctx, methods, s.UserID, s.FirstFactor)
	if err != nil {
		return false, diag.Wrap(err, "passkey: could not read the user's second factors")
	}

	if len(usable) > 0 {
		return true, nil
	}

	if !m.passkeyRoute(methods, passwordless) {
		return false, nil
	}

	active, err := m.activeCredentials(ctx, s.UserID)
	if err != nil {
		return false, err
	}

	return len(active) > 0, nil
}

// passkeyRoute reports whether a passkey of this manager can meet a second
// factor: its own MFA method is among methods, recognised by type and by the
// manager it belongs to, never by name; or passwordless login is served and
// proves the second factor.
func (m *Manager) passkeyRoute(methods []policy.MFAMethodLookup, passwordless bool) bool {
	if passwordless && !m.noProofAtLogin {
		return true
	}

	for _, lk := range methods {
		if pm, ok := lk.(*MFAMethod); ok && pm.m == m {
			return true
		}
	}

	return false
}
