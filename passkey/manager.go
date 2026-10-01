package passkey

//go:generate mockgen -source=verifier.go -destination=verifier_mock_test.go -package=passkey_test -typed
//go:generate mockgen -destination=sender_mock_test.go -package=passkey_test -typed github.com/kartaladev/scrty/notify Sender
//go:generate mockgen -destination=userloader_mock_test.go -package=passkey_test -typed github.com/kartaladev/scrty/identity UserLoader
//go:generate mockgen -destination=lookup_mock_test.go -package=passkey_test -typed github.com/kartaladev/scrty/policy MFAMethodLookup
//go:generate mockgen -destination=limiter_mock_test.go -package=passkey_test -typed github.com/kartaladev/scrty/ratelimit Limiter

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
	// whether a full session must have met its second factor to register.
	// May be empty.
	MFAMethods []policy.MFAMethodLookup
	// Sender delivers the emailed code and the notices. Required, and it must
	// report notify.NonBlocking unless WithSynchronousDelivery is given.
	Sender notify.Sender
	// Recovery wires saved recovery codes to registration. Optional: with
	// none, a registration never waits for saved codes.
	Recovery *RecoveryDeps
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
	defaultLogInterval   = time.Minute
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
// random source or identifier generator.
func New(deps Deps, opts ...Option) (*Manager, error) {
	m := &Manager{
		verifier:    deps.Verifier,
		credentials: deps.Credentials,
		handles:     deps.Handles,
		users:       deps.Users,
		methods:     deps.MFAMethods,
		sender:      deps.Sender,
		recovery:    deps.Recovery,

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

	limiter, err := ratelimit.NewMemoryLimiter(defaultConfirmLimit, defaultConfirmWindow,
		ratelimit.WithMemoryLimiterClock(m.clock), ratelimit.WithMemoryLimiterLogger(m.logger))
	if err != nil {
		return nil, fmt.Errorf("%w: emailed-code limiter: %w", ErrConfig, err)
	}

	m.confirmLimiter = limiter

	return m, nil
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
// A recovery-pending or enrolment-only session is admitted without further
// checks: the recovery is its authentication, its user has no usable second
// factor, and its life is short by construction. A full session — no pending
// challenge, never confined — must have met its second factor when its user
// can use any configured MFA method, and its latest authentication, the later
// of its creation and its second factor, must be within the freshness window.
// Anything else, a session with a pending challenge among it, is refused with
// ErrReauthenticationRequired. A failed MFA lookup refuses with fixed text.
func (m *Manager) admit(ctx context.Context, s *session.Session) error {
	if s == nil || s.UserID == "" {
		return ErrReauthenticationRequired
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

	usable, err := policy.UsableMFAMethods(ctx, m.methods, s.UserID, s.FirstFactor)
	if err != nil {
		return diag.Wrap(err, "passkey: could not read the user's second factors")
	}

	if len(usable) > 0 && s.MFA != session.MFASatisfied {
		return ErrReauthenticationRequired
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
