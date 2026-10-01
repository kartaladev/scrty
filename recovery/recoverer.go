package recovery

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// IssuedCodePurpose is the one-time purpose issued recovery codes are minted
// under. Its subject is the user reference, never the username.
const IssuedCodePurpose = "account-recovery"

const (
	// defaultIssuedCodeTTL matches a magic link's lifetime.
	defaultIssuedCodeTTL = 15 * time.Minute

	// maxIssuedCodeTTL is NIST SP 800-63B-4's cap on a code sent to an email
	// address.
	maxIssuedCodeTTL = 24 * time.Hour

	// defaultIssuedCodeLimit is how many codes a user may be sent within the
	// one-time manager's issuance window.
	defaultIssuedCodeLimit = 5

	// defaultUserLimit and defaultUserWindow bound failed recoveries per user.
	defaultUserLimit  = 5
	defaultUserWindow = 15 * time.Minute
)

// ProofKind names one kind of proof a recovery may rest on.
type ProofKind string

// The proof kinds. A recovery needs exactly two, of different kinds, and at
// least one of them a recovery code: ProofSaved or ProofIssued.
const (
	// ProofSaved is a saved recovery code, from the set shown to the user once.
	ProofSaved ProofKind = "saved"
	// ProofIssued is a code emailed to the user by Start.
	ProofIssued ProofKind = "issued"
	// ProofPassword is the user's password, checked by the login authenticator.
	ProofPassword ProofKind = "password"
	// ProofMFA is a code for an MFA method the user is enrolled on. Only a
	// method whose response is one form field and which has no begin step can
	// serve: a challenge method's begin needs a session to bind the challenge
	// to, and a recovery has none yet.
	ProofMFA ProofKind = "mfa"
)

// proofOrder is the canonical order proofs are reported in.
var proofOrder = []ProofKind{ProofSaved, ProofIssued, ProofPassword, ProofMFA}

// Deps are the ports a Recoverer is built over.
type Deps struct {
	// Users resolves the username a recovery names. Required.
	Users identity.UserLoader

	// Sessions creates the session a completed recovery produces. Required.
	Sessions *session.Manager

	// Records keeps recovery records. Nil selects NewMemoryRecordStore, which
	// holds one process's records only.
	Records RecordStore

	// Sender delivers issued codes and notices. Required whichever proof
	// kinds are enabled, since every completed recovery sends a notice. It
	// must not wait for delivery unless WithSynchronousDelivery is given.
	Sender notify.Sender

	// Codes manages saved recovery codes. Required when saved codes are
	// enabled.
	Codes *Codes
}

// Recoverer runs account recovery: it sends issued codes, checks and spends
// the two proofs a recovery rests on, and completes the recovery at once or
// after a hold.
//
// Build one with NewRecoverer. A Recoverer holds no mutable state after
// construction, and is safe for concurrent use as far as its ports are.
type Recoverer struct {
	users    identity.UserLoader
	sessions *session.Manager
	records  RecordStore
	sender   notify.Sender
	codes    *Codes

	proofs      []ProofKind
	repudiation string

	issued      *onetime.Manager
	issuedLimit int
	resolver    mfa.ContactResolver
	messages    Messages

	passwordCheck PasswordCheck
	mfaMethods    map[string]mfa.Method
	checks        []Check
	userLimiter   ratelimit.Limiter
	planner       planner
	risk          func(ctx context.Context, in RiskInput) (time.Duration, error)

	revokeSessions  bool
	sessionLifetime time.Duration
	ids             id.Generator

	delay        time.Duration
	window       time.Duration
	cancelLink   *url.URL
	holdStore    onetime.Store
	finishTokens *onetime.Manager
	cancelTokens *onetime.Manager

	clock  clock.Clock
	logger *slog.Logger
}

// Enabled reports whether proof kind k is one WithProofs enabled. A caller
// serving the recovery uses it to offer only what the recoverer accepts: an
// HTTP layer, for example, answers the endpoint that sends issued codes only
// when ProofIssued is enabled.
func (r *Recoverer) Enabled(k ProofKind) bool {
	return slices.Contains(r.proofs, k)
}

// config collects the options before NewRecoverer validates them. The *Set
// flags tell an option given nil apart from one never given.
type config struct {
	proofs      []ProofKind
	repudiation string

	issuedTTL      time.Duration
	issuedStore    onetime.Store
	issuedStoreSet bool
	issuedLimit    int
	resolver       mfa.ContactResolver
	messages       Messages
	syncDelivery   bool

	passwordCheck    PasswordCheck
	passwordCheckSet bool
	mfaMethods       []mfa.Method
	checks           []Check
	userLimiter      ratelimit.Limiter
	userLimiterSet   bool

	kinds          []AuthenticatorKind
	resetReported  bool
	resetPolicy    ResetPolicy
	resetPolicySet bool

	risk    func(ctx context.Context, in RiskInput) (time.Duration, error)
	riskSet bool

	keepSessions    bool
	sessionLifetime time.Duration
	ids             id.Generator
	idsSet          bool

	delay        time.Duration
	delaySet     bool
	window       time.Duration
	cancelLink   string
	holdStore    onetime.Store
	holdStoreSet bool

	clock  clock.Clock
	logger *slog.Logger
}

// Option configures a Recoverer. Every option names the default it replaces.
type Option func(*config)

// WithProofs enables the proof kinds a recovery may combine. There is no
// default: it is required.
//
// At least two kinds are required, since a recovery needs two of different
// kinds, and at least one of them must be ProofSaved or ProofIssued. An unknown
// or repeated kind is a configuration error.
func WithProofs(kinds ...ProofKind) Option {
	return func(c *config) { c.proofs = slices.Clone(kinds) }
}

// WithRepudiationContact sets the text every recovery notice ends with, telling
// a user who did not recover their account whom to contact. There is no
// default: it is required, and empty text is a configuration error, since a
// notice with no way to repudiate the recovery leaves its reader with nothing
// to do.
func WithRepudiationContact(text string) Option {
	return func(c *config) { c.repudiation = text }
}

// WithIssuedCodeTTL replaces how long an issued code stays valid. The default
// is 15 minutes.
//
// Zero or less is a configuration error, and so is more than 24 hours: NIST SP
// 800-63B-4 caps a code sent to an email address at 24 hours.
func WithIssuedCodeTTL(d time.Duration) Option {
	return func(c *config) { c.issuedTTL = d }
}

// WithIssuedCodeStore replaces where issued codes are kept. The default is
// onetime.NewMemoryStore, which holds one process's codes and forgets them on
// restart. A nil store is a configuration error.
func WithIssuedCodeStore(s onetime.Store) Option {
	return func(c *config) { c.issuedStore, c.issuedStoreSet = s, true }
}

// WithIssuedCodeLimit replaces how many codes one user may be sent within the
// one-time manager's issuance window (one hour). The default is 5. Below 1 is a
// configuration error, since it would send nothing ever.
//
// A start past the limit sends nothing, and looks to its caller exactly like
// any other start.
func WithIssuedCodeLimit(n int) Option {
	return func(c *config) { c.issuedLimit = n }
}

// WithContactResolver replaces how the address an issued code and the notices
// go to is found from the user's details. The default is mfa.UsernameAsAddress.
// A nil resolver is a configuration error.
//
// The library always sets the recipient itself: a message builder cannot
// redirect a code.
func WithContactResolver(r mfa.ContactResolver) Option {
	return func(c *config) { c.resolver = r }
}

// WithMessages replaces the builder of every message a recovery sends. The
// default writes plain text naming no product or organisation. A nil builder
// is a configuration error.
func WithMessages(m Messages) Option {
	return func(c *config) { c.messages = m }
}

// WithSynchronousDelivery accepts a sender that waits for delivery.
//
// The default is to refuse one. A sender that waits puts the mail server's
// response time into Start's, so a start for a username that has an account
// takes measurably longer than one for a username that does not: response time
// then reveals which usernames have accounts. The alternative is to wrap the
// sender in notify.NewQueuedSender, which needs no option here.
func WithSynchronousDelivery() Option {
	return func(c *config) { c.syncDelivery = true }
}

// WithClock replaces the time source. The default is clock.System(). A nil
// clock is a configuration error.
func WithClock(clk clock.Clock) Option {
	return func(c *config) { c.clock = clk }
}

// WithLogger replaces the logger. The default is slog.Default(). A nil logger
// is ignored. No record carries a username, an address, a code or a token.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithPasswordCheck supplies the password proof's check. There is no default:
// it is required when ProofPassword is enabled.
//
// The check must run the pre-authentication policy phase first, so a locked
// account is refused before its password is checked, then the login's password
// authenticator, recording a failure as login does. A wrong password is
// reported by an error wrapping authenticate.ErrAuthenticationFailed; any other
// error, such as a lockout, is returned by the recovery unchanged.
//
// It is called only for an active account, and only after the recovery codes
// presented have passed their check: an unknown username and a wrong code are
// both refused without it, so neither pays for a password hash.
func WithPasswordCheck(check PasswordCheck) Option {
	return func(c *config) { c.passwordCheck, c.passwordCheckSet = check, true }
}

// WithMFAMethods supplies the MFA methods whose codes may serve as a proof.
// There is no default: at least one eligible method is required when ProofMFA
// is enabled.
//
// Only a method whose response is a single form field and which is not an
// mfa.ChallengeMethod is eligible; others are not offered as a proof. A
// challenge method cannot serve, because its begin step needs a session and a
// recovery has none yet. The set is validated by mfa.LookupsFor.
func WithMFAMethods(methods ...mfa.Method) Option {
	return func(c *config) { c.mfaMethods = slices.Clone(methods) }
}

// WithChecks adds the consumer's refusal checks. The default is none. They run
// after every proof has been checked and before anything is spent, and an
// error from one is returned unchanged, leaving every code redeemable. A nil
// check is skipped.
func WithChecks(checks ...Check) Option {
	return func(c *config) { c.checks = append(c.checks, checks...) }
}

// WithUserLimiter replaces the limiter that counts failed recoveries per user.
// The default is a ratelimit.MemoryLimiter allowing 5 failures per 15 minutes,
// per process, under UserThrottleKey(user). A nil limiter is a configuration
// error. A limiter that cannot answer refuses the recovery.
func WithUserLimiter(l ratelimit.Limiter) Option {
	return func(c *config) { c.userLimiter, c.userLimiterSet = l, true }
}

// WithAuthenticatorKinds registers the kinds of authenticator a completed
// recovery resets. There is no default: at least one is required, and two
// kinds sharing a Kind is a configuration error.
func WithAuthenticatorKinds(kinds ...AuthenticatorKind) Option {
	return func(c *config) { c.kinds = slices.Clone(kinds) }
}

// WithResetReported makes a recovery remove only the authenticators the user
// reported lost, in place of the default, which removes everything the user
// holds except what they proved in the recovery.
//
// This mode trusts the user's report at the moment they are least sure what
// happened to their authenticators: one they did not report stays valid, even
// if it is in someone else's hands.
//
// Every reported loss must be held, a request must report at least one, and a
// reported loss must not be one proved in the same recovery; anything else is
// ErrMalformed before anything is spent. When a held recovery is finished,
// the reported losses are checked again against what the user holds then,
// and one the user removed during the hold is dropped rather than refused.
// It cannot be combined with WithResetPolicy.
func WithResetReported() Option {
	return func(c *config) { c.resetReported = true }
}

// WithResetPolicy replaces how a recovery decides what to remove with the
// consumer's own policy, in place of the default, which removes everything the
// user holds except what they proved in the recovery. It cannot be combined
// with WithResetReported, and a nil policy is a configuration error.
//
// A policy that removes nothing leaves possibly compromised authenticators
// valid, against NIST's requirement to invalidate an authenticator reported
// lost or compromised. See ResetPolicy.
func WithResetPolicy(policy ResetPolicy) Option {
	return func(c *config) { c.resetPolicy, c.resetPolicySet = policy, true }
}

// WithRisk supplies a risk hook, which returns how long a recovery is held
// before it can complete. The default is none: a recovery completes at once.
//
// It runs after every proof has been checked and before anything is spent. An
// error refuses the recovery behind fixed library text, and nothing is spent.
// A negative duration is taken as none. A nil hook is a configuration error.
func WithRisk(fn func(ctx context.Context, in RiskInput) (time.Duration, error)) Option {
	return func(c *config) { c.risk, c.riskSet = fn, true }
}

// NewRecoverer builds the recovery flow.
//
// Every wiring mistake is a configuration error wrapping ErrConfig, seen here
// rather than on the first request:
//   - no user loader or session manager;
//   - fewer than two proof kinds, an unknown or repeated kind, or no recovery
//     code kind among them;
//   - ProofSaved without Deps.Codes, ProofPassword without
//     WithPasswordCheck, or ProofMFA without an eligible method;
//   - no sender, or one that waits for delivery without
//     WithSynchronousDelivery;
//   - no repudiation contact;
//   - an issued-code lifetime outside (0, 24h], or an issuance limit below 1;
//   - no authenticator kind, or two sharing a Kind;
//   - both WithResetReported and WithResetPolicy;
//   - a session lifetime of zero or less, or longer than the session
//     manager's absolute timeout;
//   - a delay or a completion window of zero or less, a hold (a delay or a
//     risk hook) with no cancel link, or a cancel link that is not absolute
//     https or http on a loopback host;
//   - any option given nil where a port or function is expected.
func NewRecoverer(deps Deps, opts ...Option) (*Recoverer, error) {
	c := &config{
		issuedTTL:   defaultIssuedCodeTTL,
		issuedLimit: defaultIssuedCodeLimit,
		resolver:    mfa.UsernameAsAddress,

		sessionLifetime: defaultSessionLifetime,
		window:          defaultCompletionWindow,

		messages: DefaultMessages(),
		clock:    clock.System(),
		logger:   slog.Default(),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}

	r := &Recoverer{
		users:         deps.Users,
		sessions:      deps.Sessions,
		records:       deps.Records,
		codes:         deps.Codes,
		repudiation:   c.repudiation,
		issuedLimit:   c.issuedLimit,
		resolver:      c.resolver,
		messages:      c.messages,
		passwordCheck: c.passwordCheck,
		risk:          c.risk,

		revokeSessions:  !c.keepSessions,
		sessionLifetime: c.sessionLifetime,

		clock:  c.clock,
		logger: c.logger,
	}

	if !nilcheck.IsNil(deps.Sender) {
		r.sender = deps.Sender
	}

	steps := []func(*config) error{
		r.validateDeps,
		r.validateProofs,
		r.validateIssued,
		r.validateMFA,
		r.validateFlow,
		r.validateCompletion,
		r.validateHolds,
	}
	for _, step := range steps {
		if err := step(c); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// validateDeps checks the required ports and defaults the record store.
func (r *Recoverer) validateDeps(c *config) error {
	if nilcheck.IsNil(r.users) {
		return fmt.Errorf("%w: %w", ErrConfig, identity.MissingPort("user loader"))
	}
	if r.sessions == nil {
		return fmt.Errorf("%w: a session manager is required", ErrConfig)
	}

	switch {
	case r.records == nil:
		r.records = NewMemoryRecordStore()
	case nilcheck.IsNil(r.records):
		return fmt.Errorf("%w: the record store must not be a typed nil", ErrConfig)
	}

	if nilcheck.IsNil(c.clock) {
		return fmt.Errorf("%w: WithClock was given no clock", ErrConfig)
	}
	if strings.TrimSpace(c.repudiation) == "" {
		return fmt.Errorf("%w: WithRepudiationContact is required and must not be empty", ErrConfig)
	}
	if c.resolver == nil {
		return fmt.Errorf("%w: WithContactResolver was given no resolver", ErrConfig)
	}
	if nilcheck.IsNil(c.messages) {
		return fmt.Errorf("%w: WithMessages was given no message builder", ErrConfig)
	}

	return nil
}

// validateProofs checks the proof shape and the port each proof kind needs.
func (r *Recoverer) validateProofs(c *config) error {
	seen := make(map[ProofKind]bool, len(c.proofs))
	for _, k := range c.proofs {
		if !slices.Contains(proofOrder, k) {
			return fmt.Errorf("%w: unknown proof kind %q", ErrConfig, k)
		}
		if seen[k] {
			return fmt.Errorf("%w: proof kind %q is enabled twice", ErrConfig, k)
		}

		seen[k] = true
	}

	if len(seen) < 2 {
		return fmt.Errorf("%w: at least two proof kinds are required, since a recovery needs two of different kinds", ErrConfig)
	}
	if !seen[ProofSaved] && !seen[ProofIssued] {
		return fmt.Errorf("%w: saved or issued recovery codes must be enabled", ErrConfig)
	}

	for _, k := range proofOrder {
		if seen[k] {
			r.proofs = append(r.proofs, k)
		}
	}

	if seen[ProofSaved] && r.codes == nil {
		return fmt.Errorf("%w: saved codes are enabled with no Deps.Codes", ErrConfig)
	}
	if r.sender == nil {
		return fmt.Errorf("%w: a sender is required: every completed recovery notifies the user", ErrConfig)
	}
	if seen[ProofPassword] && r.passwordCheck == nil {
		return fmt.Errorf("%w: the password proof is enabled with no WithPasswordCheck", ErrConfig)
	}
	if c.passwordCheckSet && r.passwordCheck == nil {
		return fmt.Errorf("%w: WithPasswordCheck was given no check", ErrConfig)
	}

	if !c.syncDelivery {
		nb, ok := r.sender.(notify.NonBlocking)
		if !ok || !nb.NonBlocking() {
			return fmt.Errorf(
				"%w: this sender waits for delivery, and synchronous delivery reveals which "+
					"usernames have accounts; wrap it in notify.NewQueuedSender, or accept the "+
					"channel with WithSynchronousDelivery", ErrConfig)
		}
	}

	return nil
}

// validateIssued checks the issued-code settings and builds their manager.
func (r *Recoverer) validateIssued(c *config) error {
	if c.issuedTTL <= 0 || c.issuedTTL > maxIssuedCodeTTL {
		return fmt.Errorf("%w: the issued-code lifetime must be above zero and at most 24 hours, got %s", ErrConfig, c.issuedTTL)
	}
	if c.issuedLimit < 1 {
		return fmt.Errorf("%w: the issued-code limit must be at least 1, got %d", ErrConfig, c.issuedLimit)
	}
	if c.issuedStoreSet && nilcheck.IsNil(c.issuedStore) {
		return fmt.Errorf("%w: WithIssuedCodeStore was given no store", ErrConfig)
	}

	if !slices.Contains(r.proofs, ProofIssued) {
		return nil
	}

	topts := []onetime.Option{onetime.WithTTL(c.issuedTTL), onetime.WithClock(c.clock), onetime.WithLogger(c.logger)}
	if c.issuedStoreSet {
		topts = append(topts, onetime.WithStore(c.issuedStore))
	}

	m, err := onetime.NewManager(IssuedCodePurpose, topts...)
	if err != nil {
		return fmt.Errorf("%w: issued codes: %w", ErrConfig, err)
	}

	r.issued = m

	return nil
}

// validateMFA keeps the eligible MFA methods.
func (r *Recoverer) validateMFA(c *config) error {
	if len(c.mfaMethods) > 0 {
		if _, err := mfa.LookupsFor(c.mfaMethods...); err != nil {
			return fmt.Errorf("%w: mfa methods: %w", ErrConfig, err)
		}
	}

	r.mfaMethods = make(map[string]mfa.Method, len(c.mfaMethods))
	for _, m := range c.mfaMethods {
		if eligibleMethod(m) {
			r.mfaMethods[m.Name()] = m
		}
	}

	if slices.Contains(r.proofs, ProofMFA) && len(r.mfaMethods) == 0 {
		return fmt.Errorf("%w: the MFA proof is enabled with no method that can serve: one whose response "+
			"is a form field and which has no begin step", ErrConfig)
	}

	return nil
}

// eligibleMethod reports whether m can serve as a recovery proof: a single form
// field, and no begin step.
func eligibleMethod(m mfa.Method) bool {
	if _, challenge := m.(mfa.ChallengeMethod); challenge {
		return false
	}

	return m.Response().Kind() == mfa.ResponseFormField
}

// validateFlow checks the limiter, the reset and the hooks.
func (r *Recoverer) validateFlow(c *config) error {
	switch {
	case c.userLimiterSet && nilcheck.IsNil(c.userLimiter):
		return fmt.Errorf("%w: WithUserLimiter was given no limiter", ErrConfig)
	case c.userLimiterSet:
		r.userLimiter = c.userLimiter
	default:
		l, err := ratelimit.NewMemoryLimiter(defaultUserLimit, defaultUserWindow, ratelimit.WithMemoryLimiterClock(c.clock))
		if err != nil {
			return fmt.Errorf("%w: default user limiter: %w", ErrConfig, err)
		}

		r.userLimiter = l
	}

	mode := resetAll
	switch {
	case c.resetReported && c.resetPolicySet:
		return fmt.Errorf("%w: WithResetReported and WithResetPolicy cannot be combined", ErrConfig)
	case c.resetReported:
		mode = resetReported
	case c.resetPolicySet:
		mode = resetCustom
	}

	p, err := newPlanner(c.kinds, mode, c.resetPolicy)
	if err != nil {
		return err
	}

	r.planner = p

	if c.riskSet && c.risk == nil {
		return fmt.Errorf("%w: WithRisk was given no hook", ErrConfig)
	}

	for _, check := range c.checks {
		if check != nil {
			r.checks = append(r.checks, check)
		}
	}

	return nil
}
