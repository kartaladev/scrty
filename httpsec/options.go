package httpsec

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// ErrConfig is the wiring fault every option is refused with.
//
// It never reaches a client: a chain that does not build serves no traffic, so
// a consumer matches it once, at start-up, and does not have to know which
// option produced it to tell a configuration mistake from a refusal.
var ErrConfig = errors.New("httpsec: invalid configuration")

// newConfigError reports a wiring fault, wrapping ErrConfig so that a consumer
// matches every one of them with one errors.Is and the message still names the
// option and the dependency at fault.
func newConfigError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrConfig, fmt.Sprintf(format, args...))
}

// checkCookieTTL refuses a ceremony cookie whose lifetime, ttl, is not a whole
// number of seconds. The cookie's Max-Age is whole seconds, so a fractional
// lifetime would be truncated and the cookie would expire before what it
// binds does. It checks nothing when set is false, because no cookie is
// written then. The bound has no override: choose a lifetime in whole seconds.
func checkCookieTTL(option, what string, ttl time.Duration, set bool) error {
	if set && (ttl < time.Second || ttl%time.Second != 0) {
		return newConfigError("%s binds a cookie to %s, %s, which must be a whole number of seconds, at least one",
			option, what, ttl)
	}

	return nil
}

// defaultIPv6SourcePrefix is the prefix length IPv6 clients are counted by. It
// matches the rate-limiting default, so a consumer who configures neither gets
// one consistent answer about what "one source" means.
const defaultIPv6SourcePrefix = 64

// defaultIPv6AggregatePrefix is the prefix length the chain also counts IPv6
// clients by, as an aggregate over the sources inside it. A /56 is the
// allocation a residential customer commonly receives: 256 /64s that one
// client can rotate through.
const defaultIPv6AggregatePrefix = 56

// defaultIPv6AggregateMultiplier is how many times a flow's own limit its IPv6
// aggregate allows, since the aggregate is shared by every source inside it.
const defaultIPv6AggregateMultiplier = 4

// maxIPv6SourcePrefix is the width of an IPv6 address, and so the narrowest a
// source can be counted at: one prefix per address.
const maxIPv6SourcePrefix = 128

// defaultRefusalLogInterval is how often one refusal key is written. A refusal
// is driven by whoever is being refused, so an unsampled one is a log flood an
// attacker chooses the size of.
const defaultRefusalLogInterval = time.Minute

// Option configures a chain.
//
// Every option either takes effect or is refused when the chain is built: none
// is documented away, and none is silently ignored. A nil Option is skipped, so
// a consumer assembling the slice conditionally need not filter it.
type Option func(*config) error

// config is what the options accumulate before the chain is built. New
// validates it and only then builds a Chain, so a chain that exists is one
// whose every option took effect.
type config struct {
	registrations []registration

	// seq counts registrations so two interceptors at one slot stay in the
	// order they were registered in, which sorting alone would not preserve.
	seq int

	// enabled holds one dependency check per built-in the consumer enabled.
	enabled []enabledBuiltIn

	// wiring holds what each enabled built-in still has to be handed once the
	// chain exists. An Enable* option runs before the options that follow it,
	// so an interceptor reading c.engine or c.logger at that moment would
	// capture a setting a later option was about to replace.
	wiring []func(*Chain)

	engine *policy.Engine
	logger *slog.Logger

	// limiterFactory is the factory WithRateLimiterFactory gave, and nil when
	// the consumer gave none (see rateLimiterFactory).
	limiterFactory ratelimit.LimiterFactory

	// keyer is what every source guard the chain builds keys a client address
	// by, built at assembly from ipv6Prefix.
	keyer *ratelimit.SourceKeyer

	// enrolmentLifetime is how long a session marked for an enrolment
	// challenge may live: its deadlines are lowered to at most this far from
	// the mark. It starts at defaultEnrolmentLifetime and is replaced by the
	// enrolment interceptor's own configuration.
	enrolmentLifetime time.Duration

	// clock is the time source the chain and the components it builds read. It
	// starts as clock.System() and is replaced by WithClock.
	clock clock.Clock

	// consumerEnforced holds the challenge kinds of the consumer's own that
	// WithChallengeEnforcer declared this chain enforces.
	consumerEnforced map[policy.ChallengeKind]bool

	// builtInGates holds the built-in challenge kinds whose own built-in gate
	// is enabled on this chain, each recorded by the Enable option that
	// registers that gate through enableGate. It is what makes a built-in kind
	// count as enforced: an interceptor that merely occupies the gate's slot
	// does not.
	builtInGates map[policy.ChallengeKind]bool

	// sessions is the manager the chain records activity through: the first one
	// any enabled built-in was wired to. A deployment has one session store, so
	// taking it from the built-ins costs the consumer no second declaration,
	// and a chain that resolves no session has nothing to record.
	sessions *session.Sessions

	// sessionsExplicit records that WithSessions set sessions, which no
	// built-in's manager then replaces.
	sessionsExplicit bool

	// sessionBearer records that EnableSessionBearer is on: the chain's bearer
	// mode is the session reference, so every credential-issuing endpoint
	// issues the session's identifier and none may be given a token
	// generator.
	sessionBearer bool

	// renewal is the renewal endpoint EnableSessionRenewal registered, and nil
	// while it is off. The bearers' resolution core reads it to let a late
	// renewal through to it alone (sessionResolver.renewal).
	renewal *sessionRenewal

	// authorizer is what the authorization stage publishes for the guards
	// behind it, and what the last EnableAuthorization call named: a chain
	// judges by one authorizer, so a second call replacing the first is the
	// consumer changing their mind rather than two judges disagreeing.
	authorizer authorize.Authorizer

	// authzRules is the centralized rule set, in the order the calls arrived
	// in. It accumulates rather than being replaced, so a consumer assembles
	// one ordered set from as many EnableAuthorization calls as their own
	// wiring is split across.
	authzRules []authorize.Rule[Request]

	// logoutPath is where logout answers, and is empty when the consumer
	// enabled none. It is kept here because the gates have to exempt it, and
	// an exemption configured separately from the endpoint is one a consumer
	// can move half of.
	logoutPath string

	// logout is the registered logout interceptor, nil when the consumer
	// enabled none, kept so a later option can supply the end-session step
	// the consumer left unset.
	logout *logout

	ipv6Prefix int

	// aggregateBits and aggregateMultiplier shape the IPv6 aggregate every
	// source guard also counts by. aggregateExplicit records that
	// WithIPv6Aggregate was given and aggregateOff that WithoutIPv6Aggregate
	// was; both are only recorded by the options and checked at assembly,
	// because the options can come in any order.
	aggregateBits       int
	aggregateMultiplier int
	aggregateExplicit   bool
	aggregateOff        bool

	// recoverer is the account recovery EnableAccountRecovery's endpoints run,
	// built at assembly (wireAccountRecovery), and nil on a chain without
	// recovery. It is kept here so the other built-ins that take part in a
	// recovery — the held-recovery endpoints and login's cancellation of a
	// held recovery — reach the same one.
	recoverer *recovery.Recoverer

	errorHandler func(w http.ResponseWriter, r *http.Request, err error)

	refusalInterval time.Duration
	refusalReporter func(key string, suppressed int)

	// discloseLocks answers a locked account's login with the lock itself
	// (WithLockDisclosure), rather than as a wrong password.
	discloseLocks bool
}

// enabledBuiltIn is one built-in interceptor the consumer switched on, and the
// check its dependencies must pass before the chain is built.
type enabledBuiltIn struct {
	option string
	check  func() error
}

// enable records that the built-in switched on by option is enabled, and the
// check validate runs for it.
//
// It is the seam every Enable* option is added through: the option captures the
// dependencies it was handed and hands enable a check over them, so validate
// gains no knowledge of any one built-in and every built-in is checked the same
// way, in the order the consumer enabled them.
func (c *config) enable(option string, check func() error) {
	c.enabled = append(c.enabled, enabledBuiltIn{option: option, check: check})
}

// enableGate records that the built-in gate enforcing kind is enabled on this
// chain. Only the Enable option that registers that gate calls it: EnableMFA
// for ChallengeMFA, EnablePasswordChangeGate for ChallengePasswordChange, and
// EnableMFAEnrolment for ChallengeMFAEnrolment.
func (c *config) enableGate(kind policy.ChallengeKind) {
	if c.builtInGates == nil {
		c.builtInGates = make(map[policy.ChallengeKind]bool, len(builtInEnforcers))
	}

	c.builtInGates[kind] = true
}

// wire records what a built-in still has to be handed once the chain exists.
func (c *config) wire(fn func(*Chain)) {
	c.wiring = append(c.wiring, fn)
}

// useSessions records the session manager an enabled built-in was wired to, so
// the chain's own activity write-back has one without the consumer declaring it
// twice.
//
// The first one wins, unless WithSessions set one, and a nil one is ignored: a deployment has one session
// store, and the built-in whose dependency is missing is refused by its own
// check rather than by this one.
func (c *config) useSessions(m *session.Sessions) {
	if c.sessions == nil && !c.sessionsExplicit && m != nil {
		c.sessions = m
	}
}

// WithSessions sets the session manager the chain itself uses: the one
// that records a session's activity after the handler, and the one a mark from
// Exchange.EvaluatePerRequest is stored through.
//
// It is what a chain needs when its only session-resolving interceptor is the
// consumer's own, published through Exchange.PublishSession, and no built-in
// was wired to a manager. It takes precedence over the manager of any built-in
// whatever the order of the options; the built-ins keep using the manager they
// were given.
//
// With a built-in bearer (EnableBearerToken or EnableSessionBearer), the
// explicit manager must be that bearer's: New refuses any other with a
// configuration error, in either option order, because activity and rotation
// written through a manager the bearer does not read would end sessions in use.
// A chain with no built-in bearer is not checked.
//
// A nil manager is refused with a configuration error, since it would read as
// "activity is recorded" while nothing was.
//
// Default: the manager of the first enabled built-in that was wired to one.
// A chain with none records no activity and refuses to store an enrolment mark.
func WithSessions(m *session.Sessions) Option {
	return func(c *config) error {
		if err := requireDep("WithSessions", "session manager", m); err != nil {
			return err
		}

		c.sessions = m
		c.sessionsExplicit = true
		return nil
	}
}

// register records i at slot at, keeping the sequence that decides which of two
// interceptors sharing a slot runs first.
func (c *config) register(i Interceptor, at Order) {
	c.registrations = append(c.registrations, registration{interceptor: i, order: at, seq: c.seq})
	c.seq++
}

// eachInterceptor runs fn against every registered interceptor of type T, in
// registration order, and stops at the first error.
//
// Each built-in that has to finish assembling itself after every option has
// been applied walks the registrations looking for its own interceptor. The
// walk is the same every time and only the type differs, so they share this
// rather than each keeping a copy that can drift from the others. The
// per-built-in functions stay separate, because the order they are called in
// is what decides which of two misconfigured built-ins reports first.
func eachInterceptor[T any](c *config, fn func(T) error) error {
	for _, r := range c.registrations {
		i, ok := r.interceptor.(T)
		if !ok {
			continue
		}

		if err := fn(i); err != nil {
			return err
		}
	}

	return nil
}

// validate reports the first wiring fault, naming the option and the dependency
// at fault so the consumer fixes it without reading library source.
//
// It runs once every option has been applied, because a built-in's dependencies
// may be set by the Enable* option and refined by the sub-options that follow
// it, and checking half an option's worth of configuration would report a fault
// the next option was about to fix.
func (c *config) validate() error {
	if err := c.validateAggregate(); err != nil {
		return err
	}

	for _, e := range c.enabled {
		if err := e.check(); err != nil {
			return err
		}
	}

	return c.checkExplicitSessions()
}

// checkExplicitSessions refuses an explicit session manager other than the one
// a built-in bearer loads sessions from. Activity would otherwise be recorded
// where the bearer never reads, so sessions in use would idle-expire, and a
// second factor would rotate a session the bearer cannot find. With no
// built-in bearer there is nothing to compare, which is what the option is for.
func (c *config) checkExplicitSessions() error {
	if !c.sessionsExplicit {
		return nil
	}

	if bearer := bearerSessions(c); bearer != nil && bearer != c.sessions {
		return newConfigError("WithSessions was given a manager other than the one " +
			"EnableBearerToken or EnableSessionBearer resolves sessions through, so activity " +
			"and second-factor rotation would be written where the bearer never reads; give " +
			"both the same manager, or leave WithSessions out")
	}

	return nil
}

// requireDep refuses a dependency that is absent, or present but holding a
// typed nil.
//
// (*T)(nil) inside an interface is not nil to ==, which is exactly what an
// unchecked constructor error hands over: without this the wiring looks
// complete and the first request panics. option names the option that wanted
// the dependency and dependency names the dependency itself, so the message is
// actionable on its own.
func requireDep(option, dependency string, v any) error {
	if nilcheck.IsNil(v) {
		return newConfigError("%s needs a %s", option, dependency)
	}
	return nil
}

// New builds the chain.
//
// It applies every option in turn, validates what they set, and returns no
// chain at all when anything cannot take effect: there is no partly-configured
// chain to accidentally serve traffic with. A consumer who passes no options
// gets a usable chain with the library's defaults and no built-in interceptors
// enabled.
func New(opts ...Option) (*Chain, error) {
	c := &config{
		logger:     slog.Default(),
		ipv6Prefix: defaultIPv6SourcePrefix,

		aggregateBits:       defaultIPv6AggregatePrefix,
		aggregateMultiplier: defaultIPv6AggregateMultiplier,
		refusalInterval:     defaultRefusalLogInterval,

		enrolmentLifetime: defaultEnrolmentLifetime,

		clock: clock.System(),
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	if err := c.validate(); err != nil {
		return nil, err
	}

	return c.build()
}

// checkTouchInterval refuses a chain whose session manager coalesces activity
// writes over an interval that an idle-timeout policy in the engine does not
// exceed. The stored last-access time can be up to one interval stale, so such
// a policy could refuse a session that is in constant use. A manager that
// writes on every touch (interval zero), a chain with no manager, and an engine
// with no idle policy are all accepted. Only policies registered in the engine
// before New runs are checked.
func (c *config) checkTouchInterval() error {
	if c.sessions == nil || c.engine == nil {
		return nil
	}

	interval := c.sessions.TouchInterval()
	if interval <= 0 {
		return nil
	}

	for _, idle := range c.engine.IdleTimeouts() {
		if idle <= interval {
			return newConfigError("the session manager coalesces activity over %s, but a policy enforces an idle timeout of %s: "+
				"the stored last access can be up to one interval stale, so the idle timeout must be longer than the interval",
				interval, idle)
		}
	}

	return nil
}

// build freezes the validated configuration into the chain that serves it.
func (c *config) build() (*Chain, error) {
	// Before anything is built: a challenge nothing enforces is the one wiring
	// mistake on this chain that has no symptom at all.
	if err := c.refuseUnenforcedChallenges(); err != nil {
		return nil, err
	}

	// Before any source guard is built: every guard the chain builds keys its
	// clients by this one keyer, so WithIPv6SourcePrefix reaches all of them.
	keyer, err := ratelimit.NewSourceKeyer(ratelimit.WithIPv6SourcePrefix(c.ipv6Prefix))
	if err != nil {
		return nil, newConfigError("WithIPv6SourcePrefix could not build the source keyer: %s", err)
	}

	c.keyer = keyer

	// The second factor is handed the rest of its wiring here, because both
	// halves of it depend on options that may be applied after EnableMFA: the
	// logout path it exempts, and the logger its throttle writes through.
	if err := c.wireMFA(); err != nil {
		return nil, err
	}

	// The password-change gate exempts the chain's logout, which may be
	// configured after EnablePasswordChangeGate, so it is handed over here.
	c.wirePasswordChange()

	// A capped lockout policy holds only what its own view records, so a
	// password login handed any other store would disarm the cap silently.
	if err := c.checkAttemptViews(); err != nil {
		return nil, err
	}

	// An interval that coalesces activity writes leaves the stored last-access
	// time up to one interval stale, which an idle policy no longer than that
	// would read as an idle session.
	if err := c.checkTouchInterval(); err != nil {
		return nil, err
	}

	// The enrolment path takes the enrollable methods EnableMFA was given and the
	// chain's sessions and logout path, any of which an option applied after
	// EnableMFAEnrolment may still have set.
	if err := c.wireMFAEnrolment(); err != nil {
		return nil, err
	}

	// The passkey endpoints are checked against every other path, and handed
	// the enrolment path when it enrols the passkey method, which
	// wireMFAEnrolment has just settled.
	if err := c.wirePasskeys(); err != nil {
		return nil, err
	}

	if err := c.wireMagicLink(); err != nil {
		return nil, err
	}

	if err := c.wireOIDCLogin(); err != nil {
		return nil, err
	}

	if err := c.wireAPIKey(); err != nil {
		return nil, err
	}

	if err := c.wireSessionBearer(); err != nil {
		return nil, err
	}

	// Form login and Basic share one password-login guard, so it is settled
	// once both have been registered and every limiter option applied.
	if err := c.wirePasswordLogin(); err != nil {
		return nil, err
	}

	// Account recovery builds its Recoverer here: its password proof is the
	// chain's form login, and its logger is the chain's, either of which may
	// be configured after EnableAccountRecovery.
	if err := c.wireAccountRecovery(); err != nil {
		return nil, err
	}

	// Activity is recorded for every chain, with no option to enable: a session
	// whose idle deadline stops moving while its owner is using it is logged
	// out mid-work, and that is not a behaviour worth being able to switch off.
	// It is registered last, so a consumer's own interceptor at the same slot
	// wraps it and still sees the request on the way back out.
	touch := &sessionTouch{sessions: c.sessions}
	c.register(touch, OrderSessionTouch)
	c.wire(touch.wire)

	// Authorization is registered for every chain too, with no option to leave
	// it out: the stage is where the guards behind the chain find the authorizer
	// they judge by, and a chain that published none would leave every one of
	// them refusing. With no rules it enforces nothing centrally, which is the
	// consumer saying authorization belongs at the operations.
	stage := &authorization{authorizer: c.authorizer}

	if len(c.authzRules) > 0 {
		rules, err := authorize.NewRules(c.authzRules...)
		if err != nil {
			return nil, newConfigError("EnableAuthorization was given a rule set that "+
				"could not be built: %s", err)
		}

		stage.rules = rules
	}

	c.register(stage, OrderAuthorizer)

	chain := &Chain{
		registrations:     c.ordered(),
		engine:            c.engine,
		logger:            c.logger,
		enrolmentLifetime: c.enrolmentLifetime,
		enforced:          c.enforcedChallenges(),
		mfa:               c.mfaOf(),
		errorHandler:      c.errorHandler,
		refusalInterval:   c.refusalInterval,
		refusalReporter:   c.refusalReporter,
		reportRefusals:    c.refusalLogReporter(),
	}

	// The sampler is built here rather than by the option, because the default
	// reporter writes through the chain's logger and there is no chain until
	// every option has been applied.
	chain.sampler = logsample.New(c.refusalInterval, logsample.WithReporter(chain.reportRefusals))

	chain.perRequest = &perRequestPhase{
		engine:            c.engine,
		sessions:          c.sessions,
		enrolmentLifetime: c.enrolmentLifetime,
		enforced:          chain.enforced,
		now:               c.now,
	}

	// The built-ins are wired last, because each of them reads settings — the
	// engine, the logger — that an option applied after its own Enable may
	// still have replaced.
	for _, w := range c.wiring {
		w(chain)
	}

	return chain, nil
}

// WithPolicyEngine evaluates every policy phase through e.
//
// Default: no engine, under which every phase allows and the chain's decisions
// rest on authentication and authorization alone. Supply one to have lockout,
// second-factor and session policies judge each phase.
//
// A nil engine is refused: it would read as "no policies" while the consumer
// believed their policies were running.
//
// Register every policy on e before the chain is built. Assembly checks that
// each challenge a registered policy can raise has something on the chain to
// enforce it, and can only see the policies registered by then. A policy added
// afterwards escapes that check; a challenge it raises that nothing enforces is
// refused at runtime instead, with an error wrapping ErrConfig, on every
// request that raises it.
func WithPolicyEngine(e *policy.Engine) Option {
	return func(c *config) error {
		if err := requireDep("WithPolicyEngine", "policy engine", e); err != nil {
			return err
		}

		c.engine = e
		return nil
	}
}

// WithChallengeEnforcer declares that this chain enforces kind, a challenge
// kind of the consumer's own, through a gate the consumer registered with
// RegisterInterceptor.
//
// Default: none. Without it, a chain whose policies declare a kind the library
// does not know (through policy.Challenger) refuses to assemble, because a
// challenge nothing enforces marks the session and serves it anyway. This
// option is how a consumer who wrote both halves — the policy and its gate —
// tells the chain the pairing exists. The chain takes the declaration on trust:
// it cannot tell what the consumer's gate does.
//
// At login, a declared kind refuses with a ChallengeError like any other. Per
// request, the bearer cannot mark it on the session, so it records it on the
// exchange and continues: the declared gate, registered after the bearer,
// reads it with Exchange.RaisedChallenge and refuses or resolves the request.
// Declaring the kind is the consumer's statement that such a gate exists.
//
// A declared kind raised at login is refused with a ChallengeError carrying a
// session and a token, but the session records nothing of it: the library has
// no field for a kind it does not know, and the token's later requests reach
// the consumer's gate only through the per-request phase. So the consumer's
// policy must also raise the kind per request, or its gate never sees it and
// the token issued with the refusal reaches everything the gate guards.
//
// It is for consumer kinds only. A built-in kind (ChallengeMFA,
// ChallengePasswordChange, ChallengeMFAEnrolment) is enforced only by its own
// built-in gate (EnableMFA, EnablePasswordChangeGate, EnableMFAEnrolment), and
// declaring one here could only silence the check for it, so it is refused, as
// is ChallengeNone. There is no option to switch the
// check off.
func WithChallengeEnforcer(kind policy.ChallengeKind) Option {
	return func(c *config) error {
		if kind == policy.ChallengeNone {
			return newConfigError("WithChallengeEnforcer was given ChallengeNone, which is not a challenge")
		}

		if err := refuseGateOnly(kind, "WithChallengeEnforcer was given"); err != nil {
			return err
		}

		if b, ok := builtInEnforcers[kind]; ok {
			return newConfigError("WithChallengeEnforcer was given %s, which the library enforces "+
				"through its own gate: add %s instead", kind, b.option)
		}

		if c.consumerEnforced == nil {
			c.consumerEnforced = make(map[policy.ChallengeKind]bool)
		}

		c.consumerEnforced[kind] = true

		return nil
	}
}

// WithLogger writes the chain's own records through l.
//
// Default: slog.Default(), so a consumer who configures logging once for their
// application sees the chain's records without wiring anything here.
//
// A nil logger is refused rather than taken as "log nothing": the records this
// chain writes are refusals and outages, and silently dropping them is not a
// configuration anyone asks for on purpose. Pass a logger over
// slog.DiscardHandler to say so deliberately.
//
// A record of a failed consumer dependency never carries that dependency's
// error text: it carries a fixed reason and the error's Go type, as the
// package doc's "A dependency's failure never reaches a record or a returned
// error's text" explains, with the deliberate exceptions it names. A consumer
// who wants a dependency's own text logs it inside their own implementation of
// the port that failed.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) error {
		if err := requireDep("WithLogger", "logger", l); err != nil {
			return err
		}

		c.logger = l
		return nil
	}
}

// WithRateLimiterFactory builds every limiter the chain builds through f, each
// under its flow's namespace with that flow's own limit and window, so a
// consumer who moves the counts to shared storage keeps every flow's policy.
//
// Default: an in-memory limiter per flow, counting in this process alone and
// writing its one per-replica warning through the chain's logger. Behind N
// replicas every limit is effectively N times higher; supply a factory over
// storage the replicas share when one limit has to hold across a fleet.
//
// Precedence, at every site: a limiter the flow was given (WithAPIKeyLimiter,
// WithMagicLinkLimiter, WithOIDCHandoffLimiter, PasswordlessLimiter,
// WithRecoveryLimiter, WithRecoveryStartLimiter, WithRecoveryUserLimiter,
// WithMFAVerifyLimiter, WithEnrolmentBeginLimiter, WithEnrolmentConfirmLimiter)
// wins, and f is never asked for that flow; then f; then the in-memory default.
//
// The namespaces are fixed: "api-key", "magic-link-redeem", "oidc.handoff",
// "passkey-login", "account-recovery" and "account-recovery-start" for the
// source guards, and "mfa-verify", "mfa-enrol-begin", "mfa-enrol-confirm" and
// "recovery-user" for the user-keyed limits of the components the chain builds
// (the package documentation's "Rate limits" lists each with its default). f
// does not reach a component the consumer built and handed over, such as the
// passkey.Passkeys or the recovery.Codes; those take their own factory option.
//
// For the user-keyed second-factor flows, a shared limiter in
// ratelimit.UnavailableFallbackToLocal mode is the recommended choice: during
// an outage of the shared store each replica still bounds guessing on its own,
// and users are not locked out of sign-in.
//
// A nil factory, including an interface holding a nil pointer, is refused. An
// error from f fails New, naming the option and the namespace.
func WithRateLimiterFactory(f ratelimit.LimiterFactory) Option {
	return func(c *config) error {
		if err := requireDep("WithRateLimiterFactory", "rate-limiter factory", f); err != nil {
			return err
		}

		c.limiterFactory = f
		return nil
	}
}

// WithIPv6SourcePrefix counts IPv6 clients by a prefix of bits rather than by
// their full address, in every source guard the chain builds: the
// password-login, API-key, magic-link, OIDC handoff, passwordless begin and
// account-recovery guards.
// Addresses inside one prefix are one source, which shares one allowance and
// one throttled-source record per sampling window.
//
// Default: 64, the narrowest prefix that still costs an attacker something to
// move within. A wider prefix, such as 48, groups a whole allocation into one
// source. A prefix outside 1..128 is refused: 0 would pool every client into
// one bucket, and more than 128 is not an address. IPv4 is always counted per
// address.
//
// The chain also counts IPv6 clients by an aggregate prefix, /56 by default
// (WithIPv6Aggregate, WithoutIPv6Aggregate). A prefix of /56 or wider makes
// that default redundant, so it is skipped; an explicit aggregate must then be
// strictly wider than this prefix, or the chain is refused.
func WithIPv6SourcePrefix(bits int) Option {
	return func(c *config) error {
		if bits < 1 || bits > maxIPv6SourcePrefix {
			return newConfigError(
				"WithIPv6SourcePrefix takes a prefix length in 1..%d, and %d would either pool "+
					"every IPv6 client into one bucket or name no address at all",
				maxIPv6SourcePrefix, bits)
		}

		c.ipv6Prefix = bits
		return nil
	}
}

// aggregateOn reports whether the source guards also count IPv6 clients by an
// aggregate prefix: unless WithoutIPv6Aggregate was given, when the consumer
// asked for one, or when the default /56 is wider than the source prefix.
func (c *config) aggregateOn() bool {
	if c.aggregateOff {
		return false
	}

	return c.aggregateExplicit || c.ipv6Prefix > defaultIPv6AggregatePrefix
}

// validateAggregate refuses an aggregate that cannot take effect. It runs after
// every option has been applied, so the order the options came in does not
// matter.
func (c *config) validateAggregate() error {
	if c.aggregateExplicit && c.aggregateOff {
		return newConfigError("WithIPv6Aggregate and WithoutIPv6Aggregate contradict each other: " +
			"give one or the other")
	}

	if !c.aggregateExplicit {
		return nil
	}

	if c.aggregateMultiplier < 1 {
		return newConfigError("WithIPv6Aggregate takes a multiplier of at least 1, and %d would "+
			"leave the aggregate unable to admit even one source's allowance", c.aggregateMultiplier)
	}

	if c.aggregateBits < 1 || c.aggregateBits >= maxIPv6SourcePrefix {
		return newConfigError("WithIPv6Aggregate takes a prefix length in 1..%d, and %d would either "+
			"pool every IPv6 client into one bucket or name no wider group than an address",
			maxIPv6SourcePrefix-1, c.aggregateBits)
	}

	if c.aggregateBits >= c.ipv6Prefix {
		return newConfigError("WithIPv6Aggregate must be strictly wider than the source prefix "+
			"(WithIPv6SourcePrefix, %d): an aggregate of /%d would count exactly what the source key does",
			c.ipv6Prefix, c.aggregateBits)
	}

	return nil
}

// WithIPv6Aggregate sets the prefix and the allowance of the aggregate every
// source guard the chain builds also counts IPv6 clients by, so that a client
// rotating through the /64s of its own allocation cannot buy a fresh allowance
// with each one. Every source inside the /bits prefix shares one aggregate
// allowance of multiplier times the flow's own limit, over the flow's window:
// the aggregate counts a failure beside the source's own count, and an attempt
// is refused when either is over its limit.
//
// Default: a /56 at 4 times the flow's limit, over the flow's window, when the
// source prefix (WithIPv6SourcePrefix, default 64) is narrower than /56. The
// default is skipped when the source prefix is /56 or wider, since an aggregate
// no wider than the source would count what the source key already does. An
// explicit WithIPv6Aggregate is never skipped: it is checked instead.
//
// A /56 aggregate leaves a /48 holder 256 /56s, each with its own aggregate,
// and so still 256 times 4 times a flow's allowance; WithIPv6Aggregate(48, n)
// closes that, at the price of throttling every /56 inside the /48 together.
//
// When a flow was given a limiter of its own (WithAPIKeyLimiter and the like),
// "the flow's limit" and "the flow's window" are that limiter's, read through
// ratelimit.PolicyReporter, so the aggregate never tightens a limit the
// consumer chose. A limiter that does not implement it gets no default
// aggregate for that flow, and one warning when the chain is built; under an
// explicit WithIPv6Aggregate it is a configuration error naming the flow, since
// the chain cannot size the aggregate that was asked for. A limiter that
// reports a limit below 1 or a non-positive window is refused the same way,
// under the default or an explicit aggregate, before the factory is asked. So
// is a flow whose limit times the multiplier overflows an int; for the default
// aggregate that means an effectively unbounded consumer limiter, and the
// error points to WithoutIPv6Aggregate or an explicit WithIPv6Aggregate.
//
// Each guard's aggregate limiter is built from the chain's limiter factory
// (WithRateLimiterFactory) under the namespace "<flow>-ipv6-aggregate", for
// example "api-key-ipv6-aggregate", even when the flow was given a limiter of
// its own: the aggregate has no option of its own beyond this one. With the
// in-memory default factory the aggregate counts per replica, even when the
// flow's own limiter is a shared one; a consumer who wants a fleet-wide
// aggregate configures a shared factory with WithRateLimiterFactory.
//
// A prefix outside 1..127, a prefix not strictly narrower than the source
// prefix, a multiplier below 1, and combining it with WithoutIPv6Aggregate are
// refused when the chain is built, whatever order the options came in. IPv4
// clients, including IPv4-mapped IPv6 addresses, have no aggregate.
func WithIPv6Aggregate(bits, multiplier int) Option {
	return func(c *config) error {
		c.aggregateBits = bits
		c.aggregateMultiplier = multiplier
		c.aggregateExplicit = true

		return nil
	}
}

// WithoutIPv6Aggregate turns off the IPv6 aggregate every source guard the
// chain builds would otherwise also count clients by, so that each source is
// limited by its own allowance alone.
//
// Default: a /56 aggregate at 4 times the flow's limit, over the flow's window,
// built from the chain's limiter factory under "<flow>-ipv6-aggregate", and
// skipped when the source prefix (WithIPv6SourcePrefix) is /56 or wider. Turning
// it off gives up the cap on a client rotating through the /64s of its own
// allocation: a /48 holder gets 65536 sources, each with a flow's full
// allowance, and a /56 holder 256. Use it when a limit applied upstream already
// covers that, or when the chain's source prefix is wide enough on its own.
//
// Combining it with WithIPv6Aggregate is a configuration error, whatever order
// the two came in.
func WithoutIPv6Aggregate() Option {
	return func(c *config) error {
		c.aggregateOff = true

		return nil
	}
}

// WithRefusalLogInterval writes at most one record per refusal key per d.
//
// Default: one minute. An interval of zero or less disables sampling and writes
// every record, which is the documented way to ask for the full stream — it is
// accepted rather than refused, and it is a choice about volume, not a fault.
//
// It also sets the window of the throttled-source records written by the
// source guards the chain builds for EnableFormLogin and EnableBasicAuth,
// EnableAPIKey, EnableMagicLink and EnableOIDCLogin's handoff redemption, one
// per flow and canonical source. The account-recovery guards follow
// WithRecoveryLogInterval, and the passwordless begin guard the passkey
// manager's window (passkey.WithLogInterval), as those endpoints' own records
// do.
func WithRefusalLogInterval(d time.Duration) Option {
	return func(c *config) error {
		c.refusalInterval = d
		return nil
	}
}

// WithRefusalLogReporter reports the records sampling suppressed to fn.
//
// Default: a summary record at WARN naming the key and how many records it
// stood for. fn receives the key and the count, and runs on the goroutine whose
// refusal or flush triggered it, so it must be fast and must not panic.
//
// A nil reporter is refused: with no reporter at all the counts for a key that
// goes quiet are simply dropped, and the suppressed totals stop adding up.
// Omit the option to keep the default summary reporter.
//
// fn also receives the counts suppressed by every source guard the chain
// builds — the password-login guard of EnableFormLogin and EnableBasicAuth,
// and those of EnableAPIKey, EnableMagicLink, EnableOIDCLogin's handoff
// redemption, the passwordless begin under EnablePasskeys and both account
// recovery guards — so a throttled source is reported here like the chain's
// own refusals. Each guard keeps its own sampler and window; only where its
// held-back counts go is shared.
//
// The key takes one of two forms. The chain's own refusals use
// "<flow>|<reason>", for example "api-key|no-client-address". A guard's use
// "throttled:<flow>:<canonical source>" for a throttled source and
// "limiter:<flow>:" for a limiter that failed, the latter with an empty
// detail. A canonical IPv6 source contains colons itself, so a guard key splits
// safely only on its first two separators; everything after the second is the
// source.
func WithRefusalLogReporter(fn func(key string, suppressed int)) Option {
	return func(c *config) error {
		if fn == nil {
			return newConfigError(
				"WithRefusalLogReporter was given no reporter; omit it to keep the default " +
					"summary reporter")
		}

		c.refusalReporter = fn
		return nil
	}
}

// WithLockDisclosure answers a login for a locked account with the lock
// itself, instead of as a wrong password.
//
// Default: undisclosed. When the pre-authentication phase refuses with
// lockout.ErrAccountLocked, form login, Basic and account recovery's password
// proof first spend a decoy password verification, through the
// authenticator's authenticate.DecoyVerifier when it implements one, and then
// refuse with errors.Join(authenticate.ErrAuthenticationFailed, reason).
// StatusForError answers that 401, and Basic sets its WWW-Authenticate
// challenge, so neither the status, the headers nor the time taken tells a
// client that the account exists and is locked. The lock is not lost:
// errors.Is(err, lockout.ErrAccountLocked) still holds, and errors.As still
// reaches the *lockout.Error and its wait, so a consumer's own error
// handler can render a lock however it chooses — at which point the
// disclosure is the consumer's. Account recovery turns the joined refusal
// into its own recovery.ErrRefused, keeping it beneath, so a locked account's
// recovery reads as an unknown user's or a wrong code's, and is still
// identifiable as a lock.
//
// With this option the refusal is the policy's reason alone, which
// StatusForError answers 429 Too Many Requests, and no decoy runs. A 429 is not
// a 401, so a disclosed Basic lock carries no WWW-Authenticate header. The
// library writes no Retry-After; a consumer who wants one reads the wait from
// the *lockout.Error. A consumer who needs the 423 Locked status instead
// maps lockout.ErrAccountLocked to it in their own error handler
// (WithErrorHandler on net/http, or the framework's own error handling on gin
// and fiber).
//
// What it gives up: the response tells anyone who can guess a username
// whether that account exists and is locked, which the OWASP authentication
// guidance lists among the responses a login must not give.
//
// It governs only the response to a lock, at form login, Basic and account
// recovery's password proof, and nothing else. A lock refusal still counts
// against the source's password-login allowance either way.
func WithLockDisclosure() Option {
	return func(c *config) error {
		c.discloseLocks = true

		return nil
	}
}

// WithErrorHandler replaces what a refusal answers with on the net/http chain.
//
// Default: the status StatusForError gives and no body, so nothing the library
// knows reaches a client that the consumer did not choose to send. A handler
// set here receives the response writer, the request and the propagated error
// for every refusal, and the default response is not written: the consumer owns
// the whole answer, including its status.
//
// It is refused at construction when nil, because a chain with no way at all to
// answer a refusal would serve the refused request as though it had succeeded.
// Pass the same function to WithGuardErrorHandler so a chain refusal and a
// per-endpoint guard's refusal are rendered alike.
//
// It governs the net/http chain and nothing else, by design. A framework that
// already owns how a request is refused keeps that ownership: on gin the
// refusal goes to gin's error channel, so the consumer's own error middleware
// renders it, and on fiber it goes to fiber's error handler. Setting a handler
// here and mounting the chain on gin or fiber would leave the consumer with two
// places that answer a refusal and no way to tell which one did.
func WithErrorHandler(fn func(w http.ResponseWriter, r *http.Request, err error)) Option {
	return func(c *config) error {
		if fn == nil {
			return newConfigError("WithErrorHandler was given no handler, so a refusal " +
				"would be answered by nothing")
		}

		c.errorHandler = fn

		return nil
	}
}

// WithClock sets the time source the chain reads. Default: clock.System().
//
// These follow the chain's clock: the interceptors and the sampling of their
// logs; the MFA challenge managers and their default store; the MFA
// verification throttle; the source guards; the default limiter factory's
// limiters, including the IPv6 aggregate and enrolment limiters; and the
// recovery core, unless it is given its own recovery.WithClock.
//
// These keep their own clock: the session manager, the token issuer and
// verifier, a challenge store given with WithMFAChallengeStore, a factory given
// with WithRateLimiterFactory and the limiters a consumer gives, and the
// managers a consumer builds. Mismatched clocks are allowed and are not
// checked: a consumer who gives one of these a clock other than the chain's
// owns the difference.
//
// The option governs the chain as a whole, so it may be given with or without
// any interceptor and in any position among the options: it applies to every
// interceptor, whether it is enabled before or after it. A nil clock is a
// configuration error, never a fallback to the system clock.
func WithClock(c clock.Clock) Option {
	return func(cfg *config) error {
		if nilcheck.IsNil(c) {
			return newConfigError("WithClock was given no clock; omit the option to use the system clock")
		}

		cfg.clock = c

		return nil
	}
}

// checkAttemptViews refuses a chain whose password logins record failures
// into a store other than a view a registered policy requires.
//
// A lockout policy with a cap (lockout.WithCap) advances an identifier's
// consecutive count only when a failure is recorded through its own view,
// [github.com/kartaladev/scrty/policy/lockout.Policy.Attempts]. Form login or
// Basic handed the bare store would still lock by the window, but would never
// bring anyone closer to a hold: the configuration would read as a cap and
// enforce none. Nothing would show it, so it is refused here rather than
// documented, and there is no option to switch it off. A chain with no
// password login, or whose logins share the view, builds as before, and so
// does any store under a policy without a cap.
//
// A login records into one store, so when two registered policies require
// different views and a password login is enabled, construction fails naming
// both. Only policies registered in the engine before New runs are checked.
//
// Stores are compared as the password-change gate compares them (sameStore),
// so a view handed to both logins is one store.
func (c *config) checkAttemptViews() error {
	if c.engine == nil {
		return nil
	}

	required := c.engine.RequiredAttemptViews()
	if len(required) == 0 {
		return nil
	}

	logins := 0

	if err := eachInterceptor(c, func(*formLogin) error { logins++; return nil }); err != nil {
		return err
	}

	if err := eachInterceptor(c, func(*basicAuth) error { logins++; return nil }); err != nil {
		return err
	}

	// A login records into one store, so two policies that need different
	// views cannot both be satisfied. Without a password login nothing records.
	if logins > 0 {
		for _, r := range required[1:] {
			if !sameView(required[0].View, r.View) {
				return newConfigError("the %q and %q policies require different attempt views, "+
					"but a login records failures into only one store: register only one capped policy", required[0].Policy, r.Policy)
			}
		}
	}

	check := func(field string, attempts policy.AttemptStore) error {
		for _, r := range required {
			if !nilcheck.IsNil(attempts) && sameView(attempts, r.View) {
				continue
			}

			return newConfigError("%s records failures into a store other than the view the %q policy requires: "+
				"give it that policy's view (lockout.Policy.Attempts for an account-lockout policy)", field, r.Policy)
		}

		return nil
	}

	if err := eachInterceptor(c, func(l *formLogin) error {
		return check("FormLoginDeps.Attempts", l.attempts)
	}); err != nil {
		return err
	}

	return eachInterceptor(c, func(b *basicAuth) error {
		return check("BasicAuthDeps.Attempts", b.attempts)
	})
}

// sameView reports whether a and b are the same store, and false when either
// is nil.
func sameView(a, b policy.AttemptStore) bool {
	return !nilcheck.IsNil(a) && !nilcheck.IsNil(b) && sameStore(a, b)
}
