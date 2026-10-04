package httpsec

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

//go:generate mockgen -destination=mfamethodlookup_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/policy MFAMethodLookup

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

// defaultEnrolmentLifetime is how long a session marked for an enrolment
// challenge lives when nothing configured otherwise: long enough to scan a
// code and read an email, short enough that a first factor alone buys little.
const defaultEnrolmentLifetime = 15 * time.Minute

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
	sessions *session.Manager

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
// The first one wins and a nil one is ignored: a deployment has one session
// store, and the built-in whose dependency is missing is refused by its own
// check rather than by this one.
func (c *config) useSessions(m *session.Manager) {
	if c.sessions == nil && m != nil {
		c.sessions = m
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
// WithMagicLinkLimiter, WithHandoffLimiter, PasswordlessLimiter,
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
// passkey.Manager or the recovery.Codes; those take their own factory option.
//
// For the user-keyed second-factor flows, a shared limiter in
// ratelimit.UnavailableFallBackToLocal mode is the recommended choice: during
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
// policy.ErrAccountLocked, form login, Basic and account recovery's password
// proof first spend a decoy password verification, through the
// authenticator's authenticate.DecoyVerifier when it implements one, and then
// refuse with errors.Join(authenticate.ErrAuthenticationFailed, reason).
// StatusForError answers that 401, and Basic sets its WWW-Authenticate
// challenge, so neither the status, the headers nor the time taken tells a
// client that the account exists and is locked. The lock is not lost:
// errors.Is(err, policy.ErrAccountLocked) still holds, and errors.As still
// reaches the *policy.LockoutError and its wait, so a consumer's own error
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
// the *policy.LockoutError. A consumer who needs the 423 Locked status instead
// maps policy.ErrAccountLocked to it in their own error handler
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

// FormLoginDeps are the collaborators form login is wired to.
//
// Every one is required, and a missing or typed-nil field is refused when the
// chain is built. There is no useful default for any of them: scrty ships no
// user store to authenticate against, no durable session store, no signing key
// to issue a token with, and an attempt store of its own here would be one the
// lockout policy never reads, which is worse than none.
type FormLoginDeps struct {
	// Authenticator judges the submitted credentials. An authenticate.Manager
	// satisfies it, and so does a consumer's own provider.
	Authenticator authenticate.Authenticator

	// Sessions opens the session a successful login establishes.
	Sessions *session.Manager

	// Tokens issues the access token the response carries. The session
	// identifier is the token's jti, which is how a later bearer request finds
	// the session the token was issued for.
	Tokens token.Generator

	// Attempts is where a failed login is recorded and a successful one clears
	// what came before. Supply the same store the account-lockout policy reads
	// — a failure recorded in one store and counted in another locks nothing.
	Attempts policy.AttemptStore
}

// LoginOption configures form login. Each replaces one of the defaults named
// on EnableFormLogin.
type LoginOption func(*formLogin) error

// EnableFormLogin answers logins at the form login slot.
//
// Default: POST on DefaultLoginPath, reading DefaultLoginUsernameParam and
// DefaultLoginPasswordParam from the form and then, when the form yields
// neither and the request declares a JSON content type, from the JSON body;
// at most DefaultLoginBodyLimit bytes of it; answering a success with a JSON
// document carrying the access token, an empty refresh token and the session's
// idle expiry. Every one of those is replaced by the option that names it.
//
// Every other request passes through untouched, so enabling form login costs
// the rest of the application nothing.
//
// # Order of steps
//
// A login is answered in this order, and each step refuses before the next
// runs:
//
//  1. Read the username and password (see below).
//  2. Check the source against the password-login guard. A throttled source
//     is refused with ratelimit.ErrThrottled, and one with no attributable
//     client address as a failed authentication, before any policy or
//     password work. The guard is shared with EnableBasicAuth and counts
//     failures per source, 50 per 15 minutes by default (WithLoginLimiter).
//  3. Run the pre-authentication policy phase. A deny refuses with its
//     reason, except a locked account, which by default is refused as a
//     wrong password after a decoy password verification (WithLockDisclosure)
//     and counts against the source.
//  4. Authenticate. A failure is recorded against the account (the attempt
//     store) and against the source; a success clears the account's failures
//     and spends nothing of the source's allowance.
//  5. Run the post-authentication phase, open the session, and issue the
//     access token, refusing with a ChallengeError when a challenge is
//     raised.
//
// # What the binding reads, and what it does not
//
// The credential is bound from the parsed POST body and from nothing else. A
// credential in the URL query never authenticates, because a query string is
// already written into every access log, proxy log and browser history that saw
// the URL, and into the Referer the next page sends. Request.FormValue looks in
// the posted form first and falls back to the URL query, on every adapter, for
// the consumer interceptors that legitimately read a query parameter; only this
// binding narrows.
//
// Two narrowings follow from that, and both are deliberate:
//
//   - A body is read as a form only when it declares
//     "application/x-www-form-urlencoded". A login sent as
//     "multipart/form-data" is therefore refused with ErrCredentialsMissing
//     rather than parsed: a body is what the request says it is, and a login
//     endpoint that guessed would accept a shape nobody wired it for.
//   - A urlencoded body that does not parse yields no credential at all, rather
//     than the pairs that did parse before the error. Half a body is not a
//     credential the client sent.
func EnableFormLogin(d FormLoginDeps, opts ...LoginOption) Option {
	const option = "EnableFormLogin"

	return func(c *config) error {
		l := &formLogin{
			authn:         d.Authenticator,
			sessions:      d.Sessions,
			tokens:        d.Tokens,
			attempts:      d.Attempts,
			now:           time.Now,
			path:          DefaultLoginPath,
			usernameParam: DefaultLoginUsernameParam,
			passwordParam: DefaultLoginPasswordParam,
			bodyLimit:     DefaultLoginBodyLimit,
			respond:       writeLoginResult,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(l); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			if err := requireDep(option, "authenticator", d.Authenticator); err != nil {
				return err
			}
			if err := requireDep(option, "session manager", d.Sessions); err != nil {
				return err
			}
			if err := requireDep(option, "token generator", d.Tokens); err != nil {
				return err
			}

			return requireDep(option, "attempt store", d.Attempts)
		})

		c.useSessions(d.Sessions)
		c.wire(l.wire)
		c.register(l, OrderFormLogin)

		return nil
	}
}

// WithLoginRequestPath answers logins on path instead.
//
// Default: DefaultLoginPath. An empty path is refused: it would match nothing,
// so the endpoint the consumer asked for would silently not exist.
func WithLoginRequestPath(path string) LoginOption {
	return func(l *formLogin) error {
		if path == "" {
			return newConfigError("WithLoginRequestPath was given no path, so form login " +
				"would answer nothing")
		}

		l.path = path
		return nil
	}
}

// WithLoginParams reads the identifier and the password from these names.
//
// Default: DefaultLoginUsernameParam and DefaultLoginPasswordParam. They name
// both the form fields and the JSON members, so one call settles both shapes.
// An empty name, or two identical names, is refused: neither could read a
// credential the consumer meant to send.
func WithLoginParams(username, password string) LoginOption {
	return func(l *formLogin) error {
		switch {
		case username == "" || password == "":
			return newConfigError("WithLoginParams needs both field names, and was given "+
				"%q and %q", username, password)
		case username == password:
			return newConfigError("WithLoginParams was given %q for both fields, which cannot "+
				"carry an identifier and a password separately", username)
		}

		l.usernameParam = username
		l.passwordParam = password
		return nil
	}
}

// WithLoginBodyLimit reads at most n bytes of a login body.
//
// Default: DefaultLoginBodyLimit. The bound applies before anything is parsed,
// because the login endpoint is unauthenticated and an unbounded read there
// costs an attacker no credential at all. A limit of zero or less is refused:
// it would reject every login, including the correct ones.
func WithLoginBodyLimit(n int64) LoginOption {
	return func(l *formLogin) error {
		if n <= 0 {
			return newConfigError("WithLoginBodyLimit takes a positive bound, and %d would "+
				"refuse every login", n)
		}

		l.bodyLimit = n
		return nil
	}
}

// WithLoginResponder writes the success response through fn.
//
// Default: a JSON document carrying the access token, an empty refresh token
// field and the session's idle expiry. fn is called instead of the downstream
// handler, because a login is this library's own endpoint.
//
// A nil responder is refused: a login that succeeded and wrote nothing answers
// the caller with an empty 200, which reads as a success carrying no
// credential.
func WithLoginResponder(fn LoginResponder) LoginOption {
	return func(l *formLogin) error {
		if fn == nil {
			return newConfigError("WithLoginResponder was given no responder; omit it to keep " +
				"the default JSON response")
		}

		l.respond = fn
		return nil
	}
}

// WithLoginLimiter counts form login's failures against l, by source, instead
// of the password-login limiter form login shares with Basic.
//
// Default: one limiter shared by form login and Basic, built from the chain's
// factory (WithRateLimiterFactory, or the in-memory default) under the
// namespace "password-login", allowing 50 failures per source in 15 minutes.
// Sharing it means a source spraying passwords across both endpoints spends
// one allowance. With this option form login counts against l alone, under
// the same flow name, and Basic keeps the shared default unless it is given
// its own (WithBasicAuthLimiter). The limit and window are l's own.
//
// A nil limiter, or a typed nil, is refused: it would read as "no limit"
// while the consumer believed one was set.
func WithLoginLimiter(l ratelimit.Limiter) LoginOption {
	return func(f *formLogin) error {
		if err := requireDep("WithLoginLimiter", "limiter", l); err != nil {
			return err
		}

		f.limiter = l

		return nil
	}
}

// BasicAuthDeps are the collaborators Basic authentication is wired to.
//
// Both are required. There is no session manager and no token generator here:
// Basic authentication establishes neither, and a dependency it never uses
// would suggest otherwise.
type BasicAuthDeps struct {
	// Authenticator judges the decoded credentials.
	Authenticator authenticate.Authenticator

	// Attempts is where a refused credential is recorded. Supply the same
	// store the account-lockout policy reads, so a password guessed at over
	// Basic counts towards the same lockout as one guessed at over the login
	// form.
	Attempts policy.AttemptStore
}

// BasicAuthOption configures Basic authentication.
type BasicAuthOption func(*basicAuth) error

// EnableBasicAuth authenticates Basic credentials at the Basic slot.
//
// Default: the realm DefaultBasicAuthRealm, named in the WWW-Authenticate
// header a refusal carries. Requests whose Authorization header does not start
// with the exact prefix "Basic " pass through untouched.
//
// Basic authentication is stateless: it opens no session and issues no token,
// so a caller presents its credential on every request and has nothing to come
// back to. That is why a challenge raised here decides outright.
//
// A claimed header is answered in this order, and each step refuses before the
// next runs:
//
//  1. Decode the credential. A header that is not valid base64, or has no
//     colon, is refused as a failed authentication, and spends nothing.
//  2. Check the source against the password-login guard, shared with
//     EnableFormLogin: 50 failures per source in 15 minutes by default
//     (WithBasicAuthLimiter). A throttled or unattributable source is
//     refused before any policy or password work.
//  3. Run the pre-authentication policy phase. A deny refuses with its
//     reason, except a locked account, which by default is refused as a
//     wrong password after a decoy password verification (WithLockDisclosure)
//     and counts against the source.
//  4. Authenticate. A failure is recorded against the account and the source.
//  5. Run the stateless-authentication phase, and continue with the caller
//     published.
//
// Every refusal StatusForError answers 401 carries the WWW-Authenticate
// challenge for the realm, throttled, concealed-lock, pre-authentication and
// stateless-challenge refusals included, and no refusal answered otherwise
// does: a lock disclosed with WithLockDisclosure is a 429, and a deny answered
// 403 carries none.
func EnableBasicAuth(d BasicAuthDeps, opts ...BasicAuthOption) Option {
	const option = "EnableBasicAuth"

	return func(c *config) error {
		b := &basicAuth{
			authn:    d.Authenticator,
			attempts: d.Attempts,
			now:      time.Now,
			realm:    DefaultBasicAuthRealm,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(b); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			if err := requireDep(option, "authenticator", d.Authenticator); err != nil {
				return err
			}

			return requireDep(option, "attempt store", d.Attempts)
		})

		c.wire(b.wire)
		c.register(b, OrderBasicAuth)

		return nil
	}
}

// WithBasicAuthRealm names realm in the WWW-Authenticate header.
//
// Default: DefaultBasicAuthRealm. An empty realm is refused, and so is one
// carrying a quote, a backslash or a control character: the realm is written
// into a quoted header value, and a realm that could close that quote would let
// the configuration write header syntax of its own.
func WithBasicAuthRealm(realm string) BasicAuthOption {
	return func(b *basicAuth) error {
		if realm == "" {
			return newConfigError("WithBasicAuthRealm was given no realm; omit it to keep %q",
				DefaultBasicAuthRealm)
		}

		if i := strings.IndexFunc(realm, unquotableInRealm); i >= 0 {
			return newConfigError(
				"WithBasicAuthRealm was given a realm containing %q, which cannot be written "+
					"into a quoted header value", realm[i:i+1])
		}

		b.realm = realm
		return nil
	}
}

// WithBasicAuthLimiter counts Basic authentication's failures against l, by
// source, instead of the password-login limiter Basic shares with form login.
//
// Default: one limiter shared by Basic and form login, built from the chain's
// factory (WithRateLimiterFactory, or the in-memory default) under the
// namespace "password-login", allowing 50 failures per source in 15 minutes.
// Sharing it means a source spraying passwords across both endpoints spends
// one allowance. With this option Basic counts against l alone, under the same
// flow name, and form login keeps the shared default unless it is given its own
// (WithLoginLimiter). The limit and window are l's own.
//
// A nil limiter, or a typed nil, is refused: it would read as "no limit"
// while the consumer believed one was set.
func WithBasicAuthLimiter(l ratelimit.Limiter) BasicAuthOption {
	return func(b *basicAuth) error {
		if err := requireDep("WithBasicAuthLimiter", "limiter", l); err != nil {
			return err
		}

		b.limiter = l

		return nil
	}
}

// unquotableInRealm reports a rune that must not reach a quoted header value.
func unquotableInRealm(r rune) bool {
	return r == '"' || r == '\\' || r < ' ' || r == 0x7f
}

// BearerTokenDeps are the collaborators bearer authentication is wired to.
//
// All three are required. The session manager and the user loader are what make
// a bearer token a reference to live state rather than a self-contained grant:
// without them a revoked session and a revoked role would both be honoured for
// the rest of the token's life.
type BearerTokenDeps struct {
	// Verifier checks the presented token and reports its claims.
	Verifier token.Verifier

	// Sessions loads the session the token's jti names.
	Sessions *session.Manager

	// Users reloads the user the token's subject names, so the roles the
	// request is judged on are the ones the store holds now.
	Users identity.UserLoader
}

// BearerTokenOption configures bearer authentication.
type BearerTokenOption func(*bearerToken) error

// EnableBearerToken authenticates bearer tokens at the bearer slot.
//
// Default: the scheme DefaultBearerScheme, matched without regard to case, and
// a token presented with no scheme at all is ignored. Requests carrying another
// scheme, or no Authorization header, pass through untouched.
//
// A token that fails verification is recorded at debug with the verifier's own
// text, kept on purpose: it is the library's own protocol-failure text, not a
// dependency's, and names the check the token failed (expired, wrong
// signature, wrong audience), which an operator chasing a rejected client
// needs. Every other dependency failure — an unreadable session, a failed
// save while marking a challenge — is recorded by a fixed reason and the
// error's Go type, never its text, and a failed save is returned wrapped in
// fixed library text, its error still matching through errors.Is and
// errors.As. A consumer who wants a store's full error logs it inside their
// own implementation of BearerTokenDeps.
func EnableBearerToken(d BearerTokenDeps, opts ...BearerTokenOption) Option {
	const option = "EnableBearerToken"

	return func(c *config) error {
		b := &bearerToken{
			verifier: d.Verifier,
			sessions: d.Sessions,
			users:    d.Users,
			now:      time.Now,
			scheme:   DefaultBearerScheme,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(b); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			if err := requireDep(option, "token verifier", d.Verifier); err != nil {
				return err
			}
			if err := requireDep(option, "session manager", d.Sessions); err != nil {
				return err
			}

			return requireDep(option, "user loader", d.Users)
		})

		c.useSessions(d.Sessions)
		c.wire(b.wire)
		c.register(b, OrderBearerToken)

		return nil
	}
}

// WithBearerScheme presents tokens under scheme instead.
//
// Default: DefaultBearerScheme. The scheme is matched without regard to case
// either way. An empty scheme is refused: it would claim every Authorization
// header, including those of the schemes at neighbouring slots. Use
// WithBearerAllowEmptyScheme to accept a bare token as well.
func WithBearerScheme(scheme string) BearerTokenOption {
	return func(b *bearerToken) error {
		if strings.TrimSpace(scheme) == "" {
			return newConfigError("WithBearerScheme was given no scheme, which would claim " +
				"every Authorization header")
		}

		if strings.ContainsAny(scheme, " \t") {
			return newConfigError("WithBearerScheme was given %q, and a scheme is the one token "+
				"before the credential, so it can hold no space", scheme)
		}

		b.scheme = scheme
		return nil
	}
}

// WithBearerAllowEmptyScheme also accepts a token presented with no scheme.
//
// Default: off, so an Authorization header carrying a bare credential is left
// for whichever interceptor claims it. Turn it on for clients that send the
// token alone; it does not stop the configured scheme being accepted.
//
// The line it does not cross: a bare credential is indistinguishable from
// another scheme's opaque token, so a chain that enables this and another
// credential-bearing scheme hands both to whichever slot runs first. Enable it
// only where bearer tokens are the one thing that header carries.
func WithBearerAllowEmptyScheme() BearerTokenOption {
	return func(b *bearerToken) error {
		b.allowEmptyScheme = true
		return nil
	}
}

// MFAOption configures the second factor. Each replaces one of the defaults
// named on EnableMFA.
type MFAOption func(*mfaInterceptor) error

// EnableMFA verifies a second factor at the MFA slot, on any of methods, and
// holds every session that owes one.
//
// Each method is verified by POST at its own path: the verify prefix, "/" and
// the method's name, so TOTP is verified at "/mfa/verify/totp" by default. The
// method is read from that path and never from a header, the URL query or the
// body. A POST under the prefix naming no configured method — an empty, extra
// or trailing segment included — is refused with ErrUnknownMFAMethod (404).
// Before the body is read the endpoint also refuses a method on the session's
// first-factor channel with mfa.ErrSameChannel, and a method the user may not
// use with ErrMFAMethodNotUsable (403), deciding "usable" with
// policy.UsableMFAMethods; a failed enrolment lookup is a refusal behind
// fixed text, with the lookup's error reachable through errors.Is and
// errors.As but not repeated in the text. None of these is counted against the
// verification limiter.
//
// A method that is an mfa.ChallengeMethod also has a begin step: a POST to
// the begin prefix, "/" and its name ("/mfa/begin/<name>" by default) makes
// the same refusals, is refused while the user's verification is throttled,
// and then issues a pending challenge — a one-time token of the method's own
// purpose, for the session's user, bound to the session's handle — whose
// string the method's BeginChallenge builds its data around. The data is
// written by the begin responder. A begin path naming a method with no begin
// step is refused with ErrUnknownMFAMethod. At verification of such a method,
// the challenge its response presents is checked against the ones issued for
// that session and spent before the method verifies anything, whether the
// attempt then succeeds or not; an absent, unknown, expired, spent or
// other-session challenge is refused with mfa.ErrInvalidCode and counted.
//
// The policies that raise the challenge must be built from the same methods,
// through mfa.LookupsFor(methods...), so the endpoint never refuses a method a
// policy offered or accepts one it did not.
//
// Defaults: the verify prefix is DefaultMFAVerifyPrefix
// (WithMFAVerifyPrefix); failed verifications are counted per user reference,
// across every method, by a limiter of 5 failures per 15 minutes from the
// chain's rate-limiter factory under namespace "mfa-verify", or else in memory
// (WithMFAVerifyLimiter); and the records those refusals write are sampled
// over one minute (WithMFALogInterval). A consumer who wires nothing else gets
// all three. For challenge methods: the begin prefix is DefaultMFABeginPrefix
// (WithMFABeginPrefix), a pending challenge lives DefaultMFAChallengeTTL
// (WithMFAChallengeTTL) in an in-memory store serving one process
// (WithMFAChallengeStore), a user is issued at most DefaultMFAChallengeLimit
// (10) challenges per method within the store's one-hour issuance window
// (WithMFAChallengeLimit), and a begin answers with the method's data as a
// JSON body (WithMFABeginResponder). Begin also sweeps each method's expired
// challenges out of the store, at most once per issuance window per method in
// each process, under the begin request's own context; a sweep that fails is
// logged and retried by a later begin, and never refuses the begin. A store
// that cannot purge at all (onetime.ErrReapUnsupported) is not retried, since
// a retry would not change that: it is tried and logged once per issuance
// window. The verify and begin prefixes must not overlap.
//
// The method-listing endpoint, a GET a pending session sends to learn which
// methods its user can use, is off unless WithMFAMethodListing turns it on.
//
// Each method's response is read by the library, the way the method's
// mfa.ResponseFormat declares: one field of an
// "application/x-www-form-urlencoded" POST body (TOTP reads "code", up to
// 4 KiB), or a whole JSON body, bounded at the method's declared limit. A
// response in the URL query is never read, because a URL reaches access logs,
// proxy logs and the Referer header the next page sends. A body that carries
// no response, is not of the declared type or does not parse is refused with
// ErrCredentialsMissing (400), and one over the limit with ErrRequestTooLarge
// (413); neither is counted against the verification limiter, because no
// response was presented. The limiter is still consulted first, so a user it
// already refuses gets its refusal rather than 400. The two readers are a
// limit, not a default: a method never reads the request itself, and a
// consumer who must accept another encoding puts an interceptor of their own
// in front of the endpoint.
//
// The set is required and is checked by mfa.LookupsFor: an empty set, an
// absent method, a method reporting no channel, a name that is not one path
// segment, two methods sharing a name and a malformed response format are all
// refused here. An empty channel in particular equals the channel of an
// unrecorded first factor, so every session established without a recorded
// kind would be refused at verify as a same-channel attempt — a wiring mistake
// whose symptom appears far from its cause.
//
// The session manager is not a parameter: the handle is rotated in the one the
// chain already resolves sessions through, taken from the built-ins enabled
// alongside this one, exactly as the chain's own activity write-back takes it.
// A chain with no session manager at all is refused, because a second factor
// that could not rotate the handle would leave a pre-MFA handle live after the
// privilege change. A verify prefix that claims the chain's logout path is
// refused too, because a pending session could then not log out.
func EnableMFA(methods []mfa.Method, opts ...MFAOption) Option {
	const option = "EnableMFA"

	return func(c *config) error {
		// LookupsFor is the one place a wrongly declared method is caught, so
		// the rules and their messages are stated once for the policy lookups
		// and for this endpoint rather than drifting apart.
		lookups, err := mfa.LookupsFor(methods...)
		if err != nil {
			return newConfigError("%s was given an unusable method: %s", option, err)
		}

		byName := make(map[string]mfa.Method, len(methods))
		for _, m := range methods {
			byName[m.Name()] = m
		}

		i := &mfaInterceptor{
			methods:      slices.Clone(methods),
			byName:       byName,
			lookups:      lookups,
			now:          time.Now,
			verifyPrefix: DefaultMFAVerifyPrefix,
			respond:      writeMFAResult,
			beginPrefix:  DefaultMFABeginPrefix,
			beginRespond: writeMFABegin,
			challengeTTL: DefaultMFAChallengeTTL,
			challengeCap: DefaultMFAChallengeLimit,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(i); err != nil {
				return err
			}
		}

		// Every POST under either prefix is that endpoint's own, so two
		// prefixes that overlap would leave one endpoint answering the
		// other's requests.
		if underPrefix(i.beginPrefix, i.verifyPrefix) || underPrefix(i.verifyPrefix, i.beginPrefix) {
			return newConfigError("%s's verify prefix %q and begin prefix %q overlap, so one "+
				"endpoint would answer the other's requests", option, i.verifyPrefix, i.beginPrefix)
		}

		if err := i.checkListing(option); err != nil {
			return err
		}

		c.enable(option, func() error {
			if c.sessions == nil {
				return newConfigError("%s needs a session manager to rotate the handle with, "+
					"and none of the built-ins enabled on this chain was wired to one", option)
			}

			if i.tokens == nil {
				return newConfigError("%s needs a token generator: rotating the handle ends the "+
					"credential the caller arrived with, so the response has to hand back one "+
					"naming the rotated session (WithMFATokens)", option)
			}

			return nil
		})

		c.register(i, OrderMFAChallenge)
		c.enableGate(policy.ChallengeMFA)

		return nil
	}
}

// WithMFAVerifyPrefix verifies each method under prefix instead: a method is
// verified at prefix, "/" and its name.
//
// Default: DefaultMFAVerifyPrefix. Only POST under the prefix is a
// verification; every other request to it is judged like any other, which for
// a session that owes a second factor means the gate holds it. A trailing
// slash is dropped, so "/auth/2fa" and "/auth/2fa/" are the same prefix.
//
// An empty prefix is refused, because the endpoint the consumer asked for
// would silently not exist and the challenge could never be resolved; so is a
// prefix that does not start with "/", which matches no request path, and the
// root "/", which would claim every one-segment path of the application.
func WithMFAVerifyPrefix(prefix string) MFAOption {
	return func(i *mfaInterceptor) error {
		p, err := mfaPrefix("WithMFAVerifyPrefix", prefix)
		if err != nil {
			return err
		}

		i.verifyPrefix = p

		return nil
	}
}

// WithMFAVerifyLimiter counts failed code verifications through l.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under
// namespace "mfa-verify", or else an in-memory limiter of 5 failures per 15
// minutes; either way keyed by the user reference rather than by the request's
// source — by the time a second factor is being checked the attacker already
// holds the first and can present codes from as many addresses as they like. A
// deployment running more than one replica supplies a factory or a limiter its
// replicas share, or the limit is per process and the guesses are simply
// spread.
//
// It governs failed code verifications alone. The key is composed by mfa, and
// mfa.VerifyThrottleKey reports it, so a consumer sharing one limiter across
// flows can read or clear that bucket.
//
// For this second-factor flow, a shared limiter in ratelimit.UnavailableFallBackToLocal
// mode is the recommended choice: during an outage of the shared store each
// replica still bounds guessing on its own, and users are not locked out.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it
// would read as "no limit" while the consumer believed they had replaced one.
func WithMFAVerifyLimiter(l ratelimit.Limiter) MFAOption {
	return func(i *mfaInterceptor) error {
		if err := requireDep("WithMFAVerifyLimiter", "limiter", l); err != nil {
			return err
		}

		i.throttleOpts = append(i.throttleOpts, mfa.WithVerifyLimiter(l))

		return nil
	}
}

// WithMFATokens issues the rotated session's access token through g.
//
// There is no default, and it is required: rotation deletes the handle the
// caller arrived with, and the session identifier is the token's jti, so
// without a generator a caller who passed their second factor would hold a
// credential naming a session that no longer exists. It is the same generator
// the first factors issue through, so a token from a login and one from a
// second factor are indistinguishable to whatever verifies them.
func WithMFATokens(g token.Generator) MFAOption {
	return func(i *mfaInterceptor) error {
		if err := requireDep("WithMFATokens", "token generator", g); err != nil {
			return err
		}

		i.tokens = g

		return nil
	}
}

// WithMFAResponder replaces the response written when a second factor
// succeeds.
//
// With none supplied, the library writes a JSON document carrying an access
// token for the rotated session and that session's validity, the same shape a
// successful login answers with, so a client handles both alike.
//
// It is called instead of the downstream handler, because the verify endpoint
// is the library's own and the application has no route behind it. The session
// it receives carries the handle rotation produced, which is the only place
// that handle is available: an error it returns leaves the chain as the
// request's refusal, and nothing else will hand the caller a usable
// credential.
func WithMFAResponder(fn MFAResponder) MFAOption {
	return func(i *mfaInterceptor) error {
		if fn == nil {
			return newConfigError("WithMFAResponder was given no function; omit the option to " +
				"keep the default document")
		}

		i.respond = fn

		return nil
	}
}

// WithMFALogInterval writes at most one second-factor throttle record per
// reason per d.
//
// Default: one minute. It governs the records MFA verification refusals write
// and nothing else, so a user being guessed at cannot drown out or silence any
// other part of the chain — the chain's own refusal records keep their own
// window, set by WithRefusalLogInterval.
//
// An interval of zero or less writes every record, which is the documented way
// to ask for the full stream: it is a choice about volume, not a fault.
func WithMFALogInterval(d time.Duration) MFAOption {
	return func(i *mfaInterceptor) error {
		i.throttleOpts = append(i.throttleOpts, mfa.WithVerifyLogInterval(d))

		return nil
	}
}

// APIKeyOption configures API key authentication. Each replaces one of the
// defaults named on EnableAPIKey.
type APIKeyOption func(*apiKeyInterceptor) error

// EnableAPIKey authenticates machine callers by key at the API key slot.
//
// Defaults: a key is read from the Authorization header after the literal
// DefaultAPIKeyScheme prefix (WithAPIKeyScheme), and a source that presents
// wrong keys is cut off after 20 failures a minute by a limiter this flow alone
// uses (WithAPIKeyLimiter).
//
// A request that does not carry the scheme passes through untouched and
// consults nothing: ordinary unauthenticated traffic is not a failed attempt,
// and counting it would fill the buckets that exist to catch guessing.
//
// The caller a key resolves is published with no session. A machine has nobody
// to prompt and nothing to keep between requests, so a policy that challenges
// in the stateless phase refuses outright rather than raising a prompt nothing
// can answer.
func EnableAPIKey(m *apikey.Manager, opts ...APIKeyOption) Option {
	const option = "EnableAPIKey"

	return func(c *config) error {
		if m == nil {
			return newConfigError("%s needs an API key manager", option)
		}

		i := &apiKeyInterceptor{keys: m, now: time.Now, scheme: DefaultAPIKeyScheme}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(i); err != nil {
				return err
			}
		}

		c.register(i, OrderAPIKey)
		c.wire(i.wire)

		return nil
	}
}

// WithAPIKeyScheme matches presented keys under scheme instead.
//
// Default: DefaultAPIKeyScheme. The scheme is matched exactly, case and
// trailing space included, so include the separating space: "Service " matches
// "Service sk_...", while "Service" would also claim "Servicex".
//
// An empty scheme is refused: it would claim every Authorization header on the
// chain, including the ones another interceptor answers.
func WithAPIKeyScheme(scheme string) APIKeyOption {
	return func(i *apiKeyInterceptor) error {
		if scheme == "" {
			return newConfigError("WithAPIKeyScheme was given no scheme, which would claim " +
				"every Authorization header, including another interceptor's")
		}

		i.scheme = scheme

		return nil
	}
}

// WithAPIKeyLimiter counts failed key verifications through l.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under
// namespace "api-key", or else an in-memory limiter of 20 failures per source
// per minute, used by this flow alone. A deployment running more than one
// replica supplies a factory or a limiter its replicas share, or the limit is
// per process and a scanner simply spreads its guesses.
//
// One limiter may be handed to several flows. That shares the store and the
// limit it was built with, not the allowance: every key carries the flow it
// belongs to, so a source that exhausts its key guesses still has its whole
// allowance at every other endpoint.
// A limiter handed to several flows shares its key cap among them, so a flood
// on one refuses new sources on all.
//
// The flow's IPv6 aggregate (WithIPv6Aggregate) is sized from l: the
// aggregate's multiplier, 4 by default, times the limit l reports, over the
// window l reports, read through ratelimit.PolicyReporter, which the in-memory
// limiter and the shared limiters scrty ships implement. A limiter that does
// not implement it gets no default aggregate for this flow, and one warning
// when the chain is built; under an explicit WithIPv6Aggregate it is a
// configuration error.
//
// It counts wrong keys and nothing else: a policy refusal of a valid key is not
// a failed guess, and a request carrying no key at all never reaches it.
//
// A nil limiter, including an interface holding a nil pointer, is refused.
func WithAPIKeyLimiter(l ratelimit.Limiter) APIKeyOption {
	return func(i *apiKeyInterceptor) error {
		if err := requireDep("WithAPIKeyLimiter", "limiter", l); err != nil {
			return err
		}

		i.limiter = l

		return nil
	}
}

// MagicLinkOption configures the magic-link endpoints. Each replaces one of
// the defaults named on EnableMagicLink.
type MagicLinkOption func(*magicLinkInterceptor) error

// EnableMagicLink answers the two magic-link endpoints at the magic-link slot.
//
// Defaults: a link is asked for by POST on DefaultMagicLinkRequestPath, which
// reads "email" and "next" from a form body or a JSON one and always answers
// 202 with an empty body (WithMagicLinkRequestPath); a link is redeemed by
// POST on DefaultMagicLinkConsumePath, which reads "token" from the form and
// the binding from DefaultBindingCookieName (WithMagicLinkConsumePath,
// WithBindingCookieName); no redirect target is allowed, so every submitted
// "next" becomes "/" (WithAllowedRedirects, WithAllowedOrigins); every failed
// redemption counts against the source (WithMagicLinkCountRefusals), at 10 per
// 15 minutes through a limiter this flow alone uses (WithMagicLinkLimiter);
// the built-in redeemer is the manager's own (WithMagicLinkRedeemer) and no
// consumer refusal checks run (WithMagicLinkChecks).
//
// Whether links are bound to the requesting device is read from the manager,
// never configured here: an interceptor that could be told one thing while the
// manager was told another would emit cookies for links that carry no binding,
// or issue bound links nothing ever answers.
//
// The token generator is required, because a redeemed link establishes a
// session the caller then has to be able to present. The session manager is
// taken from the chain when WithMagicLinkSessions is not given, and a chain
// with neither is refused.
func EnableMagicLink(m *magiclink.Manager, opts ...MagicLinkOption) Option {
	const option = "EnableMagicLink"

	return func(c *config) error {
		if m == nil {
			return newConfigError("%s needs a magic-link manager", option)
		}

		i := &magicLinkInterceptor{
			manager:       m,
			respond:       writeMagicLinkResult,
			now:           time.Now,
			requestPath:   DefaultMagicLinkRequestPath,
			consumePath:   DefaultMagicLinkConsumePath,
			cookieName:    DefaultBindingCookieName,
			bodyLimit:     DefaultLoginBodyLimit,
			countRefusals: true,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(i); err != nil {
				return err
			}
		}

		c.enable(option, func() error { return i.check(c, option) })

		c.useSessions(i.sessions)
		c.register(i, OrderMagicLink)
		c.wire(i.wire)

		return nil
	}
}

// WithMagicLinkRequestPath answers link requests on path instead.
//
// Default: DefaultMagicLinkRequestPath. An empty path is refused, and so is
// one equal to the consume path: one path cannot both ask for a link and
// redeem one, and whichever branch matched first would silently swallow the
// other endpoint.
func WithMagicLinkRequestPath(path string) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if path == "" {
			return newConfigError("WithMagicLinkRequestPath was given no path, so no link " +
				"could be asked for")
		}

		i.requestPath = path

		return nil
	}
}

// WithMagicLinkConsumePath redeems links on path instead.
//
// Default: DefaultMagicLinkConsumePath. It is also what the binding cookie is
// scoped to, so moving the endpoint moves the cookie's scope with it. An empty
// path, or one equal to the request path, is refused.
func WithMagicLinkConsumePath(path string) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if path == "" {
			return newConfigError("WithMagicLinkConsumePath was given no path, so no link " +
				"could be redeemed")
		}

		i.consumePath = path

		return nil
	}
}

// WithBindingCookieName carries the same-device binding in a cookie called
// name.
//
// Default: DefaultBindingCookieName. An empty name is refused: a cookie
// without one is not set at all, and every bound link would then be
// unredeemable.
func WithBindingCookieName(name string) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if name == "" {
			return newConfigError("WithBindingCookieName was given no name, so the binding " +
				"cookie would never be set and no bound link could be redeemed")
		}

		i.cookieName = name

		return nil
	}
}

// WithAllowedRedirects allows targets as redirect destinations after a link is
// redeemed.
//
// Default: none, so every submitted target becomes "/". A target is used only
// when it exactly equals one of these entries — no prefix matching, no case
// folding, no normalisation — because every way of making two targets equal is
// a way of reaching an entry that was never configured.
//
// An entry is either a host-relative path, or an absolute http or https URL
// without userinfo whose origin was declared with WithAllowedOrigins. Anything
// else fails construction, naming the entry and this option.
//
// Calls accumulate, so a consumer whose configuration is split across several
// places builds one list from all of them.
func WithAllowedRedirects(targets ...string) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		i.allowedRedirects = append(i.allowedRedirects, targets...)

		return nil
	}
}

// WithAllowedOrigins declares the origins an absolute redirect entry may sit
// on.
//
// Default: none, under which only host-relative targets can ever be accepted,
// so nothing the consumer configures can send a browser to another site.
// Declaring an origin is deliberately a separate act from listing the entry:
// widening the set of reachable sites is not something a redirect entry should
// be able to do on its own.
//
// An origin is a scheme, a host and an optional port, and must be https except
// on a loopback host, where http is accepted so a consumer can develop against
// one. Anything else fails construction, naming the origin and this option.
func WithAllowedOrigins(origins ...string) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		i.allowedOrigins = append(i.allowedOrigins, origins...)

		return nil
	}
}

// WithMagicLinkCountRefusals decides whether a policy denial or a consumer
// check refusal of a valid link counts against the source's allowance.
//
// Default: true. An attacker holding one link the policy refuses could
// otherwise replay it without limit for as long as it lives, and each attempt
// would cost a store read and a policy evaluation.
//
// Passing false exempts exactly those two refusals. Every other redemption
// failure is still recorded, including one from a redeemer that discarded the
// denial and then failed for a reason of its own, and an enrolment-store
// outage while the check before the spend looks up the methods a raised
// second-factor challenge offers: that is a failure, not a refusal. A policy
// that reads the outage as a reason to deny is a denial like any other, and
// is exempted.
func WithMagicLinkCountRefusals(count bool) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		i.countRefusals = count

		return nil
	}
}

// WithMagicLinkLimiter counts failed redemptions through l.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under
// namespace "magic-link-redeem", or else an in-memory limiter of 10 failures
// per source per 15 minutes, used by this flow alone. A deployment running more
// than one replica supplies a factory or a limiter its replicas share, or the
// limit is per process and an attacker simply spreads their attempts.
//
// One limiter may be handed to several flows. That shares the store and the
// limit it was built with, not the allowance: every key carries the flow it
// belongs to, so a source that exhausts its redemptions still has its whole
// allowance at every other endpoint.
// A limiter handed to several flows shares its key cap among them, so a flood
// on one refuses new sources on all.
//
// The flow's IPv6 aggregate (WithIPv6Aggregate) is sized from l: the
// aggregate's multiplier, 4 by default, times the limit l reports, over the
// window l reports, read through ratelimit.PolicyReporter, which the in-memory
// limiter and the shared limiters scrty ships implement. A limiter that does
// not implement it gets no default aggregate for this flow, and one warning
// when the chain is built; under an explicit WithIPv6Aggregate it is a
// configuration error.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it
// would read as "no limit" while the consumer believed they had replaced one.
func WithMagicLinkLimiter(l ratelimit.Limiter) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if err := requireDep("WithMagicLinkLimiter", "limiter", l); err != nil {
			return err
		}

		i.limiter = l

		return nil
	}
}

// WithMagicLinkSessions opens the redeemed link's session in m.
//
// Default: the session manager the chain's other built-ins were wired to, so a
// deployment with one session store declares it once. A chain that has none at
// all is refused: a redemption that could not open a session would spend the
// link and authenticate nobody.
func WithMagicLinkSessions(m *session.Manager) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if err := requireDep("WithMagicLinkSessions", "session manager", m); err != nil {
			return err
		}

		i.sessions = m

		return nil
	}
}

// WithMagicLinkTokens issues the redeemed link's access token through g.
//
// There is no default, and it is required: the library ships no signing key, and
// a session a caller has no credential for is one they cannot use. The
// generator is the same one the other first factors issue through, so a token
// from a link and a token from a password are indistinguishable to whatever
// verifies them.
func WithMagicLinkTokens(g token.Generator) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if err := requireDep("WithMagicLinkTokens", "token generator", g); err != nil {
			return err
		}

		i.tokens = g

		return nil
	}
}

// WithMagicLinkRedeemer redeems links through r instead of the manager.
//
// Default: the magic-link manager's own Redeem, which checks everything before
// it consumes anything. A consumer who replaces it takes on that ordering
// contract — see Redeemer, which also says what the endpoint still enforces
// itself and what it cannot. In short: the login completion reuses the
// decision the endpoint's check made before the link was spent, with no second
// evaluation after it, and a success whose check never ran, or that returns a
// user with a different reference or password-change instant than the check
// was handed, is refused with policy.ErrPolicyDenied.
//
// A nil redeemer is refused: there would be nothing to redeem with.
func WithMagicLinkRedeemer(r Redeemer) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if err := requireDep("WithMagicLinkRedeemer", "redeemer", r); err != nil {
			return err
		}

		i.redeemer = r

		return nil
	}
}

// WithMagicLinkResponder replaces the response written when a link is
// successfully redeemed.
//
// With none supplied, the library writes a JSON document carrying the access
// token, an empty refresh token field, the session's validity and the resolved
// redirect target — the same document a successful login answers with, plus
// that target.
//
// It is called instead of the downstream handler, because the consume endpoint
// is the library's own and the application has no route behind it. An error it
// returns leaves the chain as the request's refusal.
//
// The result's Next is the target the allowlist resolved, never the one the
// caller submitted: a responder that redirects to it cannot send a caller
// somewhere the allowlist refused. Referrer-Policy is already set when the
// responder runs, so a response that forgets it still cannot leak the token
// through a referrer.
func WithMagicLinkResponder(fn MagicLinkResponder) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if fn == nil {
			return newConfigError("WithMagicLinkResponder was given no function; omit the " +
				"option to keep the default document")
		}

		i.respond = fn

		return nil
	}
}

// WithMagicLinkChecks runs the consumer's own refusal checks at redemption.
//
// Default: none. Each check receives the resolved principal and the user's
// password-change time, and the first that returns an error stops the
// redemption, leaving the link redeemable and returning that error unchanged.
//
// A check must have no side effects: several racing redemptions of one link may
// each run it, and only one of them will go on to spend the link.
//
// Calls accumulate, and the checks run in the order they were given, after the
// library's own policy check.
func WithMagicLinkChecks(checks ...magiclink.Check) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		for _, check := range checks {
			if check == nil {
				return newConfigError("WithMagicLinkChecks was given a nil check, which would " +
					"panic at the first redemption")
			}
		}

		i.checks = append(i.checks, checks...)

		return nil
	}
}

// PasswordChangeOption configures the password-change gate. Each replaces one
// of the defaults named on EnablePasswordChangeGate.
type PasswordChangeOption func(*passwordChangeGate) error

// EnablePasswordChangeGate holds every session that owes a password change at
// the password-change slot.
//
// Default: no resolve endpoint, under which a session that owes a change is
// refused until a new login clears it. Register one with
// WithChangePasswordEndpoint to let a caller pay the debt without logging in
// again. A request carrying no session passes the gate untouched.
//
// A POST to the chain's logout path always passes, so a caller owing a change
// can end the session; the path is the one EnableLogout configured, read when
// the chain is built, and nothing extra passes on a chain without logout.
// There is no option to refuse it: refusing logout protects nothing.
//
// The session manager is required and is the one the marker is cleared in: a
// gate that could not record the change would refuse the next request just the
// same, and the caller would have changed their password for nothing.
func EnablePasswordChangeGate(sessions *session.Manager, opts ...PasswordChangeOption) Option {
	const option = "EnablePasswordChangeGate"

	return func(c *config) error {
		g := &passwordChangeGate{sessions: sessions}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(g); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			return requireDep(option, "session manager", sessions)
		})

		c.useSessions(sessions)
		c.register(g, OrderPasswordChange)
		c.enableGate(policy.ChallengePasswordChange)

		return nil
	}
}

// WithChangePasswordEndpoint answers POST requests on path with fn.
//
// Default: no endpoint at all, under which only a new login clears the
// challenge. Requests to path pass the gate, so the one endpoint a caller who
// owes a password change can reach is the one that resolves it; every other
// method on that path is gated like anything else.
//
// An empty path, or no function, is refused: either would be an endpoint that
// cannot answer, while the consumer believed their callers had a way out of
// the gate.
func WithChangePasswordEndpoint(path string, fn ChangePasswordFunc) PasswordChangeOption {
	return func(g *passwordChangeGate) error {
		switch {
		case path == "":
			return newConfigError("WithChangePasswordEndpoint was given no path, so a caller " +
				"owing a password change would have no way to resolve it")
		case fn == nil:
			return newConfigError("WithChangePasswordEndpoint was given no function to change "+
				"the password with for %q", path)
		}

		g.path = path
		g.change = fn

		return nil
	}
}

// LogoutDeps are the collaborators logout is wired to.
//
// The session manager is required. Logout exists to end a session, and one
// wired without a store to end it in would answer every caller 200 while
// leaving every session live — a logout that reports success and does nothing
// is worse than no logout at all.
type LogoutDeps struct {
	// Sessions is where the caller's session is deleted. Supply the same
	// manager the authentication interceptors load sessions from, or a logout
	// deletes from a store nothing reads.
	Sessions *session.Manager

	// EndSession builds the identity provider's end-session URL for a session
	// a federated login created. It is optional: nil means no end-session
	// step, and logout answers every caller as it answers a password session,
	// unless EnableOIDCLogin on the same chain supplies its manager's step
	// (see WithOIDCRPInitiatedLogout). A step set here always takes precedence.
	EndSession EndSessionBuilder
}

// LogoutOption configures logout. Each replaces one of the defaults named on
// EnableLogout.
type LogoutOption func(*logout) error

// EnableLogout ends the caller's session at the logout slot.
//
// Default: POST on DefaultLogoutPath, answered 200 with an empty body. The
// downstream handler is never called, because logout is this library's own
// endpoint. A request with no authentication result is refused with
// ErrAuthenticationRequired, and a session that is already gone is a success:
// two clients ending one session is ordinary.
//
// Every other request, including a GET on that path, passes through untouched.
//
// With LogoutDeps.EndSession set, a session that records an identity provider
// is deleted first, then the builder is asked for the provider's end-session
// URL, handed the deleted session and the request's "state" form value. A URL
// is answered 200 with {"end_session_url": ...} and Cache-Control: no-store;
// an empty URL, or a builder error, which is logged, keeps the empty 200. The
// default is nil: no end-session step, and every logout answers as above,
// unless EnableOIDCLogin is on the chain, which supplies its manager's step
// when this one is nil (WithOIDCRPInitiatedLogout turns that off).
func EnableLogout(d LogoutDeps, opts ...LogoutOption) Option {
	const option = "EnableLogout"

	return func(c *config) error {
		l := &logout{sessions: d.Sessions, endSession: d.EndSession, path: DefaultLogoutPath}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(l); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			return requireDep(option, "session manager", d.Sessions)
		})

		// Recorded for the gates, which exempt this path so a session stranded
		// mid-challenge can still be ended. See wireMFA and wirePasswordChange.
		c.logoutPath = l.path
		c.logout = l

		c.useSessions(d.Sessions)
		c.wire(l.wire)
		c.register(l, OrderLogout)

		return nil
	}
}

// WithLogoutRequestPath answers logouts on path instead.
//
// Default: DefaultLogoutPath, which keeps passing through once the consumer
// moves the endpoint. An empty path is refused: it would match nothing, so the
// endpoint the consumer asked for would silently not exist.
func WithLogoutRequestPath(path string) LogoutOption {
	return func(l *logout) error {
		if path == "" {
			return newConfigError("WithLogoutRequestPath was given no path, so logout would " +
				"answer nothing")
		}

		l.path = path

		return nil
	}
}

// JWKSOption configures the key set endpoint. Each replaces one of the
// defaults named on EnableJWKSEndpoint.
type JWKSOption func(*jwksEndpoint) error

// EnableJWKSEndpoint serves the public key set at the key set slot.
//
// Default: GET on DefaultJWKSPath, answered 200 with a JSON content type and
// whatever the provider returned, unchanged. The downstream handler is never
// called, and every other request — including a POST on that path — passes
// through untouched.
//
// The slot is the outermost of the built-ins, because a client fetching the
// keys to verify a token with has no token to be authenticated by.
func EnableJWKSEndpoint(keys KeySetProvider, opts ...JWKSOption) Option {
	const option = "EnableJWKSEndpoint"

	return func(c *config) error {
		j := &jwksEndpoint{keys: keys, path: DefaultJWKSPath}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(j); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			return requireDep(option, "key set provider", keys)
		})

		c.register(j, OrderJWKS)

		return nil
	}
}

// WithJWKSEndpointPath serves the key set on path instead.
//
// Default: DefaultJWKSPath, which keeps passing through once the consumer
// moves the endpoint — a deployment that serves the conventional location
// through its own route is free to. An empty path is refused: it would match
// nothing, so the endpoint the consumer asked for would silently not exist.
func WithJWKSEndpointPath(path string) JWKSOption {
	return func(j *jwksEndpoint) error {
		if path == "" {
			return newConfigError("WithJWKSEndpointPath was given no path, so the key set " +
				"would be served nowhere")
		}

		j.path = path

		return nil
	}
}

// EnableAuthorization judges requests through az, applying rules centrally.
//
// Default: without this option the chain still runs its authorization stage,
// but publishes no authorizer and enforces nothing, so every per-endpoint
// guard behind it fails closed. With it and no rules, the authorizer reaches
// the route and the guards there decide alone.
//
// The rules are an ordered set: the first whose matcher accepts the request
// decides, and a request no rule matches is denied, so an endpoint added
// without a rule is closed rather than open. A consumer opts out of that
// default with a trailing rule that matches everything and requires
// authorize.PermitAll — one line, visible where the rules are read.
//
// Calling it more than once appends: the rules of every call form one set in
// the order the calls were made, so wiring split across modules still reads top
// to bottom. The authorizer of the last call is the one the chain judges by,
// because a chain has one authorizer and a second call is the consumer
// replacing their first choice rather than adding a second judge.
//
// A matcher sees the whole Request — path, method, headers — through the same
// abstraction every interceptor reads, so one rule set is written once and
// applies behind whichever framework the chain is mounted on.
func EnableAuthorization(az authorize.Authorizer, rules ...authorize.Rule[Request]) Option {
	const option = "EnableAuthorization"

	return func(c *config) error {
		c.authorizer = az
		c.authzRules = append(c.authzRules, rules...)

		c.enable(option, func() error {
			return requireDep(option, "authorizer", c.authorizer)
		})

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
