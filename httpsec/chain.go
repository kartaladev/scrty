package httpsec

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/token/onetime"
)

// registration is one interceptor and the slot it was registered at, with the
// sequence it arrived in so a stable sort keeps two interceptors at one slot in
// the order the consumer registered them.
type registration struct {
	interceptor Interceptor
	order       Order
	seq         int
}

// Chain is the assembled security chain.
//
// It is built once by New and is then safe for concurrent use: assembling and
// running a request read the registrations and never write them, so one chain
// serves every request of a server rather than being rebuilt per request.
type Chain struct {
	// registrations is already sorted into the order the interceptors run in,
	// because the order is a property of the chain rather than of one request
	// and sorting it per request would repeat the same work on every one.
	registrations []registration

	// The settings the options resolved, frozen at construction. They are read
	// while serving and never written, which is what makes one chain safe to
	// share across every request.
	engine *policy.Engine
	logger *slog.Logger

	// enrolmentLifetime is how long a session marked for an enrolment
	// challenge may live, handed to every built-in that marks one.
	enrolmentLifetime time.Duration

	// enforced holds the challenge kinds something on this chain enforces,
	// handed to every built-in that marks a raised challenge, so a kind raised
	// at runtime that nothing enforces is refused rather than marked and served.
	enforced map[policy.ChallengeKind]bool

	// perRequest is the per-request phase every exchange run through this
	// chain carries, so EvaluatePerRequest reaches the chain's engine,
	// enforcer set, enrolment lifetime, session manager and clock. It is built
	// once, at construction.
	perRequest *perRequestPhase

	// mfa is the MFA interceptor EnableMFA registered, and nil without one.
	// Every second-factor challenge the chain returns carries the methods it
	// looks up (challengeMethods).
	mfa *mfaInterceptor

	// errorHandler is what a refusal is answered with, and nil means the
	// library's own default: the mapped status and no body.
	errorHandler func(w http.ResponseWriter, r *http.Request, err error)

	refusalInterval time.Duration
	refusalReporter func(key string, suppressed int)

	// reportRefusals is the reporter every sampler of the chain reports to:
	// refusalReporter, or else the default summary record. It is never nil.
	reportRefusals func(key string, suppressed int)

	// sampler bounds the chain's own refusal records. It is built once, at
	// construction, so every request of every flow shares one set of windows.
	sampler *logsample.Sampler
}

// refusalLogFlusher is implemented by an interceptor that holds a component
// keeping a refusal-log sampler of its own, so FlushRefusalLogs can reach it
// without knowing which built-in it is. It flushes everything it holds even
// when one flush fails, and returns the failures joined, or nil.
type refusalLogFlusher interface{ flushRefusalLogs() error }

// FlushRefusalLogs reports every suppressed refusal count the chain can reach,
// for example from a shutdown hook, so counts held for a window that will never
// close are not lost. Each component reports through its own reporter or
// logger, exactly as its own flush does.
//
// It reaches:
//
//  1. The chain's own sampler (WithRefusalLogInterval, WithRefusalLogReporter).
//  2. The enrolment path of EnableMFAEnrolment.
//  3. The verification throttle EnableMFA builds.
//  4. The per-source guards of EnableFormLogin and EnableBasicAuth (the
//     password-login guard they share), EnableAPIKey, EnableMagicLink, handoff
//     redemption under EnableOIDCLogin, the passwordless begin under
//     EnablePasskeys and EnableAccountRecovery, whether built over the default
//     limiter or over one the consumer supplied. Each keeps its own sampler,
//     but reports to the chain's reporter, as item 1 does.
//  5. The authenticator given to EnableFormLogin or EnableBasicAuth, when it
//     implements logsample.Flusher.
//  6. The oidc.RelyingParty given to EnableOIDCLogin, which in turn flushes its
//     identity broker when that can flush, and the oidc.Handoff given
//     beside it, when there is one.
//  7. The passkey.Passkeys given to EnablePasskeys.
//  8. The policy engine given to WithPolicyEngine, which flushes every
//     registered policy implementing logsample.Flusher, including one
//     registered after the chain was built.
//
// The chain's own sampler is flushed first and the policy engine last; items 2
// to 7 are reached through the registered built-ins holding them, in the order
// the chain runs those built-ins.
//
// A component whose flush fails does not stop the others: everything above is
// flushed, and the errors are returned joined (errors.Join), the policy
// engine's own joined error included, or nil when none failed. The library's
// own components never fail to flush, so an error comes from a consumer's
// authenticator, identity broker or policy. It makes Chain a
// logsample.Flusher itself.
//
// A flush reports what is pending and forgets it, so calling this more than
// once, flushing a component directly as well, or flushing two chains that
// share a component reports each suppressed count once.
//
// It does not reach:
//
//   - A component the consumer holds but never gave the chain, such as an
//     authenticator used only outside it. The consumer flushes that itself.
//   - A signingkey.Keys, which is not a chain dependency and flushes its
//     own refusal logs when its background loops stop.
func (c *Chain) FlushRefusalLogs() error {
	c.sampler.Flush()

	var errs []error

	for _, r := range c.registrations {
		if f, ok := r.interceptor.(refusalLogFlusher); ok {
			if err := f.flushRefusalLogs(); err != nil {
				errs = append(errs, err)
			}
		}
	}

	if c.engine != nil {
		if err := c.engine.FlushRefusalLogs(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

var _ logsample.Flusher = (*Chain)(nil)

// Assemble folds the chain around terminal and returns its outermost step.
//
// It is what an integration calls to put the chain in front of its own
// handler: terminal is that handler, adapted to Next, and the returned Next is
// the whole chain with the handler innermost.
//
// Interceptors run in ascending slot order with the lowest outermost, so the
// fold runs backwards — the innermost interceptor wraps the terminal, and each
// one outside it wraps what has been built so far. Two interceptors at one slot
// run in the order they were registered.
//
// Continuation needs no code here. An interceptor stops the request by not
// calling the next step, and an error travels back out through every enclosing
// frame unchanged, because no frame this fold builds inspects it.
func (c *Chain) Assemble(terminal Next) Next {
	next := terminal
	for i := len(c.registrations) - 1; i >= 0; i-- {
		// inner and interceptor are bound per iteration, so each closure keeps
		// the step and the interceptor belonging to its own frame.
		inner := next
		interceptor := c.registrations[i].interceptor
		next = func(ex *Exchange) error { return interceptor.Intercept(ex, inner) }
	}

	// The exchange is handed the chain's per-request phase before the first
	// interceptor runs, so a consumer interceptor's EvaluatePerRequest judges
	// it as the built-ins do.
	chain := next

	return func(ex *Exchange) error {
		ex.perRequest = c.perRequest

		return chain(ex)
	}
}

// builtInEnforcer names the library's own gate for a challenge kind: the
// option that enables it, and what the challenge asks for.
type builtInEnforcer struct {
	option string

	// what says in words what the challenge asks for, so the error reads
	// without knowing the constant.
	what string
}

// builtInEnforcers maps every challenge kind the library raises to the
// built-in gate that enforces it.
//
// A kind counts as enforced only when that gate is enabled, never because
// something else occupies the gate's slot: a consumer interceptor placed with
// Before(OrderMFAChallenge) lands on OrderMFAEnrolment and would otherwise pass
// for the enrolment gate while confining nothing. The chain cannot tell what an
// arbitrary interceptor does, so it counts only the gates it knows.
var builtInEnforcers = map[policy.ChallengeKind]builtInEnforcer{
	policy.ChallengeMFA:            {option: "EnableMFA", what: "a second factor"},
	policy.ChallengePasswordChange: {option: "EnablePasswordChangeGate", what: "a password change"},
	policy.ChallengeMFAEnrolment:   {option: "EnableMFAEnrolment", what: "a second-factor enrolment"},

	// The account-recovery kind is listed so WithChallengeEnforcer refuses it
	// as a library kind rather than accepting it as the consumer's. It never
	// counts as enforced: no policy may raise it (see refuseGateOnly).
	policy.ChallengeAccountRecovery: {option: "EnableAccountRecovery", what: "an account recovery's binding"},
}

// refuseGateOnly refuses kind when it is one only a built-in gate raises,
// never a policy.
//
// The account-recovery kind is the one such kind. The recovery gate raises it
// directly, and only on a session an account recovery created; nothing would
// confine an ordinary session a policy challenged with it. Accepting such a
// declaration and letting the challenged request through would relax the
// policy silently, so assembly refuses a policy that declares it, and a policy
// added later that raises it refuses the request, whether or not the recovery
// gate is on.
func refuseGateOnly(kind policy.ChallengeKind, subject string) error {
	if kind != policy.ChallengeAccountRecovery {
		return nil
	}

	return newConfigError("%s %s, which only the recovery gate raises: it confines a session "+
		"an account recovery created, and nothing would confine an ordinary session a policy "+
		"challenged with it, so remove it from the policy", subject, kind)
}

// refuseUnenforcedChallenges refuses a chain whose policies can raise a
// challenge that nothing on it would enforce.
//
// A challenge raised per request is marked pending on the session and the
// request continues, because the gate for that kind is what enforces it and
// the endpoint that resolves it has to stay reachable. With no gate, every
// challenged session is marked and then served anyway: the caller goes on
// having satisfied nothing, and no error, no status and no record says so.
//
// That silence is why this is a construction error rather than a documented
// caution. A chain that does not build serves no traffic, whereas a chain that
// builds and quietly ignores a policy is indistinguishable, from the outside,
// from one enforcing it. There is no option to switch it off.
//
// Every kind a registered policy declares is checked against
// enforcedChallenges: a built-in kind needs its built-in gate enabled, and a
// kind the library does not know needs the consumer's WithChallengeEnforcer. A
// policy that does not declare its challenges is taken to raise none — see
// policy.Challenger, which says why, and what a consumer whose own policy
// challenges has to do so that this check can see it.
func (c *config) refuseUnenforcedChallenges() error {
	if c.engine == nil {
		return nil
	}

	enforced := c.enforcedChallenges()

	for _, kind := range c.engine.DeclaredChallenges() {
		if err := refuseGateOnly(kind, "a registered policy declares"); err != nil {
			return err
		}

		if enforced[kind] {
			continue
		}

		if b, ok := builtInEnforcers[kind]; ok {
			return newConfigError("a registered policy can raise %s, a challenge for %s, but "+
				"nothing on this chain enforces it: add %s, or remove the policy",
				kind, b.what, b.option)
		}

		return newConfigError("a registered policy can raise %s, but nothing on this chain "+
			"enforces it: register your gate for it and declare it with "+
			"WithChallengeEnforcer, or remove the policy", kind)
	}

	return nil
}

// enforcedChallenges is every challenge kind something on this chain
// enforces: a built-in kind whose built-in gate is enabled, and each kind the
// consumer declared with WithChallengeEnforcer.
//
// It is the one set both halves of the check read. The assembly check reads
// the policies registered when the chain is built; the chain checks a
// challenge raised at runtime against this same set, so a policy added to the
// engine afterwards, which the assembly check never saw, still cannot raise a
// challenge that is marked and then served.
func (c *config) enforcedChallenges() map[policy.ChallengeKind]bool {
	enforced := make(map[policy.ChallengeKind]bool, len(c.builtInGates)+len(c.consumerEnforced))

	for kind := range c.builtInGates {
		enforced[kind] = true
	}

	for kind := range c.consumerEnforced {
		enforced[kind] = true
	}

	return enforced
}

// ordered returns the registrations sorted into the order they run in: by slot
// ascending, and within one slot by the sequence they were registered in.
//
// The sort is stable and the sequence is compared explicitly, so neither the
// sort's own tie-breaking nor the order the options happened to be applied in
// can reorder two interceptors that share a slot.
func (c *config) ordered() []registration {
	regs := slices.Clone(c.registrations)
	slices.SortStableFunc(regs, func(a, b registration) int {
		if a.order != b.order {
			return cmp.Compare(a.order, b.order)
		}
		return cmp.Compare(a.seq, b.seq)
	})
	return regs
}

// Order is an interceptor's position in the chain. The lowest order is
// outermost, so an interceptor with a lower order wraps every one above it and
// the downstream handler is innermost.
//
// The named slots are spaced by at least twenty-five, and the slots either side
// of each are left free, so a consumer can register immediately before or
// after any built-in with Before and After without choosing a number that a
// later scrty release might want.
type Order int

// The slots the library's own interceptors occupy, and the ones reserved for
// the interceptors other capabilities add. They are ordered outermost first:
// a request is served the key set before anything tries to authenticate it, is
// authenticated before a gate or a challenge judges it, and is authorized last,
// when everything it is judged on has been resolved.
const (
	// OrderJWKS serves the public key set, which is answered for anyone.
	OrderJWKS Order = 100

	// OrderOIDC is federated login: the authorize redirect, the callback, the
	// handoff redemption and back-channel logout. See EnableOIDCLogin.
	OrderOIDC Order = 200

	// OrderFormLogin is the form and JSON login endpoint.
	OrderFormLogin Order = 300

	// OrderMagicLink is reserved for one-time link requests and redemptions.
	OrderMagicLink Order = 350

	// OrderAccountRecoveryEndpoints is the account-recovery endpoints, which
	// answer callers who cannot log in. They sit outside Basic, API key and
	// bearer authentication, so a stale credential a client still sends
	// cannot refuse a recovery before it is heard. See EnableAccountRecovery.
	OrderAccountRecoveryEndpoints Order = 375

	// OrderPasskeyLogin is passwordless passkey login, a first factor of its
	// own: after the one-time link slot and the account-recovery endpoints,
	// and before Basic authentication.
	OrderPasskeyLogin Order = 380

	// OrderBasicAuth is HTTP Basic authentication.
	OrderBasicAuth Order = 400

	// OrderAPIKey is reserved for API key authentication.
	OrderAPIKey Order = 450

	// OrderMTLS is reserved for client certificate authentication.
	OrderMTLS Order = 475

	// OrderBearerToken is bearer token authentication.
	OrderBearerToken Order = 500

	// OrderMFAChallenge is reserved for the second-factor verify endpoint and
	// the gate that holds a pending challenge.
	OrderMFAChallenge Order = 600

	// OrderPasswordChange is the gate a session owing a password change is
	// held at, and the endpoint that resolves it.
	OrderPasswordChange Order = 650

	// OrderPasskeys is the passkey endpoints that need a session: registration
	// and its confirmations, and the listing, rename and remove endpoints. It
	// is inside every gate, the password-change gate included, so each gate
	// has already decided whether the session may reach them. See
	// EnablePasskeys.
	OrderPasskeys Order = 660

	// OrderSessionRenewal is the session renewal endpoint. It is inside bearer
	// authentication, which resolves the session it renews, and inside every
	// gate that confines a session (recovery, enrolment, second factor,
	// password change), so a confined session is refused by its gate before it
	// can renew its way out. It is outside logout and the session-touch step.
	// See EnableSessionRenewal.
	OrderSessionRenewal Order = 675

	// OrderLogout ends the session.
	OrderLogout Order = 700

	// OrderSessionTouch records activity, and runs after the handler has
	// returned so a refused request is recorded too.
	//
	// Recording activity persists only the session's last-access time and idle
	// deadline. A handler that changes any other field of the session, such as
	// its Data, must persist it with Sessions.Save (or the store's Save): this
	// step never saves it.
	OrderSessionTouch Order = 800

	// OrderAuthorizer is the authorization stage, innermost of the built-ins
	// because it judges everything the earlier slots resolved.
	OrderAuthorizer Order = 900
)

// OrderMFAEnrolment is the second-factor enrolment gate and its endpoints. It
// is Before(OrderMFAChallenge), immediately outside the second-factor gate, so
// a session confined to enrolment is refused before anything at the
// second-factor slot, the verify endpoint included, can answer it. It is the
// one named slot not spaced from its neighbour, so that no other named slot
// lies between the two gates.
//
// That does not mean nothing runs between them: a consumer interceptor
// registered at Before(OrderMFAChallenge) shares this slot, and slot-mates run
// in the order they were registered. Registered after EnableMFAEnrolment's
// option, it runs between the two gates, after an enrolment-only session has
// already been refused. Registered before it, it runs ahead of the enrolment
// gate and sees such a session, as every interceptor outside the gate does.
const OrderMFAEnrolment = OrderMFAChallenge - 1

// OrderAccountRecovery is the recovery gate, which confines a session an
// account recovery created to the endpoints that bind a new authenticator or
// change its password, and to logout. It is Before(OrderMFAEnrolment), after
// bearer authentication has resolved the session and outside every gate a
// recovery-pending session must not be judged by first: the enrolment gate,
// the second-factor gate and the password-change gate. Like OrderMFAEnrolment
// it is not spaced from its neighbour, so that no other named slot lies
// between the recovery gate and the enrolment gate.
//
// A consumer interceptor registered at Before(OrderMFAEnrolment) shares this
// slot, and slot-mates run in the order they were registered.
const OrderAccountRecovery = OrderMFAEnrolment - 1

// Before is the slot immediately outside o, which runs just before it.
func Before(o Order) Order { return o - 1 }

// After is the slot immediately inside o, which runs just after it and before
// the next named slot.
func After(o Order) Order { return o + 1 }

// RegisterInterceptor runs i at slot at.
//
// There is no default: a chain registers only the built-ins its Enable options
// asked for, and this is how a consumer adds one of their own. Use Before and
// After to sit immediately outside or inside a named slot. Registering two
// interceptors at one slot is allowed, and they run in the order they were
// registered.
//
// An interceptor that authenticates a request publishes what it resolved with
// WithCaller, which is what the built-in first factors use. Publishing with
// authenticate.WithAuthentication alone announces the event without the caller,
// and every guard behind the interceptor then refuses a caller it had just
// authenticated.
//
// A nil interceptor, including an interface holding a nil pointer, is refused
// when the chain is built: it can only ever panic on the first request.
func RegisterInterceptor(i Interceptor, at Order) Option {
	return func(c *config) error {
		if nilcheck.IsNil(i) {
			return newConfigError("RegisterInterceptor was given no interceptor for slot %d", at)
		}

		c.registrations = append(c.registrations, registration{interceptor: i, order: at, seq: c.seq})
		c.seq++
		return nil
	}
}

// mfaChallengeTaskPrefix starts the name of each challenge method's expiry
// task; the method's name follows it.
const mfaChallengeTaskPrefix = "mfa-challenges:"

// ExpiryTasks returns the tasks that delete the expired one-time state of the
// components the chain builds itself, in this order:
//
//  1. "mfa-challenges:<method>" for each challenge method (an
//     mfa.ChallengeMethod, such as a passkey) given to EnableMFA, in the
//     order given. Its pending challenges are issued to a signed-in user who
//     still owes a second factor. A method with no challenge step, such as
//     TOTP, keeps no pending state and contributes no task.
//  2. The tasks of the recovery.Recoverer that EnableAccountRecovery builds:
//     "recovery-issued-codes" when issued codes are enabled, and
//     "recovery-finish-tokens" and "recovery-cancel-tokens" when the core may
//     hold a recovery. See recovery.Recoverer.ExpiryTasks.
//
// A component that is not enabled contributes nothing, and a chain with none
// returns an empty, non-nil slice. Passing that alone to expiry.NewRunner
// fails with expiry.ErrNoTasks rather than building a runner that sweeps
// nothing.
//
// The tasks run over the very managers that serve the chain's requests, so a
// sweep reaches the state those requests issued, whether it lives in the
// default in-memory stores or in the stores given to WithMFAChallengeStore,
// WithRecoveryCore's recovery.WithIssuedCodeStore or
// recovery.WithHoldTokenStore. Each purges through its own manager, which
// removes only tokens that are expired and older than that manager's issuance
// window, so a sweep never frees the challenge limit or the issued-code limit.
// The sweep EnableMFA's begin runs inline, at most once per issuance window per
// method, is unaffected; these tasks also cover a method nobody has begun
// lately.
//
// No task sets an Interval, because only the deployment knows its cadence, and
// none accepts a cutoff. They never delete sessions, MFA enrolments, passkeys,
// API keys, OIDC links or recovery records. A store that does not implement
// onetime.Reaper makes its task fail with an error matching both
// expiry.ErrPurgeUnsupported and onetime.ErrReapUnsupported.
//
// State of components the consumer builds and hands to the chain is theirs to
// sweep with those components' own tasks: session.ExpiryTask,
// magiclink.ExpiryTask, (*passkey.Passkeys).ExpiryTasks, oidc.FlowExpiryTask
// and oidc.HandoffExpiryTask. A consumer renames a returned task by setting its
// Name, or leaves one out.
func (c *Chain) ExpiryTasks() []expiry.Task {
	tasks := []expiry.Task{}

	for _, r := range c.registrations {
		if i, ok := r.interceptor.(*mfaInterceptor); ok {
			tasks = append(tasks, i.expiryTasks()...)
		}
	}

	for _, r := range c.registrations {
		if i, ok := r.interceptor.(*recoveryInterceptor); ok && i.recoverer != nil {
			tasks = append(tasks, i.recoverer.ExpiryTasks()...)
		}
	}

	return tasks
}

// expiryTasks returns a task per challenge method, over the manager its begin
// issues challenges with, in the methods' configured order.
func (i *mfaInterceptor) expiryTasks() []expiry.Task {
	var tasks []expiry.Task

	for _, m := range i.methods {
		if mgr, ok := i.challenges[m.Name()]; ok {
			tasks = append(tasks, onetime.ExpiryTaskNamed(mfaChallengeTaskPrefix+m.Name(), mgr))
		}
	}

	return tasks
}

// msgRefusalsSuppressed is the record the default reporter writes for a key
// whose counts are about to be discarded.
const msgRefusalsSuppressed = "httpsec: refusal logs suppressed"

// logSampled writes at most one record per key per window, carrying the count
// it stood in for.
//
// A nil sampler, or one built with an interval of zero or less, writes every
// record: sampling is a defence against a flood filling a disk, and a consumer
// who would rather have every line says so through WithRefusalLogInterval.
func logSampled(
	ctx context.Context,
	s *logsample.Sampler,
	log *slog.Logger,
	level slog.Level,
	now time.Time,
	key, msg string,
	attrs ...slog.Attr,
) {
	write, suppressed := s.Allow(key, now)
	if !write {
		return
	}

	if suppressed > 0 {
		// Attached only when it says something. Padding every ordinary record
		// with suppressed=0 costs an operator a column that is almost always
		// noise, and hides the records where the count matters.
		attrs = append(attrs, slog.Int("suppressed", suppressed))
	}

	log.LogAttrs(ctx, level, msg, attrs...)
}

// refusalLogReporter is the reporter the chain's samplers report to: the
// consumer's (WithRefusalLogReporter), or else the default summary record
// through the chain's logger.
//
// It is resolved after every option has been applied, because which reporter
// and which logger that is is not settled until then. The source guards the
// chain builds report through it too, so a consumer's reporter receives their
// throttled-source counts like the chain's own.
func (c *config) refusalLogReporter() func(key string, suppressed int) {
	if c.refusalReporter != nil {
		return c.refusalReporter
	}

	return c.reportSuppressedRefusals
}

// reportSuppressedRefusals is the default reporter before the chain exists:
// the same summary record, through the logger the options settled on.
func (c *config) reportSuppressedRefusals(key string, suppressed int) {
	summariseRefusals(c.logger, key, suppressed)
}

// summariseRefusals writes the default summary record for key.
//
// It runs on whichever goroutine's refusal or flush evicted the key, and that
// goroutine's request context has nothing to do with the counts being reported,
// so the record is written without one.
func summariseRefusals(log *slog.Logger, key string, suppressed int) {
	log.LogAttrs(context.Background(), slog.LevelWarn, msgRefusalsSuppressed,
		slog.String("key", key),
		slog.Int("suppressed", suppressed))
}

// now reads the chain's time source when it is called, not when the
// interceptor that holds it was built, so WithClock takes effect wherever it
// stands among the options.
func (c *config) now() time.Time { return c.clock.Now() }
