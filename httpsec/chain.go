package httpsec

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/internal/eventsink"
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

	// csrfOptOut is whether the chain was built with WithoutCSRFProtection,
	// handed to every exchange it runs (CheckCSRFToken).
	csrfOptOut bool

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

	// clients resolves each request's client address, host and transport
	// security before the first interceptor runs (clientResolver.begin).
	clients *clientResolver

	// headers is the security-headers layer, and nil unless EnableSecurityHeaders
	// enabled it. The chain applies its header step to a refusal written outside
	// the layer's slot (see Assemble).
	headers *securityHeaders

	// refusalSteps are the steps features run on a refusal written outside
	// every interceptor's slot (see Assemble), after the security headers'.
	// A feature that marks its own responses registers one with the wiring
	// hook, so its refusals are marked too.
	refusalSteps []func(*Exchange)

	// endpoints is the inventory of the built-in operations the chain answers,
	// collected once at construction and never written after. Endpoints hands
	// out copies of it.
	endpoints []Endpoint

	// events delivers the chain's security events, and is nil unless
	// EnableSecurityEvents gave it a sink. Every request carries it on its
	// context (eventsink), so whatever decides an outcome on the request
	// reports it there.
	events *eventEmitter

	// fold is the chain's interceptors composed once, outermost first: step i
	// calls interceptor i with step i+1, and the innermost step calls the
	// terminal of the run in progress on the exchange (runTerminal). It is
	// shared by every request, so it holds no terminal of its own; Assemble
	// records the terminal on the exchange instead.
	fold Next

	// firstGate is the position, in run order, of the first registration that
	// is one of the built-in gates (recovery, enrolment, second factor,
	// password change), and -1 when the chain has none.
	firstGate int

	// gates is the set of built-in gates the chain enables, built with fold
	// and never written after. A run of another chain inside this chain's
	// gates may publish a session only when its chain enables every gate in
	// it (gatesRunning).
	gates gateSet

	// foldOnce builds fold and firstGate. New runs it once construction has
	// settled the registrations; Assemble runs it too, so a Chain that did not
	// come from New still gets its fold.
	foldOnce sync.Once
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

// Assemble puts the chain around terminal and returns its outermost step.
//
// It is what an integration calls to put the chain in front of its own
// handler: terminal is that handler, adapted to Next, and the returned Next is
// the whole chain with the handler innermost.
//
// Interceptors run in ascending slot order with the lowest outermost. Two
// interceptors at one slot run in the order they were registered.
//
// The interceptors are composed once per chain, not per call: the returned
// step records terminal on the exchange it runs, for the length of that run,
// and the innermost step reaches it from there. A step reached on an exchange
// the chain is not running, such as one an interceptor built itself and passed
// on, or one kept and called after its run returned, reaches no terminal and
// returns an error wrapping ErrConfig.
//
// Continuation needs no code here. An interceptor stops the request by not
// calling the next step, and an error travels back out through every enclosing
// frame unchanged, because no frame of the fold inspects it.
func (c *Chain) Assemble(terminal Next) Next {
	c.foldOnce.Do(c.buildFold)

	return func(ex *Exchange) error {
		// A chain entered again on a request it is already running on, such
		// as one mounted both at an application and at one of its groups,
		// passes the request straight on: a second run would verify the
		// credentials and touch the counters again. Another chain, or this
		// one for another method or path (an in-process forward), runs in
		// full.
		method, path := ex.Request.Method(), ex.Request.EscapedPath()

		outer := nearestRun(ex.Context())
		if outer.ranOn(c, method, path) {
			return terminal(ex)
		}

		// The entry is removed however the run ends, a panic included, so the
		// exchange never holds the terminal of a run that is over.
		ex.pushTerminal(c, terminal)
		defer ex.popTerminal(c)

		// The run is marked on the context before anything else reads it, so
		// whatever the terminal hands that context to, an adapter's mount of
		// this chain further in included, sees the run in progress, and,
		// through its gatesBegun, whether this chain's gates are running
		// (gatesRunning). The gate mark itself is scoped to the first gate's
		// frame (buildFold), so neither a run of this exchange that has ended
		// nor an earlier pass of this run leaves it set.
		run := &chainRun{Context: ex.Context(), chain: c, method: method, path: path, parent: outer}
		ex.SetContext(run)

		defer run.done.Store(true)

		// The exchange is handed the chain's per-request phase before the
		// first interceptor runs, so a consumer interceptor's
		// EvaluatePerRequest judges it as the built-ins do.
		ex.perRequest = c.perRequest
		ex.csrfOptOut = c.csrfOptOut

		// The request carries the chain's event delivery before anything
		// decides an outcome on it, so every decision below reports through
		// it (emitEvent) and a request no sink watches carries nothing.
		if c.events != nil {
			ex.SetContext(eventsink.With(ex.Context(), c.events.emit))
		}

		// Client resolution is not an interceptor: it runs once, here, before
		// the first interceptor, so every interceptor and the handler read the
		// one resolved answer, and a forwarded host on none of the allowed
		// hosts is refused before any of them runs.
		if err := c.clients.begin(ex); err != nil {
			c.refuseAtEntry(ex)

			return err
		}

		// A path with a dot segment, or one that does not decode, is refused
		// before any interceptor runs: a router may resolve it to a path
		// other than the one the rules, the guards and the cool-down judge.
		// It is refused after client resolution, which reads no path, so the
		// 400 carries the headers the resolved request earns, those sent only
		// on a secure response behind a trusted TLS-terminating proxy
		// included, and a host client resolution refuses gets that refusal
		// instead. Only the header-profile matchers and the refusal steps
		// still see the path, and only to choose the headers of the empty
		// 400. There is no opt-out (refuseDotSegments).
		if err := refuseDotSegments(path); err != nil {
			c.refuseAtEntry(ex)

			return err
		}

		// The refusals that can arise anywhere in the chain, a cross-site
		// request or an invalid proof among them, are reported once, here,
		// as the request leaves it (emitRefusal).
		err := c.fold(ex)
		if err != nil {
			emitRefusal(ex, err)
		}

		return err
	}
}

// chainRunKey is the context key a chainRun answers to.
type chainRunKey struct{}

// chainRun marks a context as carrying a run of chain in progress for one
// method and escaped path. It is the context itself, rather than a value
// stored under a key, so marking a run costs one allocation.
//
// parent is the run marked on the context this run began on, nearest first,
// so a chain mounted inside another chain inside itself (A, B, then A again)
// still finds its own run past the other chain's.
type chainRun struct {
	context.Context //nolint:containedctx // the run marks the context it wraps, and is that context

	chain  *Chain
	method string
	path   string
	parent *chainRun

	// done is set as the run returns. A context kept past its run, by a
	// goroutine the handler started or a value detached from the request,
	// then marks nothing, so a request sent on it later is judged in full.
	// It is atomic because such a goroutine may read it while the run ends.
	done atomic.Bool

	// gatesBegun is set while the first gate's frame of this run is running,
	// and put back as that frame returns, a panic included. A run of another
	// chain inside it, on this exchange or on a fresh one an adapter built,
	// finds it through the parent links and publishes no session unless its
	// chain enables every gate this run's chain enables (gatesRunning).
	// It is atomic for the same reason as done.
	gatesBegun atomic.Bool
}

// Value answers chainRunKey with the run, and every other key from the
// context the run began on.
func (r *chainRun) Value(key any) any {
	if _, ok := key.(chainRunKey); ok {
		return r
	}

	return r.Context.Value(key)
}

// nearestRun returns the run in progress marked nearest on ctx, or nil when
// none is. A finished run is skipped for the run it began inside, so a
// context kept past its run, or an exchange run again, links no new run to a
// finished one.
func nearestRun(ctx context.Context) *chainRun {
	r, _ := ctx.Value(chainRunKey{}).(*chainRun)
	for r != nil && r.done.Load() {
		r = r.parent
	}

	return r
}

// ranOn reports whether c is running, on r or a run r began inside, for
// method and path. A nil r reports false.
func (r *chainRun) ranOn(c *Chain, method, path string) bool {
	for ; r != nil; r = r.parent {
		if r.chain == c && r.method == method && r.path == path && !r.done.Load() {
			return true
		}
	}

	return false
}

// runOf returns the run of c in progress marked nearest on ctx, or nil when
// none is: a consumer interceptor may have replaced the context with one that
// does not derive from the run's.
func runOf(ctx context.Context, c *Chain) *chainRun {
	for r := nearestRun(ctx); r != nil; r = r.parent {
		if r.chain == c && !r.done.Load() {
			return r
		}
	}

	return nil
}

// gatesRunning reports whether a run in progress on ctx, the nearest or any
// run it began inside, is inside the gates of a chain that enables a gate c
// does not. Such a run's gates would not judge what c publishes, since c has
// no gate of their kind. A run of c itself never counts: c's own gates judge
// what it publishes, and a run of c inside its own gates is a request the
// handler forwarded through c, which runs in full. Skipping those runs by
// identity is only a short-circuit: covers already decides it, since a chain's
// gate set covers its own. A finished run counts for
// nothing, its gate mark included. A nil c enables no gate. The walk is as
// deep as the chains nested on one request, compares gate sets of fixed size
// and allocates nothing.
func gatesRunning(ctx context.Context, c *Chain) bool {
	var have gateSet
	if c != nil {
		have = c.gates
	}

	for r := nearestRun(ctx); r != nil; r = r.parent {
		if r.chain == c || !r.gatesBegun.Load() || r.done.Load() {
			continue
		}

		// A marked run always has a chain; one without is refused rather
		// than read as enabling no gate.
		if r.chain == nil || !have.covers(r.chain.gates) {
			return true
		}
	}

	return false
}

// gateSet is a set of the built-in gates, one bit per entry of gateOrder, so
// it has a fixed size and comparing two sets allocates nothing.
type gateSet uint8

// gateSetOf returns the set of the built-in gates among registrations, named
// by gateKind, the one helper that tells a gate from any other interceptor.
func gateSetOf(registrations []registration) gateSet {
	var s gateSet

	for _, r := range registrations {
		kind, ok := gateKind(r.interceptor)
		if !ok {
			continue
		}

		if i := slices.Index(gateOrder[:], kind); i >= 0 {
			s |= 1 << i
		}
	}

	return s
}

// covers reports whether s holds every gate in other.
func (s gateSet) covers(other gateSet) bool { return other&^s == 0 }

// refuseAtEntry prepares the response to a refusal decided at the chain's
// entry, before the first interceptor: a host client resolution does not
// allow, or, once client resolution has answered, a path with a dot segment.
// Either way the headers are chosen against the resolved request, so a
// request a trusted proxy made secure gets the secure-only headers. No
// interceptor runs for it, the
// security-headers one included, so the layer's headers are set here, on the
// exchange's writer and before a consumer's error handler sees the refusal,
// and the features' refusal steps are run.
func (c *Chain) refuseAtEntry(ex *Exchange) {
	if c.headers != nil {
		c.headers.applyHeaders(ex.Writer, ex.Request)
	}

	for _, step := range c.refusalSteps {
		step(ex)
	}
}

// buildFold composes the registrations into fold, finds firstGate and
// records the chain's gate set.
//
// The fold runs backwards: the innermost step is built first, and each
// interceptor outside it wraps what has been built so far.
func (c *Chain) buildFold() {
	c.firstGate = slices.IndexFunc(c.registrations, func(r registration) bool {
		_, ok := gateKind(r.interceptor)

		return ok
	})
	c.gates = gateSetOf(c.registrations)

	next := c.runTerminal
	for i := len(c.registrations) - 1; i >= 0; i-- {
		// inner and interceptor are bound per iteration, so each closure keeps
		// the step and the interceptor belonging to its own frame.
		inner := next
		interceptor := c.registrations[i].interceptor

		if i == c.firstGate {
			// The first gate's frame marks the exchange, and this chain's
			// run on its context, before the gate runs, whatever the gate
			// then decides, so nothing inside it, a later gate's slot-mate,
			// an interceptor between two gates or a chain mounted further in
			// included, can publish a session no gate judged
			// (PublishSession). Both marks are put back as the frame
			// returns, a panic included, so they hold exactly while the
			// gates run: a second pass through the fold, or a later run of
			// the exchange, publishes before the gates as the first did.
			next = func(ex *Exchange) error {
				before := ex.gatesBegun
				ex.gatesBegun = true

				run := runOf(ex.Context(), c)
				var runBefore bool
				if run != nil {
					runBefore = run.gatesBegun.Swap(true)
				}

				defer func() {
					ex.gatesBegun = before
					if run != nil {
						run.gatesBegun.Store(runBefore)
					}
				}()

				return interceptor.Intercept(ex, inner)
			}

			continue
		}

		next = func(ex *Exchange) error { return interceptor.Intercept(ex, inner) }
	}

	c.fold = next
}

// runTerminal is the fold's innermost step: it calls the terminal of the run
// of c in progress on ex.
//
// While that terminal runs, its entry is marked running, so the same chain
// entered again from inside it starts a run of its own, and a step of the
// outer run reached from there finds the outer run's terminal, as it would
// were each run folded separately.
func (c *Chain) runTerminal(ex *Exchange) error {
	i := ex.topTerminal(c)
	if i < 0 {
		return fmt.Errorf("%w: an interceptor passed on an exchange this chain is not running", ErrConfig)
	}

	entry := ex.terminalAt(i)
	next := entry.next
	entry.running = true

	// The mark is cleared by position, not through entry: a run entered from
	// inside the terminal can grow the stack and move its spilled entries.
	defer func() {
		if i < ex.terminalCount() {
			if e := ex.terminalAt(i); e.chain == c {
				e.running = false
			}
		}
	}()

	return next(ex)
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

	// OrderReauthentication is the re-authentication endpoints, at which a
	// full session proves its user again. It is inside every gate, the
	// password-change gate included, so a session owing any challenge, or
	// confined to enrolment or recovery, is refused by that gate before it
	// can re-prove; and it is outside the passkey endpoints and session
	// renewal. See EnableReauthentication.
	OrderReauthentication Order = 655

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
	// An endpoint in an earlier slot that answers a request itself never reaches
	// it, so such a request records nothing. The signal stream (OrderSessionSignals)
	// relies on that. A consumer's interceptor in an earlier slot that records activity
	// itself asks RecordsSessionActivity first.
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

// Before is the slot immediately outside order, which runs just before it.
func Before(order Order) Order { return order - 1 }

// After is the slot immediately inside order, which runs just after it and before
// the next named slot.
func After(order Order) Order { return order + 1 }

// RegisterInterceptor runs interceptor at slot at.
//
// There is no default: a chain registers only the built-ins its Enable options
// asked for, and this is how a consumer adds one of their own. Use Before and
// After to sit immediately outside or inside a named slot. Registering two
// interceptors at one slot is allowed, and they run in the order they were
// registered.
//
// A consumer interceptor registered at a built-in's exact slot is that
// built-in's slot-mate, and the two run in the order their options were
// given: registered after the Enable option, it runs inside the built-in;
// before, outside it.
//
// An interceptor that authenticates a request publishes what it resolved with
// WithCaller, which is what the built-in first factors use. Publishing with
// authenticate.WithAuthentication alone announces the event without the caller,
// and every guard behind the interceptor then refuses a caller it had just
// authenticated.
//
// One that authenticates on a session, publishing it with
// Exchange.PublishSession, belongs at OrderBearerToken, no later, so the
// recovery cool-down and the recovery, enrolment, second-factor and
// password-change gates judge the session it publishes: an interceptor after
// OrderBearerToken judges a request by the session it carries when it runs. Once a request has entered the first of those gates
// the chain has enabled, PublishSession refuses a session with an error
// wrapping ErrConfig, answered with a 500: registered after a gate, between
// two gates, or at a gate's slot after its Enable option, such an
// interceptor fails every request it authenticates.
//
// A nil interceptor, including an interface holding a nil pointer, is refused
// when the chain is built: it can only ever panic on the first request.
func RegisterInterceptor(interceptor Interceptor, at Order) Option {
	return func(c *config) error {
		if nilcheck.IsNil(interceptor) {
			return newConfigError("RegisterInterceptor was given no interceptor for slot %d", at)
		}

		c.registrations = append(c.registrations, registration{interceptor: interceptor, order: at, seq: c.seq})
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
//  2. "reauth-challenges:<method>" for each of those challenge methods when
//     EnableReauthentication is given, in the same order. Its re-proof
//     challenges are issued to a signed-in user proving themselves again,
//     under a purpose of their own, in the store given to
//     WithReauthenticationChallengeStore or a default in-memory one.
//  3. The tasks of the recovery.Recoverer that EnableAccountRecovery builds:
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
// WithReauthenticationChallengeStore, WithRecoveryCore's
// recovery.WithIssuedCodeStore or recovery.WithHoldTokenStore. Each purges through its own manager, which
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
		if i, ok := r.interceptor.(*reauthInterceptor); ok {
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
