package httpsec

import (
	"cmp"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
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
	engine  *policy.Engine
	logger  *slog.Logger
	limiter ratelimit.Limiter

	// enrolmentLifetime is how long a session marked for an enrolment
	// challenge may live, handed to every built-in that marks one.
	enrolmentLifetime time.Duration

	// enforced holds the challenge kinds something on this chain enforces,
	// handed to every built-in that marks a raised challenge, so a kind raised
	// at runtime that nothing enforces is refused rather than marked and served.
	enforced map[policy.ChallengeKind]bool

	ipv6Prefix int

	// errorHandler is what a refusal is answered with, and nil means the
	// library's own default: the mapped status and no body.
	errorHandler func(w http.ResponseWriter, r *http.Request, err error)

	refusalInterval time.Duration
	refusalReporter func(key string, suppressed int)

	// sampler bounds the chain's own refusal records. It is built once, at
	// construction, so every request of every flow shares one set of windows.
	sampler *logsample.Sampler
}

// refusalLogFlusher is implemented by an interceptor that holds a component
// keeping a refusal-log sampler of its own, so FlushRefusalLogs can reach it
// without knowing which built-in it is.
type refusalLogFlusher interface{ flushRefusalLogs() }

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
//  4. The per-source guards of EnableAPIKey, EnableMagicLink and handoff
//     redemption under EnableOIDCLogin, whether built over the default limiter
//     or over one the consumer supplied.
//  5. The authenticator given to EnableFormLogin or EnableBasicAuth, when it
//     implements authenticate.RefusalLogFlusher.
//  6. The oidc.Manager given to EnableOIDCLogin, which in turn flushes its
//     identity broker when that can flush, and the oidc.HandoffManager given
//     beside it, when there is one.
//  7. The policy engine given to WithPolicyEngine, which flushes every
//     registered policy implementing policy.RefusalLogFlusher, including one
//     registered after the chain was built.
//
// The chain's own sampler is flushed first and the policy engine last; items 2
// to 6 are reached through the registered built-ins holding them, in the order
// the chain runs those built-ins.
//
// A flush reports what is pending and forgets it, so calling this more than
// once, flushing a component directly as well, or flushing two chains that
// share a component reports each suppressed count once.
//
// It does not reach:
//
//   - A component the consumer holds but never gave the chain, such as an
//     authenticator used only outside it. The consumer flushes that itself.
//   - A signingkey.KeyManager, which is not a chain dependency and flushes its
//     own refusal logs when its background loops stop.
func (c *Chain) FlushRefusalLogs() {
	c.sampler.Flush()

	for _, r := range c.registrations {
		if f, ok := r.interceptor.(refusalLogFlusher); ok {
			f.flushRefusalLogs()
		}
	}

	if c.engine != nil {
		c.engine.FlushRefusalLogs()
	}
}

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
	return next
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
