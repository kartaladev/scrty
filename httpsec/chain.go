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

// FlushRefusalLogs reports every suppressed refusal count the chain is still
// holding, for example from a shutdown hook, so counts held for a window that
// will never close are not lost.
//
// It flushes the chain's own sampler, which every built-in refusal record the
// chain writes itself goes through, and the enrolment path's, which
// EnableMFAEnrolment samples under its own interval. Nothing else is flushed:
//
//   - The authenticate and policy components a consumer builds sample their
//     own records under their own options, and each exposes its own flush
//     (authenticate.RefusalLogFlusher, policy.RefusalLogFlusher). Reaching into
//     them from here would make one call's meaning depend on which of them a
//     consumer happened to wire, so a consumer who wants exact counts
//     everywhere flushes each of them itself.
//   - The verification throttle EnableMFA builds, and the per-source guards
//     the built-in endpoints are wired with, keep samplers of their own that
//     this call does not reach, and no other call does either. Their own
//     reporters report what they held back as later records age it out, but
//     whatever they still hold when the process stops is not reported.
func (c *Chain) FlushRefusalLogs() {
	c.sampler.Flush()

	for _, r := range c.registrations {
		if i, ok := r.interceptor.(*enrolmentInterceptor); ok {
			i.sampler.Flush()
		}
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
