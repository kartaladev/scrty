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
// It flushes this chain's own sampler and nothing else. The authenticate and
// policy components sample their own records under their own options and expose
// their own flush; reaching into them from here would make one call's meaning
// depend on which of them a consumer happened to wire. A consumer who wants
// exact counts everywhere flushes each of them itself.
func (c *Chain) FlushRefusalLogs() { c.sampler.Flush() }

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
