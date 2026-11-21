package ctxlog

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
)

// Routing returns a new logger whose records go where the consumer configured,
// decided for each record when it is written:
//
//  1. the logger ctx carries ([From]): the logger of the chain handling the
//     request, when that chain was given one;
//  2. else slog.Default(), read at that moment, so a consumer who calls
//     slog.SetDefault after wiring has their records at their own level, Debug
//     included, with the context handed through.
//
// It is the default of every component's logger option, and of the chain's.
// The component's option replaces it.
//
// The handler's Enabled and Handle both resolve, so a chain logger at Warn
// drops a component's Info record before it is built. Attributes and groups
// added with With and WithGroup are recorded and replayed onto the resolved
// handler, in order. The replayed handler is cached per derived logger, keyed
// by the resolved *slog.Logger, so a record to the same destination as the
// one before replays nothing and allocates nothing a plain logger would not.
// A change of destination (another chain, or a slog.SetDefault) replays once
// more. Enabled answers through the replayed handler too, so a consumer
// handler whose level depends on the attributes it was given is honoured.
//
// It never routes to itself: [From] never answers a routing logger, and a
// process default that is itself a routing logger, which only a library bug
// could install, is answered by a handler writing text to standard error.
// A consumer cannot obtain a routing logger or its handler, so a handler of
// theirs wrapping one, which would loop, cannot be built (accepted).
//
// A consumer handler that panics is not recovered: its panic escapes the log
// call, as it would from any slog call on the same goroutine.
//
// Each routing logger keeps the last chain logger it resolved for a record,
// shared with the loggers derived from it, for [Summary]. It is safe for
// concurrent use as far as the handlers it resolves to are.
func Routing() *slog.Logger {
	return slog.New(&routingHandler{state: &routingState{}})
}

// Summary returns the logger a sampler's suppressed-count summary, which has
// no request context of its own, is written through: l itself when l does not
// route; for a routing logger, the chain logger it last resolved a record to,
// with l's own With and WithGroup calls applied, else l, which then resolves
// to slog.Default() at that moment. A nil l answers nil.
func Summary(l *slog.Logger) *slog.Logger {
	h := routingOf(l)
	if h == nil {
		return l
	}

	if last := h.state.last.Load(); last != nil {
		return h.loggerFor(last)
	}

	return l
}

// fallback is the handler a routing logger writes to when slog.Default() is
// itself a routing logger. Tests replace it.
var fallback slog.Handler = slog.NewTextHandler(os.Stderr, nil)

// routingState is shared by a routing logger and every logger derived from it.
type routingState struct {
	// last is the chain logger a record was last resolved to.
	last atomic.Pointer[slog.Logger]
}

// routingHandler resolves its destination for each record.
type routingHandler struct {
	state *routingState

	// ops are the WithAttrs and WithGroup calls made on the way to this
	// handler, in order. The slice is never written after it is built: a
	// derived handler gets a copy with one more entry.
	ops []op

	// cache is the last replay of ops, and the logger it was built on. It is
	// per handler, not shared: a derived handler has other ops.
	cache atomic.Pointer[replayed]
}

// replayed is a routing handler's ops replayed onto from's handler. It is
// never written after it is built.
type replayed struct {
	from   *slog.Logger
	logger *slog.Logger
}

// op is one recorded WithAttrs (attrs) or WithGroup (group) call.
type op struct {
	attrs []slog.Attr
	group string
}

// routingOf returns l's handler when it routes, else nil.
func routingOf(l *slog.Logger) *routingHandler {
	if l == nil {
		return nil
	}

	h, _ := l.Handler().(*routingHandler)

	return h
}

// isRouting reports whether l is a routing logger.
func isRouting(l *slog.Logger) bool { return routingOf(l) != nil }

// resolve returns the logger ctx carries, else nil, and the handler the
// record goes to, with the recorded operations replayed onto it.
func (h *routingHandler) resolve(ctx context.Context) (*slog.Logger, slog.Handler) {
	if l := From(ctx); l != nil {
		return l, h.loggerFor(l).Handler()
	}

	def := slog.Default()
	if isRouting(def) {
		// Only a library bug installs this; it is not cached, so a test's
		// SwapFallback is always seen.
		return nil, h.replay(fallback)
	}

	return nil, h.loggerFor(def).Handler()
}

// loggerFor returns to with h's recorded operations applied: to itself when
// there are none, else the cached replay when it was built for the same
// *slog.Logger, else a fresh replay, which replaces the cache entry.
//
// The key is the logger pointer, never its handler: a handler may be of a
// non-comparable type, and comparing it would panic. A *slog.Logger's handler
// never changes, so the same pointer means the same handler. The entry holds
// the pointer, so the logger it names cannot be collected and its address
// reused while the entry stands. Two goroutines that miss at once both replay
// and the last Store wins; each record still goes through a replay of its own
// destination.
func (h *routingHandler) loggerFor(to *slog.Logger) *slog.Logger {
	if len(h.ops) == 0 {
		return to
	}

	if c := h.cache.Load(); c != nil && c.from == to {
		return c.logger
	}

	c := &replayed{from: to, logger: slog.New(h.replay(to.Handler()))}
	h.cache.Store(c)

	return c.logger
}

// replay applies h's recorded operations to base, in order.
func (h *routingHandler) replay(base slog.Handler) slog.Handler {
	for _, o := range h.ops {
		if o.attrs != nil {
			base = base.WithAttrs(o.attrs)
		} else {
			base = base.WithGroup(o.group)
		}
	}

	return base
}

// Enabled answers as the handler ctx resolves to does.
func (h *routingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	_, to := h.resolve(ctx)

	return to.Enabled(ctx, level)
}

// Handle hands r, with ctx, to the handler ctx resolves to, and remembers a
// chain logger it resolved to for Summary. It writes the shared pointer only
// when it changes, so loggers routing many records to one chain do not contend
// on its cache line.
func (h *routingHandler) Handle(ctx context.Context, r slog.Record) error {
	l, to := h.resolve(ctx)
	if l != nil && h.state.last.Load() != l {
		h.state.last.Store(l)
	}

	return to.Handle(ctx, r)
}

// WithAttrs records attrs, to be replayed onto the resolved handler.
func (h *routingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}

	return h.with(op{attrs: append([]slog.Attr(nil), attrs...)})
}

// WithGroup records the group name, to be replayed onto the resolved handler.
// An empty name returns h, as slog.Handler requires.
func (h *routingHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}

	return h.with(op{group: name})
}

// with returns a handler sharing h's state, with o appended to a copy of h's
// operations.
func (h *routingHandler) with(o op) *routingHandler {
	ops := make([]op, len(h.ops), len(h.ops)+1)
	copy(ops, h.ops)

	return &routingHandler{state: h.state, ops: append(ops, o)}
}
