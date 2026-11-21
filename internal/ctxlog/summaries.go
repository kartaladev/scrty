package ctxlog

import (
	"context"
	"log/slog"
	"sync"
)

// DefaultSummaryKeys is how many keys one generation of a [Summaries] holds,
// matching how many keys a sampler tracks in one window by default.
const DefaultSummaryKeys = 100_000

// Summaries remembers, per sampler key, where the key's last written record
// went, so the sampler's suppressed-count summary for that key, which has no
// request context of its own, is written to the same destination and to no
// other. A component that serves several chains with different loggers
// therefore never writes one chain's key, which may name a user, into another
// chain's log.
//
// The component calls [Summaries.Note] after it writes a sampled record, and
// its sampler's reporter calls [Summaries.For] for the logger it writes the
// summary through.
//
// The zero value is ready to use. A nil *Summaries remembers nothing, so every
// summary goes to the default destination. A Summaries must not be copied
// after first use. It is safe for concurrent use, and holds no lock while a
// record is written.
//
// # Bound
//
// Memory is bounded at 2×[DefaultSummaryKeys] entries, each a key and a
// logger pointer. Keys are held in two generations: once the current one holds
// DefaultSummaryKeys keys, the next new key starts a fresh generation and the
// one before it is dropped. For removes the key it answers, and a key whose
// latest record went to the default destination, or to a concrete logger, holds
// no entry. A key noted but never summarised (its window ended with nothing
// suppressed) is therefore dropped after at most DefaultSummaryKeys newer keys,
// or by its own next Note or For. A dropped key's summary goes to the default
// destination, never to another chain (accepted: the summary is still written,
// only to the process logger).
//
// The destination is that of the key's latest Note. A reporter that runs while
// a new record for the same key is being written in another chain may write the
// summary there: that chain is already receiving records for the same key
// (accepted).
type Summaries struct {
	mu sync.Mutex

	// max is how many keys one generation holds; zero or less means
	// DefaultSummaryKeys. Only tests set it.
	max int

	// cur and prev map a key to the chain logger its latest record went to.
	// A key in cur shadows the same key in prev.
	cur, prev map[string]*slog.Logger
}

// Note records where the sampled record for key, just written through l with
// ctx, went: for a routing logger ([Routing]), the chain logger ctx carries,
// or the default destination when it carries none; for any other logger, l
// itself, which needs no entry since [Summaries.For] answers l then. A nil l,
// or a nil s, records nothing.
func (s *Summaries) Note(ctx context.Context, l *slog.Logger, key string) {
	if s == nil || !isRouting(l) {
		return
	}

	chain := From(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()

	if chain == nil {
		// The record went to the default: no entry answers the same.
		delete(s.cur, key)
		delete(s.prev, key)

		return
	}

	limit := s.max
	if limit <= 0 {
		limit = DefaultSummaryKeys
	}

	if _, ok := s.cur[key]; !ok && len(s.cur) >= limit {
		s.prev, s.cur = s.cur, nil
	}

	if s.cur == nil {
		s.cur = make(map[string]*slog.Logger)
	}

	s.cur[key] = chain
	delete(s.prev, key)
}

// For returns the logger the summary for key is written through, and forgets
// key:
//
//   - for a logger that does not route, l itself;
//   - for a routing logger with a remembered destination, that chain logger,
//     with l's own With and WithGroup calls applied;
//   - for a routing logger with none, a logger with l's With and WithGroup
//     calls applied that writes to slog.Default(), read when the summary is
//     written.
//
// A summary written through the returned logger ignores any chain logger on
// the context it is written with, so it cannot be steered to another chain. A
// nil l answers nil.
func (s *Summaries) For(l *slog.Logger, key string) *slog.Logger {
	var chain *slog.Logger

	if s != nil {
		s.mu.Lock()

		chain = s.cur[key]
		if chain == nil {
			chain = s.prev[key]
		}

		delete(s.cur, key)
		delete(s.prev, key)

		s.mu.Unlock()
	}

	h := routingOf(l)
	if h == nil {
		return l
	}

	if chain != nil {
		return h.loggerFor(chain)
	}

	return h.toDefault()
}
