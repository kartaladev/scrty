package ctxlog_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/ctxlog"
)

func TestSummaries_For(t *testing.T) {
	type sinks struct {
		a, b, def    *bytes.Buffer
		chainA       *slog.Logger
		chainB       *slog.Logger
		inA, inB     context.Context
		routing      *slog.Logger
		summaries    *ctxlog.Summaries
		writeSampled func(ctx context.Context, l *slog.Logger, key string)
	}

	type testCase struct {
		name string
		// logger is the component's logger; nil uses the shared routing logger.
		logger func(s sinks) *slog.Logger
		// setup writes the sampled records, and returns the key to summarise.
		setup  func(t *testing.T, s sinks, l *slog.Logger) string
		assert func(t *testing.T, s sinks, l, got *slog.Logger)
	}

	// summarise writes the summary for key through got, as a reporter does.
	summarise := func(got *slog.Logger, key string) {
		got.LogAttrs(context.Background(), slog.LevelInfo, "suppressed", slog.String("key", key))
	}

	// keysIn returns the key attribute of every summary record in buf.
	keysIn := func(t *testing.T, buf *bytes.Buffer) []string {
		t.Helper()

		var out []string

		for _, r := range records(t, buf) {
			if r["msg"] == "suppressed" {
				out = append(out, fmt.Sprint(r["key"]))
			}
		}

		return out
	}

	onlyIn := func(pick func(s sinks) *bytes.Buffer, key string) func(t *testing.T, s sinks, _, got *slog.Logger) {
		return func(t *testing.T, s sinks, _, got *slog.Logger) {
			t.Helper()
			require.NotNil(t, got)
			summarise(got, key)

			for _, buf := range []*bytes.Buffer{s.a, s.b, s.def} {
				if buf == pick(s) {
					assert.Equal(t, []string{key}, keysIn(t, buf))
				} else {
					assert.Empty(t, keysIn(t, buf), "the summary for %q reached another destination", key)
				}
			}
		}
	}

	inA := func(s sinks) *bytes.Buffer { return s.a }
	inB := func(s sinks) *bytes.Buffer { return s.b }
	inDefault := func(s sinks) *bytes.Buffer { return s.def }

	// twoChains writes "u:A" in chain A and "u:B" in chain B through l.
	twoChains := func(key string) func(t *testing.T, s sinks, l *slog.Logger) string {
		return func(_ *testing.T, s sinks, l *slog.Logger) string {
			s.writeSampled(s.inA, l, "u:A")
			s.writeSampled(s.inB, l, "u:B")

			return key
		}
	}

	cases := []testCase{
		{
			name:   "a key written in chain A is summarised only to A",
			setup:  twoChains("u:A"),
			assert: onlyIn(inA, "u:A"),
		},
		{
			name: "a key written in chain B is summarised only to B, though A resolved since",
			setup: func(t *testing.T, s sinks, l *slog.Logger) string {
				twoChains("")(t, s, l)
				s.writeSampled(s.inA, l, "u:A")
				return "u:B"
			},
			assert: onlyIn(inB, "u:B"),
		},
		{
			name:   "a key never noted goes to the default, never to the last chain",
			setup:  twoChains("u:C"),
			assert: onlyIn(inDefault, "u:C"),
		},
		{
			name: "a key last written to the default goes to the default, not to the chain before",
			setup: func(t *testing.T, s sinks, l *slog.Logger) string {
				s.writeSampled(s.inA, l, "u:A")
				s.writeSampled(t.Context(), l, "u:A")

				return "u:A"
			},
			assert: onlyIn(inDefault, "u:A"),
		},
		{
			name: "a key last written in another chain follows its latest record",
			setup: func(_ *testing.T, s sinks, l *slog.Logger) string {
				s.writeSampled(s.inA, l, "u:A")
				s.writeSampled(s.inB, l, "u:A")

				return "u:A"
			},
			assert: onlyIn(inB, "u:A"),
		},
		{
			name: "For forgets the key, so a second summary goes to the default",
			setup: func(_ *testing.T, s sinks, l *slog.Logger) string {
				s.writeSampled(s.inA, l, "u:A")
				s.summaries.For(l, "u:A")

				return "u:A"
			},
			assert: onlyIn(inDefault, "u:A"),
		},
		{
			name:  "a summary with no destination ignores a chain logger on its own context",
			setup: twoChains("u:C"),
			assert: func(t *testing.T, s sinks, _, got *slog.Logger) {
				got.LogAttrs(s.inA, slog.LevelInfo, "suppressed", slog.String("key", "u:C"))
				assert.Equal(t, []string{"u:C"}, keysIn(t, s.def))
				assert.Empty(t, keysIn(t, s.a))
			},
		},
		{
			name:  "a summary to a noted chain ignores another chain logger on its own context",
			setup: twoChains("u:A"),
			assert: func(t *testing.T, s sinks, _, got *slog.Logger) {
				got.LogAttrs(s.inB, slog.LevelInfo, "suppressed", slog.String("key", "u:A"))
				assert.Equal(t, []string{"u:A"}, keysIn(t, s.a))
				assert.Empty(t, keysIn(t, s.b))
			},
		},
		{
			name:  "the default is read when the summary is written",
			setup: twoChains("u:C"),
			assert: func(t *testing.T, s sinks, _, got *slog.Logger) {
				later := &bytes.Buffer{}
				swapDefault(t, slog.NewJSONHandler(later, nil))
				summarise(got, "u:C")
				assert.Equal(t, []string{"u:C"}, keysIn(t, later))
				assert.Empty(t, keysIn(t, s.def))
			},
		},
		{
			name: "a routing logger's attributes and group are kept on the summary",
			logger: func(s sinks) *slog.Logger {
				return s.routing.With("component", "policy").WithGroup("g")
			},
			setup: twoChains("u:A"),
			assert: func(t *testing.T, s sinks, _, got *slog.Logger) {
				summarise(got, "u:A")

				recs := records(t, s.a)
				require.Len(t, recs, 2)
				assert.Equal(t, "policy", recs[1]["component"])
				assert.Equal(t, map[string]any{"key": "u:A"}, recs[1]["g"])
				assert.Empty(t, keysIn(t, s.b))
			},
		},
		{
			name: "a routing logger's attributes are kept on a summary to the default",
			logger: func(s sinks) *slog.Logger {
				return s.routing.With("component", "policy")
			},
			setup: twoChains("u:C"),
			assert: func(t *testing.T, s sinks, _, got *slog.Logger) {
				summarise(got, "u:C")

				recs := records(t, s.def)
				require.Len(t, recs, 1)
				assert.Equal(t, "policy", recs[0]["component"])
			},
		},
		{
			name:   "a concrete logger is its own summary",
			logger: func(s sinks) *slog.Logger { return s.chainB },
			setup: func(_ *testing.T, s sinks, l *slog.Logger) string {
				s.writeSampled(s.inA, l, "u:A")

				return "u:A"
			},
			assert: func(t *testing.T, _ sinks, l, got *slog.Logger) {
				assert.Same(t, l, got)
			},
		},
		{
			name:   "a nil logger answers nil",
			logger: func(sinks) *slog.Logger { return nil },
			setup:  func(*testing.T, sinks, *slog.Logger) string { return "u:A" },
			assert: func(t *testing.T, _ sinks, _, got *slog.Logger) {
				assert.Nil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := sinks{a: &bytes.Buffer{}, b: &bytes.Buffer{}, def: &bytes.Buffer{}}
			swapDefault(t, slog.NewJSONHandler(s.def, nil))

			s.chainA = slog.New(slog.NewJSONHandler(s.a, nil))
			s.chainB = slog.New(slog.NewJSONHandler(s.b, nil))
			s.inA = ctxlog.With(t.Context(), s.chainA)
			s.inB = ctxlog.With(t.Context(), s.chainB)
			s.routing = ctxlog.Routing()
			s.summaries = &ctxlog.Summaries{}
			s.writeSampled = func(ctx context.Context, l *slog.Logger, key string) {
				if l != nil {
					l.InfoContext(ctx, "sampled", "key", key)
				}

				s.summaries.Note(ctx, l, key)
			}

			l := s.routing
			if tc.logger != nil {
				l = tc.logger(s)
			}

			key := tc.setup(t, s, l)
			tc.assert(t, s, l, s.summaries.For(l, key))
		})
	}
}

func TestSummaries_NilReceiver(t *testing.T) {
	def := &bytes.Buffer{}
	swapDefault(t, slog.NewJSONHandler(def, nil))

	var s *ctxlog.Summaries

	chain := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	l := ctxlog.Routing()

	assert.NotPanics(t, func() { s.Note(ctxlog.With(t.Context(), chain), l, "u:A") })

	got := s.For(l, "u:A")
	require.NotNil(t, got)
	got.Info("suppressed")
	assert.Len(t, records(t, def), 1, "a nil Summaries remembers nothing, so the summary goes to the default")
}

func TestSummaries_Bound(t *testing.T) {
	swapDefault(t, slog.DiscardHandler)

	const maxKeys = 4

	chain := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	inChain := ctxlog.With(t.Context(), chain)
	l := ctxlog.Routing()
	s := ctxlog.NewSummariesWithMax(maxKeys)

	for i := range 100 {
		s.Note(inChain, l, fmt.Sprintf("u:%d", i))
		assert.LessOrEqual(t, s.Len(), 2*maxKeys, "after %d notes", i+1)
	}

	assert.Same(t, chain, s.For(l, "u:99"), "the most recent key keeps its destination")
	assert.NotSame(t, chain, s.For(l, "u:0"), "an evicted key goes to the default")

	// A key noted then written to the default holds no entry at all.
	s2 := ctxlog.NewSummariesWithMax(maxKeys)
	s2.Note(inChain, l, "u:A")
	s2.Note(t.Context(), l, "u:A")
	assert.Equal(t, 0, s2.Len())

	// A concrete logger has nothing to remember.
	s2.Note(inChain, chain, "u:B")
	assert.Equal(t, 0, s2.Len())

	// For removes what it answers.
	s2.Note(inChain, l, "u:C")
	require.Equal(t, 1, s2.Len())
	s2.For(l, "u:C")
	assert.Equal(t, 0, s2.Len())
}

// ownerHandler counts records whose key attribute does not start with prefix
// (a record or summary that reached a chain it does not belong to) and writes
// nothing, so concurrent goroutines share no buffer.
type ownerHandler struct {
	slog.Handler
	prefix    string
	misrouted *atomic.Int64
	seen      *atomic.Int64
}

func (ownerHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h ownerHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "key" {
			h.seen.Add(1)

			if !strings.HasPrefix(a.Value.String(), h.prefix) {
				h.misrouted.Add(1)
			}
		}

		return true
	})

	return h.Handler.Handle(ctx, r)
}

func (h ownerHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.Handler = h.Handler.WithAttrs(attrs)

	return h
}

func (h ownerHandler) WithGroup(name string) slog.Handler {
	h.Handler = h.Handler.WithGroup(name)

	return h
}

func TestSummaries_Concurrent(t *testing.T) {
	var misrouted, seen atomic.Int64

	// Goroutines g and g+chains share keys, so one may summarise and forget a
	// key the other just noted; that summary goes to the default, which is
	// allowed. Only a summary in another chain counts as misrouted.
	swapDefault(t, ownerHandler{slog.DiscardHandler, "", &misrouted, &seen})

	const chains = 4

	ctxs := make([]context.Context, chains)
	for i := range chains {
		h := ownerHandler{slog.DiscardHandler, fmt.Sprintf("c%d:", i), &misrouted, &seen}
		ctxs[i] = ctxlog.With(t.Context(), slog.New(h))
	}

	l := ctxlog.Routing().With("component", "policy")
	s := ctxlog.NewSummariesWithMax(16)

	var wg sync.WaitGroup

	for g := range 8 {
		wg.Go(func() {
			c := g % chains
			for i := range 300 {
				key := fmt.Sprintf("c%d:u%d", c, i%40)
				l.InfoContext(ctxs[c], "sampled", "key", key)
				s.Note(ctxs[c], l, key)
				s.For(l, key).LogAttrs(context.Background(), slog.LevelInfo, "suppressed", slog.String("key", key))
			}
		})
	}

	wg.Wait()

	assert.Positive(t, seen.Load())
	assert.Zero(t, misrouted.Load(), "a summary reached a chain other than the one its key was written in")
	assert.LessOrEqual(t, s.Len(), 32)
}
