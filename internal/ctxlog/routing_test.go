package ctxlog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"testing/slogtest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/ctxlog"
)

// ctxAttrKey is the context key ctxAttrHandler reads.
type ctxAttrKey struct{}

// ctxAttrHandler adds the value under ctxAttrKey on the record's context as
// the attribute "from_ctx", as a consumer's handler reading a request id does.
type ctxAttrHandler struct{ slog.Handler }

func (h ctxAttrHandler) Handle(ctx context.Context, r slog.Record) error {
	if v, ok := ctx.Value(ctxAttrKey{}).(string); ok {
		r.AddAttrs(slog.String("from_ctx", v))
	}

	return h.Handler.Handle(ctx, r)
}

func (h ctxAttrHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return ctxAttrHandler{h.Handler.WithAttrs(attrs)}
}

func (h ctxAttrHandler) WithGroup(name string) slog.Handler {
	return ctxAttrHandler{h.Handler.WithGroup(name)}
}

// swapDefault makes h the process default for t, restoring the previous one
// when t ends. Tests that call it must not run in parallel.
func swapDefault(t *testing.T, h slog.Handler) {
	t.Helper()

	prev := slog.Default()
	slog.SetDefault(slog.New(h))

	t.Cleanup(func() { slog.SetDefault(prev) })
}

// records decodes the JSON lines in buf.
func records(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()

	var out []map[string]any

	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}

		m := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(line), &m))

		out = append(out, m)
	}

	return out
}

func jsonAt(buf *bytes.Buffer, level slog.Level) slog.Handler {
	return slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: level})
}

func TestRouting(t *testing.T) {
	type sinks struct {
		chain, def *bytes.Buffer
		chainLog   *slog.Logger
	}

	type testCase struct {
		name         string
		chainLevel   slog.Level
		defaultLevel slog.Level
		ctx          func(ctx context.Context, s sinks) context.Context
		log          func(ctx context.Context, l *slog.Logger) // nil logs one Info record "hello"
		assert       func(t *testing.T, s sinks)
	}

	onlyChain := func(t *testing.T, s sinks) {
		t.Helper()

		got := records(t, s.chain)
		require.Len(t, got, 1)
		assert.Equal(t, "hello", got[0]["msg"])
		assert.Empty(t, records(t, s.def))
	}

	onlyDefault := func(t *testing.T, s sinks) {
		t.Helper()

		got := records(t, s.def)
		require.Len(t, got, 1)
		assert.Equal(t, "hello", got[0]["msg"])
		assert.Empty(t, records(t, s.chain))
	}

	cases := []testCase{
		{
			name: "chain logger on ctx",
			ctx: func(ctx context.Context, s sinks) context.Context {
				return ctxlog.With(ctx, s.chainLog)
			},
			assert: onlyChain,
		},
		{
			name:   "no chain",
			assert: onlyDefault,
		},
		{
			name:         "SetDefault after construction",
			defaultLevel: slog.LevelDebug,
			ctx: func(ctx context.Context, _ sinks) context.Context {
				return context.WithValue(ctx, ctxAttrKey{}, "req-1")
			},
			log: func(ctx context.Context, l *slog.Logger) {
				l.ErrorContext(ctx, "hello")
				l.DebugContext(ctx, "debug")
			},
			assert: func(t *testing.T, s sinks) {
				got := records(t, s.def)
				require.Len(t, got, 2)
				assert.Equal(t, "ERROR", got[0]["level"])
				assert.Equal(t, "req-1", got[0]["from_ctx"])
				assert.Equal(t, "DEBUG", got[1]["level"])
				assert.Equal(t, "debug", got[1]["msg"])
				assert.Empty(t, records(t, s.chain))
			},
		},
		{
			name: "detached with WithoutCancel",
			ctx: func(ctx context.Context, s sinks) context.Context {
				cctx, cancel := context.WithCancel(ctxlog.With(ctx, s.chainLog))
				detached := context.WithoutCancel(cctx)
				cancel()

				return detached
			},
			assert: onlyChain,
		},
		{
			name: "rebuilt from Background",
			ctx: func(ctx context.Context, s sinks) context.Context {
				_ = ctxlog.With(ctx, s.chainLog)

				return context.Background()
			},
			assert: onlyDefault,
		},
		{
			name: "routing logger on ctx",
			ctx: func(ctx context.Context, _ sinks) context.Context {
				return keyAnswerer{Context: ctx, logger: ctxlog.Routing()}
			},
			assert: onlyDefault,
		},
		{
			name: "routing logger put on ctx over a chain logger keeps the chain logger",
			ctx: func(ctx context.Context, s sinks) context.Context {
				return ctxlog.With(ctxlog.With(ctx, s.chainLog), ctxlog.Routing().With("k", "v"))
			},
			assert: onlyChain,
		},
		{
			name: "typed-nil value",
			ctx: func(ctx context.Context, _ sinks) context.Context {
				return keyAnswerer{Context: ctx, logger: (*slog.Logger)(nil)}
			},
			assert: onlyDefault,
		},
		{
			name: "wrong-type value",
			ctx: func(ctx context.Context, _ sinks) context.Context {
				return keyAnswerer{Context: ctx, logger: slog.Default().Handler()}
			},
			assert: onlyDefault,
		},
		{
			name:         "Enabled follows the resolved level",
			chainLevel:   slog.LevelWarn,
			defaultLevel: slog.LevelDebug,
			ctx: func(ctx context.Context, s sinks) context.Context {
				return ctxlog.With(ctx, s.chainLog)
			},
			log: func(ctx context.Context, l *slog.Logger) {
				l.InfoContext(ctx, "info")
				l.WarnContext(ctx, "hello")
			},
			assert: func(t *testing.T, s sinks) {
				got := records(t, s.chain)
				require.Len(t, got, 1)
				assert.Equal(t, "hello", got[0]["msg"])
				assert.Empty(t, records(t, s.def))
			},
		},
		{
			name: "WithAttrs and WithGroup replayed",
			ctx: func(ctx context.Context, s sinks) context.Context {
				return ctxlog.With(ctx, s.chainLog)
			},
			log: func(ctx context.Context, l *slog.Logger) {
				l.With("a", 1).WithGroup("g").With("b", 2).InfoContext(ctx, "hello", "c", 3)
			},
			assert: func(t *testing.T, s sinks) {
				got := records(t, s.chain)
				require.Len(t, got, 1)
				assert.InDelta(t, 1.0, got[0]["a"], 0)
				assert.Equal(t, map[string]any{"b": 2.0, "c": 3.0}, got[0]["g"])
			},
		},
		{
			name: "a nil context resolves to the default",
			ctx: func(context.Context, sinks) context.Context {
				return nil
			},
			log: func(ctx context.Context, l *slog.Logger) {
				l.Handler().Enabled(ctx, slog.LevelInfo)
				//nolint:staticcheck // a nil context is the input under test
				l.InfoContext(ctx, "hello")
			},
			assert: onlyDefault,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := sinks{chain: &bytes.Buffer{}, def: &bytes.Buffer{}}
			s.chainLog = slog.New(jsonAt(s.chain, tc.chainLevel))

			// Built before the default is swapped: every row is a default set
			// after construction.
			routing := ctxlog.Routing()

			swapDefault(t, ctxAttrHandler{jsonAt(s.def, tc.defaultLevel)})

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx, s)
			}

			if tc.log != nil {
				tc.log(ctx, routing)
			} else {
				routing.InfoContext(ctx, "hello") //nolint:contextcheck // ctx may be rebuilt on purpose
			}

			tc.assert(t, s)
		})
	}
}

func TestRouting_EnabledAnswersTheResolvedHandler(t *testing.T) {
	warn := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	swapDefault(t, slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelDebug}))

	h := ctxlog.Routing().Handler()

	assert.False(t, h.Enabled(ctxlog.With(t.Context(), warn), slog.LevelInfo), "a chain logger at Warn drops Info")
	assert.True(t, h.Enabled(t.Context(), slog.LevelDebug), "the default at Debug keeps Debug")
}

func TestRouting_DefaultThatIsItselfRoutingDoesNotLoop(t *testing.T) {
	buf := &bytes.Buffer{}
	ctxlog.SwapFallback(t, slog.NewJSONHandler(buf, nil))
	swapDefault(t, ctxlog.Routing().Handler())

	ctxlog.Routing().InfoContext(t.Context(), "hello")

	got := records(t, buf)
	require.Len(t, got, 1)
	assert.Equal(t, "hello", got[0]["msg"])
}

// ctxInjector hands every record to h with ctx, so slogtest, which logs on
// context.Background(), exercises the route through a chain logger.
type ctxInjector struct {
	h   slog.Handler
	ctx context.Context //nolint:containedctx // the context under test
}

func (c ctxInjector) Enabled(_ context.Context, l slog.Level) bool { return c.h.Enabled(c.ctx, l) } //nolint:contextcheck // the injected context is the one under test; the one passed in is ignored on purpose

func (c ctxInjector) Handle(_ context.Context, r slog.Record) error { return c.h.Handle(c.ctx, r) } //nolint:contextcheck // the injected context is the one under test; the one passed in is ignored on purpose

func (c ctxInjector) WithAttrs(attrs []slog.Attr) slog.Handler {
	return ctxInjector{c.h.WithAttrs(attrs), c.ctx}
}

func (c ctxInjector) WithGroup(name string) slog.Handler {
	return ctxInjector{c.h.WithGroup(name), c.ctx}
}

func TestRouting_SlogTest(t *testing.T) {
	t.Run("to the default", func(t *testing.T) {
		buf := &bytes.Buffer{}
		swapDefault(t, slog.NewJSONHandler(buf, nil))

		require.NoError(t, slogtest.TestHandler(ctxlog.Routing().Handler(), func() []map[string]any {
			return records(t, buf)
		}))
	})

	t.Run("to the chain logger", func(t *testing.T) {
		buf := &bytes.Buffer{}
		def := &bytes.Buffer{}
		swapDefault(t, slog.NewJSONHandler(def, nil))

		ctx := ctxlog.With(t.Context(), slog.New(slog.NewJSONHandler(buf, nil)))

		require.NoError(t, slogtest.TestHandler(ctxInjector{ctxlog.Routing().Handler(), ctx}, func() []map[string]any {
			return records(t, buf)
		}))
		assert.Empty(t, def.String())
	})
}

// panicHandler panics in Handle, as a broken consumer handler would.
type panicHandler struct{ slog.Handler }

func (panicHandler) Handle(context.Context, slog.Record) error { panic("consumer handler") }

func TestRouting_ConsumerHandlerPanicIsNotRecovered(t *testing.T) {
	swapDefault(t, slog.DiscardHandler)

	chain := slog.New(panicHandler{slog.NewJSONHandler(io.Discard, nil)})

	assert.PanicsWithValue(t, "consumer handler", func() {
		ctxlog.Routing().InfoContext(ctxlog.With(t.Context(), chain), "hello")
	})
}
