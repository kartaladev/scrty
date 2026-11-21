package ctxlog_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/ctxlog"
)

// TestRouting_Allocations pins that a routing logger with recorded With calls
// costs no more allocations than a plain logger with the same attributes: a
// dropped record none, a written one no replay once the destination is cached.
func TestRouting_Allocations(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates on its own; allocation counts are pinned without -race")
	}

	chain := slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	swapDefault(t, slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))

	with := func(l *slog.Logger) *slog.Logger {
		return l.With("component", "limiter").WithGroup("g").With("k", "v")
	}

	chainCtx := ctxlog.With(t.Context(), chain)
	plainCtx := t.Context()
	routing := with(ctxlog.Routing())
	plain := with(chain)

	plainWritten := testing.AllocsPerRun(100, func() { plain.InfoContext(chainCtx, "hello") })

	type testCase struct {
		name   string
		run    func()
		assert func(t *testing.T, allocs float64)
	}

	cases := []testCase{
		{
			name: "dropped record to the chain logger",
			run:  func() { routing.DebugContext(chainCtx, "dropped") },
			assert: func(t *testing.T, allocs float64) {
				assert.Zero(t, allocs)
			},
		},
		{
			name: "dropped record to the default",
			run:  func() { routing.DebugContext(plainCtx, "dropped") },
			assert: func(t *testing.T, allocs float64) {
				assert.Zero(t, allocs)
			},
		},
		{
			name: "written record to the chain logger",
			run:  func() { routing.InfoContext(chainCtx, "hello") },
			assert: func(t *testing.T, allocs float64) {
				assert.LessOrEqual(t, allocs, plainWritten, "no allocations beyond a plain logger's")
			},
		},
		{
			name: "written record to the default",
			run:  func() { routing.InfoContext(plainCtx, "hello") },
			assert: func(t *testing.T, allocs float64) {
				assert.LessOrEqual(t, allocs, plainWritten, "no allocations beyond a plain logger's")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.run() // the first record after a change of destination replays
			allocs := testing.AllocsPerRun(100, tc.run)
			t.Logf("allocs per record: %v (plain logger, written: %v)", allocs, plainWritten)
			tc.assert(t, allocs)
		})
	}
}

// countHandler counts the records it is handed carrying the "component"
// attribute it was given, so a record that reached the wrong destination or
// lost its replayed attributes is seen.
type countHandler struct {
	n         *atomic.Int64
	component string
}

func (countHandler) Enabled(context.Context, slog.Level) bool { return true }

func (c countHandler) Handle(context.Context, slog.Record) error {
	if c.component == "limiter" {
		c.n.Add(1)
	}

	return nil
}

func (c countHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	for _, a := range attrs {
		if a.Key == "component" {
			c.component = a.Value.String()
		}
	}

	return c
}

func (c countHandler) WithGroup(string) slog.Handler { return c }

// TestRouting_CachedReplayFollowsTheDestination pins that the cached replay is
// rebuilt whenever the destination changes, alternating chains concurrently
// and swapping the process default, so no record reaches the logger the cache
// was built for instead of its own.
func TestRouting_CachedReplayFollowsTheDestination(t *testing.T) {
	var defA, defB, chainA, chainB atomic.Int64

	swapDefault(t, countHandler{n: &defA})

	l := ctxlog.Routing().With("component", "limiter")
	ctxA := ctxlog.With(t.Context(), slog.New(countHandler{n: &chainA}))
	ctxB := ctxlog.With(t.Context(), slog.New(countHandler{n: &chainB}))

	var wg sync.WaitGroup

	for i := range 8 {
		wg.Go(func() {
			ctx := ctxA
			if i%2 == 1 {
				ctx = ctxB
			}

			for range 500 {
				l.InfoContext(ctx, "hello")
			}
		})
	}

	wg.Wait()

	l.InfoContext(t.Context(), "to default A")
	slog.SetDefault(slog.New(countHandler{n: &defB}))
	l.InfoContext(t.Context(), "to default B")

	assert.Equal(t, int64(2000), chainA.Load())
	assert.Equal(t, int64(2000), chainB.Load())
	assert.Equal(t, int64(1), defA.Load())
	assert.Equal(t, int64(1), defB.Load())
}
