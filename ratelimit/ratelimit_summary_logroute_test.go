package ratelimit_test

// TestLogRouteSummary_SourceGuard replaces slog.Default() for its duration, so
// it does not run in parallel, and restores the logger it found.

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/ratelimit"
)

// summaryLines returns the suppressed-count summary lines out of one
// destination's output.
func summaryLines(out string) []string {
	var lines []string

	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "refusal records suppressed") {
			lines = append(lines, l)
		}
	}

	return lines
}

func TestLogRouteSummary_SourceGuard(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	const (
		srcA    = "203.0.113.1"
		srcB    = "203.0.113.2"
		srcNone = "203.0.113.3"
	)

	type testCase struct {
		name string
		own  bool
		// again checks srcA once more, under chain B, after the first round.
		again  bool
		assert func(t *testing.T, a, b, def, own string)
	}

	cases := []testCase{
		{
			name: "each key's summary goes to the chain its records went to",
			assert: func(t *testing.T, a, b, _, _ string) {
				require.Len(t, summaryLines(a), 1, "chain A: exactly its own key")
				assert.Contains(t, summaryLines(a)[0], srcA)
				require.Len(t, summaryLines(b), 1, "chain B: exactly its own key")
				assert.Contains(t, summaryLines(b)[0], srcB)
			},
		},
		{
			name:  "a key written under A and suppressed under B is summarised on A only",
			again: true,
			assert: func(t *testing.T, a, b, def, _ string) {
				require.Len(t, summaryLines(a), 1)
				assert.Contains(t, summaryLines(a)[0], srcA)
				assert.NotContains(t, b, srcA, "chain B received another chain's key")
				assert.NotContains(t, def, srcA, "the default received another chain's key")
			},
		},
		{
			name: "a key whose records went to no chain is summarised on the default",
			assert: func(t *testing.T, a, b, def, _ string) {
				require.Len(t, summaryLines(def), 1)
				assert.Contains(t, summaryLines(def)[0], srcNone)
				assert.NotContains(t, a, srcNone)
				assert.NotContains(t, b, srcNone)
			},
		},
		{
			name: "the guard's own logger receives every summary",
			own:  true,
			assert: func(t *testing.T, a, b, def, own string) {
				assert.Len(t, summaryLines(own), 3)
				assert.Empty(t, summaryLines(a))
				assert.Empty(t, summaryLines(b))
				assert.Empty(t, summaryLines(def))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
			aBuf, a := lrBuf()
			bBuf, b := lrBuf()
			defBuf, def := lrBuf()
			ownBuf, own := lrBuf()

			prev := slog.Default()
			slog.SetDefault(def)
			t.Cleanup(func() { slog.SetDefault(prev) })

			l := NewMockLimiter(gomock.NewController(t))
			l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

			var opts []ratelimit.GuardOption
			if tc.own {
				opts = append(opts, ratelimit.WithSourceGuardLogger(own))
			}

			g, err := ratelimit.NewSourceGuard(testFlow, l, opts...)
			require.NoError(t, err)

			ctxA := ctxlog.With(t.Context(), a)
			ctxB := ctxlog.With(t.Context(), b)

			check := func(ctx context.Context, src string) {
				_, err := g.Check(ctx, src)
				require.ErrorIs(t, err, ratelimit.ErrThrottled)
			}

			for range 2 {
				check(ctxA, srcA)
				check(ctxB, srcB)
				check(t.Context(), srcNone)
			}

			if tc.again {
				check(ctxB, srcA)
				check(ctxB, srcA)
			}

			g.Flush()

			tc.assert(t, aBuf.String(), bBuf.String(), defBuf.String(), ownBuf.String())
		})
	}
}
