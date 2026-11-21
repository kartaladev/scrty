package unavailable_test

// TestLogRouteSummary_Unavailable replaces slog.Default() for its duration, so
// it does not run in parallel, and restores the logger it found.

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/ratelimit"
)

// summaryNamespaces lists the namespaces of the allow-mode summaries in out.
func summaryNamespaces(out string) []string {
	var found []string

	for _, ns := range []string{"ns-a", "ns-b", "ns-none"} {
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, msgAllowSupp) && strings.Contains(line, `"namespace":"`+ns+`"`) {
				found = append(found, ns)
			}
		}
	}

	return found
}

func TestLogRouteSummary_Unavailable(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		own    bool
		assert func(t *testing.T, a, b, def, own string)
	}

	cases := []testCase{
		{
			name: "each key's summary goes to the chain its records went to",
			assert: func(t *testing.T, a, b, _, _ string) {
				assert.Equal(t, []string{"ns-a"}, summaryNamespaces(a))
				assert.Equal(t, []string{"ns-b"}, summaryNamespaces(b))
			},
		},
		{
			name: "a key whose records went to no chain is summarised on the default",
			assert: func(t *testing.T, _, _, def, _ string) {
				assert.Equal(t, []string{"ns-none"}, summaryNamespaces(def))
			},
		},
		{
			name: "the configuration's own logger receives every summary",
			own:  true,
			assert: func(t *testing.T, a, b, def, own string) {
				assert.Len(t, summaryNamespaces(own), 3)
				assert.Empty(t, summaryNamespaces(a))
				assert.Empty(t, summaryNamespaces(b))
				assert.Empty(t, summaryNamespaces(def))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
			var a, b, def, own routeBuffer

			prev := slog.Default()
			slog.SetDefault(routeLogger(&def))
			t.Cleanup(func() { slog.SetDefault(prev) })

			build := func(ns string) (unavailable.Limiter, *clockwork.FakeClock) {
				clk := clockwork.NewFakeClockAt(epoch)

				cfg := unavailable.DefaultConfig()
				cfg.Mode = ratelimit.UnavailableAllow
				cfg.Clock = clk
				if tc.own {
					cfg.Logger = routeLogger(&own)
				}

				backend := NewMockLimiter(gomock.NewController(t))
				gomock.InOrder(
					backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(true, errDown),
					backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, nil),
				)

				l, err := unavailable.Wrap(backend, ns, testLimit, testWindow, cfg)
				require.NoError(t, err)

				return l, clk
			}

			type step struct {
				ns  string
				log *routeBuffer
			}

			steps := []step{{"ns-a", &a}, {"ns-b", &b}, {"ns-none", nil}}
			limiters := make([]unavailable.Limiter, len(steps))
			clocks := make([]*clockwork.FakeClock, len(steps))

			ctxs := make([]context.Context, len(steps))
			for i, s := range steps {
				ctxs[i] = t.Context()
				if s.log != nil {
					ctxs[i] = ctxlog.With(ctxs[i], routeLogger(s.log))
				}
			}

			for i, s := range steps {
				limiters[i], clocks[i] = build(s.ns)

				// One outage record is written; the next two are suppressed.
				for range 3 {
					_, err := limiters[i].Exceeded(ctxs[i], testKey)
					require.NoError(t, err)
				}
			}

			// Recovery reports what each window suppressed.
			for i := range steps {
				clocks[i].Advance(unavailable.DefaultProbeInterval)

				_, err := limiters[i].Exceeded(ctxs[i], testKey)
				require.NoError(t, err)
			}

			tc.assert(t, a.String(), b.String(), def.String(), own.String())
		})
	}
}

// TestLogRouteSummary_Unavailable_SuppressedUnderOtherChain pins that a
// namespace's records written under chain A and suppressed under chain B are
// summarised on A: the summary never follows the chain that suppressed them.
func TestLogRouteSummary_Unavailable_SuppressedUnderOtherChain(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	var a, b, def routeBuffer

	prev := slog.Default()
	slog.SetDefault(routeLogger(&def))
	t.Cleanup(func() { slog.SetDefault(prev) })

	clk := clockwork.NewFakeClockAt(epoch)

	cfg := unavailable.DefaultConfig()
	cfg.Mode = ratelimit.UnavailableAllow
	cfg.Clock = clk

	backend := NewMockLimiter(gomock.NewController(t))
	gomock.InOrder(
		backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(true, errDown),
		backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, nil),
	)

	l, err := unavailable.Wrap(backend, "ns-a", testLimit, testWindow, cfg)
	require.NoError(t, err)

	ctxA := ctxlog.With(t.Context(), routeLogger(&a))
	ctxB := ctxlog.With(t.Context(), routeLogger(&b))

	// One outage record is written under A; the rest fall in the same window
	// and the ones under B are suppressed.
	for _, ctx := range []context.Context{ctxA, ctxA, ctxB, ctxB} {
		_, err := l.Exceeded(ctx, testKey)
		require.NoError(t, err)
	}

	clk.Advance(unavailable.DefaultProbeInterval)

	_, err = l.Exceeded(ctxB, testKey)
	require.NoError(t, err)

	assert.Equal(t, []string{"ns-a"}, summaryNamespaces(a.String()))
	assert.Empty(t, summaryNamespaces(b.String()), "chain B received chain A's namespace summary")
	assert.Empty(t, summaryNamespaces(def.String()), "the default received chain A's namespace summary")
}
