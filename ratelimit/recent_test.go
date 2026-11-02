package ratelimit_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/ratelimit"
)

func TestMemoryLimiter_HasRecentFailures(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock)
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, has bool, err error)
	}

	cases := []testCase{
		{
			name: "a key with no failure has none",
			assert: func(t *testing.T, has bool, err error) {
				require.NoError(t, err)
				assert.False(t, has)
			},
		},
		{
			name: "one failure in the window is a recent failure, far below the limit",
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				recordFor(t, l, "k")
			},
			assert: func(t *testing.T, has bool, err error) {
				require.NoError(t, err)
				assert.True(t, has)
			},
		},
		{
			name: "a failure another key recorded is not this key's",
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				recordFor(t, l, "other")
			},
			assert: func(t *testing.T, has bool, err error) {
				require.NoError(t, err)
				assert.False(t, has)
			},
		},
		{
			name: "a failure that has left the window is not recent",
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock) {
				recordFor(t, l, "k")
				clk.Advance(testWindow)
			},
			assert: func(t *testing.T, has bool, err error) {
				require.NoError(t, err)
				assert.False(t, has)
			},
		},
		{
			name: "an ended context is an error, reported as having failures",
			ctx: func(ctx context.Context) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				cancel()

				return ctx
			},
			assert: func(t *testing.T, has bool, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.True(t, has, "a caller reading only the bool still asks")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, clk := newExpiryLimiter(t)
			if tc.setup != nil {
				tc.setup(t, l, clk)
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			has, err := l.HasRecentFailures(ctx, "k")
			tc.assert(t, has, err)
		})
	}
}

// TestMemoryLimiter_HasRecentFailuresWhenFull pins that a full limiter cannot
// say a key it does not hold is clean: the key's failure may be one it had no
// room to store.
//
// Not a row of TestMemoryLimiter_HasRecentFailures: the limiter is built with
// a key cap of its own.
func TestMemoryLimiter_HasRecentFailuresWhenFull(t *testing.T) {
	t.Parallel()

	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterMaxKeys(1), ratelimit.WithMemoryLimiterLogger(discardLogger()))
	require.NoError(t, err)

	recordFor(t, l, "held")

	has, err := l.HasRecentFailures(t.Context(), "unheld")
	require.ErrorIs(t, err, ratelimit.ErrLimiterFull)
	assert.True(t, has)

	has, err = l.HasRecentFailures(t.Context(), "held")
	require.NoError(t, err)
	assert.True(t, has, "a held key is answered as usual")
}

// reportingLimiter is a consumer's limiter that also reports recent failures.
type reportingLimiter struct {
	*MockLimiter
	*MockRecentFailureReporter
}

func TestSourceGuard_HasRecentFailures(t *testing.T) {
	t.Parallel()

	errDown := errors.New("redis: connection refused to 10.0.0.9")

	type testCase struct {
		name    string
		limiter func(t *testing.T) ratelimit.Limiter
		addr    string
		setup   func(t *testing.T, g *ratelimit.SourceGuard)
		ctx     func(ctx context.Context) context.Context
		assert  func(t *testing.T, has bool, logs string)
	}

	memory := func(t *testing.T) ratelimit.Limiter { return memoryLimiter(t) }

	reporting := func(has bool, err error) func(t *testing.T) ratelimit.Limiter {
		return func(t *testing.T) ratelimit.Limiter {
			ctrl := gomock.NewController(t)
			r := NewMockRecentFailureReporter(ctrl)
			r.EXPECT().HasRecentFailures(gomock.Any(), testFlow+":"+testSource).Return(has, err)

			return reportingLimiter{MockLimiter: NewMockLimiter(ctrl), MockRecentFailureReporter: r}
		}
	}

	cases := []testCase{
		{
			name: "a clean source has none", limiter: memory, addr: testSource,
			assert: func(t *testing.T, has bool, _ string) { assert.False(t, has) },
		},
		{
			name: "a source with a recorded failure has one", limiter: memory, addr: testSource,
			setup: func(t *testing.T, g *ratelimit.SourceGuard) {
				src, err := g.Check(t.Context(), testSource)
				require.NoError(t, err)
				g.RecordFailure(t.Context(), src)
			},
			assert: func(t *testing.T, has bool, _ string) { assert.True(t, has) },
		},
		{
			name: "the limiter is asked under the key the guard counts by", limiter: reporting(false, nil),
			addr:   testSource,
			assert: func(t *testing.T, has bool, _ string) { assert.False(t, has) },
		},
		{
			name: "a limiter that does not report is reported as having failures",
			limiter: func(t *testing.T) ratelimit.Limiter {
				return NewMockLimiter(gomock.NewController(t))
			},
			addr:   testSource,
			assert: func(t *testing.T, has bool, _ string) { assert.True(t, has) },
		},
		{
			name:    "a limiter that cannot answer is reported as having failures, and recorded without its text",
			limiter: reporting(false, errDown), addr: testSource,
			assert: func(t *testing.T, has bool, logs string) {
				assert.True(t, has)
				assert.Contains(t, logs, `"level":"WARN"`)
				assert.NotContains(t, logs, "10.0.0.9")
			},
		},
		{
			name: "a context that ended is reported as having failures, at debug",
			limiter: func(t *testing.T) ratelimit.Limiter {
				ctrl := gomock.NewController(t)
				r := NewMockRecentFailureReporter(ctrl)
				r.EXPECT().HasRecentFailures(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ string) (bool, error) { return true, ctx.Err() })

				return reportingLimiter{MockLimiter: NewMockLimiter(ctrl), MockRecentFailureReporter: r}
			},
			addr: testSource,
			ctx: func(ctx context.Context) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				cancel()

				return ctx
			},
			assert: func(t *testing.T, has bool, logs string) {
				assert.True(t, has)
				assert.NotContains(t, logs, `"level":"WARN"`)
				assert.NotContains(t, logs, `"level":"ERROR"`)
			},
		},
		{
			name: "an address that cannot be attributed is reported as having failures", limiter: memory,
			addr:   "not-an-address",
			assert: func(t *testing.T, has bool, _ string) { assert.True(t, has) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec, logger := newLogRecorder()

			g, err := ratelimit.NewSourceGuard(testFlow, tc.limiter(t), ratelimit.WithSourceGuardLogger(logger))
			require.NoError(t, err)

			if tc.setup != nil {
				tc.setup(t, g)
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			has := g.HasRecentFailures(ctx, tc.addr)
			tc.assert(t, has, strings.TrimSpace(rec.String()))
		})
	}
}
