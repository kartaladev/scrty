package ratelimit_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
)

func TestMemoryLimiterFactory(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		limit  int
		window time.Duration
		assert func(t *testing.T, f ratelimit.LimiterFactory, l ratelimit.Limiter, err error)
	}

	cases := []testCase{
		{
			name: "builds a working limiter", limit: 2, window: time.Minute,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, l ratelimit.Limiter, err error) {
				require.NoError(t, err)
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				exceeded, err := l.Exceeded(t.Context(), "k")
				require.NoError(t, err)
				assert.True(t, exceeded)
			},
		},
		{
			name: "each call has its own buckets", limit: 1, window: time.Minute,
			assert: func(t *testing.T, f ratelimit.LimiterFactory, l ratelimit.Limiter, err error) {
				require.NoError(t, err)
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				other, err := f.NewLimiter("ns", 1, time.Minute)
				require.NoError(t, err)
				exceeded, err := other.Exceeded(t.Context(), "k")
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			name: "zero limit refused", limit: 0, window: time.Minute,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, _ ratelimit.Limiter, err error) {
				require.ErrorIs(t, err, ratelimit.ErrConfig)
			},
		},
		{
			name: "negative limit refused", limit: -1, window: time.Minute,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, _ ratelimit.Limiter, err error) {
				require.ErrorIs(t, err, ratelimit.ErrConfig)
			},
		},
		{
			name: "zero window refused", limit: 1, window: 0,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, _ ratelimit.Limiter, err error) {
				require.ErrorIs(t, err, ratelimit.ErrConfig)
			},
		},
		{
			name: "negative window refused", limit: 1, window: -time.Second,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, _ ratelimit.Limiter, err error) {
				require.ErrorIs(t, err, ratelimit.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := ratelimit.MemoryLimiterFactory(
				ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
			l, err := f.NewLimiter("ns", tc.limit, tc.window)
			tc.assert(t, f, l, err)
		})
	}
}

func TestMemoryLimiterFactory_OptionsApplyToEveryLimiter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []ratelimit.MemoryOption
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:   "a nil logger option is refused when a limiter is built",
			opts:   []ratelimit.MemoryOption{ratelimit.WithMemoryLimiterLogger(nil)},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, ratelimit.ErrConfig) },
		},
		{
			name:   "valid options build",
			opts:   []ratelimit.MemoryOption{ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler))},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := ratelimit.MemoryLimiterFactory(tc.opts...).NewLimiter("ns", 1, time.Minute)
			tc.assert(t, err)
		})
	}
}
