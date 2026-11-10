package detach_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/detach"
)

type ctxKey struct{}

func TestBounded(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		d      time.Duration
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, got context.Context, cancel context.CancelFunc)
	}

	assertDeadlineWithin := func(d time.Duration) func(t *testing.T, got context.Context, cancel context.CancelFunc) {
		return func(t *testing.T, got context.Context, _ context.CancelFunc) {
			dl, ok := got.Deadline()
			require.True(t, ok, "context has no deadline")
			remaining := time.Until(dl)
			assert.Positive(t, remaining)
			assert.LessOrEqual(t, remaining, d)
			require.NoError(t, got.Err())
		}
	}

	cases := []testCase{
		{
			name:   "write timeout sets a deadline",
			d:      detach.WriteTimeout,
			assert: assertDeadlineWithin(detach.WriteTimeout),
		},
		{
			name:   "revocation timeout sets a deadline",
			d:      detach.RevocationTimeout,
			assert: assertDeadlineWithin(detach.RevocationTimeout),
		},
		{
			name: "parent value is readable",
			d:    detach.WriteTimeout,
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, ctxKey{}, "v")
			},
			assert: func(t *testing.T, got context.Context, _ context.CancelFunc) {
				assert.Equal(t, "v", got.Value(ctxKey{}))
			},
		},
		{
			name: "cancelling the parent leaves the context live",
			d:    detach.WriteTimeout,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			assert: func(t *testing.T, got context.Context, _ context.CancelFunc) {
				require.NoError(t, got.Err())
			},
		},
		{
			name: "parent deadline already passed does not end the context",
			d:    detach.WriteTimeout,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
				cancel() // already expired; releasing it does not change Err()
				return cctx
			},
			assert: func(t *testing.T, got context.Context, _ context.CancelFunc) {
				require.NoError(t, got.Err())
			},
		},
		{
			name: "returned cancel ends the context",
			d:    detach.WriteTimeout,
			assert: func(t *testing.T, got context.Context, cancel context.CancelFunc) {
				cancel()
				require.ErrorIs(t, got.Err(), context.Canceled)
			},
		},
		{
			name: "zero duration yields an expired context",
			d:    0,
			assert: func(t *testing.T, got context.Context, _ context.CancelFunc) {
				require.ErrorIs(t, got.Err(), context.DeadlineExceeded)
			},
		},
		{
			name: "negative duration yields an expired context",
			d:    -time.Second,
			assert: func(t *testing.T, got context.Context, _ context.CancelFunc) {
				require.ErrorIs(t, got.Err(), context.DeadlineExceeded)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			got, cancel := detach.Bounded(ctx, tc.d)
			t.Cleanup(cancel)
			tc.assert(t, got, cancel)
		})
	}
}

func TestBoundReached(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		d      time.Duration
		ctx    func(ctx context.Context) context.Context // nil means identity
		act    func(ctx context.Context, cancel context.CancelFunc)
		assert func(t *testing.T, bounded, parent context.Context)
	}

	cases := []testCase{
		{
			name: "after the bound passes",
			d:    time.Nanosecond,
			act: func(ctx context.Context, _ context.CancelFunc) {
				<-ctx.Done()
			},
			assert: func(t *testing.T, bounded, _ context.Context) {
				require.ErrorIs(t, bounded.Err(), context.DeadlineExceeded)
				assert.True(t, detach.BoundReached(bounded))
			},
		},
		{
			name: "zero duration is a bound that passed",
			d:    0,
			assert: func(t *testing.T, bounded, _ context.Context) {
				assert.True(t, detach.BoundReached(bounded))
			},
		},
		{
			name: "after the returned cancel, before the bound",
			d:    detach.WriteTimeout,
			act: func(_ context.Context, cancel context.CancelFunc) {
				cancel()
			},
			assert: func(t *testing.T, bounded, _ context.Context) {
				require.ErrorIs(t, bounded.Err(), context.Canceled)
				assert.False(t, detach.BoundReached(bounded))
			},
		},
		{
			name: "still live",
			d:    detach.WriteTimeout,
			assert: func(t *testing.T, bounded, _ context.Context) {
				assert.False(t, detach.BoundReached(bounded))
			},
		},
		{
			name: "a parent-derived context that is live",
			d:    detach.WriteTimeout,
			assert: func(t *testing.T, _, parent context.Context) {
				assert.False(t, detach.BoundReached(parent))
			},
		},
		{
			name: "a plain deadline that passed is not a bound",
			d:    detach.WriteTimeout,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
				cancel()
				return cctx
			},
			assert: func(t *testing.T, _, parent context.Context) {
				require.ErrorIs(t, parent.Err(), context.DeadlineExceeded)
				assert.False(t, detach.BoundReached(parent))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			parent := t.Context()
			if tc.ctx != nil {
				parent = tc.ctx(parent)
			}

			bounded, cancel := detach.Bounded(parent, tc.d)
			t.Cleanup(cancel)
			if tc.act != nil {
				tc.act(bounded, cancel)
			}
			tc.assert(t, bounded, parent)
		})
	}
}
