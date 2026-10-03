package ratelimittest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
)

// Run executes the conformance suite against h.
//
// Cases run one after another, because Advance moves a clock the whole
// harness shares.
func Run(t *testing.T, h Harness) {
	t.Helper()

	type testCase struct {
		name   string
		limit  int
		window time.Duration
		assert func(t *testing.T, h Harness, l ratelimit.Limiter)
	}

	cases := []testCase{
		{
			name: "no failures is not exceeded", limit: 3, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				requireExceeded(t, l, "k", false)
			},
		},
		{
			name: "limit minus one is not exceeded", limit: 3, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				record(t, l, "k", 2)
				requireExceeded(t, l, "k", false)
			},
		},
		{
			name: "limit is exceeded", limit: 3, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				record(t, l, "k", 3)
				requireExceeded(t, l, "k", true)
			},
		},
		{
			name: "other keys do not count", limit: 1, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				record(t, l, "a", 1)
				requireExceeded(t, l, "b", false)
			},
		},
		{
			name: "one microsecond inside the window counts", limit: 1, window: time.Minute,
			assert: func(t *testing.T, h Harness, l ratelimit.Limiter) {
				record(t, l, "k", 1)
				h.Advance(time.Minute - time.Microsecond)
				requireExceeded(t, l, "k", true)
			},
		},
		{
			// The check in the middle matters: a limiter that refreshes a key's
			// lifetime when it is merely asked about it would never let it expire.
			name: "exactly one window old does not count", limit: 1, window: time.Minute,
			assert: func(t *testing.T, h Harness, l ratelimit.Limiter) {
				record(t, l, "k", 1)
				h.Advance(30 * time.Second)
				requireExceeded(t, l, "k", true)
				h.Advance(30 * time.Second)
				requireExceeded(t, l, "k", false)
			},
		},
		{
			// Two failures 30s apart are inside one window wherever they fall
			// against a fixed bucket boundary. The pairs start 50s apart, so one
			// of them straddles a minute boundary whatever the clock's phase.
			name: "failures straddling a boundary count together", limit: 2, window: time.Minute,
			assert: func(t *testing.T, h Harness, l ratelimit.Limiter) {
				for i := range 4 {
					key := fmt.Sprintf("pair-%d", i)
					record(t, l, key, 1)
					h.Advance(30 * time.Second)
					record(t, l, key, 1)
					requireExceeded(t, l, key, true)
					h.Advance(20 * time.Second)
				}
			},
		},
		{
			name: "excess failures keep the newest stamps", limit: 2, window: time.Minute,
			assert: func(t *testing.T, h Harness, l ratelimit.Limiter) {
				record(t, l, "k", 1)
				h.Advance(40 * time.Second)
				record(t, l, "k", 2) // three recorded, cap 2: the oldest is dropped
				h.Advance(30 * time.Second)
				requireExceeded(t, l, "k", true) // both kept stamps are 30s old
			},
		},
		{
			name: "ended context: Exceeded returns true and an error", limit: 3, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				exceeded, err := l.Exceeded(endedContext(t), "k")
				require.Error(t, err)
				assert.True(t, exceeded)
			},
		},
		{
			name: "ended context: RecordFailure still records", limit: 1, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				_ = l.RecordFailure(endedContext(t), "k")
				requireExceeded(t, l, "k", true)
			},
		},
		{
			name: "concurrent use ends exceeded without a race", limit: 5, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				var wg sync.WaitGroup
				for i := range 64 {
					wg.Go(func() {
						key := fmt.Sprintf("k%d", i%4)
						_, _ = l.Exceeded(t.Context(), key)
						_ = l.RecordFailure(t.Context(), key)
					})
				}
				wg.Wait()
				for i := range 4 {
					requireExceeded(t, l, fmt.Sprintf("k%d", i), true)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := h.New(t, "conformance", tc.limit, tc.window)
			tc.assert(t, h, l)
		})
	}

	runShared(t, h)
}

func endedContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	return ctx
}

// record records n failures for key, and fails the test if any is refused.
func record(t *testing.T, l ratelimit.Limiter, key string, n int) {
	t.Helper()

	for range n {
		require.NoError(t, l.RecordFailure(t.Context(), key))
	}
}

// requireExceeded asserts the limiter's answer for key, without an error.
func requireExceeded(t *testing.T, l ratelimit.Limiter, key string, want bool) {
	t.Helper()

	got, err := l.Exceeded(t.Context(), key)
	require.NoError(t, err)
	require.Equal(t, want, got, "Exceeded(%q)", key)
}
