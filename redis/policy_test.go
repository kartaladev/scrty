package scrtyredis_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	scrtyredis "github.com/kartaladev/scrty/redis"
)

// TestLimiter_Policy pins the "Shared limiter" scenario: the limiter reports,
// through the optional contract, the limit and window it was built with, the
// window as the backend counts it. Construction does no I/O, so a client
// pointed at nothing is enough.
func TestLimiter_Policy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		window time.Duration
		assert func(t *testing.T, limit int, window time.Duration)
	}

	cases := []testCase{
		{
			name:   "limit and window as built",
			window: 15 * time.Minute,
			assert: func(t *testing.T, limit int, window time.Duration) {
				assert.Equal(t, 10, limit)
				assert.Equal(t, 15*time.Minute, window)
			},
		},
		{
			name:   "window finer than the backend counts is truncated",
			window: 15*time.Minute + 500*time.Nanosecond,
			assert: func(t *testing.T, limit int, window time.Duration) {
				assert.Equal(t, 10, limit)
				assert.Equal(t, 15*time.Minute, window)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, _ := recordingClient(t, nil)
			l, err := scrtyredis.NewLimiter(client, "ns", 10, tc.window)
			require.NoError(t, err)

			var r ratelimit.PolicyReporter = l
			limit, window := r.Policy()
			tc.assert(t, limit, window)
		})
	}
}
