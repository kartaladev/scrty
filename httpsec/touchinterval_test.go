package httpsec_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// TestTouchIntervalWiring pins that a chain refuses to build when its session
// manager coalesces activity over an interval an idle policy does not exceed.
func TestTouchIntervalWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		interval time.Duration
		idle     []time.Duration
		assert   func(t *testing.T, err error)
	}

	builds := func(t *testing.T, err error) {
		t.Helper()

		require.NoError(t, err)
	}

	refused := func(interval, idle string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), interval)
			assert.Contains(t, err.Error(), idle)
		}
	}

	cases := []testCase{
		{
			name:     "idle policy shorter than the interval is refused",
			interval: 10 * time.Minute,
			idle:     []time.Duration{5 * time.Minute},
			assert:   refused("10m0s", "5m0s"),
		},
		{
			name:     "idle policy equal to the interval is refused",
			interval: 10 * time.Minute,
			idle:     []time.Duration{10 * time.Minute},
			assert:   refused("10m0s", "10m0s"),
		},
		{
			name:     "idle policy longer than the interval builds",
			interval: 10 * time.Minute,
			idle:     []time.Duration{15 * time.Minute},
			assert:   builds,
		},
		{
			name:     "the shortest of several idle policies decides",
			interval: 10 * time.Minute,
			idle:     []time.Duration{time.Hour, 5 * time.Minute},
			assert:   refused("10m0s", "5m0s"),
		},
		{
			name:     "no interval builds with a short idle policy",
			interval: 0,
			idle:     []time.Duration{5 * time.Minute},
			assert:   builds,
		},
		{
			name:     "an interval with no idle policy builds",
			interval: 10 * time.Minute,
			assert:   builds,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessions, err := session.New(
				session.WithStore(session.NewMemoryStore()),
				session.WithTouchInterval(tc.interval),
			)
			require.NoError(t, err)

			var policies []policy.Policy

			for _, idle := range tc.idle {
				p, err := policy.NewIdleTimeout(policy.WithIdleTimeout(idle))
				require.NoError(t, err)

				policies = append(policies, p)
			}

			_, err = httpsec.New(
				httpsec.WithSessions(sessions),
				httpsec.WithPolicyEngine(engineOf(t, policies...)),
			)
			tc.assert(t, err)
		})
	}
}
