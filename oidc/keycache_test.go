package oidc_test

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
)

// newCacheManager returns a manager for providers "corp" (p) and any extra
// providers, sending every request through p's in-memory client so that it
// can run inside a testing/synctest bubble. Build it inside the bubble: its
// default clock, time.Now, then reads the bubble's fake time.
func newCacheManager(t *testing.T, p *testProvider, opts ...oidc.ManagerOption) *oidc.Manager {
	t.Helper()

	reg, err := oidc.NewRegistry(p.Provider("corp"))
	require.NoError(t, err)
	m, err := oidc.NewManager(reg, stubBroker{},
		append([]oidc.ManagerOption{oidc.WithOutboundClient(p.InMemoryOutbound(t))}, opts...)...)
	require.NoError(t, err)

	return m
}

func TestKeyCacheTTL(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []oidc.ManagerOption
		setup  func(p *testProvider)
		after  time.Duration // time between the first and second keysFor
		assert func(t *testing.T, p *testProvider, err error)
	}

	cases := []testCase{
		{
			name: "a fresh entry makes no request", after: 10 * time.Minute,
			assert: func(t *testing.T, p *testProvider, err error) {
				require.NoError(t, err)
				assert.EqualValues(t, 1, p.jwksCalls.Load())
				assert.EqualValues(t, 1, p.discoveryCalls.Load())
			},
		},
		{
			name: "an expired entry is refetched once", after: 20 * time.Minute,
			assert: func(t *testing.T, p *testProvider, err error) {
				require.NoError(t, err)
				assert.EqualValues(t, 2, p.jwksCalls.Load())
			},
		},
		{
			name: "an entry exactly at the TTL is refetched", after: oidc.DefaultDiscoveryTTL,
			assert: func(t *testing.T, p *testProvider, err error) {
				require.NoError(t, err)
				assert.EqualValues(t, 2, p.jwksCalls.Load())
			},
		},
		{
			name: "a consumer TTL of one hour serves a 30-minute-old entry",
			opts: []oidc.ManagerOption{oidc.WithDiscoveryTTL(time.Hour)}, after: 30 * time.Minute,
			assert: func(t *testing.T, p *testProvider, err error) {
				require.NoError(t, err)
				assert.EqualValues(t, 1, p.jwksCalls.Load())
				assert.EqualValues(t, 1, p.discoveryCalls.Load())
			},
		},
		{
			name:  "a non-JSON key set is a provider failure",
			setup: func(p *testProvider) { p.jwksBody.Store("<html>oops</html>") },
			assert: func(t *testing.T, _ *testProvider, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
			},
		},
		{
			name:  "an empty key set is a provider failure",
			setup: func(p *testProvider) { p.jwksBody.Store(`{"keys":[]}`) },
			assert: func(t *testing.T, _ *testProvider, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
			},
		},
		{
			name:  "a key set with no key for an accepted algorithm is a provider failure",
			setup: func(p *testProvider) { p.jwksBody.Store(`{"keys":[{"kty":"oct","kid":"s","k":"c2VjcmV0"}]}`) },
			assert: func(t *testing.T, _ *testProvider, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
			},
		},
		{
			name:  "a truncated key set body is a provider failure",
			setup: func(p *testProvider) { p.jwksBody.Store(`{"keys":[{"kty":"RSA"`) },
			assert: func(t *testing.T, _ *testProvider, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
				require.NotErrorIs(t, err, oidc.ErrUnknownSigningKeyForTest)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newTestProvider(t)
			if tc.setup != nil {
				tc.setup(p)
			}
			synctest.Test(t, func(t *testing.T) {
				m := newCacheManager(t, p, tc.opts...)

				_, _ = oidc.KeysForTest(m, t.Context(), "corp", "k1")
				time.Sleep(tc.after)
				_, err := oidc.KeysForTest(m, t.Context(), "corp", "k1")
				tc.assert(t, p, err)
			})
		})
	}
}

func TestKeyCacheOptions(t *testing.T) {
	t.Parallel()

	p := newTestProvider(t)
	reg, err := oidc.NewRegistry(p.Provider("corp"))
	require.NoError(t, err)

	type testCase struct {
		name   string
		opt    oidc.ManagerOption
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) { require.ErrorIs(t, err, oidc.ErrConfig) }
	accepted := func(t *testing.T, err error) { require.NoError(t, err) }

	cases := []testCase{
		{name: "a zero TTL is refused", opt: oidc.WithDiscoveryTTL(0), assert: refused},
		{name: "a negative TTL is refused", opt: oidc.WithDiscoveryTTL(-time.Minute), assert: refused},
		{name: "a positive TTL is accepted", opt: oidc.WithDiscoveryTTL(time.Hour), assert: accepted},
		{name: "a zero backoff base is refused", opt: oidc.WithDiscoveryFailureBackoff(0, time.Second), assert: refused},
		{name: "a negative backoff base is refused", opt: oidc.WithDiscoveryFailureBackoff(-time.Second, time.Second), assert: refused},
		{name: "a backoff cap below the base is refused", opt: oidc.WithDiscoveryFailureBackoff(2*time.Second, time.Second), assert: refused},
		{name: "a zero cooldown is refused", opt: oidc.WithJWKSRefetchCooldown(0), assert: refused},
		{name: "a negative cooldown is refused", opt: oidc.WithJWKSRefetchCooldown(-time.Second), assert: refused},
		{name: "a positive cooldown is accepted", opt: oidc.WithJWKSRefetchCooldown(time.Minute), assert: accepted},
		{name: "a negative stale window is refused", opt: oidc.WithDiscoveryStaleWhileError(-time.Second), assert: refused},
		{name: "a zero stale window is accepted", opt: oidc.WithDiscoveryStaleWhileError(0), assert: accepted},
		{name: "a positive stale window is accepted", opt: oidc.WithDiscoveryStaleWhileError(time.Minute), assert: accepted},
		{name: "a backoff cap equal to the base is accepted", opt: oidc.WithDiscoveryFailureBackoff(time.Second, time.Second), assert: accepted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := oidc.NewManager(reg, stubBroker{}, tc.opt)
			tc.assert(t, err)
		})
	}
}
