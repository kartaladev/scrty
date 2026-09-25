package oidc_test

import (
	"log/slog"
	"testing"
	"testing/synctest"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
)

func TestKeyCacheStaleWindow(t *testing.T) {
	t.Parallel()

	tenMinutes := oidc.WithDiscoveryStaleWhileError(10 * time.Minute)

	type testCase struct {
		name string
		opts []oidc.ManagerOption
		// act runs with the key set (and document) fetched at time zero.
		act    func(t *testing.T, p *testProvider, keys func(kid string) (jwk.Set, error))
		assert func(t *testing.T, logs cacheLogCapture)
	}

	cases := []testCase{
		{
			name: "the default refuses an expired set during an outage",
			act: func(t *testing.T, p *testProvider, keys func(string) (jwk.Set, error)) {
				time.Sleep(20 * time.Minute)
				p.failJWKS.Store(true)
				_, err := keys("k1")
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
			},
			assert: func(t *testing.T, logs cacheLogCapture) {
				assert.Empty(t, logs.matching("stale"))
			},
		},
		{
			name: "a consumer window serves an expired set with a warning per use",
			opts: []oidc.ManagerOption{tenMinutes},
			act: func(t *testing.T, p *testProvider, keys func(string) (jwk.Set, error)) {
				time.Sleep(20 * time.Minute)
				p.failJWKS.Store(true)
				for range 2 { // the second use falls inside the backoff window
					set, err := keys("k1")
					require.NoError(t, err)
					_, ok := set.LookupKeyID("k1")
					require.True(t, ok)
				}
			},
			assert: func(t *testing.T, logs cacheLogCapture) {
				records := logs.matching("stale")
				require.Len(t, records, 2)
				assert.Equal(t, slog.LevelWarn, records[0].Level)
				attrs := map[string]string{}
				records[0].Attrs(func(a slog.Attr) bool {
					attrs[a.Key] = a.Value.String()
					return true
				})
				assert.Equal(t, "corp", attrs["provider"])
				assert.Equal(t, (20 * time.Minute).String(), attrs["age"])
			},
		},
		{
			name: "a stale set lacking the kid is a provider failure",
			opts: []oidc.ManagerOption{tenMinutes},
			act: func(t *testing.T, p *testProvider, keys func(string) (jwk.Set, error)) {
				time.Sleep(20 * time.Minute)
				p.failJWKS.Store(true)
				_, err := keys("k2")
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
				require.NotErrorIs(t, err, oidc.ErrUnknownSigningKeyForTest)
			},
			assert: func(t *testing.T, logs cacheLogCapture) {
				assert.Empty(t, logs.matching("stale"))
			},
		},
		{
			name: "the end of TTL plus window is still served",
			opts: []oidc.ManagerOption{tenMinutes},
			act: func(t *testing.T, p *testProvider, keys func(string) (jwk.Set, error)) {
				time.Sleep(25 * time.Minute)
				p.failJWKS.Store(true)
				_, err := keys("k1")
				require.NoError(t, err)
			},
			assert: func(t *testing.T, logs cacheLogCapture) {
				assert.Len(t, logs.matching("stale"), 1)
			},
		},
		{
			name: "beyond TTL plus window is refused",
			opts: []oidc.ManagerOption{tenMinutes},
			act: func(t *testing.T, p *testProvider, keys func(string) (jwk.Set, error)) {
				time.Sleep(26 * time.Minute)
				p.failJWKS.Store(true)
				_, err := keys("k1")
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
			},
			assert: func(t *testing.T, logs cacheLogCapture) {
				assert.Empty(t, logs.matching("stale"))
			},
		},
		{
			name: "a stale discovery document still lets the key set be fetched",
			opts: []oidc.ManagerOption{tenMinutes},
			act: func(t *testing.T, p *testProvider, keys func(string) (jwk.Set, error)) {
				time.Sleep(20 * time.Minute)
				p.failDiscovery.Store(true)
				_, err := keys("k1")
				require.NoError(t, err)
				assert.EqualValues(t, 2, p.jwksCalls.Load())
			},
			assert: func(t *testing.T, logs cacheLogCapture) {
				assert.Len(t, logs.matching("stale"), 1)
			},
		},
		{
			name: "a failed unknown-kid refetch never falls back to the fresh set",
			opts: []oidc.ManagerOption{tenMinutes},
			act: func(t *testing.T, p *testProvider, keys func(string) (jwk.Set, error)) {
				time.Sleep(time.Minute)
				p.failJWKS.Store(true)
				set, err := keys("k2")
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
				require.Nil(t, set)
			},
			assert: func(t *testing.T, logs cacheLogCapture) {
				assert.Empty(t, logs.matching("stale"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newTestProvider(t)
			logs := newCacheLogCapture()
			synctest.Test(t, func(t *testing.T) {
				opts := append([]oidc.ManagerOption{oidc.WithLogger(slog.New(logs))}, tc.opts...)
				m := newCacheManager(t, p, opts...)
				keys := func(kid string) (jwk.Set, error) { return oidc.KeysForTest(m, t.Context(), "corp", kid) }
				_, err := keys("k1")
				require.NoError(t, err)

				tc.act(t, p, keys)
				tc.assert(t, logs)
			})
		})
	}
}
