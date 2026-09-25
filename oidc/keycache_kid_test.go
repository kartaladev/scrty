package oidc_test

import (
	"context"
	"crypto/rand"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
)

func TestKeyCacheUnknownKid(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []oidc.ManagerOption
		// act runs with the "corp" key set (provider a) already cached.
		act    func(t *testing.T, a, b *testProvider, keys func(ctx context.Context, provider, kid string) keysResult)
		assert func(t *testing.T, a, b *testProvider)
	}

	cases := []testCase{
		{
			name: "key rotation is picked up",
			act: func(t *testing.T, a, _ *testProvider, keys func(context.Context, string, string) keysResult) {
				a.Rotate(t, "k2")
				r := keys(t.Context(), "corp", "k2")
				require.NoError(t, r.err)
				_, ok := r.set.LookupKeyID("k2")
				assert.True(t, ok)
			},
			assert: func(t *testing.T, a, _ *testProvider) {
				assert.EqualValues(t, 2, a.jwksCalls.Load())
			},
		},
		{
			name: "a hundred random kids cost one fetch",
			act: func(t *testing.T, _ *testProvider, _ *testProvider, keys func(context.Context, string, string) keysResult) {
				for range 100 {
					r := keys(t.Context(), "corp", rand.Text())
					require.ErrorIs(t, r.err, oidc.ErrUnknownSigningKeyForTest)
					require.NotErrorIs(t, r.err, oidc.ErrDiscoveryFailed)
					time.Sleep(100 * time.Millisecond)
				}
			},
			assert: func(t *testing.T, a, _ *testProvider) {
				assert.EqualValues(t, 2, a.jwksCalls.Load())
			},
		},
		{
			name: "the cooldown is per provider",
			act: func(t *testing.T, _, b *testProvider, keys func(context.Context, string, string) keysResult) {
				require.NoError(t, keys(t.Context(), "other", "k1").err)
				// corp enters its cooldown.
				require.ErrorIs(t, keys(t.Context(), "corp", "nope").err, oidc.ErrUnknownSigningKeyForTest)
				b.Rotate(t, "k2")
				r := keys(t.Context(), "other", "k2")
				require.NoError(t, r.err)
			},
			assert: func(t *testing.T, a, b *testProvider) {
				assert.EqualValues(t, 2, a.jwksCalls.Load())
				assert.EqualValues(t, 2, b.jwksCalls.Load())
			},
		},
		{
			name: "a refetch is allowed again once the cooldown ends",
			act: func(t *testing.T, a, _ *testProvider, keys func(context.Context, string, string) keysResult) {
				require.ErrorIs(t, keys(t.Context(), "corp", "nope").err, oidc.ErrUnknownSigningKeyForTest)
				a.Rotate(t, "k2")
				time.Sleep(oidc.DefaultJWKSRefetchCooldown - time.Millisecond)
				require.ErrorIs(t, keys(t.Context(), "corp", "k2").err, oidc.ErrUnknownSigningKeyForTest)
				time.Sleep(time.Millisecond)
				require.NoError(t, keys(t.Context(), "corp", "k2").err)
			},
			assert: func(t *testing.T, a, _ *testProvider) {
				assert.EqualValues(t, 3, a.jwksCalls.Load())
			},
		},
		{
			name: "a consumer cooldown replaces the default",
			opts: []oidc.ManagerOption{oidc.WithJWKSRefetchCooldown(5 * time.Second)},
			act: func(t *testing.T, a, _ *testProvider, keys func(context.Context, string, string) keysResult) {
				require.ErrorIs(t, keys(t.Context(), "corp", "nope").err, oidc.ErrUnknownSigningKeyForTest)
				a.Rotate(t, "k2")
				time.Sleep(5 * time.Second)
				require.NoError(t, keys(t.Context(), "corp", "k2").err)
			},
			assert: func(t *testing.T, a, _ *testProvider) {
				assert.EqualValues(t, 3, a.jwksCalls.Load())
			},
		},
		{
			name: "concurrent unknown kids share the refetch",
			act: func(t *testing.T, a, _ *testProvider, keys func(context.Context, string, string) keysResult) {
				a.Rotate(t, "k2")
				release := holdJWKS(t, a)
				var chans []chan keysResult
				for range 8 {
					ch := make(chan keysResult, 1)
					chans = append(chans, ch)
					go func() { ch <- keys(t.Context(), "corp", "k2") }()
				}
				synctest.Wait()
				release()
				for _, ch := range chans {
					require.NoError(t, (<-ch).err)
				}
			},
			assert: func(t *testing.T, a, _ *testProvider) {
				assert.EqualValues(t, 2, a.jwksCalls.Load())
			},
		},
		{
			// A long cooldown puts a cooldown refusal just before the set
			// expires; the expiry refetch that follows must still be sent.
			name: "a cooldown refusal does not open a backoff window",
			opts: []oidc.ManagerOption{oidc.WithJWKSRefetchCooldown(time.Hour)},
			act: func(t *testing.T, _ *testProvider, _ *testProvider, keys func(context.Context, string, string) keysResult) {
				require.ErrorIs(t, keys(t.Context(), "corp", "x1").err, oidc.ErrUnknownSigningKeyForTest)
				time.Sleep(oidc.DefaultDiscoveryTTL - 500*time.Millisecond)
				require.ErrorIs(t, keys(t.Context(), "corp", "x2").err, oidc.ErrUnknownSigningKeyForTest)
				time.Sleep(500 * time.Millisecond) // the set expires, well inside a 1 s window
				require.NoError(t, keys(t.Context(), "corp", "k1").err)
			},
			assert: func(t *testing.T, a, _ *testProvider) {
				assert.EqualValues(t, 3, a.jwksCalls.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a, b := newTestProvider(t), newTestProvider(t)
			synctest.Test(t, func(t *testing.T) {
				reg, err := oidc.NewRegistry(a.Provider("corp"), b.Provider("other"))
				require.NoError(t, err)
				opts := append([]oidc.ManagerOption{oidc.WithOutboundClient(inMemoryOutbound(t, a, b))}, tc.opts...)
				m, err := oidc.NewManager(reg, stubBroker{}, opts...)
				require.NoError(t, err)

				keys := func(ctx context.Context, provider, kid string) keysResult {
					set, err := oidc.KeysForTest(m, ctx, provider, kid)
					return keysResult{set: set, err: err}
				}
				require.NoError(t, keys(t.Context(), "corp", "k1").err)

				tc.act(t, a, b, keys)
				tc.assert(t, a, b)
			})
		})
	}
}
