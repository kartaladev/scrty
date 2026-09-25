package oidc_test

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
)

// keysResult is what one concurrent keysFor caller got.
type keysResult struct {
	set jwk.Set
	err error
}

// holdJWKS makes p's key-set handler wait until the returned release is
// called. Call it inside the bubble, so the wait is durably blocking.
func holdJWKS(t *testing.T, p *testProvider) (release func()) {
	t.Helper()

	gate := make(chan struct{})
	wait := func() { <-gate }
	p.jwksGate.Store(&wait)
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)

	return release
}

// startKeysFor calls keysFor for "corp" on its own goroutine and returns a
// channel that yields the result.
func startKeysFor(ctx context.Context, m *oidc.Manager, kid string) <-chan keysResult {
	out := make(chan keysResult, 1)
	go func() {
		set, err := oidc.KeysForTest(m, ctx, "corp", kid)
		out <- keysResult{set: set, err: err}
	}()
	return out
}

func TestKeyCacheCoalesces(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(t *testing.T, m *oidc.Manager, release func()) []keysResult
		assert func(t *testing.T, p *testProvider, results []keysResult)
	}

	cases := []testCase{
		{
			name: "eight concurrent misses share one fetch",
			act: func(t *testing.T, m *oidc.Manager, release func()) []keysResult {
				var chans []<-chan keysResult
				for range 8 {
					chans = append(chans, startKeysFor(t.Context(), m, "k1"))
				}
				synctest.Wait() // every caller is waiting on the held fetch
				release()

				var results []keysResult
				for _, ch := range chans {
					results = append(results, <-ch)
				}
				return results
			},
			assert: func(t *testing.T, p *testProvider, results []keysResult) {
				assert.EqualValues(t, 1, p.jwksCalls.Load())
				assert.EqualValues(t, 1, p.discoveryCalls.Load())
				require.Len(t, results, 8)
				for _, r := range results {
					require.NoError(t, r.err)
					assert.True(t, r.set == results[0].set, "every caller receives the one fetched set")
				}
			},
		},
		{
			name: "a cancelling leader does not fail a waiter",
			act: func(t *testing.T, m *oidc.Manager, release func()) []keysResult {
				leaderCtx, cancel := context.WithCancel(t.Context())
				leader := startKeysFor(leaderCtx, m, "k1")
				synctest.Wait() // the leader's fetch is in flight
				waiter := startKeysFor(t.Context(), m, "k1")
				synctest.Wait()
				cancel()
				first := <-leader // the leader stops waiting at once
				release()

				return []keysResult{first, <-waiter}
			},
			assert: func(t *testing.T, p *testProvider, results []keysResult) {
				require.ErrorIs(t, results[0].err, context.Canceled)
				require.NoError(t, results[1].err)
				k, ok := results[1].set.LookupKeyID("k1")
				require.True(t, ok)
				require.NotNil(t, k)
				assert.EqualValues(t, 1, p.jwksCalls.Load())
			},
		},
		{
			// synctest.Test fails when a goroutine started in the bubble is
			// still blocked at its end, so this row is the leak check: every
			// caller cancels, the fetch then completes, and nothing remains.
			name: "no goroutine outlives the callers",
			act: func(t *testing.T, m *oidc.Manager, release func()) []keysResult {
				var chans []<-chan keysResult
				var cancels []context.CancelFunc
				for range 4 {
					ctx, cancel := context.WithCancel(t.Context())
					cancels = append(cancels, cancel)
					chans = append(chans, startKeysFor(ctx, m, "k1"))
				}
				synctest.Wait()
				for _, cancel := range cancels {
					cancel()
				}
				var results []keysResult
				for _, ch := range chans {
					results = append(results, <-ch)
				}
				release()
				synctest.Wait() // the shared fetch finishes and its goroutine exits
				return results
			},
			assert: func(t *testing.T, p *testProvider, results []keysResult) {
				for _, r := range results {
					require.ErrorIs(t, r.err, context.Canceled)
				}
				assert.EqualValues(t, 1, p.jwksCalls.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newTestProvider(t)
			synctest.Test(t, func(t *testing.T) {
				m := newCacheManager(t, p)
				release := holdJWKS(t, p)
				results := tc.act(t, m, release)
				tc.assert(t, p, results)
			})
		})
	}
}
