package oidc_test

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/oidc"
)

func TestDiscovery(t *testing.T) {
	t.Parallel()

	// doc is a discovery document naming issuer and the endpoints under base.
	doc := func(issuer, base, jwksBase string) string {
		return `{"issuer":"` + issuer + `",` +
			`"authorization_endpoint":"` + base + `/authorize",` +
			`"token_endpoint":"` + base + `/token",` +
			`"jwks_uri":"` + jwksBase + `/jwks",` +
			`"end_session_endpoint":"` + base + `/logout"}`
	}

	type testCase struct {
		name   string
		setup  func(t *testing.T, p, other *testProvider) oidc.Provider
		assert func(t *testing.T, p, other *testProvider, md oidc.MetadataView, err error)
	}

	cases := []testCase{
		{
			name: "a matching document is accepted",
			setup: func(_ *testing.T, p, _ *testProvider) oidc.Provider {
				return p.Provider("corp")
			},
			assert: func(t *testing.T, p, _ *testProvider, md oidc.MetadataView, err error) {
				require.NoError(t, err)
				assert.Equal(t, p.Issuer()+"/authorize", md.AuthorizationEndpoint)
				assert.Equal(t, p.Issuer()+"/token", md.TokenEndpoint)
				assert.Equal(t, p.Issuer()+"/jwks", md.JWKSURI)
				assert.Equal(t, p.Issuer()+"/logout", md.EndSessionEndpoint)
				assert.EqualValues(t, 1, p.discoveryCalls.Load())
			},
		},
		{
			name: "a pinned end-session endpoint wins over the discovered one",
			setup: func(_ *testing.T, p, _ *testProvider) oidc.Provider {
				pr := p.Provider("corp")
				pr.EndSessionEndpoint = p.Issuer() + "/pinned-logout"
				return pr
			},
			assert: func(t *testing.T, p, _ *testProvider, md oidc.MetadataView, err error) {
				require.NoError(t, err)
				assert.Equal(t, p.Issuer()+"/pinned-logout", md.EndSessionEndpoint)
			},
		},
		{
			name: "issuer mismatch is refused",
			setup: func(_ *testing.T, p, _ *testProvider) oidc.Provider {
				p.discoveryBody.Store(doc("https://evil.example", p.Issuer(), p.Issuer()))
				return p.Provider("corp")
			},
			assert: func(t *testing.T, _, _ *testProvider, _ oidc.MetadataView, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
			},
		},
		{
			name: "an endpoint on another origin is refused",
			setup: func(_ *testing.T, p, other *testProvider) oidc.Provider {
				p.discoveryBody.Store(doc(p.Issuer(), p.Issuer(), other.Issuer()))
				return p.Provider("corp")
			},
			assert: func(t *testing.T, _, other *testProvider, _ oidc.MetadataView, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
				assert.Zero(t, other.discoveryCalls.Load()+other.jwksCalls.Load())
			},
		},
		{
			name: "an endpoint whose scheme the outbound client does not allow is refused",
			setup: func(_ *testing.T, p, _ *testProvider) oidc.Provider {
				plain := "http" + p.Issuer()[len("https"):]
				p.discoveryBody.Store(doc(p.Issuer(), plain, p.Issuer()))
				return p.Provider("corp")
			},
			assert: func(t *testing.T, _, _ *testProvider, _ oidc.MetadataView, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
			},
		},
		{
			name: "a document missing a required endpoint is refused",
			setup: func(_ *testing.T, p, _ *testProvider) oidc.Provider {
				p.discoveryBody.Store(`{"issuer":"` + p.Issuer() + `","authorization_endpoint":"` +
					p.Issuer() + `/authorize","token_endpoint":"` + p.Issuer() + `/token"}`)
				return p.Provider("corp")
			},
			assert: func(t *testing.T, _, _ *testProvider, _ oidc.MetadataView, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
			},
		},
		{
			name: "a fully pinned provider sends no discovery request",
			setup: func(_ *testing.T, p, _ *testProvider) oidc.Provider {
				pr := p.Provider("corp")
				pr.AuthorizationEndpoint = p.Issuer() + "/pinned-authorize"
				pr.TokenEndpoint = p.Issuer() + "/token"
				pr.JWKSURI = p.Issuer() + "/jwks"
				return pr
			},
			assert: func(t *testing.T, p, _ *testProvider, md oidc.MetadataView, err error) {
				require.NoError(t, err)
				assert.Equal(t, p.Issuer()+"/pinned-authorize", md.AuthorizationEndpoint)
				assert.Zero(t, p.discoveryCalls.Load())
			},
		},
		{
			name: "a non-JSON document is a provider failure",
			setup: func(_ *testing.T, p, _ *testProvider) oidc.Provider {
				p.discoveryBody.Store("<html><body>502 Bad Gateway</body></html>")
				return p.Provider("corp")
			},
			assert: func(t *testing.T, _, _ *testProvider, _ oidc.MetadataView, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
			},
		},
		{
			name: "a truncated document body is a provider failure",
			setup: func(_ *testing.T, p, _ *testProvider) oidc.Provider {
				p.discoveryBody.Store(`{"issuer":"` + p.Issuer() + `","authorization_endpoint":"` + p.Issuer())
				return p.Provider("corp")
			},
			assert: func(t *testing.T, _, _ *testProvider, _ oidc.MetadataView, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
			},
		},
		{
			name: "a non-200 status is a provider failure",
			setup: func(_ *testing.T, p, _ *testProvider) oidc.Provider {
				p.failDiscovery.Store(true)
				return p.Provider("corp")
			},
			assert: func(t *testing.T, _, _ *testProvider, _ oidc.MetadataView, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
			},
		},
		{
			name: "an unreachable provider is a provider failure",
			setup: func(_ *testing.T, p, _ *testProvider) oidc.Provider {
				gone := httptest.NewTLSServer(nil)
				gone.Close()
				pr := p.Provider("corp")
				pr.Issuer = gone.URL
				return pr
			},
			assert: func(t *testing.T, _, _ *testProvider, _ oidc.MetadataView, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, other := newTestProvider(t), newTestProvider(t)
			reg, err := oidc.NewRegistry(tc.setup(t, p, other))
			require.NoError(t, err)
			m, err := oidc.NewRelyingParty(reg, stubBroker{}, oidc.WithOutboundClient(p.Outbound(t)))
			require.NoError(t, err)

			md, err := oidc.MetadataForTest(m, t.Context(), "corp")
			tc.assert(t, p, other, md, err)
		})
	}
}

// newCacheManager returns a manager for providers "corp" (p) and any extra
// providers, sending every request through p's in-memory client so that it
// can run inside a testing/synctest bubble. Build it inside the bubble: its
// default clock, clock.System(), then reads the bubble's fake time.
func newCacheManager(t *testing.T, p *testProvider, opts ...oidc.Option) *oidc.RelyingParty {
	t.Helper()

	reg, err := oidc.NewRegistry(p.Provider("corp"))
	require.NoError(t, err)
	m, err := oidc.NewRelyingParty(reg, stubBroker{},
		append([]oidc.Option{oidc.WithOutboundClient(p.InMemoryOutbound(t))}, opts...)...)
	require.NoError(t, err)

	return m
}

func TestKeyCacheTTL(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []oidc.Option
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
			opts: []oidc.Option{oidc.WithDiscoveryTTL(time.Hour)}, after: 30 * time.Minute,
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

// cacheLogCapture is a slog handler that records every message it is given.
type cacheLogCapture struct {
	mu      *sync.Mutex
	records *[]slog.Record
}

func newCacheLogCapture() cacheLogCapture {
	return cacheLogCapture{mu: &sync.Mutex{}, records: &[]slog.Record{}}
}

func (c cacheLogCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c cacheLogCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.records = append(*c.records, r.Clone())
	return nil
}

func (c cacheLogCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c cacheLogCapture) WithGroup(string) slog.Handler      { return c }

// matching returns the records whose message contains substr.
func (c cacheLogCapture) matching(substr string) []slog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []slog.Record
	for _, r := range *c.records {
		if strings.Contains(r.Message, substr) {
			out = append(out, r)
		}
	}
	return out
}

// Standalone from TestKeyCacheTTL: each row drives a sequence of failing fetches and reads the captured log.
func TestKeyCacheBackoff(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []oidc.Option
		act    func(t *testing.T, p *testProvider, keys func() error)
		assert func(t *testing.T, p *testProvider, logs cacheLogCapture)
	}

	// probe calls keys and reports whether it reached the key-set endpoint.
	probe := func(t *testing.T, p *testProvider, keys func() error) bool {
		t.Helper()
		before := p.jwksCalls.Load()
		_ = keys()
		return p.jwksCalls.Load() != before
	}

	cases := []testCase{
		{
			name: "twenty requests inside the window send nothing",
			act: func(t *testing.T, p *testProvider, keys func() error) {
				p.failJWKS.Store(true)
				require.ErrorIs(t, keys(), oidc.ErrDiscoveryFailed)
				for range 20 {
					time.Sleep(40 * time.Millisecond)
					require.ErrorIs(t, keys(), oidc.ErrDiscoveryFailed)
				}
			},
			assert: func(t *testing.T, p *testProvider, _ cacheLogCapture) {
				assert.EqualValues(t, 1, p.jwksCalls.Load())
			},
		},
		{
			name: "the window doubles and caps",
			act: func(t *testing.T, p *testProvider, keys func() error) {
				p.failJWKS.Store(true)
				require.True(t, probe(t, p, keys), "the first failure reaches the network")
				for _, window := range []time.Duration{1, 2, 4, 8, 16, 30, 30} {
					window *= time.Second
					time.Sleep(window - time.Millisecond)
					require.False(t, probe(t, p, keys), "inside the %s window", window)
					time.Sleep(time.Millisecond)
					require.True(t, probe(t, p, keys), "at the end of the %s window", window)
				}
			},
			assert: func(t *testing.T, p *testProvider, _ cacheLogCapture) {
				assert.EqualValues(t, 8, p.jwksCalls.Load())
			},
		},
		{
			name: "a consumer backoff replaces the bounds",
			opts: []oidc.Option{oidc.WithDiscoveryFailureBackoff(5*time.Second, 7*time.Second)},
			act: func(t *testing.T, p *testProvider, keys func() error) {
				p.failJWKS.Store(true)
				require.True(t, probe(t, p, keys))
				for _, window := range []time.Duration{5, 7, 7} {
					window *= time.Second
					time.Sleep(window - time.Millisecond)
					require.False(t, probe(t, p, keys), "inside the %s window", window)
					time.Sleep(time.Millisecond)
					require.True(t, probe(t, p, keys), "at the end of the %s window", window)
				}
			},
			assert: func(t *testing.T, p *testProvider, _ cacheLogCapture) {
				assert.EqualValues(t, 4, p.jwksCalls.Load())
			},
		},
		{
			name: "a success resets the window",
			act: func(t *testing.T, p *testProvider, keys func() error) {
				p.failJWKS.Store(true)
				require.True(t, probe(t, p, keys))
				time.Sleep(time.Second)
				require.True(t, probe(t, p, keys)) // window now 2s
				time.Sleep(2 * time.Second)
				require.True(t, probe(t, p, keys)) // window now 4s
				time.Sleep(4 * time.Second)
				p.failJWKS.Store(false)
				require.NoError(t, keys())

				time.Sleep(oidc.DefaultDiscoveryTTL) // the set expires
				p.failJWKS.Store(true)
				require.True(t, probe(t, p, keys))
				time.Sleep(time.Second)
				require.True(t, probe(t, p, keys), "the window starts again at the base")
			},
			assert: func(t *testing.T, p *testProvider, _ cacheLogCapture) {
				assert.EqualValues(t, 6, p.jwksCalls.Load())
			},
		},
		{
			name: "a discovery failure does not open the key set's window",
			act: func(t *testing.T, p *testProvider, keys func() error) {
				p.failDiscovery.Store(true)
				require.ErrorIs(t, keys(), oidc.ErrDiscoveryFailed)
				require.Zero(t, p.jwksCalls.Load())

				time.Sleep(time.Second) // discovery's own window ends
				p.failDiscovery.Store(false)
				p.failJWKS.Store(true)
				require.True(t, probe(t, p, keys), "the key set's first failure")
				time.Sleep(time.Second)
				require.True(t, probe(t, p, keys), "the key set's window is its first, not its second")
			},
			assert: func(t *testing.T, p *testProvider, _ cacheLogCapture) {
				assert.EqualValues(t, 2, p.discoveryCalls.Load())
			},
		},
		{
			name: "each window transition is logged once",
			act: func(_ *testing.T, p *testProvider, keys func() error) {
				p.failJWKS.Store(true)
				for range 20 {
					_ = keys()
					time.Sleep(10 * time.Millisecond)
				}
				time.Sleep(time.Second)
				_ = keys() // the second failure opens the second window
			},
			assert: func(t *testing.T, _ *testProvider, logs cacheLogCapture) {
				records := logs.matching("backing off")
				require.Len(t, records, 2)
				var attrs []string
				records[0].Attrs(func(a slog.Attr) bool {
					attrs = append(attrs, a.Key+"="+a.Value.String())
					return true
				})
				assert.Contains(t, attrs, "provider=corp")
				assert.Contains(t, attrs, "window=1s")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newTestProvider(t)
			logs := newCacheLogCapture()
			synctest.Test(t, func(t *testing.T) {
				opts := append([]oidc.Option{oidc.WithLogger(slog.New(logs))}, tc.opts...)
				m := newCacheManager(t, p, opts...)
				keys := func() error {
					_, err := oidc.KeysForTest(m, t.Context(), "corp", "k1")
					return err
				}
				tc.act(t, p, keys)
				tc.assert(t, p, logs)
			})
		})
	}
}

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
func startKeysFor(ctx context.Context, m *oidc.RelyingParty, kid string) <-chan keysResult {
	out := make(chan keysResult, 1)
	go func() {
		set, err := oidc.KeysForTest(m, ctx, "corp", kid)
		out <- keysResult{set: set, err: err}
	}()
	return out
}

// Standalone from TestKeyCacheTTL: each row holds the key-set endpoint and races concurrent callers.
func TestKeyCacheCoalesces(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(t *testing.T, m *oidc.RelyingParty, release func()) []keysResult
		assert func(t *testing.T, p *testProvider, results []keysResult)
	}

	cases := []testCase{
		{
			name: "eight concurrent misses share one fetch",
			act: func(t *testing.T, m *oidc.RelyingParty, release func()) []keysResult {
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
			act: func(t *testing.T, m *oidc.RelyingParty, release func()) []keysResult {
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
			act: func(t *testing.T, m *oidc.RelyingParty, release func()) []keysResult {
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

// Standalone from TestKeyCacheTTL: each row runs over two providers with corp's key set already cached.
func TestKeyCacheUnknownKid(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []oidc.Option
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
			opts: []oidc.Option{oidc.WithJWKSRefetchCooldown(5 * time.Second)},
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
			opts: []oidc.Option{oidc.WithJWKSRefetchCooldown(time.Hour)},
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
				opts := append([]oidc.Option{oidc.WithOutboundClient(inMemoryOutbound(t, a, b))}, tc.opts...)
				m, err := oidc.NewRelyingParty(reg, stubBroker{}, opts...)
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

// Standalone from TestKeyCacheTTL: each row starts from a cached key set and reads the captured log.
func TestKeyCacheStaleWindow(t *testing.T) {
	t.Parallel()

	tenMinutes := oidc.WithDiscoveryStaleWhileError(10 * time.Minute)

	type testCase struct {
		name string
		opts []oidc.Option
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
			opts: []oidc.Option{tenMinutes},
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
			opts: []oidc.Option{tenMinutes},
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
			opts: []oidc.Option{tenMinutes},
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
			opts: []oidc.Option{tenMinutes},
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
			opts: []oidc.Option{tenMinutes},
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
			opts: []oidc.Option{tenMinutes},
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
				opts := append([]oidc.Option{oidc.WithLogger(slog.New(logs))}, tc.opts...)
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

func TestManagerPrefetch(t *testing.T) {
	t.Parallel()

	// unreachable returns a provider whose issuer is a closed port.
	unreachable := func(_ *testing.T, name string) oidc.Provider {
		gone := httptest.NewTLSServer(nil)
		gone.Close()
		return oidc.Provider{
			Name: name, Issuer: gone.URL, ClientID: "client-" + name, ClientSecret: "secret-" + name,
			RedirectURL: "https://app.example/login/oauth2/callback/" + name,
		}
	}
	calls := func(ps ...*testProvider) int64 {
		var n int64
		for _, p := range ps {
			n += p.discoveryCalls.Load() + p.jwksCalls.Load()
		}
		return n
	}

	type testCase struct {
		name string
		// providers builds the registry's providers from the two test servers.
		providers func(t *testing.T, a, b *testProvider) []oidc.Provider
		ctx       func(ctx context.Context) context.Context
		prefetch  bool
		assert    func(t *testing.T, m *oidc.RelyingParty, a, b *testProvider, err error)
	}

	cases := []testCase{
		{
			name: "construction makes no request",
			providers: func(t *testing.T, a, _ *testProvider) []oidc.Provider {
				return []oidc.Provider{a.Provider("corp"), unreachable(t, "partner")}
			},
			assert: func(t *testing.T, _ *oidc.RelyingParty, a, b *testProvider, err error) {
				require.NoError(t, err)
				assert.Zero(t, calls(a, b))
			},
		},
		{
			name: "prefetch names the unreachable provider",
			providers: func(t *testing.T, a, _ *testProvider) []oidc.Provider {
				return []oidc.Provider{a.Provider("corp"), unreachable(t, "partner")}
			},
			prefetch: true,
			assert: func(t *testing.T, _ *oidc.RelyingParty, _, _ *testProvider, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
				assert.Contains(t, err.Error(), `"partner"`)
			},
		},
		{
			name: "prefetch of reachable providers fills the cache",
			providers: func(_ *testing.T, a, b *testProvider) []oidc.Provider {
				return []oidc.Provider{a.Provider("corp"), b.Provider("partner")}
			},
			prefetch: true,
			assert: func(t *testing.T, m *oidc.RelyingParty, a, b *testProvider, err error) {
				require.NoError(t, err)
				require.EqualValues(t, 4, calls(a, b))
				for _, name := range []string{"corp", "partner"} {
					_, err := oidc.MetadataForTest(m, t.Context(), name)
					require.NoError(t, err)
					_, err = oidc.KeysForTest(m, t.Context(), name, "k1")
					require.NoError(t, err)
				}
				assert.EqualValues(t, 4, calls(a, b), "every later lookup is served from the cache")
			},
		},
		{
			name: "prefetch sends a pinned provider no discovery request",
			providers: func(_ *testing.T, a, _ *testProvider) []oidc.Provider {
				p := a.Provider("corp")
				p.AuthorizationEndpoint, p.TokenEndpoint, p.JWKSURI = a.Issuer()+"/authorize", a.Issuer()+"/token", a.Issuer()+"/jwks"
				return []oidc.Provider{p}
			},
			prefetch: true,
			assert: func(t *testing.T, _ *oidc.RelyingParty, a, _ *testProvider, err error) {
				require.NoError(t, err)
				assert.Zero(t, a.discoveryCalls.Load())
				assert.EqualValues(t, 1, a.jwksCalls.Load())
			},
		},
		{
			name: "a symmetric-only provider prefetches without a key set",
			providers: func(_ *testing.T, a, _ *testProvider) []oidc.Provider {
				p := a.Provider("corp")
				p.SigningAlgs = []string{"HS256"}
				return []oidc.Provider{p}
			},
			prefetch: true,
			assert: func(t *testing.T, m *oidc.RelyingParty, a, _ *testProvider, err error) {
				require.NoError(t, err)
				assert.EqualValues(t, 1, a.discoveryCalls.Load(), "discovery is still fetched when unpinned")
				assert.Zero(t, a.jwksCalls.Load(), "no key-set request is made for a symmetric-only provider")

				_, err = oidc.KeysForTest(m, t.Context(), "corp", "")
				require.Error(t, err)
				assert.Zero(t, a.jwksCalls.Load(), "keysFor does not fetch a symmetric-only provider's key set")
			},
		},
		{
			name: "a cancelled context stops prefetch",
			providers: func(_ *testing.T, a, b *testProvider) []oidc.Provider {
				return []oidc.Provider{a.Provider("corp"), b.Provider("partner")}
			},
			ctx: func(ctx context.Context) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				cancel()
				return ctx
			},
			prefetch: true,
			assert: func(t *testing.T, _ *oidc.RelyingParty, a, b *testProvider, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Zero(t, calls(a, b))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a, b := newTestProvider(t), newTestProvider(t)
			reg, err := oidc.NewRegistry(tc.providers(t, a, b)...)
			require.NoError(t, err)
			m, err := oidc.NewRelyingParty(reg, stubBroker{}, oidc.WithOutboundClient(a.Outbound(t)))
			if err == nil && tc.prefetch {
				ctx := t.Context()
				if tc.ctx != nil {
					ctx = tc.ctx(ctx)
				}
				err = m.Prefetch(ctx)
			}
			tc.assert(t, m, a, b, err)
		})
	}
}
