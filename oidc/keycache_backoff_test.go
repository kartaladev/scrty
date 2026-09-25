package oidc_test

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
)

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

func TestKeyCacheBackoff(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []oidc.ManagerOption
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
			opts: []oidc.ManagerOption{oidc.WithDiscoveryFailureBackoff(5*time.Second, 7*time.Second)},
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
				opts := append([]oidc.ManagerOption{oidc.WithLogger(slog.New(logs))}, tc.opts...)
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
