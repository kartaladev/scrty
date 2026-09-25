package oidc_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
)

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
		assert    func(t *testing.T, m *oidc.Manager, a, b *testProvider, err error)
	}

	cases := []testCase{
		{
			name: "construction makes no request",
			providers: func(t *testing.T, a, _ *testProvider) []oidc.Provider {
				return []oidc.Provider{a.Provider("corp"), unreachable(t, "partner")}
			},
			assert: func(t *testing.T, _ *oidc.Manager, a, b *testProvider, err error) {
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
			assert: func(t *testing.T, _ *oidc.Manager, _, _ *testProvider, err error) {
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
			assert: func(t *testing.T, m *oidc.Manager, a, b *testProvider, err error) {
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
			assert: func(t *testing.T, _ *oidc.Manager, a, _ *testProvider, err error) {
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
			assert: func(t *testing.T, m *oidc.Manager, a, _ *testProvider, err error) {
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
			assert: func(t *testing.T, _ *oidc.Manager, a, b *testProvider, err error) {
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
			m, err := oidc.NewManager(reg, stubBroker{}, oidc.WithOutboundClient(a.Outbound(t)))
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
