package oidcprovider_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
)

func TestProvider_Accessors(t *testing.T) {
	t.Parallel()

	withBinding := func(id string, b oidcprovider.BindingRequirement) oidcprovider.Client {
		c := webClient()
		c.ID = id
		c.RequireBinding = b

		return c
	}

	type testCase struct {
		name   string
		deps   func(t *testing.T, d *oidcprovider.Deps)
		opts   []oidcprovider.Option
		assert func(t *testing.T, p *oidcprovider.Provider)
	}

	cases := []testCase{
		{
			name: "by default browser sessions are on and the issuer is the one given",
			assert: func(t *testing.T, p *oidcprovider.Provider) {
				assert.True(t, p.BrowserSessionsEnabled())
				assert.Equal(t, issuer, p.Issuer())
			},
		},
		{
			name: "WithoutBrowserSessions turns them off",
			opts: []oidcprovider.Option{oidcprovider.WithoutBrowserSessions()},
			assert: func(t *testing.T, p *oidcprovider.Provider) {
				assert.False(t, p.BrowserSessionsEnabled())
			},
		},
		{
			name: "no client requires a binding",
			assert: func(t *testing.T, p *oidcprovider.Provider) {
				assert.False(t, p.RequiresBinding(oidcprovider.BindingDPoP))
				assert.False(t, p.RequiresBinding(oidcprovider.BindingMTLS))
				assert.False(t, p.RequiresBinding(oidcprovider.BindingOptional))
			},
		},
		{
			name: "a configured client requiring DPoP answers for DPoP only",
			deps: func(_ *testing.T, d *oidcprovider.Deps) {
				d.Clients = []oidcprovider.Client{webClient(), withBinding("dpop-app", oidcprovider.BindingDPoP)}
			},
			assert: func(t *testing.T, p *oidcprovider.Provider) {
				assert.True(t, p.RequiresBinding(oidcprovider.BindingDPoP))
				assert.False(t, p.RequiresBinding(oidcprovider.BindingMTLS))
				assert.False(t, p.RequiresBinding(oidcprovider.BindingOptional))
			},
		},
		{
			name: "a configured client requiring a certificate binding answers for it only",
			deps: func(_ *testing.T, d *oidcprovider.Deps) {
				d.Clients = []oidcprovider.Client{withBinding("mtls-app", oidcprovider.BindingMTLS)}
			},
			assert: func(t *testing.T, p *oidcprovider.Provider) {
				assert.True(t, p.RequiresBinding(oidcprovider.BindingMTLS))
				assert.False(t, p.RequiresBinding(oidcprovider.BindingDPoP))
			},
		},
		{
			name: "a memory registry given as the registry is seen",
			deps: func(t *testing.T, d *oidcprovider.Deps) {
				r, err := oidcprovider.NewMemoryRegistry([]oidcprovider.Client{withBinding("dpop-app", oidcprovider.BindingDPoP)})
				require.NoError(t, err)

				d.Clients = nil
				d.Registry = r
			},
			assert: func(t *testing.T, p *oidcprovider.Provider) {
				assert.True(t, p.RequiresBinding(oidcprovider.BindingDPoP))
			},
		},
		{
			name: "a consumer's own registry cannot be listed, so it answers false",
			deps: func(t *testing.T, d *oidcprovider.Deps) {
				d.Clients = nil
				d.Registry = NewMockClientRegistry(gomock.NewController(t))
			},
			assert: func(t *testing.T, p *oidcprovider.Provider) {
				assert.False(t, p.RequiresBinding(oidcprovider.BindingDPoP))
				assert.False(t, p.RequiresBinding(oidcprovider.BindingMTLS))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := validDeps(t)
			if tc.deps != nil {
				tc.deps(t, &d)
			}

			p, err := oidcprovider.New(d, tc.opts...)
			require.NoError(t, err)

			tc.assert(t, p)
		})
	}
}
