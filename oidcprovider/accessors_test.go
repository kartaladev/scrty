package oidcprovider_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/token/signingkey"
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

	managed, err := signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
	require.NoError(t, err)

	cases := []testCase{
		{
			name: "a signing-key manager given as the keys is returned",
			deps: func(_ *testing.T, d *oidcprovider.Deps) { d.Keys = managed },
			assert: func(t *testing.T, p *oidcprovider.Provider) {
				assert.Same(t, managed, p.SigningManager())
			},
		},
		{
			name: "any other key source, a wrapper of the manager included, answers nil",
			deps: func(_ *testing.T, d *oidcprovider.Deps) { d.Keys = struct{ signingkey.KeySource }{managed} },
			assert: func(t *testing.T, p *oidcprovider.Provider) {
				assert.Nil(t, p.SigningManager())
			},
		},
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

func TestProvider_Capabilities(t *testing.T) {
	t.Parallel()

	refreshing := func(id string, scopes ...string) oidcprovider.Client {
		c := webClient()
		c.ID = id
		c.Scopes = scopes
		c.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken}

		return c
	}

	type testCase struct {
		name   string
		deps   func(t *testing.T, d *oidcprovider.Deps)
		assert func(t *testing.T, c oidcprovider.Capabilities)
	}

	cases := []testCase{
		{
			name: "defaults: the standard scopes, no offline access, and RS256",
			assert: func(t *testing.T, c oidcprovider.Capabilities) {
				assert.Equal(t, []string{"openid", "profile", "email"}, c.Scopes)
				assert.Equal(t, []string{"RS256"}, c.IDTokenAlgs)
				assert.Contains(t, c.Claims, "sub")
				assert.Contains(t, c.Claims, "auth_time")
				assert.Contains(t, c.Claims, "email_verified")
				assert.NotContains(t, c.IDTokenAlgs, "none")
			},
		},
		{
			name: "every algorithm a client assertion may use, and never none",
			assert: func(t *testing.T, c oidcprovider.Capabilities) {
				assert.Equal(t, []string{
					"ES256", "ES384", "ES512", "EdDSA", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512",
				}, c.AssertionAlgs)
			},
		},
		{
			name: "a client with a refresh grant that lists offline_access offers it, and its other scopes follow, sorted",
			deps: func(_ *testing.T, d *oidcprovider.Deps) {
				d.Clients = []oidcprovider.Client{refreshing("a", "openid", "offline_access", "billing", "accounts")}
			},
			assert: func(t *testing.T, c oidcprovider.Capabilities) {
				assert.Equal(t, []string{"openid", "profile", "email", "offline_access", "accounts", "billing"}, c.Scopes)
			},
		},
		{
			name: "offline_access listed by a client with no refresh grant is not offered",
			deps: func(_ *testing.T, d *oidcprovider.Deps) {
				c := refreshing("a", "openid", "offline_access")
				c.GrantTypes = nil
				d.Clients = []oidcprovider.Client{c}
			},
			assert: func(t *testing.T, c oidcprovider.Capabilities) {
				assert.NotContains(t, c.Scopes, "offline_access")
			},
		},
		{
			name: "a consumer's own registry cannot be listed, so offline_access is offered",
			deps: func(t *testing.T, d *oidcprovider.Deps) {
				d.Clients = nil
				d.Registry = NewMockClientRegistry(gomock.NewController(t))
			},
			assert: func(t *testing.T, c oidcprovider.Capabilities) {
				assert.Equal(t, []string{"openid", "profile", "email", "offline_access"}, c.Scopes)
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

			p, err := oidcprovider.New(d)
			require.NoError(t, err)

			tc.assert(t, p.Capabilities())
		})
	}
}

// TestProvider_Capabilities_FreshCopies pins that a caller may change what it was given
// without changing what the provider reports later.
func TestProvider_Capabilities_FreshCopies(t *testing.T) {
	t.Parallel()

	p, err := oidcprovider.New(validDeps(t))
	require.NoError(t, err)

	first := p.Capabilities()

	for _, list := range [][]string{first.Scopes, first.Claims, first.IDTokenAlgs, first.AssertionAlgs} {
		for i := range list {
			list[i] = "changed"
		}
	}

	later := p.Capabilities()
	for _, list := range [][]string{later.Scopes, later.Claims, later.IDTokenAlgs, later.AssertionAlgs} {
		assert.NotContains(t, list, "changed")
	}
}
