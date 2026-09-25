package oidc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
)

// mutate returns a provider list of one: base, changed by fn.
func mutate(base func() oidc.Provider, fn func(*oidc.Provider)) func() []oidc.Provider {
	return func() []oidc.Provider {
		p := base()
		fn(&p)
		return []oidc.Provider{p}
	}
}

func TestNewRegistry(t *testing.T) {
	t.Parallel()

	const clientSecret = "s3cr3t-value"
	valid := func() oidc.Provider {
		return oidc.Provider{
			Name: "corp", Issuer: "https://idp.example", ClientID: "client",
			ClientSecret: clientSecret, RedirectURL: "https://app.example/login/oauth2/callback/corp",
		}
	}
	pinned := func(p *oidc.Provider) {
		p.AuthorizationEndpoint = "https://idp.example/authorize"
		p.TokenEndpoint = "https://idp.example/token"
		p.JWKSURI = "https://idp.example/jwks"
	}

	type testCase struct {
		name      string
		providers func() []oidc.Provider
		assert    func(t *testing.T, r *oidc.Registry, err error)
	}

	refused := func(fragments ...string) func(t *testing.T, r *oidc.Registry, err error) {
		return func(t *testing.T, r *oidc.Registry, err error) {
			require.ErrorIs(t, err, oidc.ErrConfig)
			assert.Nil(t, r)
			for _, f := range fragments {
				assert.Contains(t, err.Error(), f)
			}
			assert.NotContains(t, err.Error(), clientSecret, "a refusal never carries the client secret")
		}
	}
	accepted := func(t *testing.T, r *oidc.Registry, err error) {
		require.NoError(t, err)
		require.NotNil(t, r)
	}

	cases := []testCase{
		{name: "a valid provider is accepted", providers: func() []oidc.Provider { return []oidc.Provider{valid()} },
			assert: func(t *testing.T, r *oidc.Registry, err error) {
				require.NoError(t, err)
				p, ok := r.Lookup("corp")
				require.True(t, ok)
				assert.Equal(t, oidc.DefaultScopes, p.Scopes, "nil scopes resolve to the default")
				assert.Equal(t, []string{"RS256"}, p.SigningAlgs, "nil algorithms resolve to RS256")
				assert.Equal(t, oidc.ClientSecretPost, p.ClientAuth, "the zero auth method is client_secret_post")
				_, ok = r.Lookup("other")
				assert.False(t, ok, "an unregistered name is not found")
			}},
		{name: "names keep registration order",
			providers: func() []oidc.Provider {
				a, b := valid(), valid()
				a.Name, b.Name = "zeta", "alpha"
				return []oidc.Provider{a, b}
			},
			assert: func(t *testing.T, r *oidc.Registry, err error) {
				require.NoError(t, err)
				require.Equal(t, []string{"zeta", "alpha"}, r.Names())
				r.Names()[0] = "mutated"
				assert.Equal(t, []string{"zeta", "alpha"}, r.Names(), "the caller's copy does not alias the registry")
			}},
		{name: "a looked-up provider does not alias the registry",
			providers: mutate(valid, func(p *oidc.Provider) { p.Scopes = []string{"openid", "groups"} }),
			assert: func(t *testing.T, r *oidc.Registry, err error) {
				require.NoError(t, err)
				p, ok := r.Lookup("corp")
				require.True(t, ok)
				p.Scopes[1] = "mutated"
				p.SigningAlgs[0] = "none"
				again, _ := r.Lookup("corp")
				assert.Equal(t, []string{"openid", "groups"}, again.Scopes)
				assert.Equal(t, []string{"RS256"}, again.SigningAlgs)
			}},
		{name: "no provider", providers: func() []oidc.Provider { return nil }, assert: refused("no provider")},
		{name: "duplicate name", providers: func() []oidc.Provider { return []oidc.Provider{valid(), valid()} }, assert: refused("corp", "duplicate")},
		{name: "empty name", providers: mutate(valid, func(p *oidc.Provider) { p.Name = "" }), assert: refused("name")},
		{name: "name with a slash", providers: mutate(valid, func(p *oidc.Provider) { p.Name = "a/b" }), assert: refused("a/b")},
		{name: "name that needs escaping in a path", providers: mutate(valid, func(p *oidc.Provider) { p.Name = "a b" }), assert: refused("a b")},
		{name: "name that is a dot segment", providers: mutate(valid, func(p *oidc.Provider) { p.Name = ".." }), assert: refused("..")},
		{name: "missing issuer", providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "" }), assert: refused("corp", "issuer")},
		{name: "missing client id", providers: mutate(valid, func(p *oidc.Provider) { p.ClientID = "" }), assert: refused("corp", "client id")},
		{name: "missing redirect URL", providers: mutate(valid, func(p *oidc.Provider) { p.RedirectURL = "" }), assert: refused("corp", "redirect URL")},
		{name: "issuer without a host", providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "https:///realms/dev" }), assert: refused("corp", "issuer")},
		{name: "issuer with a port and no host name", providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "https://:8443/realms/dev" }), assert: refused("corp", "issuer")},
		{name: "relative issuer", providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "/realms/dev" }), assert: refused("corp", "issuer")},
		{name: "issuer with credentials", providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "https://u:p@idp.example" }), assert: refused("corp", "issuer")},
		{name: "unparsable issuer", providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "https://idp.example/%zz" }), assert: refused("corp", "issuer")},
		{name: "issuer with a query", providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "https://idp.example?x=1" }), assert: refused("corp", "issuer", "query")},
		{name: "issuer with a fragment", providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "https://idp.example#f" }), assert: refused("corp", "issuer", "fragment")},
		{name: "redirect URL with a fragment", providers: mutate(valid, func(p *oidc.Provider) { p.RedirectURL = "https://app.example/cb#f" }), assert: refused("corp", "redirect URL", "fragment")},
		{name: "pinned endpoint with a port and no host name",
			providers: mutate(valid, func(p *oidc.Provider) { pinned(p); p.JWKSURI = "https://:8443/jwks" }),
			assert:    refused("corp", "key-set")},
		{name: "end-session endpoint with credentials",
			providers: mutate(valid, func(p *oidc.Provider) { p.EndSessionEndpoint = "https://u:p@idp.example/logout" }),
			assert:    refused("corp", "end-session")},
		{name: "plain-text URLs are left to the manager's scheme check",
			providers: mutate(valid, func(p *oidc.Provider) {
				p.Issuer = "http://localhost:8080/realms/dev"
				p.RedirectURL = "http://localhost:3000/login/oauth2/callback/corp"
				p.AuthorizationEndpoint = "http://localhost:8080/authorize"
				p.TokenEndpoint = "http://localhost:8080/token"
				p.JWKSURI = "http://localhost:8080/jwks"
				p.EndSessionEndpoint = "http://localhost:8080/logout"
			}),
			assert: accepted},
		{name: "configured scopes without openid", providers: mutate(valid, func(p *oidc.Provider) { p.Scopes = []string{"profile", "email"} }), assert: refused("corp", "openid")},
		{name: "configured empty scopes", providers: mutate(valid, func(p *oidc.Provider) { p.Scopes = []string{} }), assert: refused("corp", "openid")},
		{name: "HS256 with an empty client secret",
			providers: mutate(valid, func(p *oidc.Provider) { p.SigningAlgs = []string{"RS256", "HS256"}; p.ClientSecret = "" }),
			assert:    refused("corp", "HS256")},
		{name: "a redirect URL with a query is accepted",
			providers: mutate(valid, func(p *oidc.Provider) { p.RedirectURL = "https://app.example/cb?tenant=a" }),
			assert:    accepted},
		{name: "partial endpoint pin", providers: mutate(valid, func(p *oidc.Provider) { p.TokenEndpoint = "https://idp.example/token" }), assert: refused("corp", "pin")},
		{name: "two of three endpoints pinned",
			providers: mutate(valid, func(p *oidc.Provider) { pinned(p); p.AuthorizationEndpoint = "" }),
			assert:    refused("corp", "pin")},
		{name: "algorithm none", providers: mutate(valid, func(p *oidc.Provider) { p.SigningAlgs = []string{"RS256", "none"} }), assert: refused("corp", "none")},
		{name: "empty algorithm list", providers: mutate(valid, func(p *oidc.Provider) { p.SigningAlgs = []string{} }), assert: refused("corp", "algorithm")},
		{name: "unknown algorithm", providers: mutate(valid, func(p *oidc.Provider) { p.SigningAlgs = []string{"RS257"} }), assert: refused("corp", "RS257")},
		{name: "unknown client authentication method",
			providers: mutate(valid, func(p *oidc.Provider) { p.ClientAuth = oidc.ClientAuthMethod(9) }),
			assert:    refused("corp", "client authentication")},
		{name: "internal development provider is accepted",
			providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "https://localhost:8443/realms/dev" }),
			assert:    accepted},
		{name: "private-network provider is accepted",
			providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "https://10.0.0.5/realms/corp" }),
			assert:    accepted},
		{name: "all three endpoints pinned is accepted", providers: mutate(valid, pinned), assert: accepted},
		{name: "end-session endpoint alone is accepted",
			providers: mutate(valid, func(p *oidc.Provider) { p.EndSessionEndpoint = "https://idp.example/logout" }),
			assert:    accepted},
		{name: "HS256 listed explicitly is accepted",
			providers: mutate(valid, func(p *oidc.Provider) { p.SigningAlgs = []string{"HS256"} }),
			assert:    accepted},
		{name: "client_secret_basic is accepted",
			providers: mutate(valid, func(p *oidc.Provider) { p.ClientAuth = oidc.ClientSecretBasic }),
			assert:    accepted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, err := oidc.NewRegistry(tc.providers()...)
			tc.assert(t, r, err)
		})
	}
}
