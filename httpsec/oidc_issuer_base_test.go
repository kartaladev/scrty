package httpsec_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
)

// TestOIDCProvider_IssuerBasePath pins that, under a base path, the provider's
// issuer must cover the base path and every path the provider serves, so the
// OpenID configuration is served under the base and every published URL names a
// path the chain serves; that the waiver lifts the check; and that with no base
// path nothing is checked.
func TestOIDCProvider_IssuerBasePath(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type setup struct {
		issuer   string
		base     string
		provider []oidcprovider.Option
		opts     []httpsec.OIDCProviderOption
		jwks     []httpsec.JWKSOption
	}

	type testCase struct {
		name   string
		setup  setup
		assert func(t *testing.T, chain *httpsec.Chain, err error)
	}

	refused := func(fragments ...string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, chain)

			for _, fragment := range fragments {
				assert.ErrorContains(t, err, fragment)
			}
		}
	}

	built := func(t *testing.T, chain *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		require.NotNil(t, chain)
	}

	// discoveryAt asserts the chain builds and answers the OpenID configuration
	// at path, whose token_endpoint is token.
	discoveryAt := func(path, token string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			t.Helper()

			built(t, chain, err)

			answer := bpServe(t, chain, http.MethodGet, path)
			require.Equal(t, http.StatusOK, answer.status, "the OpenID configuration should answer at %s", path)
			assert.Equal(t, token, answer.doc(t)["token_endpoint"])
		}
	}

	cases := []testCase{
		{
			name:   "a root issuer under a base path is refused",
			setup:  setup{issuer: opIssuer, base: bpBase},
			assert: refused("EnableOIDCProvider", `"`+opIssuer+`"`, `"/auth"`, "WithoutOIDCIssuerBasePathCheck"),
		},
		{
			name:  "an issuer at the base path builds, with discovery under the base",
			setup: setup{issuer: opIssuer + "/auth", base: bpBase},
			assert: discoveryAt("/auth"+mdOIDCPath,
				opIssuer+"/auth/oauth2/token"),
		},
		{
			name:  "an issuer at the base path with a trailing slash builds",
			setup: setup{issuer: opIssuer + "/auth/", base: bpBase},
			assert: discoveryAt("/auth"+mdOIDCPath,
				opIssuer+"/auth/oauth2/token"),
		},
		{
			name:   "an issuer outside the base path is refused",
			setup:  setup{issuer: opIssuer + "/other", base: bpBase},
			assert: refused("EnableOIDCProvider", `"`+opIssuer+`/other"`, `"/auth"`),
		},
		{
			name:   "an issuer sharing only a name prefix with the base path is refused",
			setup:  setup{issuer: opIssuer + "/authx", base: bpBase},
			assert: refused("EnableOIDCProvider", `"`+opIssuer+`/authx"`, `"/auth"`),
		},
		{
			name:   "an issuer deeper than the endpoints is refused",
			setup:  setup{issuer: opIssuer + "/auth/op", base: bpBase},
			assert: refused("EnableOIDCProvider", `"`+opIssuer+`/auth/op"`, `"/auth"`, `"/auth/oauth2/token"`),
		},
		{
			name: "an issuer under the base covering every endpoint and the key set builds",
			setup: setup{
				issuer: opIssuer + "/auth/op",
				base:   bpBase,
				opts:   []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/op/oauth2")},
				jwks:   []httpsec.JWKSOption{httpsec.WithJWKSEndpointPath("/op/keys")},
			},
			assert: discoveryAt("/auth/op"+mdOIDCPath, opIssuer+"/auth/op/oauth2/token"),
		},
		{
			name: "an endpoint override outside the issuer's path is refused",
			setup: setup{
				issuer: opIssuer + "/auth/op",
				base:   bpBase,
				opts: []httpsec.OIDCProviderOption{
					httpsec.WithOIDCProviderPrefix("/op/oauth2"),
					httpsec.WithOIDCProviderPath(httpsec.OIDCAuthorize, "/login"),
				},
				jwks: []httpsec.JWKSOption{httpsec.WithJWKSEndpointPath("/op/keys")},
			},
			assert: refused("EnableOIDCProvider", `"`+opIssuer+`/auth/op"`, `"/auth"`, `"/auth/login"`),
		},
		{
			name: "a key set outside the issuer's path is refused",
			setup: setup{
				issuer: opIssuer + "/auth/op",
				base:   bpBase,
				opts:   []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/op/oauth2")},
			},
			assert: refused("EnableOIDCProvider", `"`+opIssuer+`/auth/op"`, `"/auth"`, `"/auth/.well-known/jwks.json"`),
		},
		{
			name: "the waiver builds a root issuer, with discovery at the root",
			setup: setup{
				issuer: opIssuer,
				base:   bpBase,
				opts:   []httpsec.OIDCProviderOption{httpsec.WithoutOIDCIssuerBasePathCheck()},
			},
			assert: discoveryAt(mdOIDCPath, opIssuer+"/auth/oauth2/token"),
		},
		{
			name: "the waiver with a root issuer and an endpoint audience is refused by the assertion endpoint check",
			setup: setup{
				issuer:   opIssuer,
				base:     bpBase,
				provider: []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint)},
				opts:     []httpsec.OIDCProviderOption{httpsec.WithoutOIDCIssuerBasePathCheck()},
			},
			assert: refused("EnableOIDCProvider", "accepts assertions naming", `"`+opIssuer+`/oauth2/token"`,
				"WithAssertionTokenEndpoint"),
		},
		{
			name: "the waiver with an endpoint audience stating the published token URL builds",
			setup: setup{
				issuer: opIssuer,
				base:   bpBase,
				provider: []oidcprovider.Option{
					oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint),
					oidcprovider.WithAssertionTokenEndpoint(opIssuer + "/auth/oauth2/token"),
				},
				opts: []httpsec.OIDCProviderOption{httpsec.WithoutOIDCIssuerBasePathCheck()},
			},
			assert: discoveryAt(mdOIDCPath, opIssuer+"/auth/oauth2/token"),
		},
		{
			name:   "with no base path a root issuer builds as before",
			setup:  setup{issuer: opIssuer},
			assert: discoveryAt(mdOIDCPath, opIssuer+"/oauth2/token"),
		},
		{
			name:  "with no base path an issuer deeper than the endpoints builds as before",
			setup: setup{issuer: opIssuer + "/auth/op"},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				t.Helper()

				built(t, chain, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := f.providerOver(t, tc.setup.issuer, f.keys, nil, tc.setup.provider...)

			opts := []httpsec.Option{
				f.bearer(t, reporting(t, p)),
				httpsec.EnableJWKSEndpoint(f.keys, tc.setup.jwks...),
				httpsec.EnableSecurityHeaders(),
				httpsec.EnableCSRFProtection(),
				httpsec.EnableOIDCProvider(p, tc.setup.opts...),
			}
			if tc.setup.base != "" {
				opts = append(opts, httpsec.WithBasePath(tc.setup.base))
			}

			chain, err := httpsec.New(opts...)
			tc.assert(t, chain, err)
		})
	}
}
