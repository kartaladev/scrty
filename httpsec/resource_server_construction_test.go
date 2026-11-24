package httpsec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// TestResourceServer_Construction pins the resource server's wiring rules: each mistake fails at
// construction with a configuration error naming it, before any request.
func TestResourceServer_Construction(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		build  func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, err error)
	}

	// bound is a source that requires binding, as every source does by default.
	bound := func(name, issuer string) httpsec.ResourceServerOption {
		return httpsec.WithStubSource(&httpsec.StubSource{Name: name, Issuer: issuer})
	}

	// withBinding is a chain that can check a certificate binding.
	withBinding := func(opts ...httpsec.Option) []httpsec.Option {
		return append([]httpsec.Option{httpsec.EnableCertificateBinding()}, opts...)
	}

	builds := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err)
	}

	refused := func(names ...string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)
			for _, name := range names {
				assert.Contains(t, err.Error(), name)
			}
		}
	}

	cases := []testCase{
		{
			name: "an identifier and a bound source on a chain that checks bindings",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("urn:example:orders:api", bound("a", "")))
			},
			assert: builds,
		},
		{
			name: "an identifier that is no URI",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("orders api", bound("a", "")))
			},
			assert: refused("orders api"),
		},
		{
			name: "an identifier with a fragment",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("https://api.example.com/orders#v1", bound("a", "")))
			},
			assert: refused("https://api.example.com/orders#v1"),
		},
		{
			name: "an empty identifier",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("", bound("a", "")))
			},
			assert: refused("identifier"),
		},
		{
			name: "an alias that is no URI",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("urn:orders",
					httpsec.WithResourceAliases("orders"), bound("a", "")))
			},
			assert: refused("orders", "alias"),
		},
		{
			name: "a duplicate alias",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("urn:orders",
					httpsec.WithResourceAliases("urn:orders:v1", "urn:orders:v1"), bound("a", "")))
			},
			assert: refused("urn:orders:v1"),
		},
		{
			name: "an alias equal to the identifier",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("urn:orders",
					httpsec.WithResourceAliases("urn:orders"), bound("a", "")))
			},
			assert: refused("urn:orders"),
		},
		{
			name: "an identifier equal to the provider's issuer",
			build: func(t *testing.T) []httpsec.Option {
				p := f.provider(t)

				return withBinding(append(f.wired(t, p),
					httpsec.EnableOIDCProvider(p),
					httpsec.EnableResourceServer(opIssuer, bound("a", "")))...)
			},
			assert: refused(opIssuer, "issuer"),
		},
		{
			name: "an alias equal to the provider's issuer",
			build: func(t *testing.T) []httpsec.Option {
				p := f.provider(t)

				return withBinding(append(f.wired(t, p),
					httpsec.EnableOIDCProvider(p),
					httpsec.EnableResourceServer("urn:orders", httpsec.WithResourceAliases(opIssuer), bound("a", "")))...)
			},
			assert: refused(opIssuer, "issuer"),
		},
		{
			name: "a prefix without a trailing slash",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api"), bound("a", "")))
			},
			assert: refused(`"/api"`),
		},
		{
			name: "a relative prefix",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("api/"), bound("a", "")))
			},
			assert: refused(`"api/"`),
		},
		{
			name: "a prefix with a dot segment",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("urn:orders",
					httpsec.WithPathPrefix("/api/../admin/"), bound("a", "")))
			},
			assert: refused(`"/api/../admin/"`),
		},
		{
			name: "a prefix with an empty segment",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api//"), bound("a", "")))
			},
			assert: refused(`"/api//"`),
		},
		{
			name: "an empty prefix list",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix(), bound("a", "")))
			},
			assert: refused("WithPathPrefix"),
		},
		{
			name: "two resource servers by distinct prefixes",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(
					httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/orders/"), bound("a", "")),
					httpsec.EnableResourceServer("urn:billing", httpsec.WithPathPrefix("/billing/"), bound("b", "")),
				)
			},
			assert: builds,
		},
		{
			name: "overlapping prefixes",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(
					httpsec.EnableResourceServer("urn:api", httpsec.WithPathPrefix("/api/"), bound("a", "")),
					httpsec.EnableResourceServer("urn:billing", httpsec.WithPathPrefix("/api/billing/"), bound("b", "")),
				)
			},
			assert: refused(`"/api/"`, `"/api/billing/"`),
		},
		{
			name: "the same prefix twice",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(
					httpsec.EnableResourceServer("urn:api", httpsec.WithPathPrefix("/api/"), bound("a", "")),
					httpsec.EnableResourceServer("urn:billing", httpsec.WithPathPrefix("/api/"), bound("b", "")),
				)
			},
			assert: refused(`"/api/"`),
		},
		{
			name: "prefixes that share only text, not a segment",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(
					httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/orders/"), bound("a", "")),
					httpsec.EnableResourceServer("urn:orders2", httpsec.WithPathPrefix("/api/orders-v2/"), bound("b", "")),
				)
			},
			assert: builds,
		},
		{
			name: "an unscoped resource server beside another",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(
					httpsec.EnableResourceServer("urn:all", bound("a", "")),
					httpsec.EnableResourceServer("urn:billing", httpsec.WithPathPrefix("/billing/"), bound("b", "")),
				)
			},
			assert: refused("prefix"),
		},
		{
			name: "no source",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("urn:orders"))
			},
			assert: refused("urn:orders", "source"),
		},
		{
			name: "a nil source",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("urn:orders", httpsec.WithNilSource()))
			},
			assert: refused("source"),
		},
		{
			name: "a typed nil source",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("urn:orders", httpsec.WithStubSource(nil)))
			},
			assert: refused("source"),
		},
		{
			name: "two sources for one issuer in one resource server",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("urn:orders",
					bound("a", "https://sso.example.com"), bound("b", "https://sso.example.com")))
			},
			assert: refused("https://sso.example.com"),
		},
		{
			name: "two resource servers trusting one issuer",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(
					httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/orders/"), bound("a", "https://sso.example.com")),
					httpsec.EnableResourceServer("urn:billing", httpsec.WithPathPrefix("/billing/"), bound("b", "https://sso.example.com")),
				)
			},
			assert: builds,
		},
		{
			name: "binding required with nothing to check it",
			build: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableResourceServer("urn:orders", bound("a", ""))}
			},
			assert: refused("binding"),
		},
		{
			name: "a source that accepts unbound tokens needs nothing to check a binding",
			build: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableResourceServer("urn:orders",
					httpsec.WithStubSource(&httpsec.StubSource{Name: "a", Unbound: true}))}
			},
			assert: builds,
		},
		{
			name: "the resource server counts as a verifier of bound credentials",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.EnableResourceServer("urn:orders", bound("a", "")))
			},
			assert: builds,
		},
		{
			name: "DPoP on a chain whose only credential mode is a resource server",
			build: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}),
					httpsec.EnableResourceServer("urn:orders", bound("a", "")),
				}
			},
			assert: builds,
		},
		{
			name: "a source opting out of binding on a chain that requires DPoP",
			build: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL, Require: true}),
					httpsec.EnableResourceServer("urn:orders",
						httpsec.WithStubSource(&httpsec.StubSource{Name: "partner-sso", Unbound: true})),
				}
			},
			assert: refused("partner-sso", "unbound", "DPoP.Require"),
		},
		{
			name: "a source opting out of binding on a chain whose DPoP is optional",
			build: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}),
					httpsec.EnableResourceServer("urn:orders",
						httpsec.WithStubSource(&httpsec.StubSource{Name: "partner-sso", Unbound: true})),
				}
			},
			assert: builds,
		},
		{
			name: "the challenge turned off on a chain whose only credential mode is a resource server",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(httpsec.WithoutBearerChallenge(), httpsec.EnableResourceServer("urn:orders", bound("a", "")))
			},
			assert: builds,
		},
		{
			name: "the same prefix given twice to one resource server is one prefix",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(
					httpsec.EnableResourceServer("urn:api", httpsec.WithPathPrefix("/api/", "/API/"), bound("a", "")),
					httpsec.EnableResourceServer("urn:billing", httpsec.WithPathPrefix("/billing/"), bound("b", "")),
				)
			},
			assert: builds,
		},
		{
			name: "prefixes of two resource servers differing only in case overlap",
			build: func(*testing.T) []httpsec.Option {
				return withBinding(
					httpsec.EnableResourceServer("urn:api", httpsec.WithPathPrefix("/api/"), bound("a", "")),
					httpsec.EnableResourceServer("urn:billing", httpsec.WithPathPrefix("/API/billing/"), bound("b", "")),
				)
			},
			assert: refused(`"/api/"`, `"/API/billing/"`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(tc.build(t)...)
			tc.assert(t, err)
		})
	}
}
