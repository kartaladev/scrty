package httpsec_test

import (
	"crypto/elliptic"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
)

// A proof names the URL the metadata publishes, and the chain compares it with the URL its DPoP
// settings build from the request. Where those two cannot agree no proof is ever accepted, so that is
// a wiring mistake and fails at construction. Each row that builds also sends a proof.
func TestOIDCProvider_DPoPURLAgreesWithPublishedEndpoints(t *testing.T) {
	t.Parallel()

	forwardingHost := httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Headers: httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto,
			httpsec.ForwardedHost("id.example.com")),
	})
	underAuth := []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/auth")}

	type testCase struct {
		name     string
		issuer   string
		dpop     httpsec.DPoP
		chain    []httpsec.Option
		endpoint []httpsec.OIDCProviderOption
		// served is the token endpoint's path as the chain sees it, and empty when it refuses to build.
		served string
		// refused holds what a construction error must name.
		refused []string
	}

	cases := []testCase{
		{
			name:   "a root issuer on its own origin",
			issuer: opIssuer, dpop: httpsec.DPoP{PublicURL: opIssuer}, served: "/oauth2/token",
		},
		{
			name:   "a root issuer, its origin spelled with the default port",
			issuer: opIssuer, dpop: httpsec.DPoP{PublicURL: opIssuer + ":443"}, served: "/oauth2/token",
		},
		{
			name:   "a root issuer, on another origin",
			issuer: opIssuer, dpop: httpsec.DPoP{PublicURL: "https://api.example.com"},
			refused: []string{"EnableOIDCProvider", "PublicURL", opIssuer + "/oauth2/token"},
		},
		{
			name:   "a stripped issuer path the public URL leaves out",
			issuer: opIssuer + "/auth", dpop: httpsec.DPoP{PublicURL: opIssuer},
			refused: []string{"EnableOIDCProvider", "PublicURL", opIssuer + "/auth/oauth2/token"},
		},
		{
			name:   "a stripped issuer path the public URL holds",
			issuer: opIssuer + "/auth", dpop: httpsec.DPoP{PublicURL: opIssuer + "/auth"}, served: "/oauth2/token",
		},
		{
			name:   "an issuer path the chain serves, and a public URL of the origin",
			issuer: opIssuer + "/auth", dpop: httpsec.DPoP{PublicURL: opIssuer},
			endpoint: underAuth, served: "/auth/token",
		},
		{
			name:   "an issuer path the chain serves, and a public URL that repeats it",
			issuer: opIssuer + "/auth", dpop: httpsec.DPoP{PublicURL: opIssuer + "/auth"},
			endpoint: underAuth,
			refused:  []string{"EnableOIDCProvider", "PublicURL", opIssuer + "/auth/token"},
		},
		{
			name:   "a stripped issuer path with no public URL, which the request cannot state",
			issuer: opIssuer + "/auth", chain: []httpsec.Option{forwardingHost},
			refused: []string{"EnableOIDCProvider", "PublicURL", opIssuer + "/auth/oauth2/token"},
		},
		{
			name:   "UserInfo alone left out of the public URL",
			issuer: opIssuer + "/auth", dpop: httpsec.DPoP{PublicURL: opIssuer + "/auth"},
			endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(httpsec.OIDCUserInfo, "/auth/me")},
			refused:  []string{"EnableOIDCProvider", "PublicURL", opIssuer + "/auth/me"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newOPFixture(t)
			p := f.providerOver(t, tc.issuer, f.keys, nil, oidcprovider.WithDPoP())
			opts := append(f.wired(t, p), tc.chain...)
			opts = append(opts, httpsec.EnableDPoP(tc.dpop), httpsec.EnableOIDCProvider(p, tc.endpoint...))

			chain, err := httpsec.New(opts...)
			if len(tc.refused) > 0 {
				require.Error(t, err)
				for _, name := range tc.refused {
					assert.Contains(t, err.Error(), name)
				}

				return
			}
			require.NoError(t, err)

			// The URL a client reads from the metadata, in the served path's place when the issuer's path
			// was stripped before the chain.
			issuerPath := strings.TrimPrefix(tc.issuer, opIssuer)
			published := opIssuer + tc.served
			if !strings.HasPrefix(tc.served, issuerPath+"/") {
				published = tc.issuer + tc.served
			}

			k := newDPoPKey(t, elliptic.P256())
			send := func(jti, htu string) string {
				proof := k.validProof(jti).with(map[string]any{
					"htm": http.MethodPost, "htu": htu, "iat": time.Now().Unix(),
				}).sign(t)

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, opIssuer+tc.served,
					strings.NewReader(url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "client_id": {"billing-web"}}.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("DPoP", proof)
				r.RemoteAddr = tokenAddr

				rec := httptest.NewRecorder()
				chain.Middleware()(http.NotFoundHandler()).ServeHTTP(rec, r)
				require.NotEqual(t, http.StatusNotFound, rec.Code, "the token endpoint answered")

				return rec.Body.String()
			}

			assert.Contains(t, send("control", published+"/elsewhere"), "invalid_dpop_proof", "a proof's URL is judged here")
			assert.NotContains(t, send("named", published), "invalid_dpop_proof", "a proof naming the published endpoint passes")
		})
	}
}

// Without a public URL the proof's URL is built from the request, so an issuer path the chain serves
// agrees with it, and is not refused for want of one.
func TestOIDCProvider_DPoPWithNoPublicURLBuilds(t *testing.T) {
	t.Parallel()

	forwardingHost := httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Headers: httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto,
			httpsec.ForwardedHost("id.example.com")),
	})

	type testCase struct {
		name     string
		issuer   string
		endpoint []httpsec.OIDCProviderOption
	}

	cases := []testCase{
		{name: "a root issuer", issuer: opIssuer},
		{
			name: "an issuer path the chain serves", issuer: opIssuer + "/auth",
			endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/auth")},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newOPFixture(t)
			p := f.providerOver(t, tc.issuer, f.keys, nil, oidcprovider.WithDPoP())
			opts := append(f.wired(t, p), forwardingHost,
				httpsec.EnableDPoP(httpsec.DPoP{}), httpsec.EnableOIDCProvider(p, tc.endpoint...))

			_, err := httpsec.New(opts...)
			require.NoError(t, err)
		})
	}
}
