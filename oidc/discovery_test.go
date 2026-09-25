package oidc_test

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
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
			m, err := oidc.NewManager(reg, stubBroker{}, oidc.WithOutboundClient(p.Outbound(t)))
			require.NoError(t, err)

			md, err := oidc.MetadataForTest(m, t.Context(), "corp")
			tc.assert(t, p, other, md, err)
		})
	}
}
