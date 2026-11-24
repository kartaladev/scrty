package oidc_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/oidc"
)

func TestProvider_UserInfoEndpoint(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// discovered, when set, is the discovery document's
		// userinfo_endpoint, given the issuer.
		discovered func(issuer string) string
		configure  func(p *testProvider, cfg *oidc.Provider)
		// assert gets the error of building the relying party, and, when it
		// built, the result of a UserInfo fetch for subject-1.
		assert func(t *testing.T, p *testProvider, buildErr error, got map[string]any, err error)
	}

	fetchedFrom := func(path string) func(*testing.T, *testProvider, error, map[string]any, error) {
		return func(t *testing.T, p *testProvider, buildErr error, got map[string]any, err error) {
			t.Helper()
			require.NoError(t, buildErr)
			require.NoError(t, err)
			assert.Equal(t, map[string]any{"sub": "subject-1"}, got)
			assert.Equal(t, []string{path}, p.UserInfoPaths())
		}
	}
	noEndpoint := func(t *testing.T, p *testProvider, buildErr error, got map[string]any, err error) {
		t.Helper()
		require.NoError(t, buildErr)
		require.ErrorIs(t, err, oidc.ErrUserInfoFailed)
		assert.NotErrorIs(t, err, oidc.ErrDiscoveryFailed, "a missing endpoint is not a discovery failure")
		assert.Nil(t, got)
		assert.Empty(t, p.UserInfoPaths(), "no request is sent")
	}
	pinClassic := func(p *testProvider, cfg *oidc.Provider) {
		cfg.AuthorizationEndpoint = p.Issuer() + "/authorize"
		cfg.TokenEndpoint = p.Issuer() + "/token"
		cfg.JWKSURI = p.Issuer() + "/jwks"
	}

	cases := []testCase{
		{
			name:       "discovered",
			discovered: func(issuer string) string { return issuer + "/userinfo" },
			assert:     fetchedFrom("/userinfo"),
		},
		{
			name:       "pinned wins over discovered",
			discovered: func(issuer string) string { return issuer + "/userinfo" },
			configure:  func(p *testProvider, cfg *oidc.Provider) { cfg.UserInfoEndpoint = p.Issuer() + "/me" },
			assert:     fetchedFrom("/me"),
		},
		{
			name:      "pinned http with only https allowed is a configuration error",
			configure: func(_ *testProvider, cfg *oidc.Provider) { cfg.UserInfoEndpoint = "http://corp.example/me" },
			assert: func(t *testing.T, _ *testProvider, buildErr error, _ map[string]any, _ error) {
				require.ErrorIs(t, buildErr, oidc.ErrConfig)
				assert.Contains(t, buildErr.Error(), "userinfo endpoint")
			},
		},
		{
			name:   "discovery without the endpoint succeeds, and only UserInfo fails",
			assert: noEndpoint,
		},
		{
			name:       "a discovered endpoint off the issuer's origin is ignored, and only UserInfo fails",
			discovered: func(string) string { return "https://elsewhere.example/userinfo" },
			assert:     noEndpoint,
		},
		{
			name:       "a discovered endpoint with a refused scheme is ignored",
			discovered: func(issuer string) string { return "http" + issuer[len("https"):] + "/userinfo" },
			assert:     noEndpoint,
		},
		{
			name: "classic endpoints and UserInfo pinned make no discovery call",
			configure: func(p *testProvider, cfg *oidc.Provider) {
				pinClassic(p, cfg)
				cfg.UserInfoEndpoint = p.Issuer() + "/me"
			},
			assert: func(t *testing.T, p *testProvider, buildErr error, got map[string]any, err error) {
				fetchedFrom("/me")(t, p, buildErr, got, err)
				assert.Zero(t, p.discoveryCalls.Load())
			},
		},
		{
			name:      "classic endpoints pinned and UserInfo not pinned: no discovery, and UserInfo fails",
			configure: pinClassic,
			assert: func(t *testing.T, p *testProvider, buildErr error, got map[string]any, err error) {
				noEndpoint(t, p, buildErr, got, err)
				assert.Zero(t, p.discoveryCalls.Load())
			},
		},
		{
			name:       "UserInfo pinned and discovery down: the pin is used",
			discovered: func(issuer string) string { return issuer + "/userinfo" },
			configure: func(p *testProvider, cfg *oidc.Provider) {
				cfg.UserInfoEndpoint = p.Issuer() + "/me"
				p.failDiscovery.Store(true)
			},
			assert: fetchedFrom("/me"),
		},
		{
			name: "discovery down and no pin: UserInfo fails matching the discovery failure",
			configure: func(p *testProvider, _ *oidc.Provider) {
				p.failDiscovery.Store(true)
			},
			assert: func(t *testing.T, p *testProvider, buildErr error, got map[string]any, err error) {
				require.NoError(t, buildErr)
				require.ErrorIs(t, err, oidc.ErrUserInfoFailed)
				assert.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
				assert.Nil(t, got)
				assert.Empty(t, p.UserInfoPaths())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newTestProvider(t)
			if tc.discovered != nil {
				p.discoveredUserInfo.Store(tc.discovered(p.Issuer()))
			}
			cfg := p.Provider("corp")
			if tc.configure != nil {
				tc.configure(p, &cfg)
			}

			reg, err := oidc.NewRegistry(cfg)
			require.NoError(t, err)
			var logs bytes.Buffer
			m, buildErr := oidc.NewRelyingParty(reg, stubBroker{},
				oidc.WithOutboundClient(p.Outbound(t)), oidc.WithLogger(testTextLogger(&logs)))
			if buildErr != nil {
				tc.assert(t, p, buildErr, nil, nil)
				return
			}

			got, err := oidc.UpstreamForTest(m, "corp", upstreamAccessToken, "subject-1").UserInfo(t.Context())
			tc.assert(t, p, nil, got, err)
			assert.NotContains(t, logs.String(), upstreamAccessToken)
		})
	}
}
