package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// oidcLoginRedirecting enables federated login over a registry whose provider
// "corp" is registered with redirectURL, with the chain options and OIDC
// options given.
func oidcLoginRedirecting(t *testing.T, redirectURL string, chain []httpsec.Option,
	opts ...httpsec.OIDCOption,
) []httpsec.Option {
	t.Helper()

	flows, err := oidc.NewMemoryFlowStore()
	require.NoError(t, err)

	registry, err := oidc.NewRegistry(oidc.Provider{ //nolint:gosec // G101: a fixture, not a credential
		Name:                  testOIDCProvider,
		Issuer:                "https://idp.example.com",
		ClientID:              "app",
		ClientSecret:          "secret-" + testOIDCProvider,
		RedirectURL:           redirectURL,
		AuthorizationEndpoint: "https://idp.example.com/authorize",
		TokenEndpoint:         "https://idp.example.com/token",
		JWKSURI:               "https://idp.example.com/jwks",
	})
	require.NoError(t, err)

	broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(gomock.NewController(t)))
	require.NoError(t, err)

	rp, err := oidc.NewRelyingParty(registry, broker, oidc.WithFlowStore(flows))
	require.NoError(t, err)

	handoffs, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(gomock.NewController(t)))
	require.NoError(t, err)

	sessions, err := session.New()
	require.NoError(t, err)

	all := append([]httpsec.OIDCOption{
		httpsec.WithOIDCSessions(sessions),
		httpsec.WithOIDCTokens(newMockGenerator(gomock.NewController(t))),
	}, opts...)

	return append(chain, httpsec.EnableOIDCLogin(
		httpsec.OIDCDeps{RelyingParty: rp, Handoff: handoffs}, all...))
}

// TestOIDCLogin_RefusesRedirectURLThatCannotReachCallback pins that a
// provider's redirect URL must end with the callback path the chain serves,
// followed by the provider's name: a mismatch fails every login at the
// identity provider, so it is refused at construction.
func TestOIDCLogin_RefusesRedirectURLThatCannotReachCallback(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		redirectURL string
		chain       []httpsec.Option
		opts        []httpsec.OIDCOption
		assert      func(t *testing.T, err error)
	}

	refused := func(wants ...string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.Error(t, err)
			require.ErrorIs(t, err, httpsec.ErrConfig)
			for _, want := range wants {
				assert.ErrorContains(t, err, want)
			}
		}
	}

	accepted := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err)
	}

	cases := []testCase{
		{
			name:        "callback moved without the redirect URL",
			redirectURL: "https://app.example.com/sso/callback/corp",
			opts:        []httpsec.OIDCOption{httpsec.WithOIDCCallbackPath("/federation/callback/")},
			assert:      refused("corp", "/sso/callback/corp", "/federation/callback/corp"),
		},
		{
			name:        "base path not reflected in the redirect URL",
			redirectURL: "https://app.example.com/sso/callback/corp",
			chain:       []httpsec.Option{httpsec.WithBasePath("/auth")},
			assert:      refused("corp", "/sso/callback/corp", "/auth/sso/callback/corp"),
		},
		{
			name:        "redirect URL for another provider name",
			redirectURL: "https://app.example.com/sso/callback/other",
			assert:      refused("corp", "/sso/callback/other", "/sso/callback/corp"),
		},
		{
			name:        "redirect path with a trailing slash",
			redirectURL: "https://app.example.com/sso/callback/corp/",
			assert:      refused("corp", "/sso/callback/corp/"),
		},
		{
			name:        "redirect path continuing past the name",
			redirectURL: "https://app.example.com/sso/callback/corp/extra",
			assert:      refused("corp", "/sso/callback/corp/extra"),
		},
		{
			name:        "matching redirect URL",
			redirectURL: "https://app.example.com/sso/callback/corp",
			assert:      accepted,
		},
		{
			name:        "matching redirect URL under the base path",
			redirectURL: "https://app.example.com/auth/sso/callback/corp",
			chain:       []httpsec.Option{httpsec.WithBasePath("/auth")},
			assert:      accepted,
		},
		{
			name:        "matching redirect URL for the moved callback",
			redirectURL: "https://app.example.com/federation/callback/corp",
			opts:        []httpsec.OIDCOption{httpsec.WithOIDCCallbackPath("/federation/callback/")},
			assert:      accepted,
		},
		{
			name:        "proxy that removes a prefix",
			redirectURL: "https://example.com/public/sso/callback/corp",
			assert:      accepted,
		},
		{
			name:        "percent-encoded redirect path",
			redirectURL: "https://app.example.com/sso/callback/%63orp",
			assert:      accepted,
		},
		{
			name:        "waiver accepts a redirect URL that cannot arrive",
			redirectURL: "https://example.com/cb?p=corp",
			opts:        []httpsec.OIDCOption{httpsec.WithoutOIDCRedirectPathCheck()},
			assert:      accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(oidcLoginRedirecting(t, tc.redirectURL, tc.chain, tc.opts...)...)
			tc.assert(t, err)
		})
	}
}

// TestOIDCLogin_TrailingSlashOfCallbackPrefix pins that a callback prefix given
// with its trailing slash, and no base path, builds with a redirect URL ending
// in the prefix and the provider's name, and that the callback is then served
// there and not at the default prefix.
func TestOIDCLogin_TrailingSlashOfCallbackPrefix(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		path   string
		assert func(t *testing.T, out served)
	}

	cases := []testCase{
		{
			name: "the callback under the moved prefix reaches the callback",
			path: "/federation/callback/corp?code=c&state=s",
			assert: func(t *testing.T, out served) {
				// No flow cookie travels with the request, so the callback
				// refuses it as one that does not belong to a flow.
				require.ErrorIs(t, out.err, oidc.ErrInvalidState)
				assert.False(t, out.handlerRan)
			},
		},
		{
			name: "the default prefix is no longer the callback",
			path: "/sso/callback/corp?code=c&state=s",
			assert: func(t *testing.T, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(oidcLoginRedirecting(t, "https://app.example.com/federation/callback/corp", nil,
				httpsec.WithOIDCCallbackPath("/federation/callback/"))...)
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, nil)
			tc.assert(t, serve(t, chain, req))
		})
	}
}
