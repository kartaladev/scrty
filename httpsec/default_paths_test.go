package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// TestDefaultEndpointPaths pins, with no path configured, where each built-in
// answers: the new default is answered by the chain itself, and the old
// default is not, so it reaches the consumer's handler.
func TestDefaultEndpointPaths(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		build   func(t *testing.T) (*httpsec.Chain, error)
		method  string
		path    string
		oldPath string
	}

	cases := []testCase{
		{
			name: "password sign-in",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				h := newLoginGuardHarness(t)

				return httpsec.New(httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
				}))
			},
			method: http.MethodPost, path: "/sign-in/password", oldPath: "/login",
		},
		{
			name: "logout",
			build: func(_ *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: must.Must(session.New())}))
			},
			method: http.MethodPost, path: "/sign-out", oldPath: "/logout",
		},
		{
			name:   "magic-link request",
			build:  func(t *testing.T) (*httpsec.Chain, error) { return newMagicLinkHarness(t).build() },
			method: http.MethodPost, path: "/sign-in/magic-link", oldPath: "/login/magic",
		},
		{
			name:   "magic-link redeem",
			build:  func(t *testing.T) (*httpsec.Chain, error) { return newMagicLinkHarness(t).build() },
			method: http.MethodPost, path: "/sign-in/magic-link/redeem", oldPath: "/login/magic/consume",
		},
		{
			name: "passwordless passkey begin",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(newPwlDeployment(t).options(t)...)
			},
			method: http.MethodPost, path: "/sign-in/passkey/begin", oldPath: "/passkey/login/begin",
		},
		{
			name: "passwordless passkey finish",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(newPwlDeployment(t).options(t)...)
			},
			method: http.MethodPost, path: "/sign-in/passkey/finish", oldPath: "/passkey/login/finish",
		},
		{
			name: "passkey registration begin",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(newPasskeyHarness(t).chainOptions(t, nil)...)
			},
			method: http.MethodPost, path: "/passkeys/register/begin", oldPath: "/passkey/register/begin",
		},
		{
			name: "passkey list",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(newPasskeyHarness(t).chainOptions(t, nil)...)
			},
			method: http.MethodGet, path: "/passkeys", oldPath: "/passkey/credentials",
		},
		{
			name: "passkey rename",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(newPasskeyHarness(t).chainOptions(t, nil)...)
			},
			method: http.MethodPost, path: "/passkeys/rename", oldPath: "/passkey/credentials/rename",
		},
		{
			name: "passkey remove",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(newPasskeyHarness(t).chainOptions(t, nil)...)
			},
			method: http.MethodPost, path: "/passkeys/remove", oldPath: "/passkey/credentials/remove",
		},
		{
			name: "MFA challenge",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				h := newMFAHarness(t)
				h.channel(factor.AuthenticatorApp)

				return h.buildChain(t)
			},
			method: http.MethodPost, path: "/mfa/challenge/totp", oldPath: "/mfa/begin/totp",
		},
		{
			name: "re-authentication challenge",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return newReauthHarness(t).build(nil)
			},
			method: http.MethodPost, path: "/reauth/challenge/totp", oldPath: "/reauth/begin/totp",
		},
		{
			name: "SSO login",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return buildOIDCLogin(t)
			},
			method: http.MethodGet, path: "/sso/login/corp", oldPath: "/oauth2/authorization/corp",
		},
		{
			name: "SSO callback",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return buildOIDCLogin(t)
			},
			method: http.MethodGet, path: "/sso/callback/corp", oldPath: "/login/oauth2/callback/corp",
		},
		{
			name: "SSO handoff",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return buildOIDCLogin(t)
			},
			method: http.MethodPost, path: "/sso/handoff", oldPath: "/login/oauth2/handoff",
		},
		{
			name: "SSO back-channel logout",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return buildOIDCLogin(t)
			},
			method: http.MethodPost, path: "/sso/backchannel-logout/corp", oldPath: "/logout/oauth2/backchannel/corp",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := tc.build(t)
			require.NoError(t, err)

			answered := serve(t, chain, httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil))
			assert.False(t, answered.handlerRan, "%s %s must be answered by the chain", tc.method, tc.path)

			passed := serve(t, chain, httptest.NewRequestWithContext(t.Context(), tc.method, tc.oldPath, nil))
			assert.True(t, passed.handlerRan, "%s %s is no longer a built-in path and must pass through", tc.method, tc.oldPath)
		})
	}
}
