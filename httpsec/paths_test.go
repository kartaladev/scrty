package httpsec_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// pathForm is one way a built-in endpoint path is set: the setting that names
// it in an error, and a build that places path there on an otherwise complete
// chain.
type pathForm struct {
	setting string

	// emptyIsDefault marks a setting whose empty path means the default path.
	emptyIsDefault bool
	build          func(t *testing.T, path string) (*httpsec.Chain, error)
}

// mfaBuild builds EnableMFA with opt, over the harness the listing form uses.
func mfaBuild(t *testing.T, opt httpsec.MFAOption) (*httpsec.Chain, error) {
	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp)

	return httpsec.New(httpsec.EnableMFA([]mfa.Method{h.method},
		httpsec.WithMFAVerifyLimiter(h.limiter), httpsec.WithMFATokens(h.tokens), opt))
}

// enrolBuild builds the enrolment chain with opt.
func enrolBuild(t *testing.T, opt httpsec.EnrolmentOption) (*httpsec.Chain, error) {
	h := newEnrolHarness(t)
	h.enrolOpts = []httpsec.EnrolmentOption{opt}

	return httpsec.New(h.options(t, nil)...)
}

// passkeyBuild builds the passkey chain with opt.
func passkeyBuild(t *testing.T, opt httpsec.PasskeyOption) (*httpsec.Chain, error) {
	h := newPasskeyHarness(t)
	h.passkeyOpts = append(h.passkeyOpts, opt)

	return httpsec.New(h.chainOptions(t, nil)...)
}

// recoveryBuild builds the recovery chain with opt.
func recoveryBuild(t *testing.T, opt httpsec.RecoveryOption) (*httpsec.Chain, error) {
	h := newRecoveryHarness(t)
	h.recOpts = []httpsec.RecoveryOption{opt}

	return httpsec.New(h.options(t)...)
}

// magicLinkBuild builds the magic-link chain with opt.
func magicLinkBuild(t *testing.T, opt httpsec.MagicLinkOption) (*httpsec.Chain, error) {
	h := newMagicLinkHarness(t)
	h.linkOpts = []httpsec.MagicLinkOption{opt}

	return h.build()
}

// providerBuild builds the OIDC provider chain with opt.
func providerBuild(t *testing.T, opt httpsec.OIDCProviderOption) (*httpsec.Chain, error) {
	f := newOPFixture(t)
	p := f.provider(t)

	return httpsec.New(append(f.wired(t, p), httpsec.EnableOIDCProvider(p, opt))...)
}

// pathForms lists every exported setting that places a built-in endpoint path,
// each with a build that sets it on an otherwise complete chain.
func pathForms() map[string]pathForm {
	forms := map[string]pathForm{
		"MFA verify prefix": {
			setting: "WithMFAVerifyPrefix",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return mfaBuild(t, httpsec.WithMFAVerifyPrefix(path))
			},
		},
		"MFA begin prefix": {
			setting: "WithMFABeginPrefix",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return mfaBuild(t, httpsec.WithMFABeginPrefix(path))
			},
		},
		"enrolment begin": {
			setting: "WithEnrolmentBeginPrefix",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return enrolBuild(t, httpsec.WithEnrolmentBeginPrefix(path))
			},
		},
		"enrolment confirm": {
			setting: "WithEnrolmentConfirmPrefix",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return enrolBuild(t, httpsec.WithEnrolmentConfirmPrefix(path))
			},
		},
		"enrolment email confirm": {
			setting: "WithEnrolmentEmailConfirmPrefix",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return enrolBuild(t, httpsec.WithEnrolmentEmailConfirmPrefix(path))
			},
		},
		"passkey registration": {
			setting: "WithPasskeyRegistrationPrefix",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return passkeyBuild(t, httpsec.WithPasskeyRegistrationPrefix(path))
			},
		},
		"passkey credentials": {
			setting: "WithPasskeyCredentialsPrefix",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return passkeyBuild(t, httpsec.WithPasskeyCredentialsPrefix(path))
			},
		},
		"passkey passwordless": {
			setting: "WithPasskeyPasswordlessPrefix",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				d := newPwlDeployment(t)
				d.passkeyOpts = append(d.passkeyOpts, httpsec.WithPasskeyPasswordlessPrefix(path))

				return httpsec.New(d.options(t)...)
			},
		},
		"OIDC authorize": {
			setting: "WithOIDCAuthorizePath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return buildOIDCLogin(t, httpsec.WithOIDCAuthorizePath(path))
			},
		},
		"OIDC callback": {
			setting: "WithOIDCCallbackPath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return buildOIDCLogin(t, httpsec.WithOIDCCallbackPath(path))
			},
		},
		"OIDC handoff": {
			setting: "WithOIDCHandoffPath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return buildOIDCLogin(t, httpsec.WithOIDCHandoffPath(path))
			},
		},
		"OIDC back-channel": {
			setting: "WithOIDCBackchannelLogoutPath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return buildOIDCLogin(t, httpsec.WithOIDCBackchannelLogoutPath(path))
			},
		},
		"re-authentication": {
			setting: "WithReauthenticationPrefix",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				h := newReauthHarness(t)
				h.reauthOpts = []httpsec.ReauthenticationOption{httpsec.WithReauthenticationPrefix(path)}

				return h.build(nil)
			},
		},
		"session management": {
			setting: "WithSessionManagementPrefix",
			build: func(_ *testing.T, path string) (*httpsec.Chain, error) {
				return httpsec.New(httpsec.WithSessions(must.Must(session.New())),
					httpsec.EnableSessionManagement(httpsec.WithSessionManagementPrefix(path)))
			},
		},
		"recovery complete": {
			setting: "WithRecoveryCompletePath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return recoveryBuild(t, httpsec.WithRecoveryCompletePath(path))
			},
		},
		"recovery start": {
			setting: "WithRecoveryStartPath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return recoveryBuild(t, httpsec.WithRecoveryStartPath(path))
			},
		},
		"recovery finish": {
			setting: "WithRecoveryFinishPath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return recoveryBuild(t, httpsec.WithRecoveryFinishPath(path))
			},
		},
		"recovery cancel": {
			setting: "WithRecoveryCancelPath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return recoveryBuild(t, httpsec.WithRecoveryCancelPath(path))
			},
		},
		"recovery codes": {
			setting: "WithRecoveryCodesPath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return recoveryBuild(t, httpsec.WithRecoveryCodesPath(path))
			},
		},
		"magic-link request": {
			setting: "WithMagicLinkRequestPath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return magicLinkBuild(t, httpsec.WithMagicLinkRequestPath(path))
			},
		},
		"magic-link consume": {
			setting: "WithMagicLinkConsumePath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return magicLinkBuild(t, httpsec.WithMagicLinkConsumePath(path))
			},
		},
		"login": {
			setting: "WithLoginRequestPath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				h := newLoginGuardHarness(t)

				return httpsec.New(httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
				}, httpsec.WithLoginRequestPath(path)))
			},
		},
		"logout": {
			setting: "WithLogoutRequestPath",
			build: func(_ *testing.T, path string) (*httpsec.Chain, error) {
				return httpsec.New(httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: must.Must(session.New())},
					httpsec.WithLogoutRequestPath(path)))
			},
		},
		"JWKS": {
			setting: "WithJWKSEndpointPath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return httpsec.New(httpsec.EnableJWKSEndpoint(NewMockKeySetProvider(gomock.NewController(t)),
					httpsec.WithJWKSEndpointPath(path)))
			},
		},
		"renewal": {
			setting: "WithRenewalPath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				h := newAuthHarness(t)

				return httpsec.New(httpsec.EnableSessionBearer(h.sessionBearerDeps()),
					httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Sessions: h.sessions, Users: h.users},
						httpsec.WithRenewalPath(path)))
			},
		},
		"provider prefix": {
			setting: "WithOIDCProviderPrefix",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return providerBuild(t, httpsec.WithOIDCProviderPrefix(path))
			},
		},
		"provider path": {
			setting: "WithOIDCProviderPath for OIDCToken",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				return providerBuild(t, httpsec.WithOIDCProviderPath(httpsec.OIDCToken, path))
			},
		},
		"signals": {
			setting:        "SessionSignals.Path",
			emptyIsDefault: true,
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				f := newConstructionFixture(t)

				return httpsec.New(f.bearer, httpsec.EnableSessionSignals(httpsec.SessionSignals{Path: path}))
			},
		},
		"listing": {
			setting: "ListingPath",
			build: func(t *testing.T, path string) (*httpsec.Chain, error) {
				h := newMFAHarness(t)
				h.channel(factor.AuthenticatorApp)

				return httpsec.New(httpsec.EnableMFA([]mfa.Method{h.method},
					httpsec.WithMFAVerifyLimiter(h.limiter),
					httpsec.WithMFATokens(h.tokens),
					httpsec.WithMFAMethodListing(httpsec.ListingPath(path))))
			},
		},
		"password change": {
			setting: "WithPasswordChangeEndpoint",
			build: func(_ *testing.T, path string) (*httpsec.Chain, error) {
				return httpsec.New(httpsec.EnablePasswordChangeGate(must.Must(session.New()),
					httpsec.WithPasswordChangeEndpoint(path, func(*httpsec.Exchange) error { return nil })))
			},
		},
	}

	return forms
}

// buildOIDCLogin builds a chain with federated login under opts.
func buildOIDCLogin(t *testing.T, opts ...httpsec.OIDCOption) (*httpsec.Chain, error) {
	t.Helper()

	f := oidcFixture{
		manager:  newTestOIDCManager(t),
		handoffs: newTestHandoffManager(t),
		tokens:   newMockGenerator(gomock.NewController(t)),
		sessions: mustSessions(t),
	}

	return httpsec.New(httpsec.EnableOIDCLogin(httpsec.OIDCDeps{RelyingParty: f.manager, Handoff: f.handoffs},
		f.required(opts...)...))
}

// badPaths are the inputs every path setting refuses.
var badPaths = []string{
	"", "signin", "/", "//", "/a/../b", "/a//b", "/session/sig nals", "/a%20b", "/a?b", "/a#b", "/caf\u00e9",
}

// TestEndpointPathShape pins that every form that sets a built-in endpoint path
// refuses a path of the wrong shape at construction, naming the setting, and
// accepts a single trailing slash.
func TestEndpointPathShape(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) (*httpsec.Chain, error)
		assert func(t *testing.T, chain *httpsec.Chain, err error)
	}

	refusedNaming := func(setting string, also ...string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.ErrorContains(t, err, setting)
			assert.Nil(t, chain)

			for _, s := range also {
				assert.ErrorContains(t, err, s)
			}
		}
	}

	// saying is what the error adds to the setting's name: the value it was
	// given, and for the root and the empty path what is wrong with them.
	saying := func(bad string) []string {
		switch bad {
		case "":
			return []string{"no path"}
		case "/", "//":
			return []string{fmt.Sprintf("%q", bad), "root path", "every one-segment path"}
		}

		return []string{fmt.Sprintf("%q", bad)}
	}

	built := func(t *testing.T, chain *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, chain)
	}

	forms := pathForms()

	var cases []testCase

	for _, form := range forms {
		for _, bad := range badPaths {
			if bad == "" && form.emptyIsDefault {
				continue
			}

			cases = append(cases, testCase{
				name:   fmt.Sprintf("%s refuses %q", form.setting, bad),
				build:  func(t *testing.T) (*httpsec.Chain, error) { return form.build(t, bad) },
				assert: refusedNaming(form.setting, saying(bad)...),
			})
		}
	}

	cases = append(cases,
		testCase{
			name:   "a session management prefix takes one trailing slash",
			build:  func(t *testing.T) (*httpsec.Chain, error) { return forms["session management"].build(t, "/sessions/") },
			assert: built,
		},
		testCase{
			name:   "a provider prefix takes one trailing slash",
			build:  func(t *testing.T) (*httpsec.Chain, error) { return forms["provider prefix"].build(t, "/oauth2/") },
			assert: built,
		},
		testCase{
			name:   "the provider refuses a colon",
			build:  func(t *testing.T) (*httpsec.Chain, error) { return forms["provider path"].build(t, "/a:b") },
			assert: refusedNaming("WithOIDCProviderPath for OIDCToken"),
		},
		testCase{
			name:   "the provider refuses an at sign",
			build:  func(t *testing.T) (*httpsec.Chain, error) { return forms["provider path"].build(t, "/a@b") },
			assert: refusedNaming("WithOIDCProviderPath for OIDCToken"),
		},
		testCase{
			name: "a callback prefix keeps its trailing slash",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return buildOIDCLogin(t, httpsec.WithOIDCCallbackPath("/federation/callback/"))
			},
			assert: built,
		},
		testCase{
			name: "the back-channel prefix refuses a wildcard",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return buildOIDCLogin(t, httpsec.WithOIDCBackchannelLogoutPath("/idp/*/logout"))
			},
			assert: refusedNaming("WithOIDCBackchannelLogoutPath"),
		},
		testCase{
			name:   "the signal stream path takes a trailing slash",
			build:  func(t *testing.T) (*httpsec.Chain, error) { return forms["signals"].build(t, "/session/signals/") },
			assert: built,
		},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := tc.build(t)
			tc.assert(t, chain, err)
		})
	}
}
