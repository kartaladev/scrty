package httpsec_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// collisionRefused asserts New refused the chain as a configuration error whose
// message carries every one of parts.
func collisionRefused(parts ...string) func(*testing.T, *httpsec.Chain, error) {
	return func(t *testing.T, c *httpsec.Chain, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Nil(t, c)

		for _, p := range parts {
			assert.ErrorContains(t, err, p)
		}
	}
}

// collisionBuilt asserts New built the chain.
func collisionBuilt(t *testing.T, c *httpsec.Chain, err error) {
	t.Helper()

	require.NoError(t, err)
	assert.NotNil(t, c)
}

// providerBeside is the provider with its defaults on a chain that has
// everything it needs, followed by others, each built over the session
// manager the provider is told of.
func providerBeside(t *testing.T, f *opFixture, popts []httpsec.OIDCProviderOption,
	others ...func(*testing.T, *session.Sessions) []httpsec.Option,
) []httpsec.Option {
	t.Helper()

	return providerBesideKeys(t, f, popts, nil, others...)
}

// providerBesideKeys is providerBeside with jwksOpts given to the key set the
// chain already serves, for a row that moves it. A second key set on the chain
// would list one operation twice, which is its own refusal.
func providerBesideKeys(t *testing.T, f *opFixture, popts []httpsec.OIDCProviderOption,
	jwksOpts []httpsec.JWKSOption, others ...func(*testing.T, *session.Sessions) []httpsec.Option,
) []httpsec.Option {
	t.Helper()

	p := f.provider(t)
	m := reporting(t, p)

	opts := []httpsec.Option{
		f.bearer(t, m),
		httpsec.EnableJWKSEndpoint(f.keys, jwksOpts...),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableOIDCProvider(p, popts...),
	}

	for _, other := range others {
		opts = append(opts, other(t, m)...)
	}

	return opts
}

// TestChainPathCollisions pins "Colliding endpoint paths fail at
// construction": two built-in operations that would answer one request path
// refuse the chain, naming both settings, both paths and what would break,
// and the paths a feature declares it shares build.
func TestChainPathCollisions(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		build  func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	cases := []testCase{
		{
			// "Two features on one path".
			name: "password sign-in and magic-link requests on one path",
			build: func(t *testing.T) []httpsec.Option {
				login := newLoginGuardHarness(t)
				link := newMagicLinkHarness(t)
				link.linkOpts = append(link.linkOpts, httpsec.WithMagicLinkRequestPath("/signin"))

				return []httpsec.Option{
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: login.authn, Sessions: login.sessions, Tokens: login.tokens, Attempts: login.attempts,
					}, httpsec.WithLoginRequestPath("/signin")),
					httpsec.EnableMagicLink(link.manager, link.options()...),
				}
			},
			assert: collisionRefused("WithLoginRequestPath", "WithMagicLinkRequestPath", `"/signin"`,
				httpsec.OperationSignInPassword, httpsec.OperationSignInMagicLinkRequest),
		},
		{
			// "Path under another endpoint's prefix".
			name: "the re-authentication prefix under the MFA verify prefix",
			build: func(t *testing.T) []httpsec.Option {
				h := newReauthHarness(t)
				h.reauthOpts = []httpsec.ReauthenticationOption{
					httpsec.WithReauthenticationPrefix(httpsec.DefaultMFAVerifyPrefix),
				}

				return h.options(nil)
			},
			assert: collisionRefused("WithReauthenticationPrefix", "WithMFAVerifyPrefix",
				httpsec.OperationMFAVerify, httpsec.DefaultMFAVerifyPrefix+"/{method}",
				httpsec.OperationReauthChallenge, httpsec.DefaultMFAVerifyPrefix+"/challenge/{method}"),
		},
		{
			// "Within one feature".
			name: "the MFA challenge and verify prefixes on one path",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, []httpsec.MFAOption{
					httpsec.WithMFABeginPrefix("/mfa/step"),
					httpsec.WithMFAVerifyPrefix("/mfa/step"),
				}, nil)
			},
			assert: collisionRefused("WithMFABeginPrefix", "WithMFAVerifyPrefix",
				httpsec.OperationMFAChallenge, httpsec.OperationMFAVerify, `"/mfa/step"`, collidesMatchesFirst),
		},
		{
			// "A built-in endpoint and a provider endpoint".
			name: "password sign-in on the provider's token path",
			build: func(t *testing.T) []httpsec.Option {
				return providerBeside(t, f, nil, func(t *testing.T, m *session.Sessions) []httpsec.Option {
					return []httpsec.Option{httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: NewMockAuthenticator(gomock.NewController(t)),
						Sessions:      m,
						Attempts:      must.Must(lockout.NewMemoryAttemptStore()),
					}, httpsec.WithLoginRequestPath("/oauth2/token"))}
				})
			},
			assert: collisionRefused("WithLoginRequestPath", "EnableFormLogin", "WithOIDCProviderPrefix",
				"EnableOIDCProvider", `"/oauth2/token"`, httpsec.OperationSignInPassword, httpsec.OperationOAuth2Token),
		},
		{
			// "Declared sharing".
			name: "the saved recovery codes counted and regenerated on one path",
			build: func(t *testing.T) []httpsec.Option {
				return endpointsRecovery(t)
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				collisionBuilt(t, c, err)

				_, count := findEndpoint(c.Endpoints(), httpsec.OperationRecoveryCodesCount)
				_, regenerate := findEndpoint(c.Endpoints(), httpsec.OperationRecoveryCodesRegenerate)
				assert.True(t, count && regenerate, "both operations on the codes path are listed")
			},
		},
		{
			// "Default session management builds".
			name: "session management with its defaults",
			build: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithSessions(must.Must(session.New())),
					httpsec.EnableSessionManagement(),
				}
			},
			assert: collisionBuilt,
		},
		{
			// "Default consents build".
			name:   "the provider with its defaults, consents included",
			build:  func(t *testing.T) []httpsec.Option { return providerBeside(t, f, nil) },
			assert: collisionBuilt,
		},
		{
			// "Colliding endpoint paths fail at construction": the first pair in
			// inventory order is the one reported, however many others collide.
			name: "the first colliding pair in inventory order is reported",
			build: func(t *testing.T) []httpsec.Option {
				return providerBesideKeys(t, f, nil, []httpsec.JWKSOption{httpsec.WithJWKSEndpointPath("/sso/handoff")},
					oidcLoginOn, func(t *testing.T, m *session.Sessions) []httpsec.Option {
						login := newLoginGuardHarness(t)
						link := newMagicLinkHarness(t)

						return []httpsec.Option{
							httpsec.EnableFormLogin(httpsec.FormLoginDeps{
								Authenticator: login.authn, Sessions: m, Attempts: login.attempts,
							}, httpsec.WithLoginRequestPath("/signin")),
							httpsec.EnableMagicLink(link.manager, httpsec.WithMagicLinkSessions(m),
								httpsec.WithMagicLinkRequestPath("/signin")),
						}
					})
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				collisionRefused(httpsec.OperationSSOHandoff, "WithJWKSEndpointPath", `"/sso/handoff"`)(t, c, err)
				assert.NotContains(t, err.Error(), httpsec.OperationSignInMagicLinkRequest)
			},
		},
		{
			// "Path under another endpoint's prefix": a subtree rooted one segment
			// below a segment endpoint's prefix holds that endpoint's paths.
			name: "a subtree root one segment below a segment prefix",
			build: func(t *testing.T) []httpsec.Option {
				return providerBeside(t, f, nil, func(t *testing.T, m *session.Sessions) []httpsec.Option {
					flows, err := oidc.NewMemoryFlowStore()
					require.NoError(t, err)

					return []httpsec.Option{
						httpsec.EnableOIDCLogin(httpsec.OIDCDeps{
							RelyingParty: oidcManagerOver(t, flows), Handoff: newTestHandoffManager(t),
						}, httpsec.WithOIDCSessions(m), httpsec.WithOIDCBackchannelLogoutPath("/mfa")),
						mfaOn(t),
					}
				})
			},
			assert: collisionRefused(httpsec.OperationSSOBackchannelLogout, httpsec.OperationMFAChallenge),
		},
		{
			// "Path under another endpoint's prefix": an endpoint that answers
			// 405 to other methods claims its path for every method.
			name: "the signal stream under the MFA verify prefix",
			build: func(t *testing.T) []httpsec.Option {
				return providerBeside(t, f, nil, formLoginOn, func(t *testing.T, _ *session.Sessions) []httpsec.Option {
					return []httpsec.Option{
						mfaOn(t),
						httpsec.EnableSessionSignals(httpsec.SessionSignals{Path: httpsec.DefaultMFAVerifyPrefix + "/stream"}),
					}
				})
			},
			assert: collisionRefused(httpsec.OperationSessionSignals, httpsec.OperationMFAVerify),
		},
		{
			// "The error says what would break".
			name: "the logout path under the MFA verify prefix",
			build: func(t *testing.T) []httpsec.Option {
				h := newReauthHarness(t)
				h.off = true
				h.logoutOpts = []httpsec.LogoutOption{
					httpsec.WithLogoutRequestPath(httpsec.DefaultMFAVerifyPrefix + "/out"),
				}

				return h.options(nil)
			},
			assert: collisionRefused("WithLogoutRequestPath", "WithMFAVerifyPrefix",
				httpsec.OperationSignOut, httpsec.OperationMFAVerify,
				"a session owing a second factor could not sign out"),
		},
		{
			// "Collisions judged after the base path".
			name: "the key set on the OpenID configuration's path under the base path",
			build: func(t *testing.T) []httpsec.Option {
				p := f.providerOver(t, bpIssuer, f.keys, nil)

				return []httpsec.Option{
					httpsec.WithBasePath(bpBase),
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(f.keys, httpsec.WithJWKSEndpointPath("/.well-known/openid-configuration")),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: collisionRefused("WithJWKSEndpointPath", "EnableOIDCProvider",
				`"/auth/.well-known/openid-configuration"`,
				httpsec.OperationKeySet, httpsec.OperationOAuth2OpenIDConfiguration),
		},
		{
			// An endpoint that answers 405 claims its path for every method, so
			// a GET-only stream refuses a POST-only sign-in on its path.
			name: "the signal stream, which refuses other methods, on the sign-in path",
			build: func(t *testing.T) []httpsec.Option {
				return providerBeside(t, f, nil, formLoginOn, func(*testing.T, *session.Sessions) []httpsec.Option {
					return []httpsec.Option{httpsec.EnableSessionSignals(httpsec.SessionSignals{Path: httpsec.DefaultLoginPath})}
				})
			},
			assert: collisionRefused("WithLoginRequestPath", "SessionSignals.Path",
				httpsec.OperationSignInPassword, httpsec.OperationSessionSignals, `"`+httpsec.DefaultLoginPath+`"`),
		},
		{
			// An exact path equal to another feature's prefix, without its
			// trailing slash, is refused although no request reaches both.
			name: "the key set on a federated-login prefix without its trailing slash",
			build: func(t *testing.T) []httpsec.Option {
				return providerBesideKeys(t, f, nil,
					[]httpsec.JWKSOption{httpsec.WithJWKSEndpointPath("/sso/login")}, oidcLoginOn)
			},
			assert: collisionRefused("WithJWKSEndpointPath", "WithOIDCAuthorizePath",
				httpsec.OperationKeySet, httpsec.OperationSSOLogin, `"/sso/login"`),
		},
		{
			// Two features on one path with different methods share it without
			// declaring it, which only operations of one feature may do.
			name: "password sign-in on the passkey list's path",
			build: func(t *testing.T) []httpsec.Option {
				return providerBeside(t, f, nil, passkeysOn, func(t *testing.T, m *session.Sessions) []httpsec.Option {
					return []httpsec.Option{httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: NewMockAuthenticator(gomock.NewController(t)),
						Sessions:      m,
						Attempts:      must.Must(lockout.NewMemoryAttemptStore()),
					}, httpsec.WithLoginRequestPath(httpsec.DefaultPasskeyCredentialsPrefix))}
				})
			},
			assert: collisionRefused("WithLoginRequestPath", "WithPasskeyCredentialsPrefix",
				httpsec.OperationSignInPassword, httpsec.OperationPasskeysList, "told apart only by method"),
		},
		// The rows below are the collision checks each built-in used to hold
		// for itself.
		{
			name: "the MFA verify prefix on the logout path",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix(httpsec.DefaultLogoutPath)}, nil)
			},
			assert: collisionRefused("WithMFAVerifyPrefix", "WithLogoutRequestPath",
				httpsec.OperationMFAVerify, httpsec.OperationSignOut, `"`+httpsec.DefaultLogoutPath+`"`,
				"a session owing a second factor could not sign out"),
		},
		{
			name: "the logout path under the MFA verify prefix",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, nil, []httpsec.LogoutOption{
					httpsec.WithLogoutRequestPath(httpsec.DefaultMFAVerifyPrefix + "/logout"),
				})
			},
			assert: collisionRefused("WithMFAVerifyPrefix", "WithLogoutRequestPath",
				httpsec.OperationMFAVerify, httpsec.OperationSignOut, `"`+httpsec.DefaultMFAVerifyPrefix+`"`,
				`"`+httpsec.DefaultMFAVerifyPrefix+`/logout"`, "a session owing a second factor could not sign out"),
		},
		{
			name: "the MFA begin prefix on the logout path",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, []httpsec.MFAOption{httpsec.WithMFABeginPrefix(httpsec.DefaultLogoutPath)}, nil)
			},
			assert: collisionRefused("WithMFABeginPrefix", "WithLogoutRequestPath",
				httpsec.OperationMFAChallenge, httpsec.OperationSignOut, `"`+httpsec.DefaultLogoutPath+`"`,
				"a session owing a second factor could not sign out"),
		},
		{
			name: "the MFA begin prefix equal to the verify prefix with a trailing slash",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, []httpsec.MFAOption{httpsec.WithMFABeginPrefix(httpsec.DefaultMFAVerifyPrefix + "/")}, nil)
			},
			assert: collisionRefused("WithMFABeginPrefix", "WithMFAVerifyPrefix",
				httpsec.OperationMFAChallenge, httpsec.OperationMFAVerify, `"`+httpsec.DefaultMFAVerifyPrefix+`"`,
				collidesMatchesFirst),
		},
		{
			name: "the MFA verify prefix moved onto the begin prefix",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix(httpsec.DefaultMFABeginPrefix)}, nil)
			},
			assert: collisionRefused("WithMFABeginPrefix", "WithMFAVerifyPrefix",
				httpsec.OperationMFAChallenge, httpsec.OperationMFAVerify, `"`+httpsec.DefaultMFABeginPrefix+`"`,
				collidesMatchesFirst),
		},
		{
			name: "the MFA begin prefix under the verify prefix",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, []httpsec.MFAOption{httpsec.WithMFABeginPrefix(httpsec.DefaultMFAVerifyPrefix + "/begin")}, nil)
			},
			assert: collisionRefused("WithMFABeginPrefix", "WithMFAVerifyPrefix",
				httpsec.OperationMFAChallenge, httpsec.OperationMFAVerify, `"`+httpsec.DefaultMFAVerifyPrefix+`"`,
				collidesMatchesFirst),
		},
		{
			name: "the MFA begin prefix above the verify prefix",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, []httpsec.MFAOption{httpsec.WithMFABeginPrefix("/mfa")}, nil)
			},
			assert: collisionRefused("WithMFABeginPrefix", "WithMFAVerifyPrefix",
				httpsec.OperationMFAChallenge, httpsec.OperationMFAVerify, `"/mfa"`, collidesMatchesFirst),
		},
		{
			name: "the MFA method listing on the verify prefix itself",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, listingAt(httpsec.DefaultMFAVerifyPrefix), nil)
			},
			assert: collisionRefused("WithMFAMethodListing", "WithMFAVerifyPrefix",
				httpsec.OperationMFAMethods, httpsec.OperationMFAVerify, `"`+httpsec.DefaultMFAVerifyPrefix+`"`,
				"told apart only by method"),
		},
		{
			// Changed verdict (D7). The listing answers GET on its one path,
			// and the verify endpoint answers POST, passing every other method
			// on, so no request is answered by both and the pair builds.
			name: "the MFA method listing under the verify prefix",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, listingAt(httpsec.DefaultMFAVerifyPrefix+"/totp"), nil)
			},
			assert: collisionBuilt,
		},
		{
			// Changed verdict (D7), as above, under the begin prefix.
			name: "the MFA method listing under the begin prefix",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, listingAt(httpsec.DefaultMFABeginPrefix+"/passkey"), nil)
			},
			assert: collisionBuilt,
		},
		{
			// Changed verdict (D7), as above, under a consumer's verify prefix.
			name: "the MFA method listing under a consumer's verify prefix",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, append(listingAt("/2fa/check/totp"), httpsec.WithMFAVerifyPrefix("/2fa/check")), nil)
			},
			assert: collisionBuilt,
		},
		{
			name: "the default verify path once the verify prefix has moved",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, append(listingAt(httpsec.DefaultMFAVerifyPrefix+"/totp"),
					httpsec.WithMFAVerifyPrefix("/2fa/check")), nil)
			},
			assert: collisionBuilt,
		},
		{
			name: "the MFA method listing on the logout path",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, listingAt(httpsec.DefaultLogoutPath), nil)
			},
			assert: collisionRefused("WithMFAMethodListing", "WithLogoutRequestPath",
				httpsec.OperationMFAMethods, httpsec.OperationSignOut, `"`+httpsec.DefaultLogoutPath+`"`,
				"told apart only by method"),
		},
		{
			name: "the MFA method listing on a consumer's logout path",
			build: func(t *testing.T) []httpsec.Option {
				return mfaChain(t, listingAt("/auth/sign-out"),
					[]httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/auth/sign-out")})
			},
			assert: collisionRefused("WithMFAMethodListing", "WithLogoutRequestPath",
				httpsec.OperationMFAMethods, httpsec.OperationSignOut, `"/auth/sign-out"`, "told apart only by method"),
		},
		{
			name: "two enrolment endpoints on one prefix",
			build: func(t *testing.T) []httpsec.Option {
				return enrolChain(t, []httpsec.EnrolmentOption{
					httpsec.WithEnrolmentConfirmPrefix(httpsec.DefaultEnrolmentBeginPrefix),
				}, nil, nil)
			},
			assert: collisionRefused("WithEnrolmentBeginPrefix", "WithEnrolmentConfirmPrefix",
				httpsec.OperationMFAEnrolmentBegin, httpsec.OperationMFAEnrolmentConfirm,
				`"`+httpsec.DefaultEnrolmentBeginPrefix+`"`, collidesMatchesFirst),
		},
		{
			name: "one enrolment prefix under another",
			build: func(t *testing.T) []httpsec.Option {
				return enrolChain(t, []httpsec.EnrolmentOption{
					httpsec.WithEnrolmentConfirmPrefix(httpsec.DefaultEnrolmentBeginPrefix + "/device"),
				}, nil, nil)
			},
			assert: collisionRefused("WithEnrolmentBeginPrefix", "WithEnrolmentConfirmPrefix",
				httpsec.OperationMFAEnrolmentBegin, httpsec.OperationMFAEnrolmentConfirm,
				`"`+httpsec.DefaultEnrolmentBeginPrefix+`"`, collidesMatchesFirst),
		},
		{
			// With email confirmation off the emailed-code endpoint does not
			// exist, so its prefix claims nothing.
			name: "the emailed-code prefix on another's with email confirmation off",
			build: func(t *testing.T) []httpsec.Option {
				return enrolChain(t, []httpsec.EnrolmentOption{
					httpsec.WithoutEnrolmentEmailConfirmation(),
					httpsec.WithEnrolmentEmailConfirmPrefix(httpsec.DefaultEnrolmentBeginPrefix),
				}, nil, nil)
			},
			assert: collisionBuilt,
		},
		{
			name: "an enrolment prefix on the logout path",
			build: func(t *testing.T) []httpsec.Option {
				return enrolChain(t, []httpsec.EnrolmentOption{
					httpsec.WithEnrolmentEmailConfirmPrefix(httpsec.DefaultLogoutPath),
				}, nil, nil)
			},
			assert: collisionRefused("WithEnrolmentEmailConfirmPrefix", "WithLogoutRequestPath",
				httpsec.OperationMFAEnrolmentConfirmEmail, httpsec.OperationSignOut, `"`+httpsec.DefaultLogoutPath+`"`,
				"an enrolment-only session could not sign out"),
		},
		{
			name: "an enrolment prefix above the logout path",
			build: func(t *testing.T) []httpsec.Option {
				return enrolChain(t, []httpsec.EnrolmentOption{httpsec.WithEnrolmentBeginPrefix("/account/2fa/start")}, nil,
					[]httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/account/2fa/start/sign-out")})
			},
			assert: collisionRefused("WithEnrolmentBeginPrefix", "WithLogoutRequestPath",
				httpsec.OperationMFAEnrolmentBegin, httpsec.OperationSignOut, `"/account/2fa/start"`,
				`"/account/2fa/start/sign-out"`, "an enrolment-only session could not sign out"),
		},
		{
			name: "an enrolment prefix on the MFA verify prefix",
			build: func(t *testing.T) []httpsec.Option {
				return enrolChain(t, []httpsec.EnrolmentOption{httpsec.WithEnrolmentBeginPrefix(httpsec.DefaultMFAVerifyPrefix)},
					nil, nil)
			},
			assert: collisionRefused("WithEnrolmentBeginPrefix", "WithMFAVerifyPrefix",
				httpsec.OperationMFAEnrolmentBegin, httpsec.OperationMFAVerify, `"`+httpsec.DefaultMFAVerifyPrefix+`"`,
				collidesMatchesFirst),
		},
		{
			name: "an enrolment prefix above the MFA verify prefix",
			build: func(t *testing.T) []httpsec.Option {
				return enrolChain(t, []httpsec.EnrolmentOption{httpsec.WithEnrolmentConfirmPrefix("/2fa")},
					[]httpsec.MFAOption{httpsec.WithMFAVerifyPrefix("/2fa/verify")}, nil)
			},
			assert: collisionRefused("WithEnrolmentConfirmPrefix", "WithMFAVerifyPrefix",
				httpsec.OperationMFAEnrolmentConfirm, httpsec.OperationMFAVerify, `"/2fa"`, `"/2fa/verify"`,
				collidesMatchesFirst),
		},
		{
			name: "an enrolment prefix under the MFA begin prefix",
			build: func(t *testing.T) []httpsec.Option {
				return enrolChain(t, []httpsec.EnrolmentOption{
					httpsec.WithEnrolmentConfirmPrefix(httpsec.DefaultMFABeginPrefix + "/enrol"),
				}, nil, nil)
			},
			assert: collisionRefused("WithEnrolmentConfirmPrefix", "WithMFABeginPrefix",
				httpsec.OperationMFAEnrolmentConfirm, httpsec.OperationMFAChallenge, `"`+httpsec.DefaultMFABeginPrefix+`"`,
				collidesMatchesFirst),
		},
		{
			name: "a passkey registration prefix under the MFA verify prefix",
			build: func(t *testing.T) []httpsec.Option {
				return passkeyChain(t, func(h *passkeyHarness) {
					h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyRegistrationPrefix(httpsec.DefaultMFAVerifyPrefix+"/x"))
				})
			},
			assert: collisionRefused("WithPasskeyRegistrationPrefix", "WithMFAVerifyPrefix",
				httpsec.OperationPasskeysRegisterBegin, httpsec.OperationMFAVerify, `"`+httpsec.DefaultMFAVerifyPrefix+`"`,
				collidesMatchesFirst),
		},
		{
			name: "a passkey registration prefix on the MFA begin prefix",
			build: func(t *testing.T) []httpsec.Option {
				return passkeyChain(t, func(h *passkeyHarness) {
					h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyRegistrationPrefix(httpsec.DefaultMFABeginPrefix))
				})
			},
			assert: collisionRefused("WithPasskeyRegistrationPrefix", "WithMFABeginPrefix",
				httpsec.OperationPasskeysRegisterBegin, httpsec.OperationMFAChallenge, `"`+httpsec.DefaultMFABeginPrefix+`"`,
				collidesMatchesFirst),
		},
		{
			name: "the logout path on a passkey registration path",
			build: func(t *testing.T) []httpsec.Option {
				return passkeyChain(t, func(h *passkeyHarness) {
					h.logoutOpts = append(h.logoutOpts, httpsec.WithLogoutRequestPath(passkeyFinishPath))
				})
			},
			assert: collisionRefused("WithLogoutRequestPath", "WithPasskeyRegistrationPrefix",
				httpsec.OperationSignOut, httpsec.OperationPasskeysRegisterFinish, `"`+passkeyFinishPath+`"`,
				"a sign-out could be answered by "+httpsec.OperationPasskeysRegisterFinish),
		},
		{
			name: "the login path on a passkey registration path",
			build: func(t *testing.T) []httpsec.Option {
				return passkeyChain(t, func(h *passkeyHarness) {
					h.extra = append(h.extra, httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: NewMockAuthenticator(gomock.NewController(t)),
						Sessions:      h.sessions,
						Tokens:        h.tokens,
						Attempts:      must.Must(lockout.NewMemoryAttemptStore()),
					}, httpsec.WithLoginRequestPath(passkeyBeginPath)))
				})
			},
			assert: collisionRefused("WithLoginRequestPath", "WithPasskeyRegistrationPrefix",
				httpsec.OperationSignInPassword, httpsec.OperationPasskeysRegisterBegin, `"`+passkeyBeginPath+`"`,
				collidesMatchesFirst),
		},
		{
			name: "the password-change resolve path on a passkey registration path",
			build: func(t *testing.T) []httpsec.Option {
				return passkeyChain(t, func(h *passkeyHarness) {
					h.extra = append(h.extra, httpsec.EnablePasswordChangeGate(h.sessions,
						httpsec.WithPasswordChangeEndpoint(passkeyBeginPath, func(*httpsec.Exchange) error { return nil })))
				})
			},
			assert: collisionRefused("WithPasswordChangeEndpoint", "WithPasskeyRegistrationPrefix",
				httpsec.OperationPasswordChange, httpsec.OperationPasskeysRegisterBegin, `"`+passkeyBeginPath+`"`,
				collidesMatchesFirst),
		},
		{
			name: "the password-change resolve path on a passkey credentials path",
			build: func(t *testing.T) []httpsec.Option {
				return passkeyChain(t, func(h *passkeyHarness) {
					h.extra = append(h.extra, httpsec.EnablePasswordChangeGate(h.sessions,
						httpsec.WithPasswordChangeEndpoint(passkeyListPath+"/remove", func(*httpsec.Exchange) error { return nil })))
				})
			},
			assert: collisionRefused("WithPasswordChangeEndpoint", "WithPasskeyCredentialsPrefix",
				httpsec.OperationPasswordChange, httpsec.OperationPasskeysRemove, `"`+passkeyListPath+`/remove"`,
				collidesMatchesFirst),
		},
		{
			name: "a password-change resolve path elsewhere than the passkey paths",
			build: func(t *testing.T) []httpsec.Option {
				return passkeyChain(t, func(h *passkeyHarness) {
					h.extra = append(h.extra, httpsec.EnablePasswordChangeGate(h.sessions,
						httpsec.WithPasswordChangeEndpoint("/account/password", func(*httpsec.Exchange) error { return nil })))
				})
			},
			assert: collisionBuilt,
		},
		{
			name: "the passkey credentials prefix on a registration path",
			build: func(t *testing.T) []httpsec.Option {
				return passkeyChain(t, func(h *passkeyHarness) {
					h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyCredentialsPrefix(passkeyConfirmPath))
				})
			},
			assert: collisionRefused("WithPasskeyRegistrationPrefix", "WithPasskeyCredentialsPrefix",
				httpsec.OperationPasskeysRegisterConfirm, httpsec.OperationPasskeysList, `"`+passkeyConfirmPath+`"`,
				"told apart only by method"),
		},
		{
			name: "the passwordless finish path on the logout path",
			build: func(t *testing.T) []httpsec.Option {
				opts := newPwlDeployment(t)
				o := opts.options(t)
				o[6] = httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: opts.sessions},
					httpsec.WithLogoutRequestPath(passwordlessFinishPath))

				return o
			},
			assert: collisionRefused("WithPasskeyPasswordlessPrefix", "WithLogoutRequestPath",
				httpsec.OperationSignInPasskeyFinish, httpsec.OperationSignOut, `"`+passwordlessFinishPath+`"`,
				"a sign-out could be answered by "+httpsec.OperationSignInPasskeyFinish),
		},
		{
			name: "the passwordless begin path on the login path",
			build: func(t *testing.T) []httpsec.Option {
				d := newPwlDeployment(t)
				d.passkeyOpts = append(d.passkeyOpts, httpsec.WithPasskeyPasswordlessPrefix("/login"))
				o := d.options(t)

				authn, err := authenticate.NewUsernamePasswordAuthenticator(d.users)
				require.NoError(t, err)

				o[1] = httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: authn, Sessions: d.sessions, Tokens: d.tokens, Attempts: must.Must(lockout.NewMemoryAttemptStore()),
				}, httpsec.WithLoginRequestPath("/login/begin"))

				return o
			},
			assert: collisionRefused("WithPasskeyPasswordlessPrefix", "WithLoginRequestPath",
				httpsec.OperationSignInPasskeyBegin, httpsec.OperationSignInPassword, `"/login/begin"`,
				collidesMatchesFirst),
		},
		{
			name: "a passwordless path under the MFA verify prefix",
			build: func(t *testing.T) []httpsec.Option {
				d := newPwlDeployment(t)
				d.passkeyOpts = append(d.passkeyOpts, httpsec.WithPasskeyPasswordlessPrefix(httpsec.DefaultMFAVerifyPrefix))

				return d.options(t)
			},
			assert: collisionRefused("WithPasskeyPasswordlessPrefix", "WithMFAVerifyPrefix",
				httpsec.OperationSignInPasskeyBegin, httpsec.OperationMFAVerify, `"`+httpsec.DefaultMFAVerifyPrefix+`"`,
				collidesMatchesFirst),
		},
		{
			name: "the recovery start path on the logout path",
			build: func(t *testing.T) []httpsec.Option {
				return recoveryChain(t, httpsec.WithRecoveryStartPath(httpsec.DefaultLogoutPath))
			},
			assert: collisionRefused("WithRecoveryStartPath", "WithLogoutRequestPath",
				httpsec.OperationRecoveryStart, httpsec.OperationSignOut, `"`+httpsec.DefaultLogoutPath+`"`,
				"a sign-out could be answered by "+httpsec.OperationRecoveryStart),
		},
		{
			name: "the recovery complete path on the login path",
			build: func(t *testing.T) []httpsec.Option {
				return recoveryChain(t, httpsec.WithRecoveryCompletePath(httpsec.DefaultLoginPath))
			},
			assert: collisionRefused("WithRecoveryCompletePath", "WithLoginRequestPath",
				httpsec.OperationRecoveryComplete, httpsec.OperationSignInPassword, `"`+httpsec.DefaultLoginPath+`"`,
				collidesMatchesFirst),
		},
		{
			name: "the recovery codes path on the complete path",
			build: func(t *testing.T) []httpsec.Option {
				return recoveryChain(t, httpsec.WithRecoveryCodesPath(httpsec.DefaultRecoveryCompletePath))
			},
			assert: collisionRefused("WithRecoveryCompletePath", "WithRecoveryCodesPath",
				httpsec.OperationRecoveryComplete, `"`+httpsec.DefaultRecoveryCompletePath+`"`),
		},
		{
			name: "the recovery start path on the finish path of a recovery that holds",
			build: func(t *testing.T) []httpsec.Option {
				return holdingRecoveryChain(t, httpsec.WithRecoveryStartPath(httpsec.DefaultRecoveryFinishPath))
			},
			assert: collisionRefused("WithRecoveryStartPath", "WithRecoveryFinishPath",
				httpsec.OperationRecoveryStart, httpsec.OperationRecoveryFinish, `"`+httpsec.DefaultRecoveryFinishPath+`"`,
				collidesMatchesFirst),
		},
		{
			// Changed verdict (D7). A recovery that never holds answers no
			// finish endpoint, so the path it was given claims nothing and
			// the start path beside it is its own.
			name: "the recovery start path on the finish path of a recovery that never holds",
			build: func(t *testing.T) []httpsec.Option {
				return recoveryChain(t, httpsec.WithRecoveryStartPath(httpsec.DefaultRecoveryFinishPath))
			},
			assert: collisionBuilt,
		},
		{
			name: "a passkey registration path on the recovery complete path",
			build: func(t *testing.T) []httpsec.Option {
				return recoveryBesidePasskeys(t, false, httpsec.WithRecoveryCompletePath(passkeyBeginPath))
			},
			assert: collisionRefused("WithRecoveryCompletePath", "WithPasskeyRegistrationPrefix",
				httpsec.OperationRecoveryComplete, httpsec.OperationPasskeysRegisterBegin, `"`+passkeyBeginPath+`"`,
				collidesMatchesFirst),
		},
		{
			name: "a passkey registration path on the recovery start path",
			build: func(t *testing.T) []httpsec.Option {
				return recoveryBesidePasskeys(t, false, httpsec.WithRecoveryStartPath(passkeyFinishPath))
			},
			assert: collisionRefused("WithRecoveryStartPath", "WithPasskeyRegistrationPrefix",
				httpsec.OperationRecoveryStart, httpsec.OperationPasskeysRegisterFinish, `"`+passkeyFinishPath+`"`,
				collidesMatchesFirst),
		},
		{
			name: "a passkey registration path on the saved-codes path",
			build: func(t *testing.T) []httpsec.Option {
				return recoveryBesidePasskeys(t, false, httpsec.WithRecoveryCodesPath(passkeyConfirmPath))
			},
			assert: collisionRefused("WithRecoveryCodesPath", "WithPasskeyRegistrationPrefix",
				httpsec.OperationPasskeysRegisterConfirm, `"`+passkeyConfirmPath+`"`),
		},
		{
			name: "the passkey credentials listing on the cancel path of a recovery that holds",
			build: func(t *testing.T) []httpsec.Option {
				return recoveryBesidePasskeys(t, true, httpsec.WithRecoveryCancelPath(passkeyListPath))
			},
			assert: collisionRefused("WithRecoveryCancelPath", "WithPasskeyCredentialsPrefix",
				httpsec.OperationRecoveryCancel, httpsec.OperationPasskeysList, `"`+passkeyListPath+`"`,
				"told apart only by method"),
		},
		{
			// Changed verdict (D7), as for the finish path above.
			name: "the passkey credentials listing on the cancel path of a recovery that never holds",
			build: func(t *testing.T) []httpsec.Option {
				return recoveryBesidePasskeys(t, false, httpsec.WithRecoveryCancelPath(passkeyListPath))
			},
			assert: collisionBuilt,
		},
		{
			name: "the session renewal path on the logout path",
			build: func(t *testing.T) []httpsec.Option {
				h := newAuthHarness(t)

				return []httpsec.Option{
					httpsec.EnableSessionBearer(h.sessionBearerDeps()),
					httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Sessions: h.sessions, Users: h.users},
						httpsec.WithRenewalPath(httpsec.DefaultLogoutPath)),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}),
				}
			},
			assert: collisionRefused("WithRenewalPath", "WithLogoutRequestPath",
				httpsec.OperationSessionRenewal, httpsec.OperationSignOut, `"`+httpsec.DefaultLogoutPath+`"`,
				"a sign-out could renew the session it meant to end"),
		},
		{
			// One path cannot both ask for a link and redeem one.
			name: "the magic-link request and redeem endpoints on one path",
			build: func(t *testing.T) []httpsec.Option {
				link := newMagicLinkHarness(t)
				link.linkOpts = append(link.linkOpts,
					httpsec.WithMagicLinkRequestPath("/sign-in/magic-link"),
					httpsec.WithMagicLinkConsumePath("/sign-in/magic-link"))

				return []httpsec.Option{httpsec.EnableMagicLink(link.manager, link.options()...)}
			},
			assert: collisionRefused("WithMagicLinkRequestPath", "WithMagicLinkConsumePath",
				httpsec.OperationSignInMagicLinkRequest, httpsec.OperationSignInMagicLinkRedeem,
				`"/sign-in/magic-link"`, collidesMatchesFirst),
		},
		{
			// Every built-in with its default paths, on one chain.
			name: "every built-in with its defaults",
			build: func(t *testing.T) []httpsec.Option {
				return providerBeside(t, f, nil, everyOtherBuiltIn...)
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				collisionBuilt(t, c, err)

				seen := map[string]bool{}
				for _, e := range c.Endpoints() {
					seen[e.OperationID] = true
				}

				for _, id := range []string{
					httpsec.OperationSignInPassword, httpsec.OperationSignInMagicLinkRequest,
					httpsec.OperationSignInPasskeyBegin, httpsec.OperationSignOut, httpsec.OperationSSOLogin,
					httpsec.OperationSSOHandoff, httpsec.OperationSessionRenewal, httpsec.OperationSessionSignals,
					httpsec.OperationSessionsEnd, httpsec.OperationPasswordChange, httpsec.OperationMFAMethods,
					httpsec.OperationMFAEnrolmentConfirmEmail, httpsec.OperationPasskeysRemove,
					httpsec.OperationRecoveryStart, httpsec.OperationRecoveryCodesRegenerate,
					httpsec.OperationReauthPassword, httpsec.OperationKeySet, httpsec.OperationOAuth2ConsentsRevoke,
				} {
					assert.Truef(t, seen[id], "%s is on the chain", id)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(tc.build(t)...)
			tc.assert(t, c, err)
		})
	}
}

// collidesMatchesFirst is what the shared check says of two operations that
// answer one request path with a method in common.
const collidesMatchesFirst = "whichever matches first would answer the other's requests"

// mfaChain is the chain of the second-factor tests, with re-authentication
// left off, over the given MFA and logout options.
func mfaChain(t *testing.T, mfaOpts []httpsec.MFAOption, logoutOpts []httpsec.LogoutOption) []httpsec.Option {
	t.Helper()

	h := newReauthHarness(t)
	h.off = true
	h.mfaOpts = mfaOpts
	h.logoutOpts = logoutOpts

	return h.options(nil)
}

// listingAt is the MFA option that turns the method listing on at path.
func listingAt(path string) []httpsec.MFAOption {
	return []httpsec.MFAOption{httpsec.WithMFAMethodListing(httpsec.ListingPath(path))}
}

// enrolChain is the chain of the enrolment tests over the given options.
func enrolChain(t *testing.T, enrol []httpsec.EnrolmentOption, mfaOpts []httpsec.MFAOption,
	logoutOpts []httpsec.LogoutOption,
) []httpsec.Option {
	t.Helper()

	h := newEnrolHarness(t)
	h.enrolOpts = enrol
	h.mfaOpts = mfaOpts
	h.logoutOpts = logoutOpts

	return h.options(t, nil)
}

// passkeyChain is the chain of the passkey tests, after change has been
// applied to its harness.
func passkeyChain(t *testing.T, change func(h *passkeyHarness)) []httpsec.Option {
	t.Helper()

	h := newPasskeyHarness(t)
	change(h)

	return h.chainOptions(t, nil)
}

// recoveryChain is the chain of the recovery tests with the given options.
func recoveryChain(t *testing.T, opts ...httpsec.RecoveryOption) []httpsec.Option {
	t.Helper()

	h := newRecoveryHarness(t)
	h.recOpts = opts

	return h.options(t)
}

// holdingRecoveryChain is recoveryChain with the core holding a recovery, which
// is what makes the finish and cancel endpoints exist.
func holdingRecoveryChain(t *testing.T, opts ...httpsec.RecoveryOption) []httpsec.Option {
	t.Helper()

	h := newRecoveryHarness(t)
	h.coreOpts = append(h.coreOpts, recovery.WithHoldDelay(time.Hour),
		recovery.WithCancelLink("https://app.example.com/cancel"))
	h.recOpts = opts

	return h.options(t)
}

// recoveryBesidePasskeys is recovery with passkey registration and the passkey
// method as its way to bind a recovered session.
func recoveryBesidePasskeys(t *testing.T, held bool, opts ...httpsec.RecoveryOption) []httpsec.Option {
	t.Helper()

	h := newRecoveryHarness(t)
	h.noBinding = true

	if held {
		h.coreOpts = append(h.coreOpts, recovery.WithHoldDelay(time.Hour),
			recovery.WithCancelLink("https://app.example.com/cancel"))
	}

	m, err := passkey.New(passkey.Deps{
		Verifier: newPasskeyVerifierStub(t).mock, Users: h.users, Sender: h.sender, Sessions: h.sessions,
	}, passkey.WithRepudiationContact("help@example.com"))
	require.NoError(t, err)

	h.chainOpts = append(h.chainOpts,
		httpsec.EnableMFA([]mfa.Method{h.totp, m.MFAMethod()}, httpsec.WithMFATokens(h.tokens)),
		httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: m, Sessions: h.sessions}),
		httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(h.tokens)))
	h.recOpts = opts

	return h.options(t)
}

// everyOtherBuiltIn enables, beside the provider, every other built-in that
// answers a path, each with its default paths.
var everyOtherBuiltIn = []func(*testing.T, *session.Sessions) []httpsec.Option{
	formLoginOn,
	magicLinkOn,
	oidcLoginOn,
	renewalOn,
	managementOn,
	recoveryOn, // with the password-change endpoint
	func(t *testing.T, m *session.Sessions) []httpsec.Option {
		users := NewMockUserLoader(gomock.NewController(t))
		pm := must.Must(passkey.New(passkey.Deps{
			Verifier: newPasskeyVerifierStub(t).mock,
			Users:    users,
			Sender:   exampleSender{},
			Sessions: m,
		}, passkey.WithRepudiationContact("help@example.com"), passkey.WithOptionalRecoveryCodes(), passkey.WithoutCloneGrantRevocation()))

		return []httpsec.Option{httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: pm, Sessions: m, Users: users},
			httpsec.WithPasskeyPasswordlessLogin())}
	},
	func(t *testing.T, m *session.Sessions) []httpsec.Option {
		return []httpsec.Option{
			httpsec.WithPolicyEngine(collisionsEngine(t)),
			httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: m}),
			httpsec.EnableSessionSignals(httpsec.SessionSignals{}),
			httpsec.EnableMFA([]mfa.Method{must.Must(mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example"))},
				httpsec.WithMFAMethodListing()),
			httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{
				Users:  NewMockUserLoader(gomock.NewController(t)),
				Sender: exampleSender{},
			}),
			httpsec.EnableReauthentication(),
		}
	},
}

// collisionsEngine raises the enrolment challenge, which EnableMFAEnrolment
// needs to be reachable, and exempts federated logins, so the chain with
// federated login beside it builds.
func collisionsEngine(t *testing.T) *policy.Engine {
	t.Helper()

	lookup := NewMockMFAMethodLookup(gomock.NewController(t))
	lookup.EXPECT().Name().Return("totp").AnyTimes()
	lookup.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	lookup.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()

	p, err := policy.NewMFARequirement(everyoneRequired{}, []policy.MFAMethodLookup{enrollableLookup{lookup}},
		policy.WithMFAEnrolmentPath(),
		policy.WithMFAExemption(func(k factor.Kind) bool { return k == factor.OIDC || k.MFAExempt() }))
	require.NoError(t, err)

	return engineOf(t, p)
}
