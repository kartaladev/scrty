package httpsec_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// TestChainPathCollisions_AuthFeatures pins the shared collision check for the
// features whose own checks it replaced: re-authentication, the signal stream,
// federated login and the provider. Every refusal those checks made is kept,
// worded as the shared check words it, and each verdict the shared check
// changed has its own row.
func TestChainPathCollisions_AuthFeatures(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		build  func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	// reauth is the re-authentication harness's chain after wire.
	reauth := func(wire func(t *testing.T, h *reauthHarness)) func(*testing.T) []httpsec.Option {
		return func(t *testing.T) []httpsec.Option {
			h := newReauthHarness(t)
			wire(t, h)

			return h.options(nil)
		}
	}

	// prefix moves re-authentication to p, then applies more.
	prefix := func(p string, more ...func(*testing.T, *reauthHarness)) func(*testing.T) []httpsec.Option {
		return reauth(func(t *testing.T, h *reauthHarness) {
			h.reauthOpts = []httpsec.ReauthenticationOption{httpsec.WithReauthenticationPrefix(p)}
			for _, m := range more {
				m(t, h)
			}
		})
	}

	// signalsAt is the signal stream at path beside others, on a chain with the
	// signal tests' session bearer.
	signalsAt := func(path string, others func(t *testing.T, f *constructionFixture) []httpsec.Option) func(*testing.T) []httpsec.Option {
		return func(t *testing.T) []httpsec.Option {
			f := newConstructionFixture(t)

			return append(append([]httpsec.Option{f.bearer}, others(t, f)...),
				httpsec.EnableSessionSignals(httpsec.SessionSignals{Path: path}))
		}
	}

	formLogin := func(t *testing.T, f *constructionFixture) httpsec.Option {
		return httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: NewMockAuthenticator(gomock.NewController(t)),
			Sessions:      f.sessions,
			Attempts:      NewMockAttemptStore(gomock.NewController(t)),
		})
	}

	// oidcLogin is federated login with the construction tests' wiring and opts.
	oidcLogin := func(opts ...httpsec.OIDCOption) func(*testing.T) []httpsec.Option {
		return func(t *testing.T) []httpsec.Option {
			o := oidcFixture{
				manager:  newTestOIDCManager(t),
				handoffs: newTestHandoffManager(t),
				tokens:   newMockGenerator(gomock.NewController(t)),
				sessions: mustSessions(t),
			}

			return []httpsec.Option{httpsec.EnableOIDCLogin(
				httpsec.OIDCDeps{RelyingParty: o.manager, Handoff: o.handoffs}, o.required(opts...)...)}
		}
	}

	// provider is the provider given popts, on a chain with everything it
	// needs and what others add over the manager it is told of.
	provider := func(popts []httpsec.OIDCProviderOption,
		others ...func(*testing.T, *session.Sessions) []httpsec.Option,
	) func(*testing.T) []httpsec.Option {
		return func(t *testing.T) []httpsec.Option {
			p := f.provider(t)
			opts := f.wired(t, p)

			for _, other := range others {
				opts = append(opts, other(t, reporting(t, p))...)
			}

			return append(opts, httpsec.EnableOIDCProvider(p, popts...))
		}
	}

	at := func(e httpsec.OIDCEndpoint, path string) []httpsec.OIDCProviderOption {
		return []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(e, path)}
	}

	logoutAt := func(path string) func(*testing.T, *session.Sessions) []httpsec.Option {
		return func(_ *testing.T, m *session.Sessions) []httpsec.Option {
			return []httpsec.Option{httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: m}, httpsec.WithLogoutRequestPath(path))}
		}
	}

	cases := []testCase{
		// Re-authentication.
		{
			// reauthentication, "Prefix collides with MFA verify".
			name:  "the re-authentication prefix at the MFA verify prefix",
			build: prefix(httpsec.DefaultMFAVerifyPrefix),
			assert: collisionRefused("WithReauthenticationPrefix", "WithMFAVerifyPrefix",
				httpsec.OperationMFAVerify, httpsec.OperationReauthChallenge, `"/mfa/verify/challenge/{method}"`),
		},
		{
			// The trailing slash is dropped from the prefix, so it collides as
			// its slash-free form does.
			name:  "the re-authentication prefix at the MFA verify prefix with a trailing slash",
			build: prefix(httpsec.DefaultMFAVerifyPrefix + "/"),
			assert: collisionRefused("WithReauthenticationPrefix", "WithMFAVerifyPrefix",
				httpsec.OperationMFAVerify, `"/mfa/verify/challenge/{method}"`),
		},
		{
			name:  "the re-authentication prefix under the MFA begin prefix",
			build: prefix(httpsec.DefaultMFABeginPrefix + "/again"),
			assert: collisionRefused("WithReauthenticationPrefix", "WithMFABeginPrefix",
				httpsec.OperationMFAChallenge, `"/mfa/challenge/again/challenge/{method}"`),
		},
		{
			// The re-proof begin and verify paths of the prefix /mfa are the
			// MFA begin and verify prefixes themselves.
			name:  "a re-authentication prefix whose paths are the MFA prefixes",
			build: prefix("/mfa"),
			assert: collisionRefused("WithReauthenticationPrefix", "WithMFABeginPrefix",
				httpsec.OperationMFAChallenge, httpsec.OperationReauthChallenge, `"/mfa/challenge/{method}"`),
		},
		{
			// The segment boundary: "/mfa/verifyx" is not under "/mfa/verify".
			name:   "a re-authentication prefix that only starts like the MFA verify prefix",
			build:  prefix(httpsec.DefaultMFAVerifyPrefix + "x"),
			assert: collisionBuilt,
		},
		{
			// Logout moved under the re-proof verify path would be answered as
			// a re-proof.
			name: "the logout path under the re-authentication verify path",
			build: reauth(func(_ *testing.T, h *reauthHarness) {
				h.logoutOpts = []httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/reauth/verify/out")}
			}),
			assert: collisionRefused("WithLogoutRequestPath", "WithReauthenticationPrefix",
				httpsec.OperationSignOut, httpsec.OperationReauthVerify, `"/reauth/verify/out"`),
		},
		{
			name: "the form login path at the re-authentication password path",
			build: reauth(func(_ *testing.T, h *reauthHarness) {
				h.loginOpts = []httpsec.LoginOption{httpsec.WithLoginRequestPath("/reauth/password")}
			}),
			assert: collisionRefused("WithLoginRequestPath", "WithReauthenticationPrefix",
				httpsec.OperationSignInPassword, httpsec.OperationReauthPassword, `"/reauth/password"`),
		},
		{
			// A changed verdict (D13): re-authentication once judged the
			// passkey registration prefix a subtree, while registration answers
			// four exact paths, none of which a re-proof path overlaps.
			name:   "the re-authentication prefix at the passkey registration prefix builds",
			build:  prefix(httpsec.DefaultPasskeyRegistrationPrefix, enablePasskeys()),
			assert: collisionBuilt,
		},
		{
			// A changed verdict (D13), as the row above: the credentials list
			// answers its own path exactly, and renaming and removing one path
			// each beneath it, none a re-proof path.
			name:   "the re-authentication prefix at the passkey credentials prefix builds",
			build:  prefix(httpsec.DefaultPasskeyCredentialsPrefix, enablePasskeys()),
			assert: collisionBuilt,
		},
		{
			// reauthentication, "Prefix collides with passkey registration".
			name: "the passkey registration prefix under the re-authentication begin path",
			build: reauth(func(t *testing.T, h *reauthHarness) {
				enablePasskeys(httpsec.WithPasskeyRegistrationPrefix("/reauth/challenge"))(t, h)
			}),
			assert: collisionRefused("WithReauthenticationPrefix", "WithPasskeyRegistrationPrefix",
				httpsec.OperationReauthChallenge, `"/reauth/challenge/begin"`),
		},
		{
			name: "the passwordless begin path under the re-authentication begin path",
			build: prefix("/a", enablePasskeys(httpsec.WithPasskeyPasswordlessLogin(),
				httpsec.WithPasskeyPasswordlessPrefix("/a/challenge"))),
			assert: collisionRefused("WithReauthenticationPrefix", "WithPasskeyPasswordlessPrefix",
				httpsec.OperationReauthChallenge, httpsec.OperationSignInPasskeyBegin),
		},
		{
			name:  "the re-authentication prefix at the MFA enrolment begin prefix",
			build: prefix(httpsec.DefaultEnrolmentBeginPrefix, enableEnrolment()),
			assert: collisionRefused("WithReauthenticationPrefix", "WithEnrolmentBeginPrefix",
				httpsec.OperationMFAEnrolmentBegin),
		},
		{
			// reauthentication, "Another endpoint's exact path collides".
			name: "the session renewal path at the re-authentication password path",
			build: reauth(func(_ *testing.T, h *reauthHarness) {
				h.chainOpts = append(h.chainOpts, httpsec.EnableSessionRenewal(
					httpsec.SessionRenewalDeps{Sessions: h.sessions, Users: h.users, Tokens: h.tokens},
					httpsec.WithRenewalPath("/reauth/password")))
			}),
			assert: collisionRefused("WithRenewalPath", "WithReauthenticationPrefix",
				httpsec.OperationSessionRenewal, httpsec.OperationReauthPassword, `"/reauth/password"`),
		},
		{
			name: "the password-change endpoint at the re-authentication password path",
			build: reauth(func(_ *testing.T, h *reauthHarness) {
				h.chainOpts = append(h.chainOpts, httpsec.EnablePasswordChangeGate(h.sessions,
					httpsec.WithPasswordChangeEndpoint("/reauth/password", func(*httpsec.Exchange) error { return nil })))
			}),
			assert: collisionRefused("WithPasswordChangeEndpoint", "WithReauthenticationPrefix",
				httpsec.OperationPasswordChange, httpsec.OperationReauthPassword, `"/reauth/password"`),
		},
		{
			// The recovery start exists only once the chain is wired, so the
			// check build runs over the full inventory refuses it.
			name:  "the recovery start path at the re-authentication password path",
			build: reauth(enableRecovery(httpsec.WithRecoveryStartPath("/reauth/password"))),
			assert: collisionRefused("WithRecoveryStartPath", "WithReauthenticationPrefix",
				httpsec.OperationRecoveryStart, httpsec.OperationReauthPassword, `"/reauth/password"`),
		},
		{
			name:  "the magic-link request path at the re-authentication password path",
			build: reauth(enableMagicLink(httpsec.WithMagicLinkRequestPath("/reauth/password"))),
			assert: collisionRefused("WithMagicLinkRequestPath", "WithReauthenticationPrefix",
				httpsec.OperationSignInMagicLinkRequest, httpsec.OperationReauthPassword, `"/reauth/password"`),
		},
		{
			name:  "the magic-link consume path under the re-authentication verify path",
			build: reauth(enableMagicLink(httpsec.WithMagicLinkConsumePath("/reauth/verify/link"))),
			assert: collisionRefused("WithMagicLinkConsumePath", "WithReauthenticationPrefix",
				httpsec.OperationSignInMagicLinkRedeem, httpsec.OperationReauthVerify, `"/reauth/verify/link"`),
		},
		{
			name:  "the re-authentication prefix at the federated-login authorize prefix",
			build: prefix("/sso/login", enableOIDC()),
			assert: collisionRefused("WithReauthenticationPrefix", "WithOIDCAuthorizePath",
				httpsec.OperationSSOLogin, httpsec.OperationReauthMethods, `"/sso/login/methods"`),
		},
		{
			// The handoff exists only once the chain is wired.
			name:  "the federated-login handoff path at the re-authentication password path",
			build: reauth(enableOIDC(httpsec.WithOIDCHandoffPath("/reauth/password"))),
			assert: collisionRefused("WithOIDCHandoffPath", "WithReauthenticationPrefix",
				httpsec.OperationSSOHandoff, httpsec.OperationReauthPassword, `"/reauth/password"`),
		},
		{
			name: "the re-authentication listing path at the MFA listing path",
			build: reauth(func(_ *testing.T, h *reauthHarness) {
				h.mfaOpts = []httpsec.MFAOption{
					httpsec.WithMFAVerifyPrefix("/2fa/verify"),
					httpsec.WithMFABeginPrefix("/2fa/begin"),
					httpsec.WithMFAMethodListing(),
				}
				h.reauthOpts = []httpsec.ReauthenticationOption{httpsec.WithReauthenticationPrefix("/mfa")}
			}),
			assert: collisionRefused("WithMFAMethodListing", "WithReauthenticationPrefix",
				httpsec.OperationMFAMethods, httpsec.OperationReauthMethods, `"`+httpsec.DefaultMFAMethodListingPath+`"`),
		},
		{
			name: "the key set path at the re-authentication listing path",
			build: prefix("/keys", func(t *testing.T, h *reauthHarness) {
				h.chainOpts = append(h.chainOpts, httpsec.EnableJWKSEndpoint(
					NewMockKeySetProvider(gomock.NewController(t)), httpsec.WithJWKSEndpointPath("/keys/methods")))
			}),
			assert: collisionRefused("WithJWKSEndpointPath", "WithReauthenticationPrefix",
				httpsec.OperationKeySet, httpsec.OperationReauthMethods, `"/keys/methods"`),
		},

		// The signal stream.
		{
			name: "the signal stream at the session management path",
			build: signalsAt("/sessions", func(*testing.T, *constructionFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableSessionManagement()}
			}),
			assert: collisionRefused("SessionSignals.Path", "WithSessionManagementPrefix",
				httpsec.OperationSessionSignals, httpsec.OperationSessionsList, `"/sessions"`),
		},
		{
			name: "the signal stream one segment under the session management path",
			build: signalsAt("/sessions/signals", func(*testing.T, *constructionFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableSessionManagement()}
			}),
			assert: collisionRefused("SessionSignals.Path", "WithSessionManagementPrefix",
				httpsec.OperationSessionSignals, httpsec.OperationSessionsEnd, `"/sessions/signals"`),
		},
		{
			name: "the signal stream at the logout path",
			build: signalsAt(httpsec.DefaultLogoutPath, func(_ *testing.T, f *constructionFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: f.sessions})}
			}),
			assert: collisionRefused("SessionSignals.Path", "WithLogoutRequestPath",
				httpsec.OperationSessionSignals, httpsec.OperationSignOut, `"`+httpsec.DefaultLogoutPath+`"`),
		},
		{
			name: "the signal stream at the session renewal path",
			build: signalsAt(httpsec.DefaultSessionRenewalPath, func(_ *testing.T, f *constructionFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: f.users})}
			}),
			assert: collisionRefused("SessionSignals.Path", "WithRenewalPath",
				httpsec.OperationSessionSignals, httpsec.OperationSessionRenewal, `"`+httpsec.DefaultSessionRenewalPath+`"`),
		},
		{
			// A changed verdict: the old check claimed everything under the
			// re-authentication prefix, while re-authentication answers none of
			// the prefix itself, only its listing, password, begin and verify
			// paths.
			name: "the signal stream at the re-authentication prefix builds",
			build: signalsAt(httpsec.DefaultReauthenticationPrefix, func(t *testing.T, f *constructionFixture) []httpsec.Option {
				return []httpsec.Option{formLogin(t, f), httpsec.EnableReauthentication()}
			}),
			assert: collisionBuilt,
		},
		{
			name: "the signal stream at the re-authentication listing path",
			build: signalsAt(httpsec.DefaultReauthenticationPrefix+"/methods", func(t *testing.T, f *constructionFixture) []httpsec.Option {
				return []httpsec.Option{formLogin(t, f), httpsec.EnableReauthentication()}
			}),
			assert: collisionRefused("SessionSignals.Path", "WithReauthenticationPrefix",
				httpsec.OperationSessionSignals, httpsec.OperationReauthMethods),
		},

		// Federated login.
		{
			// oidc-login, "Colliding paths".
			name:  "the handoff path at the callback prefix",
			build: oidcLogin(httpsec.WithOIDCHandoffPath(httpsec.DefaultOIDCCallbackPath)),
			assert: collisionRefused("WithOIDCHandoffPath", "WithOIDCCallbackPath",
				httpsec.OperationSSOHandoff, httpsec.OperationSSOCallback, `"`+httpsec.DefaultOIDCCallbackPath+`"`),
		},
		{
			name:  "the handoff path at the callback prefix without its trailing slash",
			build: oidcLogin(httpsec.WithOIDCHandoffPath("/sso/callback")),
			assert: collisionRefused("WithOIDCHandoffPath", "WithOIDCCallbackPath",
				httpsec.OperationSSOHandoff, httpsec.OperationSSOCallback, `"/sso/callback"`),
		},
		{
			// A changed verdict: the handoff answers POST alone and starting a
			// login GET alone, each passing other methods on, so no request
			// reaches both, and the shared rule does not refuse a path one
			// segment under a prefix when no method meets.
			name:   "the handoff path one segment under the authorize prefix builds",
			build:  oidcLogin(httpsec.WithOIDCHandoffPath(httpsec.DefaultOIDCAuthorizePath + "handoff")),
			assert: collisionBuilt,
		},
		{
			// oidc-logout, "Back-channel path shadows the callback".
			name:  "the back-channel prefix at the callback prefix",
			build: oidcLogin(httpsec.WithOIDCBackchannelLogoutPath(httpsec.DefaultOIDCCallbackPath)),
			assert: collisionRefused("WithOIDCBackchannelLogoutPath", "WithOIDCCallbackPath",
				httpsec.OperationSSOBackchannelLogout, httpsec.OperationSSOCallback,
				// Both settle at the callback's one-segment path, which the
				// refusal names for each.
				`"`+httpsec.DefaultOIDCCallbackPath+`{provider}"`),
		},
		{
			name:  "the authorize prefix at the callback prefix without its slash",
			build: oidcLogin(httpsec.WithOIDCAuthorizePath("/sso/callback")),
			assert: collisionRefused("WithOIDCAuthorizePath", "WithOIDCCallbackPath",
				httpsec.OperationSSOLogin, httpsec.OperationSSOCallback),
		},

		// The provider.
		{
			// http-security-chain "Provider wiring mistakes fail at
			// construction", "Path collision".
			name:  "the provider's end-session path at the logout path",
			build: provider(at(httpsec.OIDCEndSession, httpsec.DefaultLogoutPath), logoutAt(httpsec.DefaultLogoutPath)),
			assert: collisionRefused("EnableOIDCProvider", "WithLogoutRequestPath",
				"WithOIDCProviderPath for "+httpsec.OIDCEndSession.String(),
				httpsec.OperationSignOut, httpsec.OperationOAuth2EndSession, `"`+httpsec.DefaultLogoutPath+`"`),
		},
		{
			name: "the provider given before the logout its end-session path collides with",
			build: func(t *testing.T) []httpsec.Option {
				p := f.provider(t)

				return append([]httpsec.Option{
					httpsec.EnableOIDCProvider(p, httpsec.WithOIDCProviderPath(httpsec.OIDCEndSession, httpsec.DefaultLogoutPath)),
				}, append(f.wired(t, p), httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: reporting(t, p)}))...)
			},
			assert: collisionRefused("EnableOIDCProvider", "WithLogoutRequestPath",
				httpsec.OperationOAuth2EndSession, `"`+httpsec.DefaultLogoutPath+`"`),
		},
		{
			name: "the provider given before the key set its token path collides with",
			build: func(t *testing.T) []httpsec.Option {
				p := f.provider(t)

				return append([]httpsec.Option{
					httpsec.EnableOIDCProvider(p, httpsec.WithOIDCProviderPath(httpsec.OIDCToken, httpsec.DefaultJWKSPath)),
				}, f.wired(t, p)...)
			},
			assert: collisionRefused("EnableOIDCProvider", "WithJWKSEndpointPath",
				httpsec.OperationOAuth2Token, httpsec.OperationKeySet, `"`+httpsec.DefaultJWKSPath+`"`),
		},
		{
			name:  "the provider's token path at the key set path",
			build: provider(at(httpsec.OIDCToken, httpsec.DefaultJWKSPath)),
			assert: collisionRefused("EnableOIDCProvider", "WithJWKSEndpointPath",
				httpsec.OperationOAuth2Token, httpsec.OperationKeySet, `"`+httpsec.DefaultJWKSPath+`"`),
		},
		{
			// The provider once refused two of its own endpoints on one path
			// while it resolved them; the shared check refuses them now.
			name:  "two provider endpoints at one path",
			build: provider(at(httpsec.OIDCRevoke, "/oauth2/token")),
			assert: collisionRefused("EnableOIDCProvider", "WithOIDCProviderPrefix",
				"WithOIDCProviderPath for "+httpsec.OIDCRevoke.String(),
				httpsec.OperationOAuth2Token, httpsec.OperationOAuth2Revoke, `"/oauth2/token"`),
		},
		{
			// http-security-chain, "Undeclared sharing": the two answer
			// different methods, but each answers 405 to the other's, and only
			// operations that declare they share a path may share one.
			name: "the end-session confirmation and the consents at one path",
			build: provider([]httpsec.OIDCProviderOption{
				httpsec.WithOIDCProviderPath(httpsec.OIDCLogoutConfirm, "/oauth2/me"),
				httpsec.WithOIDCProviderPath(httpsec.OIDCConsents, "/oauth2/me"),
			}),
			assert: collisionRefused("two endpoints collide",
				"WithOIDCProviderPath for "+httpsec.OIDCLogoutConfirm.String()+" (EnableOIDCProvider)",
				"WithOIDCProviderPath for "+httpsec.OIDCConsents.String()+" (EnableOIDCProvider)",
				httpsec.OperationOAuth2EndSessionConfirm, httpsec.OperationOAuth2ConsentsList,
				`"/oauth2/me"`, "the other would never be reached"),
		},
		{
			// A revocation answers the consents path and one segment.
			name: "the logout path one segment under the consents path",
			build: provider(at(httpsec.OIDCConsents, "/consents"), func(_ *testing.T, m *session.Sessions) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: m},
					httpsec.WithLogoutRequestPath("/consents/out"))}
			}),
			assert: collisionRefused("WithLogoutRequestPath", "WithOIDCProviderPath for "+httpsec.OIDCConsents.String(),
				httpsec.OperationSignOut, httpsec.OperationOAuth2ConsentsRevoke, `"/consents/out"`),
		},
		{
			name: "the session management path one segment under the consents path",
			build: provider(at(httpsec.OIDCConsents, "/consents"), func(*testing.T, *session.Sessions) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableSessionManagement(httpsec.WithSessionManagementPrefix("/consents/sessions"))}
			}),
			assert: collisionRefused("WithSessionManagementPrefix", "WithOIDCProviderPath for "+httpsec.OIDCConsents.String(),
				httpsec.OperationOAuth2ConsentsRevoke, `"/consents/sessions"`),
		},
		{
			// A changed verdict (D13): the consents once claimed every path
			// beneath theirs, and answer only the one segment their entry
			// declares now.
			name: "the logout path two segments under the consents path builds",
			build: provider(at(httpsec.OIDCConsents, "/consents"), func(_ *testing.T, m *session.Sessions) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: m},
					httpsec.WithLogoutRequestPath("/consents/a/out"))}
			}),
			assert: collisionBuilt,
		},
		// Changed verdicts (D13): a feature claims only the paths its entries
		// declare, not everything under its prefix.
		{
			// Changed verdict (D13): federated login's start answers one
			// segment under its prefix, not "/sso/login/idp/x".
			name:   "the provider's token under the federated-login authorize prefix, two segments down, builds",
			build:  provider(at(httpsec.OIDCToken, httpsec.DefaultOIDCAuthorizePath+"idp/x"), oidcLoginOn),
			assert: collisionBuilt,
		},
		{
			// Changed verdict (D13): session management answers one segment
			// under its prefix, not "/sessions/a/b".
			name:   "the provider's token under the session management prefix, two segments down, builds",
			build:  provider(at(httpsec.OIDCToken, httpsec.DefaultSessionManagementPrefix+"/a/b"), managementOn),
			assert: collisionBuilt,
		},
		{
			// Changed verdict (D13): re-authentication answers none of the
			// paths under its prefix but its own four.
			name: "the signal stream under the re-authentication prefix builds",
			build: signalsAt(httpsec.DefaultReauthenticationPrefix+"/stream", func(t *testing.T, f *constructionFixture) []httpsec.Option {
				return []httpsec.Option{formLogin(t, f), httpsec.EnableReauthentication()}
			}),
			assert: collisionBuilt,
		},
		{
			// Changed verdict (D13): a recovery that issues no codes answers no
			// start, so its path may be another endpoint's.
			name: "the recovery start path at the logout path, with no issued codes, builds",
			build: func(t *testing.T) []httpsec.Option {
				h := newRecoveryHarness(t)
				h.proofs = []recovery.ProofKind{recovery.ProofSaved, recovery.ProofPassword, recovery.ProofMFA}
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryStartPath(httpsec.DefaultLogoutPath)}

				return h.options(t)
			},
			assert: collisionBuilt,
		},
		{
			// Changed verdict (D13): federated login without redemption has no
			// handoff, so another endpoint may answer its default path.
			name: "the provider's token at the handoff path, with no redemption, builds",
			build: provider(at(httpsec.OIDCToken, httpsec.DefaultOIDCHandoffPath),
				func(t *testing.T, m *session.Sessions) []httpsec.Option {
					flows, err := oidc.NewMemoryFlowStore()
					require.NoError(t, err)

					return []httpsec.Option{httpsec.EnableOIDCLogin(
						httpsec.OIDCDeps{RelyingParty: oidcManagerOver(t, flows)},
						httpsec.WithOIDCSessions(m),
						httpsec.WithOIDCCallbackSuccess(func(*httpsec.Exchange, oidc.CallbackResult, string) error { return nil }))}
				}),
			assert: collisionBuilt,
		},
	}

	// Each endpoint family of the chain that the provider's paths must stay
	// clear of, whatever the order of the options: the provider is given the
	// family's path.
	for _, fam := range []struct {
		name     string
		endpoint httpsec.OIDCEndpoint
		path     string
		enable   func(t *testing.T, m *session.Sessions) []httpsec.Option
	}{
		{"the magic-link request path", httpsec.OIDCToken, httpsec.DefaultMagicLinkRequestPath, magicLinkOn},
		{"the magic-link consume path", httpsec.OIDCRevoke, httpsec.DefaultMagicLinkConsumePath, magicLinkOn},
		{"a federated-login authorize path", httpsec.OIDCToken, httpsec.DefaultOIDCAuthorizePath + "idp", oidcLoginOn},
		{"a federated-login callback path", httpsec.OIDCToken, httpsec.DefaultOIDCCallbackPath + "idp", oidcLoginOn},
		{"a federated-login back-channel logout path", httpsec.OIDCToken, httpsec.DefaultOIDCBackchannelPath + "idp", oidcLoginOn},
		{"the federated-login handoff path", httpsec.OIDCToken, httpsec.DefaultOIDCHandoffPath, oidcLoginOn},
		{"the re-authentication listing path", httpsec.OIDCToken, httpsec.DefaultReauthenticationPrefix + "/methods", reauthOn},
		{"a re-authentication begin path", httpsec.OIDCToken, httpsec.DefaultReauthenticationPrefix + "/challenge/totp", reauthOn},
		{"a re-authentication verify path", httpsec.OIDCToken, httpsec.DefaultReauthenticationPrefix + "/verify/totp", reauthOn},
		{"the re-authentication password path", httpsec.OIDCToken, httpsec.DefaultReauthenticationPrefix + "/password", reauthOn},
		{"the session management path", httpsec.OIDCToken, httpsec.DefaultSessionManagementPrefix, managementOn},
		{"a session management path under its own", httpsec.OIDCToken, httpsec.DefaultSessionManagementPrefix + "/s-1", managementOn},
		{"the MFA method listing path", httpsec.OIDCToken, httpsec.DefaultMFAMethodListingPath, mfaListingOn},
		{"the login path", httpsec.OIDCToken, httpsec.DefaultLoginPath, formLoginOn},
		{"the session renewal path", httpsec.OIDCToken, httpsec.DefaultSessionRenewalPath, renewalOn},
		{"the password-change resolve path", httpsec.OIDCToken, opPasswordChangePath, passwordChangeOn},
		{"a recovery path", httpsec.OIDCToken, httpsec.DefaultRecoveryStartPath, recoveryOn},
		{"a passkey path", httpsec.OIDCToken, httpsec.DefaultPasskeyCredentialsPrefix, passkeysOn},
		{"a second-factor begin path", httpsec.OIDCToken, httpsec.DefaultMFABeginPrefix + "/totp", mfaPrefixesOn},
		{"a second-factor verify path", httpsec.OIDCToken, httpsec.DefaultMFAVerifyPrefix + "/totp", mfaPrefixesOn},
		{"an enrolment begin path", httpsec.OIDCToken, httpsec.DefaultEnrolmentBeginPrefix + "/totp", enrolmentRaised},
		{"an enrolment confirm path", httpsec.OIDCToken, httpsec.DefaultEnrolmentConfirmPrefix + "/totp", enrolmentRaised},
	} {
		cases = append(cases, testCase{
			name:  "the provider's path at " + fam.name,
			build: provider(at(fam.endpoint, fam.path), fam.enable),
			assert: collisionRefused("two endpoints collide", "WithOIDCProviderPath for "+fam.endpoint.String(),
				`"`+fam.path+`"`),
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(tc.build(t)...)
			tc.assert(t, c, err)
		})
	}
}

// enrolmentRaised is the enrolment feature over a method that can enrol, with
// the policy that raises the enrolment challenge. The chain refuses to be built
// without either, so a collision on an enrolment path is the first thing it
// finds wrong.
func enrolmentRaised(t *testing.T, _ *session.Sessions) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{
		httpsec.WithPolicyEngine(collisionsEngine(t)),
		httpsec.EnableMFA([]mfa.Method{must.Must(mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example"))}),
		httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{
			Users:  NewMockUserLoader(gomock.NewController(t)),
			Sender: exampleSender{},
		}),
	}
}
