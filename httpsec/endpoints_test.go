package httpsec_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// endpointsBase is the base path the inventory tests move the endpoints under.
const endpointsBase = "/auth"

// findEndpoint returns the entry with the operation identifier id.
func findEndpoint(eps []httpsec.Endpoint, id string) (httpsec.Endpoint, bool) {
	i := slices.IndexFunc(eps, func(e httpsec.Endpoint) bool { return e.OperationID == id })
	if i < 0 {
		return httpsec.Endpoint{}, false
	}

	return eps[i], true
}

// operationIDs are the identifiers of eps, in order.
func operationIDs(eps []httpsec.Endpoint) []string {
	ids := make([]string, 0, len(eps))
	for _, e := range eps {
		ids = append(ids, e.OperationID)
	}

	return ids
}

// endpointsFormLoginMFA enables password sign-in and a second factor by TOTP,
// and nothing else that answers a path.
func endpointsFormLoginMFA(t *testing.T) []httpsec.Option {
	t.Helper()

	h := newLoginGuardHarness(t)

	totp, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example")
	require.NoError(t, err)

	return []httpsec.Option{
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
		}),
		httpsec.EnableMFA([]mfa.Method{totp}, httpsec.WithMFATokens(h.tokens)),
	}
}

// endpointsRecovery enables account recovery with every proof, saved codes
// among them, and a hold, so each of its endpoints exists.
func endpointsRecovery(t *testing.T) []httpsec.Option {
	t.Helper()

	for _, row := range featureEndpoints() {
		if row.option == "WithRecoveryCodesPath" {
			return row.options(t, "")
		}
	}

	require.FailNow(t, "no recovery row among the feature endpoints")

	return nil
}

// endpointsOIDCLogin enables federated login with redemption, over a registry
// holding the provider testOIDCProvider, registered under the base path.
func endpointsOIDCLogin(t *testing.T) []httpsec.Option {
	t.Helper()

	flows, err := oidc.NewMemoryFlowStore()
	require.NoError(t, err)

	handoffs, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(gomock.NewController(t)))
	require.NoError(t, err)

	return []httpsec.Option{httpsec.EnableOIDCLogin(
		httpsec.OIDCDeps{RelyingParty: oidcManagerAt(t, flows, endpointsBase+httpsec.DefaultOIDCCallbackPath), Handoff: handoffs},
		httpsec.WithOIDCSessions(must.Must(session.New())),
		httpsec.WithOIDCTokens(newMockGenerator(gomock.NewController(t))),
	)}
}

// endpointsReauth enables re-authentication beside password sign-in.
func endpointsReauth(t *testing.T) []httpsec.Option {
	t.Helper()

	h := newLoginGuardHarness(t)

	return []httpsec.Option{
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
		}),
		httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(h.tokens)),
	}
}

// TestChainEndpoints pins the scenarios of "The chain lists the endpoints it
// answers": what is listed, where, and what is not.
func TestChainEndpoints(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		chain  func(t *testing.T) (*httpsec.Chain, error)
		assert func(t *testing.T, eps []httpsec.Endpoint, err error)
	}

	cases := []testCase{
		{
			name: "enabled endpoints listed under the base path",
			chain: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(append(endpointsFormLoginMFA(t), httpsec.WithBasePath(endpointsBase))...)
			},
			assert: func(t *testing.T, eps []httpsec.Endpoint, err error) {
				require.NoError(t, err)

				login, ok := findEndpoint(eps, httpsec.OperationSignInPassword)
				require.True(t, ok, "password sign-in is listed: %v", operationIDs(eps))
				assert.Equal(t, []string{http.MethodPost}, login.Methods)
				assert.Equal(t, "/auth/sign-in/password", login.Path)

				verify, ok := findEndpoint(eps, httpsec.OperationMFAVerify)
				require.True(t, ok, "second-factor verification is listed: %v", operationIDs(eps))
				assert.Equal(t, []string{http.MethodPost}, verify.Methods)
				assert.Equal(t, "/auth/mfa/verify/{method}", verify.Path)

				for _, e := range eps {
					assert.Truef(t, strings.HasPrefix(e.Path, endpointsBase+"/"), "%s answers under the base: %q", e.OperationID, e.Path)
				}
			},
		},
		{
			name: "endpoints not enabled are absent",
			chain: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(endpointsFormLoginMFA(t)...)
			},
			assert: func(t *testing.T, eps []httpsec.Endpoint, err error) {
				require.NoError(t, err)
				require.NotEmpty(t, eps)

				for _, e := range eps {
					for _, absent := range []string{"scrty.sign-out", "scrty.passkeys.", "scrty.sign-in.passkey.", "scrty.recovery."} {
						assert.Falsef(t, strings.HasPrefix(e.OperationID, absent), "%s is listed although not enabled", e.OperationID)
					}
				}

				_, listing := findEndpoint(eps, httpsec.OperationMFAMethods)
				assert.False(t, listing, "the method listing is listed only with WithMFAMethodListing")
			},
		},
		{
			name: "discovery documents listed where they are served",
			chain: func(t *testing.T) (*httpsec.Chain, error) {
				return bpChain(t, newOPFixture(t), true)
			},
			assert: func(t *testing.T, eps []httpsec.Endpoint, err error) {
				require.NoError(t, err)

				openid, ok := findEndpoint(eps, httpsec.OperationOAuth2OpenIDConfiguration)
				require.True(t, ok, "the OpenID configuration is listed: %v", operationIDs(eps))
				assert.Equal(t, "/auth/.well-known/openid-configuration", openid.Path)
				assert.Contains(t, openid.Methods, http.MethodGet)

				oauth, ok := findEndpoint(eps, httpsec.OperationOAuth2AuthorizationServerMetadata)
				require.True(t, ok, "the authorization server metadata is listed: %v", operationIDs(eps))
				assert.Equal(t, "/.well-known/oauth-authorization-server/auth", oauth.Path)
				assert.Contains(t, oauth.Methods, http.MethodGet)
			},
		},
		{
			name: "one entry per operation on the recovery codes path",
			chain: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(endpointsRecovery(t)...)
			},
			assert: func(t *testing.T, eps []httpsec.Endpoint, err error) {
				require.NoError(t, err)

				var onCodes []httpsec.Endpoint
				for _, e := range eps {
					if e.Path == httpsec.DefaultRecoveryCodesPath {
						onCodes = append(onCodes, e)
					}
				}

				require.Len(t, onCodes, 2, "the codes path holds two entries: %v", operationIDs(eps))
				assert.Equal(t, []string{http.MethodGet}, onCodes[0].Methods)
				assert.Equal(t, httpsec.OperationRecoveryCodesCount, onCodes[0].OperationID)
				assert.Equal(t, []string{http.MethodPost}, onCodes[1].Methods)
				assert.Equal(t, httpsec.OperationRecoveryCodesRegenerate, onCodes[1].OperationID)
				assert.NotEmpty(t, onCodes[0].SharesPath)
				assert.Equal(t, onCodes[0].SharesPath, onCodes[1].SharesPath)
			},
		},
		{
			name: "an operation is listed once",
			chain: func(t *testing.T) (*httpsec.Chain, error) {
				keys := NewMockKeySetProvider(gomock.NewController(t))

				return httpsec.New(
					httpsec.EnableJWKSEndpoint(keys),
					httpsec.EnableJWKSEndpoint(keys, httpsec.WithJWKSEndpointPath("/keys")),
				)
			},
			assert: func(t *testing.T, eps []httpsec.Endpoint, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), httpsec.OperationKeySet)
				assert.Contains(t, err.Error(), "WithJWKSEndpointPath")
				assert.Nil(t, eps)
			},
		},
		{
			name: "a consumer interceptor is not listed",
			chain: func(t *testing.T) (*httpsec.Chain, error) {
				status := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					if ex.Request.Path() == "/status" {
						ex.Writer.WriteHeader(http.StatusNoContent)

						return nil
					}

					return next(ex)
				})

				return httpsec.New(append(endpointsFormLoginMFA(t), httpsec.RegisterInterceptor(status, httpsec.OrderJWKS-1))...)
			},
			assert: func(t *testing.T, eps []httpsec.Endpoint, err error) {
				require.NoError(t, err)
				require.NotEmpty(t, eps)

				for _, e := range eps {
					assert.NotEqual(t, "/status", e.Path, "%s is the consumer's", e.OperationID)
				}
			},
		},
		{
			name:  "a chain with no built-in endpoint lists none, as an empty slice",
			chain: func(*testing.T) (*httpsec.Chain, error) { return httpsec.New() },
			assert: func(t *testing.T, eps []httpsec.Endpoint, err error) {
				require.NoError(t, err)
				assert.NotNil(t, eps)
				assert.Empty(t, eps)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := tc.chain(t)
			if err != nil {
				tc.assert(t, nil, err)

				return
			}

			tc.assert(t, c.Endpoints(), nil)
		})
	}
}

// TestChainEndpoints_ConditionalEntriesAbsent pins that an operation the
// configuration leaves off is not listed, and that its sibling that stays on
// still is, so the absence is the condition's and not an empty list's.
func TestChainEndpoints_ConditionalEntriesAbsent(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T) []httpsec.Option
		listed  []string
		absent  []string
	}

	recoveryWith := func(proofs []recovery.ProofKind, hold bool) func(t *testing.T) []httpsec.Option {
		return func(t *testing.T) []httpsec.Option {
			h := newRecoveryHarness(t)
			h.proofs = proofs

			if hold {
				h.coreOpts = append(h.coreOpts,
					recovery.WithHoldDelay(time.Hour), recovery.WithCancelLink("https://app.example.com/cancel"))
			}

			return h.options(t)
		}
	}

	allProofs := []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued, recovery.ProofPassword, recovery.ProofMFA}

	cases := []testCase{
		{
			name: "the handoff without redemption",
			options: func(t *testing.T) []httpsec.Option {
				flows, err := oidc.NewMemoryFlowStore()
				require.NoError(t, err)

				return []httpsec.Option{httpsec.EnableOIDCLogin(
					httpsec.OIDCDeps{RelyingParty: oidcManagerOver(t, flows)},
					httpsec.WithOIDCSessions(must.Must(session.New())),
					httpsec.WithOIDCCallbackSuccess(func(*httpsec.Exchange, oidc.CallbackResult, string) error { return nil }),
				)}
			},
			listed: []string{httpsec.OperationSSOLogin, httpsec.OperationSSOCallback, httpsec.OperationSSOBackchannelLogout},
			absent: []string{httpsec.OperationSSOHandoff},
		},
		{
			name:    "recovery without issued codes has no start",
			options: recoveryWith([]recovery.ProofKind{recovery.ProofSaved, recovery.ProofPassword, recovery.ProofMFA}, true),
			listed:  []string{httpsec.OperationRecoveryComplete, httpsec.OperationRecoveryFinish, httpsec.OperationRecoveryCodesCount},
			absent:  []string{httpsec.OperationRecoveryStart},
		},
		{
			name:    "recovery without holds has no finish or cancel",
			options: recoveryWith(allProofs, false),
			listed:  []string{httpsec.OperationRecoveryComplete, httpsec.OperationRecoveryStart, httpsec.OperationRecoveryCodesCount},
			absent:  []string{httpsec.OperationRecoveryFinish, httpsec.OperationRecoveryCancel},
		},
		{
			name:    "recovery without saved codes has no codes count or regenerate",
			options: recoveryWith([]recovery.ProofKind{recovery.ProofIssued, recovery.ProofPassword, recovery.ProofMFA}, true),
			listed:  []string{httpsec.OperationRecoveryComplete, httpsec.OperationRecoveryStart},
			absent:  []string{httpsec.OperationRecoveryCodesCount, httpsec.OperationRecoveryCodesRegenerate},
		},
		{
			name: "enrolment without email confirmation has no confirm-email",
			options: func(t *testing.T) []httpsec.Option {
				h := newEnrolHarness(t)
				h.enrolOpts = append(h.enrolOpts, httpsec.WithoutEnrolmentEmailConfirmation())

				return h.options(t, h.enrolmentOnly(t, factor.Password))
			},
			listed: []string{httpsec.OperationMFAEnrolmentBegin, httpsec.OperationMFAEnrolmentConfirm},
			absent: []string{httpsec.OperationMFAEnrolmentConfirmEmail},
		},
		{
			name: "the password-change gate without an endpoint lists nothing of its own",
			options: func(t *testing.T) []httpsec.Option {
				return append(endpointsFormLoginMFA(t), httpsec.EnablePasswordChangeGate(must.Must(session.New())))
			},
			listed: []string{httpsec.OperationSignInPassword},
			absent: []string{httpsec.OperationPasswordChange},
		},
		{
			name: "the method listing off",
			options: func(t *testing.T) []httpsec.Option {
				return endpointsFormLoginMFA(t)
			},
			listed: []string{httpsec.OperationMFAVerify, httpsec.OperationMFAChallenge},
			absent: []string{httpsec.OperationMFAMethods},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(tc.options(t)...)
			require.NoError(t, err)

			ids := operationIDs(c.Endpoints())

			for _, id := range tc.listed {
				assert.Contains(t, ids, id, "the sibling that stays on is listed")
			}

			for _, id := range tc.absent {
				assert.NotContains(t, ids, id, "listed although its condition is off")
			}
		})
	}
}

// TestChainEndpoints_ReturnsACopy pins that the list cannot change the chain:
// a caller that changes what it was given, an entry's methods included, leaves
// a fresh list and the requests the chain answers as they were.
func TestChainEndpoints_ReturnsACopy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		mutate func(eps []httpsec.Endpoint) []httpsec.Endpoint
		assert func(t *testing.T, c *httpsec.Chain, before []httpsec.Endpoint)
	}

	unchanged := func(t *testing.T, c *httpsec.Chain, before []httpsec.Endpoint) {
		t.Helper()

		assert.Equal(t, before, c.Endpoints(), "a fresh list is unchanged")
		assert.True(t, answered(t, c, http.MethodPost, "/auth/mfa/verify/totp"),
			"the chain still answers second-factor verification")
		assert.False(t, answered(t, c, http.MethodPost, "/auth/elsewhere"),
			"the chain still passes a path it does not answer")
	}

	cases := []testCase{
		{
			name: "an entry's path and identifier changed",
			mutate: func(eps []httpsec.Endpoint) []httpsec.Endpoint {
				for i := range eps {
					eps[i].Path = "/elsewhere"
					eps[i].OperationID = "changed"
				}

				return eps
			},
			assert: unchanged,
		},
		{
			name: "an entry's methods changed in place",
			mutate: func(eps []httpsec.Endpoint) []httpsec.Endpoint {
				for i := range eps {
					eps[i].Methods[0] = http.MethodDelete
				}

				return eps
			},
			assert: unchanged,
		},
		{
			name: "an entry's methods appended to",
			mutate: func(eps []httpsec.Endpoint) []httpsec.Endpoint {
				for i := range eps {
					eps[i].Methods = append(eps[i].Methods[:0], http.MethodPut, http.MethodPatch)
				}

				return eps
			},
			assert: unchanged,
		},
		{
			name: "the list appended to and cleared",
			mutate: func(eps []httpsec.Endpoint) []httpsec.Endpoint {
				eps = append(eps[:0], httpsec.Endpoint{Path: "/status"})
				clear(eps)

				return eps
			},
			assert: unchanged,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(append(endpointsFormLoginMFA(t), httpsec.WithBasePath(endpointsBase))...)
			require.NoError(t, err)

			// The snapshot is copied here, not trusted to Endpoints, so a list
			// that shared the chain's arrays would change under it too and
			// could not be compared against.
			before := slices.Clone(c.Endpoints())
			for i := range before {
				before[i].Methods = slices.Clone(before[i].Methods)
			}

			require.NotEmpty(t, before)

			tc.mutate(c.Endpoints())
			tc.assert(t, c, before)
		})
	}
}

// TestChainEndpoints_IdentifiersStableUnderBasePath pins that each endpoint
// carries the same operation identifier with and without a base path, and
// that the base path changes only where it answers.
func TestChainEndpoints_IdentifiersStableUnderBasePath(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T) []httpsec.Option
		assert  func(t *testing.T, without, under []httpsec.Endpoint)
	}

	stable := func(t *testing.T, without, under []httpsec.Endpoint) {
		t.Helper()

		require.NotEmpty(t, without)
		assert.Equal(t, operationIDs(without), operationIDs(under))

		for i := range min(len(without), len(under)) {
			assert.Equal(t, endpointsBase+without[i].Path, under[i].Path, without[i].OperationID)
			assert.Equal(t, without[i].Methods, under[i].Methods, without[i].OperationID)
			assert.Equal(t, without[i].PlacedBy, under[i].PlacedBy, without[i].OperationID)
		}
	}

	var cases []testCase

	for _, row := range coreEndpoints() {
		cases = append(cases, testCase{
			name:    row.name,
			options: func(t *testing.T) []httpsec.Option { return row.options(t, "") },
			assert:  stable,
		})
	}

	for _, row := range featureEndpoints() {
		cases = append(cases, testCase{
			name:    row.name,
			options: func(t *testing.T) []httpsec.Option { return row.options(t, "") },
			assert:  stable,
		})
	}

	cases = append(cases,
		testCase{name: "re-authentication", options: endpointsReauth, assert: stable},
		testCase{name: "federated login", options: endpointsOIDCLogin, assert: stable},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			without, err := httpsec.New(tc.options(t)...)
			require.NoError(t, err)

			under, err := httpsec.New(append(tc.options(t), httpsec.WithBasePath(endpointsBase))...)
			require.NoError(t, err)

			tc.assert(t, without.Endpoints(), under.Endpoints())
		})
	}
}

// pinned asserts an entry is what the inventory documents for its operation.
func pinned(methods []string, path string, match httpsec.PathMatch, other httpsec.MethodPolicy,
	req httpsec.Requirement, placedBy, sharesPath string,
) func(t *testing.T, e httpsec.Endpoint, listed bool) {
	return func(t *testing.T, e httpsec.Endpoint, listed bool) {
		t.Helper()

		require.True(t, listed, "the operation is listed")
		assert.Equal(t, methods, e.Methods, "methods")
		assert.Equal(t, path, e.Path, "path")
		assert.Equal(t, match, e.Match, "match")
		assert.Equal(t, other, e.OtherMethods, "other methods")
		assert.Equal(t, req, e.Requires, "requires")
		assert.Equal(t, placedBy, e.PlacedBy, "placed by")
		assert.Equal(t, sharesPath, e.SharesPath, "shares path")
	}
}

// everyBuiltInEndpoint is every entry of chains that, between them, enable
// every built-in endpoint with its default paths: the provider's under
// endpointsBase, with its issuer there, and every other without a base path.
func everyBuiltInEndpoint(t *testing.T) []httpsec.Endpoint {
	t.Helper()

	var sets [][]httpsec.Option

	for _, row := range coreEndpoints() {
		sets = append(sets, row.options(t, ""))
	}

	for _, row := range featureEndpoints() {
		sets = append(sets, row.options(t, ""))
	}

	sets = append(sets, endpointsReauth(t), endpointsOIDCLogin(t))

	var all []httpsec.Endpoint

	for _, opts := range sets {
		c, err := httpsec.New(opts...)
		require.NoError(t, err)

		all = append(all, c.Endpoints()...)
	}

	provider, err := bpChain(t, newOPFixture(t), true)
	require.NoError(t, err)

	return append(all, provider.Endpoints()...)
}

// TestChainEndpoints_PinsEveryOperation pins, for every operation identifier,
// the methods, default path, match kind, other-method policy, requirement,
// placing setting and declared sharing the inventory lists it with.
func TestChainEndpoints_PinsEveryOperation(t *testing.T) {
	t.Parallel()

	const (
		get  = http.MethodGet
		post = http.MethodPost
		del  = http.MethodDelete
		head = http.MethodHead
	)

	var (
		exact   = httpsec.MatchExact
		segment = httpsec.MatchSegment
		subtree = httpsec.MatchSubtree
		pass    = httpsec.OtherMethodsPassThrough
		refused = httpsec.OtherMethodsRefused

		nothing     = httpsec.RequiresNothing
		authed      = httpsec.RequiresAuthentication
		pendingMFA  = httpsec.RequiresPendingSecondFactor
		pendingEnr  = httpsec.RequiresPendingEnrolment
		signedIn    = httpsec.RequiresSession
		bearer      = httpsec.RequiresBearer
		clientAuthn = httpsec.RequiresClientAuthentication
	)

	m := func(methods ...string) []string { return methods }

	const opPrefix = "WithOIDCProviderPrefix"

	type testCase struct {
		id      string
		literal string // the identifier as documented, so a changed constant is noticed
		assert  func(t *testing.T, e httpsec.Endpoint, listed bool)
	}

	cases := []testCase{
		{httpsec.OperationSignInPassword, "scrty.sign-in.password", pinned(m(post), "/sign-in/password", exact, pass, nothing, "WithLoginRequestPath", "")},
		{httpsec.OperationSignInMagicLinkRequest, "scrty.sign-in.magic-link.request", pinned(m(post), "/sign-in/magic-link", exact, pass, nothing, "WithMagicLinkRequestPath", "")},
		{httpsec.OperationSignInMagicLinkRedeem, "scrty.sign-in.magic-link.redeem", pinned(m(post), "/sign-in/magic-link/redeem", exact, pass, nothing, "WithMagicLinkConsumePath", "")},
		{httpsec.OperationSignInPasskeyBegin, "scrty.sign-in.passkey.begin", pinned(m(post), "/sign-in/passkey/begin", exact, pass, nothing, "WithPasskeyPasswordlessPrefix", "")},
		{httpsec.OperationSignInPasskeyFinish, "scrty.sign-in.passkey.finish", pinned(m(post), "/sign-in/passkey/finish", exact, pass, nothing, "WithPasskeyPasswordlessPrefix", "")},
		{httpsec.OperationSignOut, "scrty.sign-out", pinned(m(post), "/sign-out", exact, pass, authed, "WithLogoutRequestPath", "")},

		{httpsec.OperationSSOLogin, "scrty.sso.login", pinned(m(get), "/sso/login/{provider}", segment, pass, nothing, "WithOIDCAuthorizePath", "")},
		{httpsec.OperationSSOCallback, "scrty.sso.callback", pinned(m(get), "/sso/callback/{provider}", segment, pass, nothing, "WithOIDCCallbackPath", "")},
		{httpsec.OperationSSOHandoff, "scrty.sso.handoff", pinned(m(post), "/sso/handoff", exact, pass, nothing, "WithOIDCHandoffPath", "")},
		{httpsec.OperationSSOBackchannelLogout, "scrty.sso.backchannel-logout", pinned(m(post), "/sso/backchannel-logout/{provider}", segment, pass, nothing, "WithOIDCBackchannelLogoutPath", "")},

		{httpsec.OperationSessionRenewal, "scrty.session.renewal", pinned(m(post), "/session/renewal", exact, pass, signedIn, "WithRenewalPath", "")},
		{httpsec.OperationSessionSignals, "scrty.session.signals", pinned(m(get), "/session/signals", exact, refused, signedIn, "SessionSignals.Path", "")},
		{httpsec.OperationSessionsList, "scrty.sessions.list", pinned(m(get), "/sessions", exact, pass, signedIn, "WithSessionManagementPrefix", "scrty.sessions")},
		{httpsec.OperationSessionsEndOthers, "scrty.sessions.end-others", pinned(m(del), "/sessions", exact, pass, signedIn, "WithSessionManagementPrefix", "scrty.sessions")},
		{httpsec.OperationSessionsEnd, "scrty.sessions.end", pinned(m(del), "/sessions/{handle}", segment, pass, signedIn, "WithSessionManagementPrefix", "scrty.sessions")},
		{httpsec.OperationPasswordChange, "scrty.password.change", pinned(m(post), "/account/password", exact, pass, signedIn, "WithPasswordChangeEndpoint", "")},

		{httpsec.OperationMFAChallenge, "scrty.mfa.challenge", pinned(m(post), "/mfa/challenge/{method}", subtree, pass, pendingMFA, "WithMFABeginPrefix", "")},
		{httpsec.OperationMFAVerify, "scrty.mfa.verify", pinned(m(post), "/mfa/verify/{method}", subtree, pass, pendingMFA, "WithMFAVerifyPrefix", "")},
		{httpsec.OperationMFAMethods, "scrty.mfa.methods", pinned(m(get), "/mfa/methods", exact, pass, pendingMFA, "WithMFAMethodListing", "")},
		{httpsec.OperationMFAEnrolmentBegin, "scrty.mfa.enrolment.begin", pinned(m(post), "/mfa/enrol/begin/{method}", subtree, pass, pendingEnr, "WithEnrolmentBeginPrefix", "")},
		{httpsec.OperationMFAEnrolmentConfirm, "scrty.mfa.enrolment.confirm", pinned(m(post), "/mfa/enrol/confirm/{method}", subtree, pass, pendingEnr, "WithEnrolmentConfirmPrefix", "")},
		{httpsec.OperationMFAEnrolmentConfirmEmail, "scrty.mfa.enrolment.confirm-email", pinned(m(post), "/mfa/enrol/confirm-email/{method}", subtree, pass, pendingEnr, "WithEnrolmentEmailConfirmPrefix", "")},

		{httpsec.OperationPasskeysRegisterBegin, "scrty.passkeys.register.begin", pinned(m(post), "/passkeys/register/begin", exact, pass, signedIn, "WithPasskeyRegistrationPrefix", "")},
		{httpsec.OperationPasskeysRegisterFinish, "scrty.passkeys.register.finish", pinned(m(post), "/passkeys/register/finish", exact, pass, signedIn, "WithPasskeyRegistrationPrefix", "")},
		{httpsec.OperationPasskeysRegisterConfirm, "scrty.passkeys.register.confirm", pinned(m(post), "/passkeys/register/confirm", exact, pass, signedIn, "WithPasskeyRegistrationPrefix", "")},
		{httpsec.OperationPasskeysRegisterConfirmEmail, "scrty.passkeys.register.confirm-email", pinned(m(post), "/passkeys/register/confirm-email", exact, pass, signedIn, "WithPasskeyRegistrationPrefix", "")},
		{httpsec.OperationPasskeysList, "scrty.passkeys.list", pinned(m(get), "/passkeys", exact, pass, signedIn, "WithPasskeyCredentialsPrefix", "")},
		{httpsec.OperationPasskeysRename, "scrty.passkeys.rename", pinned(m(post), "/passkeys/rename", exact, pass, signedIn, "WithPasskeyCredentialsPrefix", "")},
		{httpsec.OperationPasskeysRemove, "scrty.passkeys.remove", pinned(m(post), "/passkeys/remove", exact, pass, signedIn, "WithPasskeyCredentialsPrefix", "")},

		{httpsec.OperationRecoveryComplete, "scrty.recovery.complete", pinned(m(post), "/recovery/complete", exact, pass, nothing, "WithRecoveryCompletePath", "")},
		{httpsec.OperationRecoveryStart, "scrty.recovery.start", pinned(m(post), "/recovery/start", exact, pass, nothing, "WithRecoveryStartPath", "")},
		{httpsec.OperationRecoveryFinish, "scrty.recovery.finish", pinned(m(post), "/recovery/finish", exact, pass, nothing, "WithRecoveryFinishPath", "")},
		{httpsec.OperationRecoveryCancel, "scrty.recovery.cancel", pinned(m(post), "/recovery/cancel", exact, pass, nothing, "WithRecoveryCancelPath", "")},
		{httpsec.OperationRecoveryCodesCount, "scrty.recovery.codes.count", pinned(m(get), "/recovery/codes", exact, pass, signedIn, "WithRecoveryCodesPath", "scrty.recovery.codes")},
		{httpsec.OperationRecoveryCodesRegenerate, "scrty.recovery.codes.regenerate", pinned(m(post), "/recovery/codes", exact, pass, signedIn, "WithRecoveryCodesPath", "scrty.recovery.codes")},

		{httpsec.OperationReauthMethods, "scrty.reauth.methods", pinned(m(get), "/reauth/methods", exact, pass, signedIn, "WithReauthenticationPrefix", "")},
		{httpsec.OperationReauthChallenge, "scrty.reauth.challenge", pinned(m(post), "/reauth/challenge/{method}", subtree, pass, signedIn, "WithReauthenticationPrefix", "")},
		{httpsec.OperationReauthVerify, "scrty.reauth.verify", pinned(m(post), "/reauth/verify/{method}", subtree, pass, signedIn, "WithReauthenticationPrefix", "")},
		{httpsec.OperationReauthPassword, "scrty.reauth.password", pinned(m(post), "/reauth/password", exact, pass, signedIn, "WithReauthenticationPrefix", "")},

		{httpsec.OperationKeySet, "scrty.key-set", pinned(m(get), "/.well-known/jwks.json", exact, pass, nothing, "WithJWKSEndpointPath", "")},

		{httpsec.OperationOAuth2Authorize, "scrty.oauth2.authorize", pinned(m(get, post), "/auth/oauth2/authorize", exact, refused, nothing, opPrefix, "")},
		{httpsec.OperationOAuth2AuthorizeResume, "scrty.oauth2.authorize.resume", pinned(m(post), "/auth/oauth2/authorize/resume", exact, refused, signedIn, opPrefix, "")},
		{httpsec.OperationOAuth2Token, "scrty.oauth2.token", pinned(m(post), "/auth/oauth2/token", exact, refused, clientAuthn, opPrefix, "")},
		{httpsec.OperationOAuth2UserInfo, "scrty.oauth2.userinfo", pinned(m(get, post), "/auth/oauth2/userinfo", exact, refused, bearer, opPrefix, "")},
		{httpsec.OperationOAuth2Revoke, "scrty.oauth2.revoke", pinned(m(post), "/auth/oauth2/revoke", exact, refused, clientAuthn, opPrefix, "")},
		{httpsec.OperationOAuth2Introspect, "scrty.oauth2.introspect", pinned(m(post), "/auth/oauth2/introspect", exact, refused, clientAuthn, opPrefix, "")},
		{httpsec.OperationOAuth2EndSession, "scrty.oauth2.end-session", pinned(m(get, post), "/auth/oauth2/logout", exact, refused, nothing, opPrefix, "")},
		{httpsec.OperationOAuth2EndSessionConfirm, "scrty.oauth2.end-session.confirm", pinned(m(post), "/auth/oauth2/logout/confirm", exact, refused, nothing, opPrefix, "")},
		{httpsec.OperationOAuth2ConsentsList, "scrty.oauth2.consents.list", pinned(m(get), "/auth/oauth2/consents", exact, refused, signedIn, opPrefix, "scrty.oauth2.consents")},
		{httpsec.OperationOAuth2ConsentsRevoke, "scrty.oauth2.consents.revoke", pinned(m(del), "/auth/oauth2/consents/{client}", segment, refused, signedIn, opPrefix, "scrty.oauth2.consents")},
		{httpsec.OperationOAuth2OpenIDConfiguration, "scrty.oauth2.openid-configuration", pinned(m(get, head), "/auth/.well-known/openid-configuration", exact, refused, nothing, "EnableOIDCProvider", "")},
		{httpsec.OperationOAuth2AuthorizationServerMetadata, "scrty.oauth2.authorization-server-metadata", pinned(m(get, head), "/.well-known/oauth-authorization-server/auth", exact, refused, nothing, "EnableOIDCProvider", "")},
	}

	all := everyBuiltInEndpoint(t)

	t.Run("no operation goes unpinned", func(t *testing.T) {
		t.Parallel()

		pinnedIDs := make([]string, 0, len(cases))
		for _, tc := range cases {
			pinnedIDs = append(pinnedIDs, tc.id)
		}

		for _, id := range operationIDs(all) {
			assert.Contains(t, pinnedIDs, id, "listed but not pinned")
		}
	})

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.literal, tc.id, "the identifier's documented string")

			e, listed := findEndpoint(all, tc.id)
			tc.assert(t, e, listed)
		})
	}
}

// TestNew_RefusesAKeySetEnabledTwice pins that a built-in enabled twice on
// different paths, so one operation would be listed twice, fails New and names
// both paths.
func TestNew_RefusesAKeySetEnabledTwice(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) (*httpsec.Chain, error)
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	keys := func(t *testing.T, path string) httpsec.Option {
		t.Helper()

		return httpsec.EnableJWKSEndpoint(NewMockKeySetProvider(gomock.NewController(t)),
			httpsec.WithJWKSEndpointPath(path))
	}

	cases := []testCase{
		{
			name: "two key sets on different paths",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(keys(t, "/.well-known/jwks.json"), keys(t, "/keys"))
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithJWKSEndpointPath")
				assert.Contains(t, err.Error(), `"/.well-known/jwks.json"`)
				assert.Contains(t, err.Error(), `"/keys"`)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := tc.build(t)
			tc.assert(t, c, err)
		})
	}
}
