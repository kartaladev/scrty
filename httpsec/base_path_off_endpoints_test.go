package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// TestBasePath_OffEndpointPathIsNotJudged pins that a path set for an endpoint
// the configuration leaves off is not judged against the base path: it moves
// nothing, so it is accepted where a feature has no refusal of its own, and
// refused by the feature's own check where it has one. The same path set for an
// endpoint that is served is refused as repeating the base, wherever the base
// path and the path option stand among the chain's options.
func TestBasePath_OffEndpointPathIsNotJudged(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// options are the chain's options; the base path is given before them
		// unless baseLast is set.
		options  func(t *testing.T) []httpsec.Option
		baseLast bool

		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	base := httpsec.WithBasePath("/auth")

	// recoveryWith enables recovery with the proofs given and the path options,
	// before or after the recovery core option, and a hold delay when held.
	type recoverySetup struct {
		proofs      []recovery.ProofKind
		held        bool
		paths       []httpsec.RecoveryOption
		pathsBefore bool
	}

	recoveryWith := func(s recoverySetup) func(t *testing.T) []httpsec.Option {
		return func(t *testing.T) []httpsec.Option {
			t.Helper()

			h := newRecoveryHarness(t)
			h.proofs = s.proofs

			if s.held {
				h.withHold()
			}

			opts := h.options(t)

			if s.pathsBefore {
				// Rebuild the recovery option with the path options ahead of
				// the core option the harness puts first.
				kind, err := recovery.MFAEnrolments(h.totp)
				require.NoError(t, err)

				core := httpsec.WithRecoveryCore(
					recovery.WithProofs(h.proofs...),
					recovery.WithRepudiationContact("Write to security@example.com if this was not you."),
					recovery.WithAuthenticatorKinds(kind),
					recovery.WithMFAMethods(h.totp),
					recovery.WithMessages(recoveryMessages{}),
					recovery.WithClock(h.clock),
				)
				opts[len(opts)-1] = httpsec.EnableAccountRecovery(h.deps(), append(slices.Clone(s.paths), core)...)

				return opts
			}

			h.recOpts = s.paths

			return h.options(t)
		}
	}

	withoutProof := func(drop recovery.ProofKind) []recovery.ProofKind {
		return slices.DeleteFunc([]recovery.ProofKind{
			recovery.ProofSaved, recovery.ProofIssued, recovery.ProofPassword, recovery.ProofMFA,
		}, func(k recovery.ProofKind) bool { return k == drop })
	}

	allProofs := []recovery.ProofKind{
		recovery.ProofSaved, recovery.ProofIssued, recovery.ProofPassword, recovery.ProofMFA,
	}

	enrolmentWith := func(opts ...httpsec.EnrolmentOption) func(t *testing.T) []httpsec.Option {
		return func(t *testing.T) []httpsec.Option {
			t.Helper()

			h := newEnrolHarness(t)
			h.enrolOpts = append(h.enrolOpts, opts...)

			// A session that has met its second factor, so the enrolment gate
			// does not confine it and a path no built-in answers reaches the
			// handler.
			return h.options(t, h.sessionIn(t, factor.Password, session.MFASatisfied))
		}
	}

	// oidcConveyed enables federated login with the consumer's own conveyance,
	// which issues no handoff code, and the OIDC options given.
	oidcConveyed := func(opts ...httpsec.OIDCOption) func(t *testing.T) []httpsec.Option {
		return func(t *testing.T) []httpsec.Option {
			t.Helper()

			flows, err := oidc.NewMemoryFlowStore()
			require.NoError(t, err)

			sessions, err := session.New()
			require.NoError(t, err)

			conveyed := httpsec.WithOIDCCallbackSuccess(func(*httpsec.Exchange, oidc.CallbackResult, string) error {
				return nil
			})

			return []httpsec.Option{httpsec.EnableOIDCLogin(
				httpsec.OIDCDeps{RelyingParty: oidcManagerAt(t, flows, "/auth"+httpsec.DefaultOIDCCallbackPath)},
				append([]httpsec.OIDCOption{
					httpsec.WithOIDCSessions(sessions),
					httpsec.WithOIDCTokens(newMockGenerator(gomock.NewController(t))),
					conveyed,
				}, opts...)...)}
		}
	}

	// accepted is a chain that builds: the path moves nothing, so no doubled
	// path is refused.
	accepted := func(t *testing.T, c *httpsec.Chain, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, c)
	}

	// passesThroughOn is accepted, and a request with each of methods to each
	// path reaches the next handler: no built-in answers there.
	passesThroughOn := func(methods []string, paths ...string) func(t *testing.T, c *httpsec.Chain, err error) {
		return func(t *testing.T, c *httpsec.Chain, err error) {
			t.Helper()
			accepted(t, c, err)

			for _, m := range methods {
				for _, p := range paths {
					req := httptest.NewRequestWithContext(t.Context(), m, p, nil)
					req.RemoteAddr = "203.0.113.7:51000"

					out := serve(t, c, req)
					assert.True(t, out.handlerRan, "%s %s passes through to the handler", m, p)
				}
			}
		}
	}

	// passesThrough is passesThroughOn for a POST, with or without the base.
	passesThrough := func(paths ...string) func(t *testing.T, c *httpsec.Chain, err error) {
		return passesThroughOn([]string{http.MethodPost}, paths...)
	}

	// repeatsBase is the base path's refusal of a served path that repeats it.
	repeatsBase := func(option string) func(t *testing.T, c *httpsec.Chain, err error) {
		return func(t *testing.T, c *httpsec.Chain, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, c)
			assert.Contains(t, err.Error(), option)
			assert.Contains(t, err.Error(), "WithBasePath")
			assert.Contains(t, err.Error(), "/auth/auth/x")
		}
	}

	cases := []testCase{
		{
			name: "recovery start path without issued codes moves nothing",
			options: recoveryWith(recoverySetup{
				proofs: withoutProof(recovery.ProofIssued),
				paths:  []httpsec.RecoveryOption{httpsec.WithRecoveryStartPath("/auth/x")},
			}),
			assert: passesThrough("/auth/auth/x", "/auth/x"),
		},
		{
			name: "recovery codes path without saved codes moves nothing",
			options: recoveryWith(recoverySetup{
				proofs: withoutProof(recovery.ProofSaved),
				paths:  []httpsec.RecoveryOption{httpsec.WithRecoveryCodesPath("/auth/x")},
			}),
			assert: passesThroughOn([]string{http.MethodGet, http.MethodPost}, "/auth/auth/x"),
		},
		{
			name: "recovery finish path with no recovery held moves nothing",
			options: recoveryWith(recoverySetup{
				proofs: allProofs,
				paths:  []httpsec.RecoveryOption{httpsec.WithRecoveryFinishPath("/auth/x")},
			}),
			assert: passesThrough("/auth/auth/x"),
		},
		{
			name: "recovery cancel path with no recovery held moves nothing",
			options: recoveryWith(recoverySetup{
				proofs: allProofs,
				paths:  []httpsec.RecoveryOption{httpsec.WithRecoveryCancelPath("/auth/x")},
			}),
			assert: passesThrough("/auth/auth/x"),
		},
		{
			name: "enrolment email confirm prefix without email confirmation moves nothing",
			options: enrolmentWith(
				httpsec.WithEnrolmentEmailConfirmPrefix("/auth/x"), httpsec.WithoutEnrolmentEmailConfirmation()),
			// A session that has met its second factor passes the enrolment gate
			// whether or not the endpoint is served, so the pass-through alone
			// proves only that New built: the inventory pins that nothing answers.
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				t.Helper()
				passesThrough("/auth/auth/x/totp")(t, c, err)

				for _, e := range c.Endpoints() {
					assert.NotEqual(t, httpsec.OperationMFAEnrolmentConfirmEmail, e.OperationID,
						"the emailed-code endpoint is listed at %q although email confirmation is off", e.Path)
				}
			},
		},
		{
			name:    "OIDC handoff path without a handoff code is refused by the OIDC login's own check",
			options: oidcConveyed(httpsec.WithOIDCHandoffPath("/auth/x")),
			assert: func(t *testing.T, _ *httpsec.Chain, err error) {
				t.Helper()
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithOIDCHandoffPath")
				assert.Contains(t, err.Error(), "issues no handoff code")
				assert.NotContains(t, err.Error(), "/auth/auth/x")
			},
		},
		{
			// The redeemer is set by an option, before wiring, so the handoff
			// path must still wait for the late pass: judged early, the doubled
			// path would be refused ahead of the OIDC login's own refusal.
			name: "OIDC handoff path with a redeemer but the consumer's conveyance is refused by the OIDC login's own check",
			options: oidcConveyed(
				httpsec.WithOIDCHandoffRedeemer(newTestHandoffManager(t)), httpsec.WithOIDCHandoffPath("/auth/x")),
			assert: func(t *testing.T, _ *httpsec.Chain, err error) {
				t.Helper()
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithOIDCCallbackSuccess")
				assert.Contains(t, err.Error(), "issues no handoff code")
				assert.NotContains(t, err.Error(), "/auth/auth/x")
			},
		},
		{
			name: "recovery start path with issued codes repeats the base",
			options: recoveryWith(recoverySetup{
				proofs: allProofs,
				paths:  []httpsec.RecoveryOption{httpsec.WithRecoveryStartPath("/auth/x")},
			}),
			assert: repeatsBase("WithRecoveryStartPath"),
		},
		{
			name: "recovery codes path with saved codes repeats the base",
			options: recoveryWith(recoverySetup{
				proofs: allProofs,
				paths:  []httpsec.RecoveryOption{httpsec.WithRecoveryCodesPath("/auth/x")},
			}),
			assert: repeatsBase("WithRecoveryCodesPath"),
		},
		{
			name: "recovery finish path with a hold delay repeats the base",
			options: recoveryWith(recoverySetup{
				proofs: allProofs,
				held:   true,
				paths:  []httpsec.RecoveryOption{httpsec.WithRecoveryFinishPath("/auth/x")},
			}),
			assert: repeatsBase("WithRecoveryFinishPath"),
		},
		{
			name: "recovery cancel path with a hold delay repeats the base",
			options: recoveryWith(recoverySetup{
				proofs: allProofs,
				held:   true,
				paths:  []httpsec.RecoveryOption{httpsec.WithRecoveryCancelPath("/auth/x")},
			}),
			assert: repeatsBase("WithRecoveryCancelPath"),
		},
		{
			name:    "enrolment email confirm prefix with email confirmation repeats the base",
			options: enrolmentWith(httpsec.WithEnrolmentEmailConfirmPrefix("/auth/x")),
			assert:  repeatsBase("WithEnrolmentEmailConfirmPrefix"),
		},
		{
			name: "OIDC handoff path with a handoff redeemer repeats the base",
			options: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return oidcLoginOptions(t, httpsec.WithOIDCHandoffPath("/auth/x"))
			},
			assert: repeatsBase("WithOIDCHandoffPath"),
		},
		{
			name: "recovery start path given before the recovery core option still repeats the base",
			options: recoveryWith(recoverySetup{
				proofs:      allProofs,
				paths:       []httpsec.RecoveryOption{httpsec.WithRecoveryStartPath("/auth/x")},
				pathsBefore: true,
			}),
			assert: repeatsBase("WithRecoveryStartPath"),
		},
		{
			name: "recovery start path with the base path given last still repeats the base",
			options: recoveryWith(recoverySetup{
				proofs: allProofs,
				paths:  []httpsec.RecoveryOption{httpsec.WithRecoveryStartPath("/auth/x")},
			}),
			baseLast: true,
			assert:   repeatsBase("WithRecoveryStartPath"),
		},
		{
			name: "recovery start path without issued codes with the base path given last moves nothing",
			options: recoveryWith(recoverySetup{
				proofs: withoutProof(recovery.ProofIssued),
				paths:  []httpsec.RecoveryOption{httpsec.WithRecoveryStartPath("/auth/x")},
			}),
			baseLast: true,
			assert:   accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opts []httpsec.Option
			if tc.baseLast {
				opts = append(tc.options(t), base)
			} else {
				opts = append([]httpsec.Option{base}, tc.options(t)...)
			}

			c, err := httpsec.New(opts...)
			tc.assert(t, c, err)
		})
	}
}

// TestBasePath_DoubledPathRefusedBeforeOtherChecks pins that a path repeating
// the base path is refused by the repeat check, which names the option that set
// it, before a feature check that reads the resolved path refuses it with
// advice that would have the consumer register or state the doubled URL.
func TestBasePath_DoubledPathRefusedBeforeOtherChecks(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T) []httpsec.Option
		assert  func(t *testing.T, c *httpsec.Chain, err error)
	}

	cases := []testCase{
		{
			// The redirect URL is registered where the consumer meant the
			// callback to answer, so the redirect check would refuse the
			// doubled callback and advise registering it.
			name: "OIDC callback path with the base in it is refused before the redirect check",
			options: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return append(
					oidcLoginRegisteredAt(t, "/auth/sso/callback/", httpsec.WithOIDCCallbackPath("/auth/sso/callback/")),
					httpsec.WithBasePath("/auth"))
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				t.Helper()
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.ErrorContains(t, err, "WithOIDCCallbackPath")
				assert.ErrorContains(t, err, `"/auth/auth/sso/callback/"`)
				assert.NotContains(t, err.Error(), "register a redirect URL")
				assert.NotContains(t, err.Error(), "WithoutOIDCRedirectPathCheck")
			},
		},
		{
			// The provider's assertion endpoint states where the consumer
			// meant the token endpoint to answer, so the assertion check would
			// refuse the doubled token path and advise stating it.
			name: "OIDC provider token path with the base in it is refused before the assertion endpoint check",
			options: func(t *testing.T) []httpsec.Option {
				t.Helper()

				f := newOPFixture(t)

				p, err := oidcprovider.New(oidcprovider.Deps{
					Issuer: bpIssuer,
					Clients: []oidcprovider.Client{{
						ID: "billing-web", Type: oidcprovider.Confidential,
						Secret:       []byte("0123456789abcdef0123456789abcdef"),
						RedirectURIs: []string{rpCallback}, Scopes: []string{"openid", "profile"},
					}},
					Keys: f.keys, Users: NewMockUserLoader(gomock.NewController(t)),
					LoginURL: bpLoginPage, ConsentURL: "https://id.example.com/consent",
					LogoutURL: "https://id.example.com/logout-page", LoggedOutURL: "https://id.example.com/bye",
				},
					oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint),
					oidcprovider.WithAssertionTokenEndpoint("https://id.example.com/auth/token"),
				)
				require.NoError(t, err)

				return append(f.wired(t, p),
					httpsec.EnableOIDCProvider(p, httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/auth/token")),
					httpsec.WithBasePath(bpBase))
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				t.Helper()
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.ErrorContains(t, err, "WithOIDCProviderPath")
				assert.ErrorContains(t, err, `"/auth/auth/token"`)
				assert.NotContains(t, err.Error(), "WithAssertionTokenEndpoint")
				assert.NotContains(t, err.Error(), "accepts assertions")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(tc.options(t)...)
			tc.assert(t, c, err)
		})
	}
}
