package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// A required-but-unenrolled user redeeming a handoff that carries no
// assurance, under the default classification, is refused with enrolment
// required, keeps the code, and gets no session.
func TestOIDCRedeem_RequiredUserWithoutAssuranceIsRefused(t *testing.T) {
	t.Parallel()

	h := newOIDCHarness(t)
	h.issueTokens()
	h.chainOpts = []httpsec.Option{
		httpsec.WithPolicyEngine(oidcMFAEngine(t, false, func() bool { return false })),
		enableMFAFor(t),
	}

	c := h.chain(t)
	code := h.issueHandoff(t, "")

	out := serve(t, c, handoffRequest(t.Context(), oidcTestSource, code))

	require.ErrorIs(t, out.err, policy.ErrMFAEnrollmentRequired)
	require.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
	require.Zero(t, h.activeSessions(t), "no session may be created")

	again := serve(t, c, handoffRequest(t.Context(), oidcAnotherSource, code))
	require.ErrorIs(t, again.err, policy.ErrMFAEnrollmentRequired, "the code was not consumed")
}

// The values the assurance cases sign in with.
const (
	assuranceACR      = "urn:corp:loa:2"
	assuranceGoodCode = "246810"
	assuranceUsername = "ada@example.com"
)

var (
	errAssuranceLookupDown    = errors.New("oidc_assurance_test: the enrolment store is down")
	errAssuranceEvaluatorDown = errors.New("oidc_assurance_test: the assurance evaluator is down")
)

// assuranceConfig is how a case wires its assurance deployment beside the
// defaults: the real OIDC manager matching its default configuration, the
// requirement policy in its default mode, and the library's own redeemer.
type assuranceConfig struct {
	// managerOpts configure the OIDC manager; d is the deployment being built,
	// whose switches an option may read.
	managerOpts func(t *testing.T, d *assuranceDeployment) []oidc.ManagerOption

	// requirementOpts configure the requirement policy beside the
	// requirement for all and the assurance source.
	requirementOpts []policy.MFARequirementOption

	// oidcOpts configure OIDC login beside the harness's required wiring.
	oidcOpts func(t *testing.T, d *assuranceDeployment) []httpsec.OIDCOption
}

// assuranceDeployment is a federated-login chain wired the way a consumer
// wires provider assurance: the real MFA policies over one second-factor
// method, MFA required for all, the OIDC manager as the assurance source,
// bearer tokens and the verify endpoint, in one chain.
//
// The source is the manager held in current, behind a generated double that
// delegates to it, so a case can tighten the provider's configuration or
// remove the provider while a session is live, as an operator would by
// rebuilding the manager.
type assuranceDeployment struct {
	h       *oidcHarness
	current atomic.Pointer[oidc.Manager]

	// enrolled is whether the user is enrolled on the method, and lookupDown
	// fails the method's enrolment lookup.
	enrolled   atomic.Bool
	lookupDown atomic.Bool

	// evaluatorDown fails the consumer evaluator a case wires.
	evaluatorDown atomic.Bool

	chain *httpsec.Chain
}

func newAssuranceDeployment(t *testing.T, cfg assuranceConfig) *assuranceDeployment {
	t.Helper()

	d := &assuranceDeployment{}

	var managerOpts []oidc.ManagerOption
	if cfg.managerOpts != nil {
		managerOpts = cfg.managerOpts(t, d)
	}

	d.h = newOIDCHarness(t, managerOpts...)
	d.current.Store(d.h.manager)

	ctrl := gomock.NewController(t)

	src := NewMockFederatedAssuranceSource(ctrl)
	src.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, user identity.UserID, ev policy.FederatedAssurance) (bool, error) {
			return d.current.Load().MeetsAssurance(ctx, user, ev)
		})

	method := NewMockMethod(ctrl)
	method.EXPECT().Name().Return("totp").AnyTimes()
	method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
	method.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
	method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (bool, error) {
			if d.lookupDown.Load() {
				return false, errAssuranceLookupDown
			}

			return d.enrolled.Load(), nil
		})
	method.EXPECT().Verify(gomock.Any(), oidcTestUserID, gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, _ identity.UserID, response []byte) error {
			if string(response) != assuranceGoodCode {
				return errors.New("oidc_assurance_test: wrong code")
			}

			return nil
		})

	lookups, err := mfa.LookupsFor(method)
	require.NoError(t, err)

	challenge, err := policy.NewMFAPolicy(lookups)
	require.NoError(t, err)

	requirement, err := policy.NewMFARequirementPolicy(nil, lookups, append([]policy.MFARequirementOption{
		policy.WithMFARequiredForAll(),
		policy.WithFederatedAssuranceSource(src),
	}, cfg.requirementOpts...)...)
	require.NoError(t, err)

	// Tokens name the session they were issued for, and verify back to it,
	// as a real generator does through the jti.
	d.h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			d.h.issued.Add(1)

			return mfaTokenFor(id), nil
		})
	d.h.tokens.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, presented string) (*token.Claims, error) {
			id, ok := strings.CutPrefix(presented, mfaTokenPrefix)
			if !ok {
				return nil, errMFATokenUnreadable
			}

			return token.NewClaims(assuranceUsername, id), nil
		})

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUsername(gomock.Any(), assuranceUsername).AnyTimes().
		Return(&identity.Details{ID: oidcTestUserID, Username: assuranceUsername, Active: true}, nil)

	d.h.chainOpts = []httpsec.Option{
		httpsec.WithPolicyEngine(engineOf(t, challenge, requirement)),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: d.h.tokens, Sessions: d.h.sessions, Users: users,
		}),
		httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(d.h.tokens)),
	}

	var oidcOpts []httpsec.OIDCOption
	if cfg.oidcOpts != nil {
		oidcOpts = cfg.oidcOpts(t, d)
	}

	d.chain = d.h.chain(t, oidcOpts...)

	return d
}

// issue issues a handoff code for the linked user, as a genuine callback
// whose verified ID token asserted amr and acr would.
func (d *assuranceDeployment) issue(t *testing.T, amr []string, acr string) string {
	t.Helper()

	res := d.h.handoffResult()
	res.AMR, res.ACR = amr, acr

	return d.h.issueHandoffFor(t, res)
}

// redeem posts code to the redemption endpoint from source.
func (d *assuranceDeployment) redeem(t *testing.T, source, code string) served {
	t.Helper()

	return serve(t, d.chain, handoffRequest(t.Context(), source, code))
}

// invoices requests a protected route with credential.
func (d *assuranceDeployment) invoices(t *testing.T, credential string) served {
	t.Helper()

	req := getFrom(t.Context(), "/invoices", oidcTestSource)
	req.Header.Set("Authorization", "Bearer "+credential)

	return serve(t, d.chain, req)
}

// verify answers the MFA challenge of credential's session with the good
// code, and returns the credential the verification rotated to.
func (d *assuranceDeployment) verify(t *testing.T, credential string) string {
	t.Helper()

	req := postValues(t.Context(), testMFAVerifyPath, oidcTestSource, url.Values{"code": {assuranceGoodCode}})
	req.Header.Set("Authorization", "Bearer "+credential)

	out := serve(t, d.chain, req)
	require.NoError(t, out.err)
	require.Equal(t, http.StatusOK, out.rec.Code)

	rotated := accessTokenFrom(t, out)
	require.NotEqual(t, credential, rotated)

	return rotated
}

// sessionOf loads the session credential was issued for.
func (d *assuranceDeployment) sessionOf(t *testing.T, credential string) *session.Session {
	t.Helper()

	id, ok := strings.CutPrefix(credential, mfaTokenPrefix)
	require.True(t, ok, "a credential this deployment issued")

	s, err := d.h.sessions.Load(t.Context(), id)
	require.NoError(t, err)

	return s
}

// tighten replaces the manager the source matches against with one whose
// provider accepts only amr, as an operator tightening its configuration
// would.
func (d *assuranceDeployment) tighten(t *testing.T, amr ...string) {
	t.Helper()

	d.current.Store(d.h.managerWith(t, NewMockIdentityBroker(gomock.NewController(t)), nil,
		oidc.WithProviderAssurance(testOIDCProvider, oidc.Assurance{AcceptedAMR: amr})))
}

// removeProvider replaces the manager the source matches against with one
// that no longer registers the provider the sessions came from.
func (d *assuranceDeployment) removeProvider(t *testing.T) {
	t.Helper()

	d.current.Store(d.h.managerWith(t, NewMockIdentityBroker(gomock.NewController(t)),
		func(p *oidc.Provider) { p.Name = "elsewhere" }))
}

// loggedIn asserts out is a redemption that completed without a challenge,
// and returns the credential it issued.
func loggedIn(t *testing.T, out served) string {
	t.Helper()

	require.NoError(t, out.err)

	var doc struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.AccessToken)

	return doc.AccessToken
}

// TestOIDCRedeemAssurance pins what a handoff redemption does with the
// assurance the code's record carries: it reaches the policy as evidence the
// library minted, is recorded on the session without marking the second
// factor, and cannot be widened by the request or by a replaced redeemer.
func TestOIDCRedeemAssurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		cfg  assuranceConfig

		// amr and acr are what the code's record carries.
		amr []string
		acr string

		// enrolled is whether the user is enrolled on the method.
		enrolled bool

		// act redeems the code; nil means one redemption from oidcTestSource.
		act func(t *testing.T, d *assuranceDeployment, code string) served

		assert func(t *testing.T, d *assuranceDeployment, code string, out served)
	}

	// changing is a consumer redeemer that redeems through the library and
	// then changes the result's assurance by edit.
	changing := func(edit func(res *oidc.HandoffResult)) func(t *testing.T, d *assuranceDeployment) []httpsec.OIDCOption {
		return func(t *testing.T, d *assuranceDeployment) []httpsec.OIDCOption {
			r := NewMockHandoffRedeemer(gomock.NewController(t))
			r.EXPECT().Redeem(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(ctx context.Context, code string, checks ...oidc.RedeemCheck) (oidc.HandoffResult, error) {
					res, err := d.h.handoffs.Redeem(ctx, code, checks...)
					if err == nil {
						edit(&res)
					}

					return res, err
				})

			return []httpsec.OIDCOption{httpsec.WithHandoffRedeemer(r)}
		}
	}

	// refusedByGuard is a redemption the endpoint refused after a redeemer
	// reported success: the policy-denied error, and nothing created.
	refusedByGuard := func(t *testing.T, d *assuranceDeployment, _ string, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, policy.ErrPolicyDenied)
		assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
		assert.Zero(t, d.h.activeSessions(t), "no session is created")
		assert.Zero(t, d.h.issued.Load(), "and no token is issued")
	}

	cases := []testCase{
		{
			name: "met assurance completes a required, unenrolled user's login without a challenge",
			amr:  []string{"mfa"},
			acr:  assuranceACR,
			assert: func(t *testing.T, d *assuranceDeployment, _ string, out served) {
				credential := loggedIn(t, out)

				s := d.sessionOf(t, credential)
				assert.Equal(t, factor.OIDC, s.FirstFactor)
				assert.Equal(t, []string{"mfa"}, s.FederatedAMR, "the session carries the asserted amr")
				assert.Equal(t, assuranceACR, s.FederatedACR, "and the asserted acr")
				assert.Equal(t, session.MFANone, s.MFA, "provider assurance never marks the second factor")
				assert.False(t, s.MFAAtFirstFactor, "nor the met-at-first-factor marker")
			},
		},
		{
			name:     "unmet assurance for an enrolled user redeems into the MFA challenge",
			enrolled: true,
			assert: func(t *testing.T, d *assuranceDeployment, code string, out served) {
				ch := challengedFor(t, out, policy.ChallengeMFA)
				require.NotEmpty(t, ch)

				s := d.sessionOf(t, ch)
				assert.Equal(t, session.MFAPending, s.MFA)
				assert.Empty(t, s.FederatedAMR)
				assert.Equal(t, 1, d.h.activeSessions(t))

				again := d.redeem(t, oidcAnotherSource, code)
				require.ErrorIs(t, again.err, oidc.ErrInvalidHandoff, "the code was consumed")
			},
		},
		{
			name:     "a policy lookup failure does not spend the code",
			enrolled: true,
			act: func(t *testing.T, d *assuranceDeployment, code string) served {
				d.lookupDown.Store(true)

				first := d.redeem(t, oidcTestSource, code)
				require.ErrorIs(t, first.err, errAssuranceLookupDown)
				require.Zero(t, d.h.activeSessions(t), "the refused redemption creates no session")

				d.lookupDown.Store(false)

				return d.redeem(t, oidcAnotherSource, code)
			},
			assert: func(t *testing.T, d *assuranceDeployment, _ string, out served) {
				challengedFor(t, out, policy.ChallengeMFA)
				assert.Equal(t, 1, d.h.activeSessions(t), "the second redemption completes")
			},
		},
		{
			name: "assurance presented with the redemption is ignored",
			act: func(t *testing.T, d *assuranceDeployment, code string) served {
				target := httpsec.DefaultOIDCHandoffPath + "?" +
					url.Values{"amr": {"mfa"}, "acr": {assuranceACR}}.Encode()

				return serve(t, d.chain, postValues(t.Context(), target, oidcTestSource, url.Values{
					httpsec.DefaultOIDCHandoffParam: {code},
					"amr":                           {"mfa"},
					"acr":                           {assuranceACR},
				}))
			},
			assert: func(t *testing.T, d *assuranceDeployment, code string, out served) {
				require.ErrorIs(t, out.err, policy.ErrMFAEnrollmentRequired,
					"decided as the record's absent assurance")
				assert.Zero(t, d.h.activeSessions(t))
				requireRedeemable(t, d.h, code)
			},
		},
		{
			name: "an evaluator failure denies and does not spend the code",
			cfg: assuranceConfig{
				managerOpts: func(t *testing.T, d *assuranceDeployment) []oidc.ManagerOption {
					e := NewMockAssuranceEvaluator(gomock.NewController(t))
					e.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any()).AnyTimes().
						DoAndReturn(func(context.Context, oidc.AssuranceInput) (bool, error) {
							if d.evaluatorDown.Load() {
								return false, errAssuranceEvaluatorDown
							}

							return true, nil
						})

					return []oidc.ManagerOption{oidc.WithAssuranceEvaluator(e)}
				},
			},
			amr: []string{"mfa"},
			act: func(t *testing.T, d *assuranceDeployment, code string) served {
				d.evaluatorDown.Store(true)

				first := d.redeem(t, oidcTestSource, code)
				require.ErrorIs(t, first.err, errAssuranceEvaluatorDown, "refused with the evaluator's error")
				require.Zero(t, d.h.activeSessions(t))

				d.evaluatorDown.Store(false)

				return d.redeem(t, oidcAnotherSource, code)
			},
			assert: func(t *testing.T, _ *assuranceDeployment, _ string, out served) {
				loggedIn(t, out)
			},
		},
		{
			name:     "refuse mode keeps the code and counts the refusal against the source",
			cfg:      assuranceConfig{requirementOpts: []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceRefuse)}},
			enrolled: true,
			act: func(t *testing.T, d *assuranceDeployment, code string) served {
				for range 10 {
					out := d.redeem(t, oidcTestSource, code)
					require.ErrorIs(t, out.err, policy.ErrFederatedAssuranceNotMet)
					require.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				}

				return d.redeem(t, oidcTestSource, code)
			},
			assert: func(t *testing.T, d *assuranceDeployment, code string, out served) {
				require.ErrorIs(t, out.err, oidc.ErrInvalidHandoff, "the eleventh is throttled")
				assert.Zero(t, d.h.activeSessions(t))
				requireRedeemable(t, d.h, code)
			},
		},
		{
			name:     "a replaced redeemer naming an amr the check never saw is refused",
			cfg:      assuranceConfig{oidcOpts: changing(func(res *oidc.HandoffResult) { res.AMR = []string{"mfa"} })},
			enrolled: true,
			assert:   refusedByGuard,
		},
		{
			name:     "a replaced redeemer naming an acr the check never saw is refused",
			cfg:      assuranceConfig{oidcOpts: changing(func(res *oidc.HandoffResult) { res.ACR = assuranceACR })},
			amr:      []string{"pwd"},
			enrolled: true,
			assert:   refusedByGuard,
		},
		{
			name:     "a replaced redeemer dropping the asserted amr is refused",
			cfg:      assuranceConfig{oidcOpts: changing(func(res *oidc.HandoffResult) { res.AMR = nil })},
			amr:      []string{"pwd"},
			enrolled: true,
			assert:   refusedByGuard,
		},
		{
			name:     "a replaced redeemer naming a provider the check never saw is refused",
			cfg:      assuranceConfig{oidcOpts: changing(func(res *oidc.HandoffResult) { res.Provider = "elsewhere" })},
			amr:      []string{"mfa"},
			enrolled: true,
			assert:   refusedByGuard,
		},
		{
			name:     "a replaced redeemer naming an issuer the check never saw is refused",
			cfg:      assuranceConfig{oidcOpts: changing(func(res *oidc.HandoffResult) { res.Issuer = "https://elsewhere.example" })},
			amr:      []string{"mfa"},
			enrolled: true,
			assert:   refusedByGuard,
		},
		{
			name: "a replaced redeemer returning the assurance the check saw completes",
			cfg:  assuranceConfig{oidcOpts: changing(func(*oidc.HandoffResult) {})},
			amr:  []string{"mfa"},
			acr:  assuranceACR,
			assert: func(t *testing.T, d *assuranceDeployment, _ string, out served) {
				s := d.sessionOf(t, loggedIn(t, out))
				assert.Equal(t, []string{"mfa"}, s.FederatedAMR)
				assert.Equal(t, assuranceACR, s.FederatedACR)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newAssuranceDeployment(t, tc.cfg)
			d.enrolled.Store(tc.enrolled)

			code := d.issue(t, tc.amr, tc.acr)

			var out served
			if tc.act != nil {
				out = tc.act(t, d, code)
			} else {
				out = d.redeem(t, oidcTestSource, code)
			}

			tc.assert(t, d, code, out)
		})
	}
}

// TestFederatedRematch pins per-request evaluation of a federated session: the
// session's stored assurance reaches the policies as evidence on every
// request and is matched against the provider's configuration as it is now,
// not as it was at login; a session whose second factor the library verified
// is allowed whatever its stored assurance.
func TestFederatedRematch(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// amr is what the login's record carries, and enrolled whether the
		// user is enrolled on the method.
		amr      []string
		enrolled bool

		// after runs between the login and the request under test, and
		// returns the credential that request presents.
		after func(t *testing.T, d *assuranceDeployment, login served) string

		assert func(t *testing.T, d *assuranceDeployment, credential string, out served)
	}

	// reachedOnce asserts the login's credential reaches the protected route
	// once, before anything changes, and returns it.
	reachedOnce := func(t *testing.T, d *assuranceDeployment, login served) string {
		t.Helper()

		credential := loggedIn(t, login)

		first := d.invoices(t, credential)
		require.NoError(t, first.err)
		require.True(t, first.handlerRan, "the met session reaches the handler")

		return credential
	}

	reached := func(t *testing.T, _ *assuranceDeployment, _ string, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.True(t, out.handlerRan)
	}

	challenged := func(t *testing.T, _ *assuranceDeployment, _ string, out served) {
		t.Helper()

		challengedFor(t, out, policy.ChallengeMFA)
	}

	cases := []testCase{
		{
			name:     "a met session reaches the handler while the provider accepts mfa",
			amr:      []string{"mfa"},
			enrolled: true,
			after:    reachedOnce,
			assert:   reached,
		},
		{
			name:     "a tightened provider configuration challenges the live session",
			amr:      []string{"mfa"},
			enrolled: true,
			after: func(t *testing.T, d *assuranceDeployment, login served) string {
				credential := reachedOnce(t, d, login)
				d.tighten(t, "hwk")

				return credential
			},
			assert: challenged,
		},
		{
			name:     "a removed provider never matches",
			amr:      []string{"mfa"},
			enrolled: true,
			after: func(t *testing.T, d *assuranceDeployment, login served) string {
				credential := reachedOnce(t, d, login)
				d.removeProvider(t)

				return credential
			},
			assert: challenged,
		},
		{
			name: "a tightened configuration refuses an unenrolled user with enrolment required",
			amr:  []string{"mfa"},
			after: func(t *testing.T, d *assuranceDeployment, login served) string {
				credential := reachedOnce(t, d, login)
				d.tighten(t, "hwk")

				return credential
			},
			assert: func(t *testing.T, _ *assuranceDeployment, _ string, out served) {
				require.ErrorIs(t, out.err, policy.ErrMFAEnrollmentRequired)
				assert.False(t, out.handlerRan, "the stale login is not honoured")
			},
		},
		{
			name:     "a locally satisfied session is allowed whatever its stored assurance",
			amr:      []string{"pwd"},
			enrolled: true,
			after: func(t *testing.T, d *assuranceDeployment, login served) string {
				credential := d.verify(t, challengedFor(t, login, policy.ChallengeMFA))

				s := d.sessionOf(t, credential)
				assert.Equal(t, session.MFASatisfied, s.MFA)
				assert.Equal(t, []string{"pwd"}, s.FederatedAMR, "the rotated session keeps the asserted amr")

				d.removeProvider(t)

				return credential
			},
			assert: reached,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newAssuranceDeployment(t, assuranceConfig{})
			d.enrolled.Store(tc.enrolled)

			login := d.redeem(t, oidcTestSource, d.issue(t, tc.amr, ""))
			credential := tc.after(t, d, login)

			tc.assert(t, d, credential, d.invoices(t, credential))
		})
	}
}

// TestBearerPerRequestFederatedAssurance pins that the per-request phase is
// handed federated assurance evidence only for a session whose first factor is
// on the federated channel: a session of any other first factor is inert,
// whatever federated fields its record holds.
func TestBearerPerRequestFederatedAssurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		firstFactor factor.Kind
		assert      func(t *testing.T, seen *policy.Input)
	}

	cases := []testCase{
		{
			name:        "a password session carrying federated fields is inert",
			firstFactor: factor.Password,
			assert: func(t *testing.T, seen *policy.Input) {
				require.NotNil(t, seen)
				assert.False(t, seen.FederatedAssurance.Asserted(),
					"a session that did not log in through the provider carries no evidence")
			},
		},
		{
			name:        "an oidc session is handed the evidence its record holds",
			firstFactor: factor.OIDC,
			assert: func(t *testing.T, seen *policy.Input) {
				require.NotNil(t, seen)
				ev := seen.FederatedAssurance
				assert.True(t, ev.Asserted())
				assert.Equal(t, "idp", ev.Provider())
				assert.Equal(t, "https://idp.example", ev.Issuer())
				assert.Equal(t, []string{"mfa"}, ev.AMR())
				assert.Equal(t, "x", ev.ACR())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var seen *policy.Input

			recorder := NewMockPolicy(gomock.NewController(t))
			recorder.EXPECT().Name().Return("test: input recorder").AnyTimes()
			recorder.EXPECT().Phases().Return([]policy.Phase{policy.PerRequest}).AnyTimes()
			recorder.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, in *policy.Input) policy.Decision {
					seen = in

					return policy.Decision{Outcome: policy.Allow}
				})

			loaded := liveSession()
			loaded.FirstFactor = tc.firstFactor
			loaded.ExternalProvider = "idp"
			loaded.ExternalIssuer = "https://idp.example"
			loaded.FederatedAMR = []string{"mfa"}
			loaded.FederatedACR = "x"

			h := newAuthHarness(t)
			h.expectVerified()
			h.store.EXPECT().Load(gomock.Any(), testJTI).Return(loaded, nil)
			h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil)
			h.acceptsActivityWriteBack()

			s := serveBearer(t, h, engineOf(t, recorder), bearerRequest(t.Context(), "Bearer abc.def.ghi"))
			require.NoError(t, s.err)

			tc.assert(t, seen)
		})
	}
}
