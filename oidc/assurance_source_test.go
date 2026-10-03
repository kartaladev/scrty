package oidc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/assurance"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/policy"
)

// TestManager_MeetsAssurance decides federated evidence through the manager
// as the MFA policies' assurance source: every scenario of "Each provider has
// an assurance configuration with a safe default" by its default matching, and
// "A consumer can replace the assurance decision" through an evaluator.
func TestManager_MeetsAssurance(t *testing.T) {
	t.Parallel()

	p := newTestProvider(t)
	issuer := p.Issuer()
	reg, err := oidc.NewRegistry(p.Provider("corp"), p.Provider("partner"))
	require.NoError(t, err)

	errEvaluator := errors.New("evaluator store down")

	// corpEv is evidence that corp, through its registered issuer, asserted
	// amr and acr.
	corpEv := func(amr []string, acr string) policy.FederatedAssurance {
		return assurance.NewFederated("corp", issuer, amr, acr)
	}
	corp := func(a oidc.Assurance) func(*testing.T, *gomock.Controller) []oidc.ManagerOption {
		return func(*testing.T, *gomock.Controller) []oidc.ManagerOption {
			return []oidc.ManagerOption{oidc.WithProviderAssurance("corp", a)}
		}
	}
	// evaluator wires a mock evaluator that expect configures.
	evaluator := func(expect func(e *MockAssuranceEvaluator)) func(*testing.T, *gomock.Controller) []oidc.ManagerOption {
		return func(_ *testing.T, ctrl *gomock.Controller) []oidc.ManagerOption {
			e := NewMockAssuranceEvaluator(ctrl)
			expect(e)
			return []oidc.ManagerOption{oidc.WithAssuranceEvaluator(e)}
		}
	}
	met := func(t *testing.T, got bool, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.True(t, got, "assurance must be met")
	}
	notMet := func(t *testing.T, got bool, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.False(t, got, "assurance must not be met")
	}

	type testCase struct {
		name   string
		opts   func(t *testing.T, ctrl *gomock.Controller) []oidc.ManagerOption
		user   identity.UserID
		ev     policy.FederatedAssurance
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, got bool, err error)
	}

	cases := []testCase{
		{name: "default accepts only mfa", ev: corpEv([]string{"pwd", "otp"}, ""), assert: notMet},
		{name: "default with mfa asserted", ev: corpEv([]string{"pwd", "mfa"}, ""), assert: met},
		{name: "default with nothing asserted", ev: corpEv(nil, ""), assert: notMet},
		{
			name: "consumer accepts an acr",
			opts: corp(oidc.Assurance{AcceptedACR: []string{"urn:corp:loa:2"}}),
			ev:   corpEv(nil, "urn:corp:loa:2"), assert: met,
		},
		{
			name: "values match exactly",
			opts: corp(oidc.Assurance{AcceptedAMR: []string{"mfa"}}),
			ev:   corpEv([]string{"MFA"}, ""), assert: notMet,
		},
		{
			name: "match all",
			opts: corp(oidc.Assurance{AcceptedAMR: []string{"mfa"}, AcceptedACR: []string{"gold"}, Match: oidc.MatchAll}),
			ev:   corpEv([]string{"mfa"}, "silver"), assert: notMet,
		},
		{
			name: "configured with nothing accepted",
			opts: corp(oidc.Assurance{}),
			ev:   corpEv([]string{"mfa"}, ""), assert: notMet,
		},
		{
			name: "provider ignores the requested acr",
			opts: corp(oidc.Assurance{AcceptedACR: []string{"urn:corp:loa:2"}, RequestACR: []string{"urn:corp:loa:2"}}),
			ev:   corpEv(nil, "urn:corp:loa:1"), assert: notMet,
		},
		{
			name: "another provider's configuration is not corp's",
			opts: corp(oidc.Assurance{AcceptedACR: []string{"gold"}}),
			ev:   assurance.NewFederated("partner", issuer, []string{"mfa"}, ""), assert: met,
		},
		{
			name: "an unregistered provider never matches",
			ev:   assurance.NewFederated("ghost", issuer, []string{"mfa"}, ""), assert: notMet,
		},
		{
			name: "an issuer other than the registered one never matches",
			ev:   assurance.NewFederated("corp", "https://evil.example", []string{"mfa"}, ""), assert: notMet,
		},
		{
			name: "evidence that asserts nothing never matches",
			ev:   policy.FederatedAssurance{}, assert: notMet,
		},
		{
			name: "the evaluator receives the user, provider, issuer and asserted values",
			user: "u-1",
			opts: evaluator(func(e *MockAssuranceEvaluator) {
				e.EXPECT().MeetsAssurance(gomock.Any(), oidc.AssuranceInput{
					User: "u-1", Provider: "corp", Issuer: issuer, AMR: []string{"pwd", "mfa"}, ACR: "gold",
				}).Return(true, nil)
			}),
			ev: corpEv([]string{"pwd", "mfa"}, "gold"), assert: met,
		},
		{
			name: "the evaluator replaces the matching: met although the default would refuse",
			user: "u-2",
			opts: evaluator(func(e *MockAssuranceEvaluator) {
				e.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any()).Return(true, nil)
			}),
			ev: corpEv([]string{"pwd"}, ""), assert: met,
		},
		{
			name: "per-user rule: u-1 is not met without hwk",
			user: "u-1",
			opts: evaluator(func(e *MockAssuranceEvaluator) {
				e.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, in oidc.AssuranceInput) (bool, error) {
						if in.User == "u-1" {
							for _, v := range in.AMR {
								if v == "hwk" {
									return true, nil
								}
							}
							return false, nil
						}
						return true, nil
					})
			}),
			ev: corpEv([]string{"mfa", "otp"}, ""), assert: notMet,
		},
		{
			name: "the evaluator's error is returned unchanged",
			user: "u-1",
			opts: evaluator(func(e *MockAssuranceEvaluator) {
				e.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any()).Return(true, errEvaluator)
			}),
			ev: corpEv([]string{"mfa"}, ""),
			assert: func(t *testing.T, got bool, err error) {
				require.ErrorIs(t, err, errEvaluator)
				assert.Same(t, errEvaluator, err, "the evaluator's error is not wrapped")
				assert.False(t, got, "an error is never met")
			},
		},
		{
			name: "the evaluator is handed the caller's context",
			user: "u-1",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, evaluatorCtxKey{}, "marker")
			},
			opts: evaluator(func(e *MockAssuranceEvaluator) {
				e.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ oidc.AssuranceInput) (bool, error) {
						return ctx.Value(evaluatorCtxKey{}) == "marker", nil
					})
			}),
			ev: corpEv([]string{"mfa"}, ""), assert: met,
		},
		{
			name: "evidence that asserts nothing is not met and the evaluator is not asked",
			user: "u-1",
			opts: evaluator(func(e *MockAssuranceEvaluator) {
				e.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any()).Times(0)
			}),
			ev: policy.FederatedAssurance{}, assert: notMet,
		},
		{
			name: "an unregistered provider is not met and the evaluator is not asked",
			user: "u-1",
			opts: evaluator(func(e *MockAssuranceEvaluator) {
				e.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any()).Times(0)
			}),
			ev: assurance.NewFederated("ghost", issuer, []string{"mfa"}, ""), assert: notMet,
		},
		{
			name: "an issuer other than the registered one is not met and the evaluator is not asked",
			user: "u-1",
			opts: evaluator(func(e *MockAssuranceEvaluator) {
				e.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any()).Times(0)
			}),
			ev: assurance.NewFederated("corp", "https://evil.example", []string{"mfa"}, ""), assert: notMet,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			opts := []oidc.ManagerOption{oidc.WithOutboundClient(p.Outbound(t))}
			if tc.opts != nil {
				opts = append(opts, tc.opts(t, ctrl)...)
			}
			m, err := oidc.NewManager(reg, stubBroker{}, opts...)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			var src policy.FederatedAssuranceSource = m
			got, err := src.MeetsAssurance(ctx, tc.user, tc.ev)
			tc.assert(t, got, err)
		})
	}
}

// evaluatorCtxKey marks the context a row hands MeetsAssurance.
type evaluatorCtxKey struct{}
