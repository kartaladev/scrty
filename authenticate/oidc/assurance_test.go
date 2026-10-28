package oidc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/assurance"
	"github.com/kartaladev/scrty/policy"
)

// assuranceManager builds a manager for providers corp and partner with the
// given options, sending no request.
func assuranceManager(t *testing.T, opts ...oidc.Option) *oidc.RelyingParty {
	t.Helper()

	p := newTestProvider(t)
	reg, err := oidc.NewRegistry(p.Provider("corp"), p.Provider("partner"))
	require.NoError(t, err)
	m, err := oidc.NewRelyingParty(reg, stubBroker{}, append([]oidc.Option{oidc.WithOutboundClient(p.Outbound(t))}, opts...)...)
	require.NoError(t, err)
	return m
}

// TestMatchAssurance decides the asserted values of a verified login against
// corp's resolved configuration, one row per scenario of the requirement
// "Each provider has an assurance configuration with a safe default".
func TestMatchAssurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []oidc.Option
		amr    []string
		acr    string
		assert func(t *testing.T, met bool)
	}

	met := func(t *testing.T, got bool) { t.Helper(); assert.True(t, got, "assurance must be met") }
	notMet := func(t *testing.T, got bool) { t.Helper(); assert.False(t, got, "assurance must not be met") }
	corp := func(a oidc.Assurance) []oidc.Option {
		return []oidc.Option{oidc.WithProviderAssurance("corp", a)}
	}

	cases := []testCase{
		{name: "default does not accept single-method values", amr: []string{"pwd", "otp"}, assert: notMet},
		{name: "default accepts mfa", amr: []string{"pwd", "mfa"}, assert: met},
		{name: "default with nothing asserted", assert: notMet},
		{name: "default ignores an asserted acr", acr: "urn:corp:loa:2", assert: notMet},
		{
			name: "a consumer accepts an acr and no amr",
			opts: corp(oidc.Assurance{AcceptedACR: []string{"urn:corp:loa:2"}}),
			acr:  "urn:corp:loa:2", assert: met,
		},
		{
			name: "configuring replaces the whole default, so mfa is no longer accepted",
			opts: corp(oidc.Assurance{AcceptedACR: []string{"urn:corp:loa:2"}}),
			amr:  []string{"mfa"}, assert: notMet,
		},
		{
			name: "values match exactly and case-sensitively",
			opts: corp(oidc.Assurance{AcceptedAMR: []string{"mfa"}}),
			amr:  []string{"MFA"}, assert: notMet,
		},
		{
			name: "acr values match exactly",
			opts: corp(oidc.Assurance{AcceptedACR: []string{"gold"}}),
			acr:  "Gold", assert: notMet,
		},
		{
			name: "match any holds on either criterion",
			opts: corp(oidc.Assurance{AcceptedAMR: []string{"mfa"}, AcceptedACR: []string{"gold"}}),
			amr:  []string{"pwd"}, acr: "gold", assert: met,
		},
		{
			name: "match all refuses when one criterion fails",
			opts: corp(oidc.Assurance{AcceptedAMR: []string{"mfa"}, AcceptedACR: []string{"gold"}, Match: oidc.AssuranceMatchAll}),
			amr:  []string{"mfa"}, acr: "silver", assert: notMet,
		},
		{
			name: "match all holds when every criterion holds",
			opts: corp(oidc.Assurance{AcceptedAMR: []string{"mfa"}, AcceptedACR: []string{"gold"}, Match: oidc.AssuranceMatchAll}),
			amr:  []string{"pwd", "mfa"}, acr: "gold", assert: met,
		},
		{
			name: "match all skips a criterion with no accepted values",
			opts: corp(oidc.Assurance{AcceptedAMR: []string{"mfa"}, Match: oidc.AssuranceMatchAll}),
			amr:  []string{"mfa"}, assert: met,
		},
		{
			name: "configured with nothing accepted never meets assurance",
			opts: corp(oidc.Assurance{AcceptedAMR: []string{}, AcceptedACR: []string{}}),
			amr:  []string{"mfa"}, acr: "gold", assert: notMet,
		},
		{
			name: "match all with nothing accepted never meets assurance",
			opts: corp(oidc.Assurance{Match: oidc.AssuranceMatchAll}),
			amr:  []string{"mfa"}, acr: "gold", assert: notMet,
		},
		{
			name: "a requested acr the provider ignored is not evidence",
			opts: corp(oidc.Assurance{RequestACR: []string{"urn:corp:loa:2"}, AcceptedACR: []string{"urn:corp:loa:2"}}),
			acr:  "urn:corp:loa:1", assert: notMet,
		},
		{
			name:   "an empty asserted acr never matches",
			opts:   corp(oidc.Assurance{AcceptedACR: []string{"gold"}}),
			assert: notMet,
		},
		{
			name: "another provider's configuration does not apply to corp",
			opts: []oidc.Option{oidc.WithProviderAssurance("partner", oidc.Assurance{AcceptedAMR: []string{"otp"}})},
			amr:  []string{"otp"}, assert: notMet,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := assuranceManager(t, tc.opts...)
			a, ok := oidc.AssuranceForTest(m, "corp")
			require.True(t, ok, "corp is registered")
			tc.assert(t, oidc.MatchAssuranceForTest(a, tc.amr, tc.acr))
		})
	}
}

// TestManagerAssuranceFor pins how a provider's configuration is resolved:
// the default, a consumer's replacement kept as given, and none for a
// provider the registry does not hold.
func TestManagerAssuranceFor(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		opts     func() []oidc.Option
		provider string
		assert   func(t *testing.T, got oidc.Assurance, ok bool)
	}

	cases := []testCase{
		{
			name: "a provider with no option gets the default", provider: "corp",
			assert: func(t *testing.T, got oidc.Assurance, ok bool) {
				require.True(t, ok)
				assert.Equal(t, oidc.Assurance{AcceptedAMR: []string{"mfa"}, Match: oidc.AssuranceMatchAny}, got)
			},
		},
		{
			name: "a configured empty set stays empty", provider: "corp",
			opts: func() []oidc.Option {
				return []oidc.Option{oidc.WithProviderAssurance("corp", oidc.Assurance{})}
			},
			assert: func(t *testing.T, got oidc.Assurance, ok bool) {
				require.True(t, ok)
				assert.Empty(t, got.AcceptedAMR, "the default must not fill a configured empty set")
				assert.Empty(t, got.AcceptedACR)
				assert.Empty(t, got.RequestACR)
			},
		},
		{
			name: "the configuration is the manager's own copy", provider: "corp",
			opts: func() []oidc.Option {
				amr, acr, req := []string{"hwk"}, []string{"gold"}, []string{"gold"}
				opt := oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedAMR: amr, AcceptedACR: acr, RequestACR: req})
				return []oidc.Option{opt, func(*oidc.RelyingParty) error {
					amr[0], acr[0], req[0] = "changed", "changed", "changed"
					return nil
				}}
			},
			assert: func(t *testing.T, got oidc.Assurance, ok bool) {
				require.True(t, ok)
				assert.Equal(t, []string{"hwk"}, got.AcceptedAMR)
				assert.Equal(t, []string{"gold"}, got.AcceptedACR)
				assert.Equal(t, []string{"gold"}, got.RequestACR)
			},
		},
		{
			name: "the last option for a provider replaces an earlier one", provider: "corp",
			opts: func() []oidc.Option {
				return []oidc.Option{
					oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedAMR: []string{"hwk"}}),
					oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedACR: []string{"gold"}, Match: oidc.AssuranceMatchAll}),
				}
			},
			assert: func(t *testing.T, got oidc.Assurance, ok bool) {
				require.True(t, ok)
				assert.Equal(t, oidc.Assurance{AcceptedACR: []string{"gold"}, Match: oidc.AssuranceMatchAll}, got)
			},
		},
		{
			name: "an unregistered provider has no configuration", provider: "corpp",
			assert: func(t *testing.T, got oidc.Assurance, ok bool) {
				assert.False(t, ok)
				assert.Equal(t, oidc.Assurance{}, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opts []oidc.Option
			if tc.opts != nil {
				opts = tc.opts()
			}
			got, ok := oidc.AssuranceForTest(assuranceManager(t, opts...), tc.provider)
			tc.assert(t, got, ok)
		})
	}
}

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
	corp := func(a oidc.Assurance) func(*testing.T, *gomock.Controller) []oidc.Option {
		return func(*testing.T, *gomock.Controller) []oidc.Option {
			return []oidc.Option{oidc.WithProviderAssurance("corp", a)}
		}
	}
	// evaluator wires a mock evaluator that expect configures.
	evaluator := func(expect func(e *MockAssuranceEvaluator)) func(*testing.T, *gomock.Controller) []oidc.Option {
		return func(_ *testing.T, ctrl *gomock.Controller) []oidc.Option {
			e := NewMockAssuranceEvaluator(ctrl)
			expect(e)
			return []oidc.Option{oidc.WithAssuranceEvaluator(e)}
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
		opts   func(t *testing.T, ctrl *gomock.Controller) []oidc.Option
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
			opts: corp(oidc.Assurance{AcceptedAMR: []string{"mfa"}, AcceptedACR: []string{"gold"}, Match: oidc.AssuranceMatchAll}),
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
			opts := []oidc.Option{oidc.WithOutboundClient(p.Outbound(t))}
			if tc.opts != nil {
				opts = append(opts, tc.opts(t, ctrl)...)
			}
			m, err := oidc.NewRelyingParty(reg, stubBroker{}, opts...)
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
