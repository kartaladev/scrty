package policy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

// errAssuranceSource stands for an assurance source that could not answer.
var errAssuranceSource = errors.New("the assurance evaluator could not reach its rules")

// federatedEvidence is evidence from provider corp that asserted amr, minted
// the way only library code can.
func federatedEvidence(amr ...string) policy.FederatedAssurance {
	return policy.MintFederatedForTest("corp", "https://idp.example", amr, "")
}

// federatedInput is a login of kind carrying ev.
func federatedInput(kind factor.Kind, ev policy.FederatedAssurance) *policy.Input {
	in := mfaInput(kind)
	in.FederatedAssurance = ev

	return in
}

// assuranceSource returns a source that answers met and err for every
// question. A source not expected to be asked carries no expectation, so a
// rule that asked it anyway fails the case.
func assuranceSource(t *testing.T, asked, met bool, err error) *MockFederatedAssuranceSource {
	t.Helper()

	m := NewMockFederatedAssuranceSource(gomock.NewController(t))
	if asked {
		m.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any(), gomock.Any()).Return(met, err).AnyTimes()
	}

	return m
}

func TestFederatedMet(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		source func(t *testing.T) policy.FederatedAssuranceSource
		in     *policy.Input
		assert func(t *testing.T, met bool, err error)
	}

	notMet := func(t *testing.T, met bool, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.False(t, met)
	}

	cases := []testCase{
		{
			name:   "no source meets nothing",
			source: func(*testing.T) policy.FederatedAssuranceSource { return nil },
			in:     federatedInput(factor.OIDC, federatedEvidence("mfa")),
			assert: notMet,
		},
		{
			name: "zero evidence never asks the source",
			source: func(t *testing.T) policy.FederatedAssuranceSource {
				return assuranceSource(t, false, true, nil)
			},
			in:     federatedInput(factor.OIDC, policy.FederatedAssurance{}),
			assert: notMet,
		},
		{
			// Evidence placed on a login of another channel is not a federated
			// login, whatever it carries.
			name: "a first factor off the federated channel never asks the source",
			source: func(t *testing.T) policy.FederatedAssuranceSource {
				return assuranceSource(t, false, true, nil)
			},
			in:     federatedInput(factor.Password, federatedEvidence("mfa")),
			assert: notMet,
		},
		{
			name: "the source decides met",
			source: func(t *testing.T) policy.FederatedAssuranceSource {
				m := NewMockFederatedAssuranceSource(gomock.NewController(t))
				m.EXPECT().MeetsAssurance(gomock.Any(), identity.UserID(mfaUser), gomock.Any()).
					DoAndReturn(func(_ context.Context, _ identity.UserID, ev policy.FederatedAssurance) (bool, error) {
						assert.Equal(t, "corp", ev.Provider(), "the source was not handed the login's evidence")
						assert.Equal(t, []string{"mfa"}, ev.AMR())

						return true, nil
					})

				return m
			},
			in: federatedInput(factor.OIDC, federatedEvidence("mfa")),
			assert: func(t *testing.T, met bool, err error) {
				require.NoError(t, err)
				assert.True(t, met)
			},
		},
		{
			name: "the source decides not met",
			source: func(t *testing.T) policy.FederatedAssuranceSource {
				return assuranceSource(t, true, false, nil)
			},
			in:     federatedInput(factor.OIDC, federatedEvidence("pwd")),
			assert: notMet,
		},
		{
			name: "a source error is returned, never read as met",
			source: func(t *testing.T) policy.FederatedAssuranceSource {
				return assuranceSource(t, true, true, errAssuranceSource)
			},
			in: federatedInput(factor.OIDC, federatedEvidence("mfa")),
			assert: func(t *testing.T, met bool, err error) {
				require.ErrorIs(t, err, errAssuranceSource)
				assert.False(t, met)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			met, err := policy.FederatedMetForTest(t.Context(), tc.source(t), tc.in)
			tc.assert(t, met, err)
		})
	}
}

// TestWithFederatedAssuranceSource pins that both MFA policies accept the one
// option value, and refuse an absent source at construction rather than at
// the first federated login.
func TestWithFederatedAssuranceSource(t *testing.T) {
	t.Parallel()

	var typedNil *MockFederatedAssuranceSource

	type testCase struct {
		name   string
		source policy.FederatedAssuranceSource
		assert func(t *testing.T, challengeErr, requirementErr error)
	}

	cases := []testCase{
		{
			name:   "a source is accepted by both policies",
			source: NewMockFederatedAssuranceSource(gomock.NewController(t)),
			assert: func(t *testing.T, challengeErr, requirementErr error) {
				assert.NoError(t, challengeErr)
				assert.NoError(t, requirementErr)
			},
		},
		{
			name:   "a nil source is a configuration error",
			source: nil,
			assert: func(t *testing.T, challengeErr, requirementErr error) {
				assert.ErrorIs(t, challengeErr, policy.ErrConfig)
				assert.ErrorIs(t, requirementErr, policy.ErrConfig)
			},
		},
		{
			name:   "a typed nil source is a configuration error",
			source: typedNil,
			assert: func(t *testing.T, challengeErr, requirementErr error) {
				assert.ErrorIs(t, challengeErr, policy.ErrConfig)
				assert.ErrorIs(t, requirementErr, policy.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opt := policy.WithFederatedAssuranceSource(tc.source)
			method := idleMFAMethod(t, mfaMethodName(factor.AuthenticatorApp))

			_, challengeErr := policy.NewMFAPolicy(mfaMethods(method), opt)
			_, requirementErr := policy.NewMFARequirementPolicy(nil, mfaMethods(method),
				policy.WithMFARequiredForAll(), opt)

			tc.assert(t, challengeErr, requirementErr)
		})
	}
}
