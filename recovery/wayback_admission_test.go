package recovery_test

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
	"github.com/kartaladev/scrty/recovery"
)

// TestHasWayBack_LinkedProvider pins that a linked OIDC identity counts as a
// way back exactly when the MFA requirement policy, wired through
// WayBackDeps.Admits, would admit its login without a local second factor.
// The user has nothing else: no saved codes, no password, no authenticator.
func TestHasWayBack_LinkedProvider(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")
	errLookup := errors.New("requirement store down: dial tcp 10.0.0.7:5432")

	type testCase struct {
		name   string
		mode   policy.FederatedAssuranceMode
		opts   []policy.MFARequirementOption
		lookup func(m *MockMFARequirementLookup)
		assert func(t *testing.T, ok bool, err error)
	}

	cases := []testCase{
		{
			// Exempt mode admits before the requirement is looked up.
			name:   "linked provider under the exempt mode",
			mode:   policy.FederatedAssuranceExempt,
			lookup: func(*MockMFARequirementLookup) {},
			assert: func(t *testing.T, ok bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, ok)
			},
		},
		{
			// An exemption rule that marks the oidc kind exempt is a total
			// exemption, so the login is admitted before any lookup.
			name: "linked provider under an exemption rule that exempts oidc",
			mode: policy.FederatedAssuranceChallenge,
			opts: []policy.MFARequirementOption{
				policy.WithMFAExemption(func(k factor.Kind) bool { return k == factor.OIDC }),
			},
			lookup: func(*MockMFARequirementLookup) {},
			assert: func(t *testing.T, ok bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, ok)
			},
		},
		{
			name: "linked provider, required user, default mode",
			mode: policy.FederatedAssuranceChallenge,
			lookup: func(m *MockMFARequirementLookup) {
				m.EXPECT().Required(gomock.Any(), user).Return(true, nil)
			},
			assert: func(t *testing.T, ok bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, ok)
			},
		},
		{
			name: "linked provider, user not required",
			mode: policy.FederatedAssuranceChallenge,
			lookup: func(m *MockMFARequirementLookup) {
				m.EXPECT().Required(gomock.Any(), user).Return(false, nil)
			},
			assert: func(t *testing.T, ok bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, ok)
			},
		},
		{
			name: "requirement lookup failure",
			mode: policy.FederatedAssuranceChallenge,
			lookup: func(m *MockMFARequirementLookup) {
				m.EXPECT().Required(gomock.Any(), user).Return(false, errLookup)
			},
			assert: func(t *testing.T, ok bool, err error) {
				t.Helper()
				require.ErrorIs(t, err, errLookup)
				assert.NotContains(t, err.Error(), "10.0.0.7")
				assert.False(t, ok)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			lookup := NewMockMFARequirementLookup(ctrl)
			tc.lookup(lookup)

			p, err := policy.NewMFARequirementPolicy(lookup, nil,
				append([]policy.MFARequirementOption{policy.WithFederatedAssurance(tc.mode)}, tc.opts...)...)
			require.NoError(t, err)
			adm, ok := p.(policy.LoginAdmission)
			require.True(t, ok, "the requirement policy must implement LoginAdmission")

			m := newWayBackMocks(ctrl)
			m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)

			c, err := recovery.NewWayBackCheck(recovery.WayBackDeps{
				Users: m.users,
				Codes: newCodes(t, recovery.WithCodeStore(m.codes)),
				Kinds: []recovery.AuthenticatorKind{m.kind},
				LinkedLogins: func(context.Context, identity.UserID) ([]factor.Kind, error) {
					return []factor.Kind{factor.OIDC}, nil
				},
				Admits: adm.AdmitsWithoutLocalSecondFactor,
			})
			require.NoError(t, err)

			got, err := c.HasWayBack(t.Context(), user)
			tc.assert(t, got, err)
		})
	}
}
