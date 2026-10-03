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

// TestAdmitsWithoutLocalSecondFactor pins the requirement policy's answer to
// whether a login of a kind would be admitted without a local second factor,
// which the way-back check asks before any login has happened.
func TestAdmitsWithoutLocalSecondFactor(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")
	errLookup := errors.New("requirement store down: dial tcp 10.0.0.7:5432")

	// lookup answers for user alone; a lookup built with no answer must not
	// be consulted at all, which gomock enforces.
	lookup := func(answer *bool, err error) func(t *testing.T) identity.MFARequirementLookup {
		return func(t *testing.T) identity.MFARequirementLookup {
			m := NewMockMFARequirementLookup(gomock.NewController(t))
			if answer != nil || err != nil {
				m.EXPECT().Required(gomock.Any(), user).DoAndReturn(
					func(ctx context.Context, _ identity.UserID) (bool, error) {
						if ctx.Err() != nil {
							return false, ctx.Err()
						}
						if err != nil {
							return false, err
						}

						return *answer, nil
					})
			}

			return m
		}
	}
	yes, no := true, false
	required := lookup(&yes, nil)
	notRequired := lookup(&no, nil)
	notConsulted := lookup(nil, nil)

	type testCase struct {
		name     string
		required func(t *testing.T) identity.MFARequirementLookup // nil means WithMFARequiredForAll
		opts     []policy.MFARequirementOption
		kind     factor.Kind
		ctx      func(ctx context.Context) context.Context
		assert   func(t *testing.T, ok bool, err error)
	}

	admits := func(t *testing.T, ok bool, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.True(t, ok)
	}
	refuses := func(t *testing.T, ok bool, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.False(t, ok)
	}

	cases := []testCase{
		{
			name:     "exempt mode admits a federated kind without looking the requirement up",
			required: notConsulted,
			opts:     []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceExempt)},
			kind:     factor.OIDC,
			assert:   admits,
		},
		{
			name:   "exempt mode admits even when everyone is required",
			opts:   []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceExempt)},
			kind:   factor.OIDC,
			assert: admits,
		},
		{
			name:     "exempt mode does not cover a kind off the federated channel",
			required: required,
			opts:     []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceExempt)},
			kind:     factor.Password,
			assert:   refuses,
		},
		{
			name:     "a consumer exemption rule marking oidc admits it without a lookup",
			required: notConsulted,
			opts: []policy.MFARequirementOption{policy.WithMFAExemption(func(k factor.Kind) bool {
				return k == factor.OIDC
			})},
			kind:   factor.OIDC,
			assert: admits,
		},
		{
			name:     "the default exemption rule admits api-key without a lookup",
			required: notConsulted,
			kind:     factor.APIKey,
			assert:   admits,
		},
		{
			name:     "a user not required to use MFA is admitted",
			required: notRequired,
			kind:     factor.OIDC,
			assert:   admits,
		},
		{
			name:     "a required user under the default mode is not admitted: assurance is never assumed",
			required: required,
			kind:     factor.OIDC,
			assert:   refuses,
		},
		{
			name:     "a required user under refuse mode is not admitted",
			required: required,
			opts:     []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceRefuse)},
			kind:     factor.OIDC,
			assert:   refuses,
		},
		{
			name:   "everyone required under the default mode is not admitted",
			kind:   factor.OIDC,
			assert: refuses,
		},
		{
			name:     "a requirement lookup failure is an error with fixed text",
			required: lookup(nil, errLookup),
			kind:     factor.OIDC,
			assert: func(t *testing.T, ok bool, err error) {
				t.Helper()
				require.ErrorIs(t, err, errLookup)
				assert.NotContains(t, err.Error(), "10.0.0.7")
				assert.False(t, ok)
			},
		},
		{
			name:     "a cancelled context reaches the requirement lookup",
			required: required,
			kind:     factor.OIDC,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, ok bool, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.False(t, ok)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var lk identity.MFARequirementLookup
			opts := tc.opts
			if tc.required != nil {
				lk = tc.required(t)
			} else {
				opts = append([]policy.MFARequirementOption{policy.WithMFARequiredForAll()}, opts...)
			}
			methods := mfaMethods(idleMFAMethod(t, mfaMethodName(factor.AuthenticatorApp)))
			p := mfaRequirementPolicyOver(t, lk, methods, opts...)

			adm, ok := p.(policy.LoginAdmission)
			require.True(t, ok, "the requirement policy must implement LoginAdmission")

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			got, err := adm.AdmitsWithoutLocalSecondFactor(ctx, user, tc.kind)
			tc.assert(t, got, err)
		})
	}
}
