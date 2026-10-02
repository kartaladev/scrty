package policy_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/policy"
)

// errLeakyStore is a store failure whose text quotes values the policy never
// saw: another column of the row and a user reference. Neither may reach a
// refusal's text or a record.
var errLeakyStore = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// leakedValues are the values errLeakyStore quotes.
var leakedValues = []string{"alice@example.com", "u-123"}

// assertFixedReason checks that a denial caused by errLeakyStore carries fixed
// text, with kind (when there is one) and the store's error both reachable.
func assertFixedReason(t *testing.T, d policy.Decision, kind error) {
	t.Helper()

	assert.Equal(t, policy.Deny, d.Outcome, "a store that could not answer was not a refusal")
	require.Error(t, d.Reason, "the refusal gave no reason")

	for _, v := range leakedValues {
		assert.NotContains(t, d.Reason.Error(), v, "the reason's text quoted the store's error")
	}

	assert.ErrorIs(t, d.Reason, errLeakyStore, "the store's error is no longer reachable from the reason")

	if kind != nil {
		assert.ErrorIs(t, d.Reason, kind, "the reason no longer matches the policy's sentinel")
	}
}

const (
	logAssuranceSourceFailed = "policy: the federated assurance source failed"
	logAssuranceNotMet       = "policy: refusing a federated login whose provider assurance is not met"
)

func TestPolicyStoreFailureReasons(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T, buf *bytes.Buffer) policy.Policy
		input  *policy.Input
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, d policy.Decision, buf *bytes.Buffer)
	}

	cases := []testCase{
		{
			name: "lockout: the attempt store could not count failures",
			build: func(t *testing.T, _ *bytes.Buffer) policy.Policy {
				store := NewMockAttemptStore(gomock.NewController(t))
				store.EXPECT().FailureCount(gomock.Any(), gomock.Any(), gomock.Any()).Return(0, errLeakyStore)

				p, err := policy.NewAccountLockoutPolicy(policy.WithAttemptStore(store))
				require.NoError(t, err)

				return p
			},
			input: &policy.Input{Username: "alice", Now: mfaNow},
			assert: func(t *testing.T, d policy.Decision, _ *bytes.Buffer) {
				assertFixedReason(t, d, policy.ErrPolicyDenied)
			},
		},
		{
			name: "concurrent session: the counter could not count sessions",
			build: func(t *testing.T, _ *bytes.Buffer) policy.Policy {
				counter := NewMockSessionCounter(gomock.NewController(t))
				counter.EXPECT().CountActiveByUser(gomock.Any(), gomock.Any()).Return(0, errLeakyStore)

				p, err := policy.NewConcurrentSessionPolicy(counter, 3)
				require.NoError(t, err)

				return p
			},
			input: mfaInput(factor.Password),
			assert: func(t *testing.T, d policy.Decision, _ *bytes.Buffer) {
				assertFixedReason(t, d, policy.ErrTooManySessions)
			},
		},
		{
			name: "second-factor challenge: the enrolment could not be read",
			build: func(t *testing.T, buf *bytes.Buffer) policy.Policy {
				return mfaPolicyFor(t, mfaMethod(t, factor.AuthenticatorApp, false, errLeakyStore),
					policy.WithMFAPolicyLogger(mfaLogger(buf)))
			},
			input: mfaInput(factor.Password),
			assert: func(t *testing.T, d policy.Decision, buf *bytes.Buffer) {
				assertFixedReason(t, d, nil)

				for _, v := range leakedValues {
					assert.NotContains(t, buf.String(), v, "a record quoted the store's error")
				}
			},
		},
		{
			name: "mfa requirement: the requirement lookup failed, and its record keeps the user alone",
			build: func(t *testing.T, buf *bytes.Buffer) policy.Policy {
				return mfaRequirementPolicyFor(t,
					mfaRequirementLookup(t, true, false, errLeakyStore),
					mfaMethod(t, factor.AuthenticatorApp, true, nil),
					policy.WithMFARequirementLogger(mfaLogger(buf)))
			},
			input: mfaInput(factor.Password),
			assert: func(t *testing.T, d policy.Decision, buf *bytes.Buffer) {
				assertFixedReason(t, d, nil)

				records := mfaRecordsOf(t, buf, logRequirementLookupFailed)
				require.Len(t, records, 1, "the lookup failure was not recorded")
				assert.Equal(t, string(mfaUser), records[0]["user"],
					"the record lost its deliberate user reference")
				assert.Equal(t, "requirement-lookup", records[0]["reason"])
				assert.Equal(t, "*errors.errorString", records[0]["error_type"])
				assert.NotContains(t, records[0], "error", "the record still carries the error's text")

				for _, v := range leakedValues {
					assert.NotContains(t, buf.String(), v, "a record quoted the store's error")
				}
			},
		},
		{
			name: "mfa requirement: the enrolment of a required user could not be read",
			build: func(t *testing.T, buf *bytes.Buffer) policy.Policy {
				return mfaRequirementPolicyFor(t,
					mfaRequirementLookup(t, true, true, nil),
					mfaMethod(t, factor.AuthenticatorApp, false, errLeakyStore),
					policy.WithMFARequirementLogger(mfaLogger(buf)))
			},
			input: mfaInput(factor.Password),
			ctx: func(ctx context.Context) context.Context {
				return policy.ContextWithPhase(ctx, policy.PerRequest)
			},
			assert: func(t *testing.T, d policy.Decision, buf *bytes.Buffer) {
				assertFixedReason(t, d, nil)

				for _, v := range leakedValues {
					assert.NotContains(t, buf.String(), v, "a record quoted the store's error")
				}
			},
		},
		{
			name: "mfa requirement: the federated assurance source failed, and its record keeps the user and provider",
			build: func(t *testing.T, buf *bytes.Buffer) policy.Policy {
				return mfaRequirementPolicyFor(t,
					mfaRequirementLookup(t, true, true, nil),
					mfaMethod(t, factor.AuthenticatorApp, true, nil),
					policy.WithFederatedAssuranceSource(assuranceSource(t, true, false, errLeakyStore)),
					policy.WithMFARequirementLogger(mfaLogger(buf)))
			},
			input: federatedInput(factor.OIDC, federatedEvidence("pwd")),
			ctx: func(ctx context.Context) context.Context {
				return policy.ContextWithPhase(ctx, policy.PostAuthentication)
			},
			assert: func(t *testing.T, d policy.Decision, buf *bytes.Buffer) {
				assertFixedReason(t, d, nil)

				records := mfaRecordsOf(t, buf, logAssuranceSourceFailed)
				require.Len(t, records, 1, "the source failure was not recorded")
				assert.Equal(t, string(mfaUser), records[0]["user"])
				assert.Equal(t, "corp", records[0]["provider"])
				assert.Equal(t, "assurance-source", records[0]["reason"])
				assert.NotContains(t, records[0], "error", "the record still carries the error's text")

				for _, v := range leakedValues {
					assert.NotContains(t, buf.String(), v, "a record quoted the source's error")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			buf := &bytes.Buffer{}
			d := tc.build(t, buf).Evaluate(ctx, tc.input)
			tc.assert(t, d, buf)
		})
	}
}
