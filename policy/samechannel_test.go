package policy_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/policy"
)

// TestSameChannelEnrolmentIsRefusedByDefault pins the departure, and stands
// apart from the table below it on purpose: it is the test that was written
// against the behaviour this change replaced, watched failing while a
// same-channel login still completed silently, and then kept. It asserts the
// one fact that departure turns on; the table covers each mode in full.
//
// The user enrolled a second factor on the very channel their first factor
// arrived on: a magic link and an email one-time code both land in one mailbox.
// Two factors on one channel are one factor, so the enrolment cannot be
// challenged for — but completing anyway lowers the assurance the user chose
// when they enrolled, and leaves no record that it happened.
func TestSameChannelEnrolmentIsRefusedByDefault(t *testing.T) {
	t.Parallel()

	p := mfaPolicyFor(t, mfaMethod(t, factor.Email, true, nil))

	d := p.Evaluate(t.Context(), mfaInput(factor.MagicLink))

	require.Equal(t, policy.Deny, d.Outcome,
		"an enrolled user completed on one channel with no second factor and no record")
}

func TestSameChannelEnrolmentModes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []policy.MFAOption
		assert func(t *testing.T, d policy.Decision, in *policy.Input, buf *bytes.Buffer)
	}

	cases := []testCase{
		{
			name: "with nothing configured the login is refused, and the refusal is recorded",
			assert: func(t *testing.T, d policy.Decision, _ *policy.Input, buf *bytes.Buffer) {
				require.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, policy.ErrSecondFactorSameChannel,
					"the caller cannot tell this refusal from any other")

				records := mfaRecordsOf(t, buf,
					logSameChannelRefused)
				require.Len(t, records, 1, "the refusal happened with no record of it")
				assert.Equal(t, "WARN", records[0]["level"])
				assert.Equal(t, string(factor.Email), records[0]["channel"])
			},
		},
		{
			name: "a consumer may complete such logins on the first factor, and is still warned",
			opts: []policy.MFAOption{
				policy.WithSameChannelEnrolment(policy.SameChannelCompleteOnFirstFactor),
			},
			assert: func(t *testing.T, d policy.Decision, in *policy.Input, buf *bytes.Buffer) {
				require.Equal(t, policy.Allow, d.Outcome)
				assert.NoError(t, d.Reason)

				// Decision carries no MFA-satisfied field, and a policy never
				// writes to the Input it is handed. Reading it back is how a
				// test shows the allow recorded a second factor that did not
				// happen — it must still be false.
				assert.False(t, in.MFASatisfied,
					"the override recorded a second factor that never happened")

				records := mfaRecordsOf(t, buf,
					logSameChannelAllowed)
				require.Len(t, records, 1, "the override stopped warning, so the login completes unrecorded")
				assert.Equal(t, "WARN", records[0]["level"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			buf := &bytes.Buffer{}
			p, err := policy.NewMFAPolicy(mfaMethod(t, factor.Email, true, nil),
				append([]policy.MFAOption{policy.WithMFAPolicyLogger(mfaLogger(buf))}, tc.opts...)...)
			require.NoError(t, err)

			in := mfaInput(factor.MagicLink)
			tc.assert(t, p.Evaluate(t.Context(), in), in, buf)
		})
	}
}

// TestSameChannelOverrideDoesNotReachARequiredUser is the line the override may
// not cross.
//
// Completing on the first factor is a choice a deployment may make for users
// who were never required to use a second factor. A user who *is* required is
// governed by the requirement policy, which counts a same-channel enrolment as
// no usable enrolment — and no setting of the challenge policy changes that.
func TestSameChannelOverrideDoesNotReachARequiredUser(t *testing.T) {
	t.Parallel()

	method := mfaMethod(t, factor.Email, true, nil)
	in := mfaInput(factor.MagicLink)

	completed := mfaPolicyFor(t, method,
		policy.WithSameChannelEnrolment(policy.SameChannelCompleteOnFirstFactor)).
		Evaluate(t.Context(), in)
	require.Equal(t, policy.Allow, completed.Outcome,
		"the override under test did not take effect, so the case proves nothing")

	required := mfaRequirementPolicyFor(t, mfaRequirementLookup(t, true, true, nil), method).
		Evaluate(mfaPhaseContext(t, policy.PostAuthentication), in)

	require.Equal(t, policy.Deny, required.Outcome,
		"a consumer setting on the challenge policy let a required user through")
	assert.ErrorIs(t, required.Reason, policy.ErrMFAEnrollmentRequired)
}
