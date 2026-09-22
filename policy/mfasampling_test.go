package policy_test

import (
	"bytes"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/policy"
)

// mfaSamplingPair builds one policy of each kind over its own buffer, each
// refusing every request it is given: the challenge policy on a same-channel
// enrolment, the requirement policy on a stateless request from a required
// user. The refusal both write is the only thing under test here; what they
// decided is covered elsewhere.
func mfaSamplingPair(
	t *testing.T,
	challengeOpts []policy.MFAOption,
	requirementOpts []policy.MFARequirementOption,
) (challenge, requirement policy.Policy, challengeLog, requirementLog *bytes.Buffer) {
	t.Helper()

	challengeLog, requirementLog = &bytes.Buffer{}, &bytes.Buffer{}

	challenge, err := policy.NewMFAPolicy(mfaMethod(t, factor.Email, true, nil),
		append([]policy.MFAOption{policy.WithMFAPolicyLogger(mfaLogger(challengeLog))},
			challengeOpts...)...)
	require.NoError(t, err)

	requirement, err = policy.NewMFARequirementPolicy(
		mfaRequirementLookup(t, true, true, nil),
		mfaMethod(t, factor.AuthenticatorApp, true, nil),
		append([]policy.MFARequirementOption{
			policy.WithMFARequirementLogger(mfaLogger(requirementLog)),
		}, requirementOpts...)...)
	require.NoError(t, err)

	return challenge, requirement, challengeLog, requirementLog
}

// mfaRefuseBoth drives one refusal out of each policy, n times.
func mfaRefuseBoth(t *testing.T, challenge, requirement policy.Policy, n int) {
	t.Helper()

	login := mfaInput(factor.MagicLink)
	stateless := &policy.Input{User: mfaUser, FirstFactor: factor.Basic, Now: mfaNow}
	statelessCtx := mfaPhaseContext(t, policy.StatelessAuthentication)

	for range n {
		require.Equal(t, policy.Deny, challenge.Evaluate(t.Context(), login).Outcome)
		require.Equal(t, policy.Deny, requirement.Evaluate(statelessCtx, stateless).Outcome)
	}
}

// mfaFlush flushes a policy's held-back counts through the flusher a consumer
// reaches by type assertion, the constructors returning Policy.
func mfaFlush(t *testing.T, p policy.Policy) {
	t.Helper()

	flusher, ok := p.(policy.RefusalLogFlusher)
	require.True(t, ok, "the policy offers no way to report what it suppressed")
	require.NoError(t, flusher.FlushRefusalLogs())
}

func TestPolicyRefusalLogsAreSampledPerSubsystem(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// The two windows differ, which is the point: each policy samples
		// under its own option, so advancing past one must not reset the
		// other.
		challenge, requirement, challengeLog, requirementLog := mfaSamplingPair(t,
			[]policy.MFAOption{policy.WithMFAPolicyLogInterval(time.Minute)},
			[]policy.MFARequirementOption{policy.WithMFARequirementLogInterval(time.Hour)})

		mfaRefuseBoth(t, challenge, requirement, 50)
		synctest.Wait()

		require.Len(t, mfaRecordsOf(t, challengeLog, logSameChannelRefused), 1,
			"the challenge policy wrote more than one record inside its own window")
		require.Len(t, mfaRecordsOf(t, requirementLog, logMFARequired), 1,
			"the requirement policy wrote more than one record inside its own window")

		time.Sleep(time.Minute)
		synctest.Wait()
		mfaRefuseBoth(t, challenge, requirement, 50)
		synctest.Wait()

		challengeRecords := mfaRecordsOf(t, challengeLog, logSameChannelRefused)
		require.Len(t, challengeRecords, 2,
			"suppression outlived the challenge policy's own window")
		assert.Equal(t, float64(49), challengeRecords[1]["suppressed"],
			"the record that reopened the window understated the burst behind it")

		assert.Len(t, mfaRecordsOf(t, requirementLog, logMFARequired), 1,
			"one interval option governed both subsystems, so a minute reset an hour")

		mfaFlush(t, challenge)
		mfaFlush(t, requirement)

		challengeSummary := mfaRecordsOf(t, challengeLog, logMFASuppressed)
		require.Len(t, challengeSummary, 1, "the challenge policy dropped what it held back")
		assert.Equal(t, float64(49), challengeSummary[0]["suppressed"])

		requirementSummary := mfaRecordsOf(t, requirementLog, logRequirementSuppressed)
		require.Len(t, requirementSummary, 1, "the requirement policy dropped what it held back")
		assert.Equal(t, float64(99), requirementSummary[0]["suppressed"],
			"each policy must report its own count, not a count the two shared")
	})
}

func TestPolicyRefusalLogIntervalOfZeroWritesEveryRecord(t *testing.T) {
	t.Parallel()

	// The spec's case for this: a consumer whose own handler samples turns the
	// requirement policy's sampling off, and the challenge policy, configured
	// with nothing, keeps its default minute.
	challenge, requirement, challengeLog, requirementLog := mfaSamplingPair(t,
		nil,
		[]policy.MFARequirementOption{policy.WithMFARequirementLogInterval(0)})

	mfaRefuseBoth(t, challenge, requirement, 20)

	assert.Len(t, mfaRecordsOf(t, requirementLog, logMFARequired), 20,
		"an interval of zero still suppressed records, so an audit trail is missing them")
	assert.Len(t, mfaRecordsOf(t, challengeLog, logSameChannelRefused), 1,
		"one policy's override disabled the other policy's sampling")
}

// TestPolicySamplingClockOverride covers the override point for the clock each
// policy measures its sampling window by. The default is time.Now; a consumer
// who steps time themselves — a test, or a deployment replaying records —
// supplies their own.
func TestPolicySamplingClockOverride(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		message string
		build   func(t *testing.T, buf *bytes.Buffer, clock func() time.Time) policy.Policy
		refuse  func(t *testing.T, p policy.Policy)
	}

	cases := []testCase{
		{
			name:    "the second-factor challenge policy",
			message: logSameChannelRefused,
			build: func(t *testing.T, buf *bytes.Buffer, clock func() time.Time) policy.Policy {
				t.Helper()

				p, err := policy.NewMFAPolicy(mfaMethod(t, factor.Email, true, nil),
					policy.WithMFAPolicyLogger(mfaLogger(buf)),
					policy.WithMFAPolicyClock(clock))
				require.NoError(t, err)

				return p
			},
			refuse: func(t *testing.T, p policy.Policy) {
				t.Helper()

				require.Equal(t, policy.Deny,
					p.Evaluate(t.Context(), mfaInput(factor.MagicLink)).Outcome)
			},
		},
		{
			name:    "the mfa requirement policy",
			message: logMFARequired,
			build: func(t *testing.T, buf *bytes.Buffer, clock func() time.Time) policy.Policy {
				t.Helper()

				p, err := policy.NewMFARequirementPolicy(
					mfaRequirementLookup(t, true, true, nil),
					mfaMethod(t, factor.AuthenticatorApp, true, nil),
					policy.WithMFARequirementLogger(mfaLogger(buf)),
					policy.WithMFARequirementClock(clock))
				require.NoError(t, err)

				return p
			},
			refuse: func(t *testing.T, p policy.Policy) {
				t.Helper()

				in := &policy.Input{User: mfaUser, FirstFactor: factor.Basic, Now: mfaNow}
				require.Equal(t, policy.Deny,
					p.Evaluate(mfaPhaseContext(t, policy.StatelessAuthentication), in).Outcome)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			at := mfaNow
			buf := &bytes.Buffer{}
			p := tc.build(t, buf, func() time.Time { return at })

			tc.refuse(t, p)
			tc.refuse(t, p)
			require.Len(t, mfaRecordsOf(t, buf, tc.message), 1,
				"the second refusal was written inside the first one's window")

			// Exactly one window, so the record that reopens it carries the
			// count held back rather than the reporter taking it.
			at = at.Add(policy.DefaultLogInterval)
			tc.refuse(t, p)

			records := mfaRecordsOf(t, buf, tc.message)
			require.Len(t, records, 2,
				"the window was measured by a clock the consumer did not supply")
			assert.Equal(t, float64(1), records[1]["suppressed"],
				"the refusal held back in the first window was not carried forward")
		})
	}
}
