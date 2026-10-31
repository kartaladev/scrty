package policy_test

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
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

				p, err := lockout.New(lockout.WithAttemptStore(store))
				require.NoError(t, err)

				return p
			},
			input: &policy.Input{Username: "alice", Now: mfaNow},
			assert: func(t *testing.T, d policy.Decision, _ *bytes.Buffer) {
				assertFixedReason(t, d, policy.ErrDenied)
			},
		},
		{
			// The window's count succeeded and owes a wait; the query that
			// asks whether it has been served is the one that fails.
			name: "lockout: the attempt store could not count failures inside the wait",
			build: func(t *testing.T, _ *bytes.Buffer) policy.Policy {
				store := NewMockAttemptStore(gomock.NewController(t))
				gomock.InOrder(
					store.EXPECT().FailureCount(gomock.Any(), "alice", mfaNow.Add(-24*time.Hour)).Return(7, nil),
					store.EXPECT().FailureCount(gomock.Any(), "alice", mfaNow.Add(-120*time.Second)).
						Return(0, errLeakyStore),
				)

				p, err := lockout.New(lockout.WithAttemptStore(store))
				require.NoError(t, err)

				return p
			},
			input: &policy.Input{Username: "alice", Now: mfaNow},
			assert: func(t *testing.T, d policy.Decision, _ *bytes.Buffer) {
				assertFixedReason(t, d, policy.ErrDenied)
				assert.NotErrorIs(t, d.Reason, lockout.ErrAccountLocked,
					"an outage was reported to the caller as a locked account")
			},
		},
		{
			name: "concurrent session: the counter could not count sessions",
			build: func(t *testing.T, _ *bytes.Buffer) policy.Policy {
				counter := NewMockSessionCounter(gomock.NewController(t))
				counter.EXPECT().CountActiveByUser(gomock.Any(), gomock.Any()).Return(0, errLeakyStore)

				p, err := policy.NewConcurrentSessions(counter, 3)
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
					policy.WithMFALogger(mfaLogger(buf)))
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

// TestChallengesDoesNotAliasPolicyState pins that a caller cannot write into a
// policy's own state through what it reported.
func TestChallengesDoesNotAliasPolicyState(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		policy func(t *testing.T) policy.Challenger
	}

	cases := []testCase{
		{
			name: "the second-factor challenge policy",
			policy: func(t *testing.T) policy.Challenger {
				t.Helper()

				p, err := policy.NewMFA([]policy.MFAMethodLookup{idleMFAMethod(t, "totp")})
				require.NoError(t, err)

				return p
			},
		},
		{
			name: "the requirement policy",
			policy: func(t *testing.T) policy.Challenger {
				t.Helper()

				ctrl := gomock.NewController(t)

				p, err := policy.NewMFARequirement(
					NewMockMFARequirementLookup(ctrl), mfaMethods(idleMFAMethod(t, "totp")))
				require.NoError(t, err)

				return p
			},
		},
		{
			name: "the password-age policy",
			policy: func(t *testing.T) policy.Challenger {
				t.Helper()

				p, err := policy.NewPasswordAge()
				require.NoError(t, err)

				return p
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := tc.policy(t)

			reported := p.Challenges()
			require.NotEmpty(t, reported)

			before := reported[0]
			reported[0] = policy.ChallengeNone

			assert.Equal(t, before, p.Challenges()[0],
				"what a policy reports is a copy, not a way into its own state")
		})
	}
}

// TestTimeoutPolicyConfigurationErrors pins that a value which would make one
// of these policies fire on everything, or on nothing, is refused while the
// application is being wired rather than discovered from its traffic.
func TestTimeoutPolicyConfigurationErrors(t *testing.T) {
	t.Parallel()

	// A counter held by a nil pointer: what an unchecked constructor result
	// hands over, and what `if counter == nil` fails to catch.
	var absentStore *session.MemoryStore

	type testCase struct {
		name        string
		construct   func() (policy.Policy, error)
		names       string // the part of the message that says what is wrong
		consequence string // the part that says what it would have done
	}

	cases := []testCase{
		{
			name: "an idle timeout of zero",
			construct: func() (policy.Policy, error) {
				return policy.NewIdleTimeout(policy.WithIdleTimeout(0))
			},
			names:       "idle timeout must be positive",
			consequence: "refuse every request",
		},
		{
			name: "a negative idle timeout",
			construct: func() (policy.Policy, error) {
				return policy.NewIdleTimeout(policy.WithIdleTimeout(-time.Minute))
			},
			names:       "idle timeout must be positive",
			consequence: "refuse every request",
		},
		{
			name: "an absolute timeout of zero",
			construct: func() (policy.Policy, error) {
				return policy.NewIdleTimeout(policy.WithIdleAbsoluteTimeout(0))
			},
			names:       "absolute timeout must be positive",
			consequence: "already past its final deadline",
		},
		{
			name: "a maximum password age of zero",
			construct: func() (policy.Policy, error) {
				return policy.NewPasswordAge(policy.WithMaxPasswordAge(0))
			},
			names:       "maximum password age must be positive",
			consequence: "challenge every login",
		},
		{
			name: "a negative maximum password age",
			construct: func() (policy.Policy, error) {
				return policy.NewPasswordAge(policy.WithMaxPasswordAge(-time.Hour))
			},
			names:       "maximum password age must be positive",
			consequence: "challenge every login",
		},
		{
			// A mode from outside the enumeration would otherwise fall to
			// whichever branch the implementation happens to end in, which is
			// not a decision anybody made.
			name: "an unknown-change-time mode naming neither choice",
			construct: func() (policy.Policy, error) {
				return policy.NewPasswordAge(policy.WithUnknownPasswordAge(policy.UnknownAgeMode(7)))
			},
			names:       "unknown-password-age mode",
			consequence: "UnknownAgeAllow nor UnknownAgeChallenge",
		},
		{
			// "Zero maximum": a cap of zero refuses every login, since every
			// user already holds at least none.
			name: "a maximum of zero sessions",
			construct: func() (policy.Policy, error) {
				return policy.NewConcurrentSessions(session.NewMemoryStore(), 0)
			},
			names:       "maximum number of sessions must be positive",
			consequence: "refuse every login",
		},
		{
			name: "a negative maximum of sessions",
			construct: func() (policy.Policy, error) {
				return policy.NewConcurrentSessions(session.NewMemoryStore(), -1)
			},
			names:       "maximum number of sessions must be positive",
			consequence: "refuse every login",
		},
		{
			name: "no session counter at all",
			construct: func() (policy.Policy, error) {
				return policy.NewConcurrentSessions(nil, 3)
			},
			names:       "session counter must not be nil",
			consequence: "no count can be made",
		},
		{
			name: "a session counter held by a nil pointer",
			construct: func() (policy.Policy, error) {
				return policy.NewConcurrentSessions(absentStore, 3)
			},
			names:       "session counter must not be nil",
			consequence: "no count can be made",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := tc.construct()

			require.ErrorIs(t, err, policy.ErrConfig,
				"a wiring mistake was not reported as a configuration error")
			assert.ErrorContains(t, err, tc.names, "the error does not say what was rejected")
			assert.ErrorContains(t, err, tc.consequence,
				"the error does not say what the policy would have done")
			assert.Nil(t, p, "a refused configuration handed back a policy to register")
		})
	}
}

// TestMFAPolicies_HonourSecondFactorProof pins that both MFA policies honour
// the library's proof that a login met its second factor at the first, that
// the zero proof is judged like any other login, and that a replaced
// exemption rule does not hide the proof.
func TestMFAPolicies_HonourSecondFactorProof(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	exemptNothing := policy.WithMFAExemption(func(factor.Kind) bool { return false })

	// totpEnrolled is a user enrolled on TOTP, whose channel a passkey login
	// does not share, so without the proof they are challenged.
	totpEnrolled := func(t *testing.T) policy.MFAMethodLookup {
		return mfaMethod(t, factor.AuthenticatorApp, true, nil)
	}
	// passkeyOnly is a user whose only enrolment is on the passkey's own
	// channel, so without the proof they have no usable second factor.
	passkeyOnly := func(t *testing.T) policy.MFAMethodLookup {
		return namedMFAMethod(t, "passkey", factor.PublicKey, true, nil)
	}
	challengePolicy := func(lookup func(*testing.T) policy.MFAMethodLookup, opts ...policy.MFAOption) func(*testing.T) policy.Policy {
		return func(t *testing.T) policy.Policy { return mfaPolicyFor(t, lookup(t), opts...) }
	}
	requiredForAll := func(lookup func(*testing.T) policy.MFAMethodLookup, opts ...policy.MFARequirementOption) func(*testing.T) policy.Policy {
		return func(t *testing.T) policy.Policy {
			return mfaRequirementPolicyFor(t, nil, lookup(t),
				append([]policy.MFARequirementOption{policy.WithMFARequiredForAll()}, opts...)...)
		}
	}
	withProof := policy.Input{
		User: mfaUser, FirstFactor: factor.Passkey,
		SecondFactorAtLogin: policy.MintProofForTest(factor.Passkey, at), Now: at,
	}
	withoutProof := policy.Input{User: mfaUser, FirstFactor: factor.Passkey, Now: at}

	// exemptionCalls counts the calls made to a replaced exemption rule that
	// exempts nothing, for the row pinning that the proof is decided without
	// consulting it.
	var exemptionCalls atomic.Int64
	countingExemption := policy.WithMFAExemption(func(factor.Kind) bool {
		exemptionCalls.Add(1)

		return false
	})

	type testCase struct {
		name   string
		build  func(t *testing.T) policy.Policy
		in     policy.Input
		assert func(t *testing.T, d policy.Decision)
	}

	cases := []testCase{
		{
			name:  "challenge policy allows on a holding proof",
			build: challengePolicy(totpEnrolled),
			in:    withProof,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome)
			},
		},
		{
			name:  "challenge policy challenges on a zero proof",
			build: challengePolicy(totpEnrolled),
			in:    withoutProof,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Challenge, d.Outcome)
				assert.Equal(t, policy.ChallengeMFA, d.Challenge)
			},
		},
		{
			name:  "challenge policy with an exemption rule exempting nothing still allows on the proof",
			build: challengePolicy(totpEnrolled, exemptNothing),
			in:    withProof,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome)
			},
		},
		{
			name:  "requirement policy allows a required passkey-only user on the proof in post-authentication",
			build: requiredForAll(passkeyOnly),
			in:    withProof,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome)
			},
		},
		{
			name:  "requirement policy denies the same user without it",
			build: requiredForAll(passkeyOnly),
			in:    withoutProof,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, policy.ErrMFAEnrolmentRequired)
			},
		},
		{
			name:  "requirement policy with an exemption rule exempting nothing still allows on the proof",
			build: requiredForAll(passkeyOnly, exemptNothing),
			in:    withProof,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome)
			},
		},
		{
			name:  "requirement policy does not consult the exemption rule on the proof in post-authentication",
			build: requiredForAll(passkeyOnly, countingExemption),
			in:    withProof,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome)
				assert.Zero(t, exemptionCalls.Load(), "the exemption rule was consulted")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, err := policy.NewEngine(tc.build(t))
			require.NoError(t, err)

			in := tc.in
			tc.assert(t, e.EvaluatePhase(t.Context(), policy.PostAuthentication, &in))
		})
	}
}

// mfaSamplingPair builds one policy of each kind over its own buffer, each
// refusing every request it is given: the challenge policy on a same-channel
// enrolment, the requirement policy on a stateless request from a required
// user. The refusal both write is the only thing under test here; what they
// decided is covered elsewhere.
func mfaSamplingPair(
	t *testing.T,
	challengeOpts []policy.MFAOption,
	requirementOpts []policy.MFARequirementOption,
) (challenge *policy.MFA, requirement *policy.MFARequirement, challengeLog, requirementLog *bytes.Buffer) {
	t.Helper()

	challengeLog, requirementLog = &bytes.Buffer{}, &bytes.Buffer{}

	challenge, err := policy.NewMFA([]policy.MFAMethodLookup{mfaMethod(t, factor.Email, true, nil)},
		append([]policy.MFAOption{policy.WithMFALogger(mfaLogger(challengeLog))},
			challengeOpts...)...)
	require.NoError(t, err)

	requirement, err = policy.NewMFARequirement(
		mfaRequirementLookup(t, true, true, nil),
		mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil)),
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

func TestPolicyRefusalLogsAreSampledPerSubsystem(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// The two windows differ, which is the point: each policy samples
		// under its own option, so advancing past one must not reset the
		// other.
		challenge, requirement, challengeLog, requirementLog := mfaSamplingPair(t,
			[]policy.MFAOption{policy.WithMFALogInterval(time.Minute)},
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

		require.NoError(t, challenge.FlushRefusalLogs())
		require.NoError(t, requirement.FlushRefusalLogs())

		challengeSummary := mfaRecordsOf(t, challengeLog, logMFASuppressed)
		require.Len(t, challengeSummary, 1, "the challenge policy dropped what it held back")
		assert.Equal(t, float64(49), challengeSummary[0]["suppressed"])

		requirementSummary := mfaRecordsOf(t, requirementLog, logRequirementSuppressed)
		require.Len(t, requirementSummary, 1, "the requirement policy dropped what it held back")
		assert.Equal(t, float64(99), requirementSummary[0]["suppressed"],
			"each policy must report its own count, not a count the two shared")
	})
}

// Standalone: TestPolicyRefusalLogsAreSampledPerSubsystem runs inside a synctest bubble and this does not.
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
// policy measures its sampling window by. The default is clock.System(); a
// consumer who steps time themselves — a test, or a deployment replaying
// records — supplies their own.
func TestPolicySamplingClockOverride(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		message string
		build   func(t *testing.T, buf *bytes.Buffer, clk *clockwork.FakeClock) policy.Policy
		refuse  func(t *testing.T, p policy.Policy)
	}

	cases := []testCase{
		{
			name:    "the second-factor challenge policy",
			message: logSameChannelRefused,
			build: func(t *testing.T, buf *bytes.Buffer, clk *clockwork.FakeClock) policy.Policy {
				t.Helper()

				p, err := policy.NewMFA([]policy.MFAMethodLookup{mfaMethod(t, factor.Email, true, nil)},
					policy.WithMFALogger(mfaLogger(buf)),
					policy.WithMFAClock(clk))
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
			build: func(t *testing.T, buf *bytes.Buffer, clk *clockwork.FakeClock) policy.Policy {
				t.Helper()

				p, err := policy.NewMFARequirement(
					mfaRequirementLookup(t, true, true, nil),
					mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil)),
					policy.WithMFARequirementLogger(mfaLogger(buf)),
					policy.WithMFARequirementClock(clk))
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

			clk := clockwork.NewFakeClockAt(mfaNow)
			buf := &bytes.Buffer{}
			p := tc.build(t, buf, clk)

			tc.refuse(t, p)
			tc.refuse(t, p)
			require.Len(t, mfaRecordsOf(t, buf, tc.message), 1,
				"the second refusal was written inside the first one's window")

			// Exactly one window, so the record that reopens it carries the
			// count held back rather than the reporter taking it.
			clk.Advance(policy.DefaultLogInterval)
			tc.refuse(t, p)

			records := mfaRecordsOf(t, buf, tc.message)
			require.Len(t, records, 2,
				"the window was measured by a clock the consumer did not supply")
			assert.Equal(t, float64(1), records[1]["suppressed"],
				"the refusal held back in the first window was not carried forward")
		})
	}
}

// TestMFAPolicies_FederatedEvidenceIsNotTheProof pins that a required user's
// OIDC login with accepted assurance is allowed by both MFA policies, and
// leaves the login carrying no proof that its second factor was met at the
// first, and no satisfied second factor.
func TestMFAPolicies_FederatedEvidenceIsNotTheProof(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		policy func(t *testing.T) policy.Policy
		assert func(t *testing.T, d policy.Decision, in *policy.Input)
	}

	allowedWithoutProof := func(t *testing.T, d policy.Decision, in *policy.Input) {
		t.Helper()

		assert.Equal(t, policy.Allow, d.Outcome)
		assert.False(t, in.SecondFactorAtLogin.Holds(), "federated evidence was turned into the proof")
		assert.False(t, in.MFASatisfied, "federated evidence marked the second factor satisfied")
	}

	cases := []testCase{
		{
			name: "the requirement policy",
			policy: func(t *testing.T) policy.Policy {
				return mfaRequirementPolicyFor(t,
					mfaRequirementLookup(t, true, true, nil),
					idleMFAMethod(t, mfaMethodName(factor.AuthenticatorApp)),
					policy.WithFederatedAssuranceSource(assuranceSource(t, true, true, nil)))
			},
			assert: allowedWithoutProof,
		},
		{
			name: "the second-factor challenge policy, challenging unmet federated logins",
			policy: func(t *testing.T) policy.Policy {
				return mfaPolicyFor(t,
					idleMFAMethod(t, mfaMethodName(factor.AuthenticatorApp)),
					policy.WithFederatedAssuranceSource(assuranceSource(t, true, true, nil)),
					policy.WithMFAFederatedChallengeWhenUnmet(true))
			},
			assert: allowedWithoutProof,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			in := federatedInput(factor.OIDC, federatedEvidence("mfa"))
			d := tc.policy(t).Evaluate(mfaPhaseContext(t, policy.PostAuthentication), in)
			tc.assert(t, d, in)
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
		policy.WithMFASameChannelEnrolment(policy.SameChannelCompleteOnFirstFactor)).
		Evaluate(t.Context(), in)
	require.Equal(t, policy.Allow, completed.Outcome,
		"the override under test did not take effect, so the case proves nothing")

	required := mfaRequirementPolicyFor(t, mfaRequirementLookup(t, true, true, nil), method).
		Evaluate(mfaPhaseContext(t, policy.PostAuthentication), in)

	require.Equal(t, policy.Deny, required.Outcome,
		"a consumer setting on the challenge policy let a required user through")
	assert.ErrorIs(t, required.Reason, policy.ErrMFAEnrolmentRequired)
}

func TestMFAExemptionRule(t *testing.T) {
	t.Parallel()

	enforceEverything := func(factor.Kind) bool { return false }
	exemptFederatedAndMachine := func(k factor.Kind) bool { return k == factor.OIDC || k == factor.APIKey }

	type testCase struct {
		name   string
		kind   factor.Kind
		opts   []policy.MFAOption
		reqOpt policy.MFARequirementOption
		assert func(t *testing.T, challenge, requirement policy.Decision)
	}

	cases := []testCase{
		{
			name: "by default the identity model's own rule decides, and exempts a machine caller",
			kind: factor.APIKey,
			assert: func(t *testing.T, challenge, requirement policy.Decision) {
				assert.Equal(t, policy.Allow, challenge.Outcome,
					"the default exemption stopped exempting a machine caller")
				assert.Equal(t, policy.Allow, requirement.Outcome)
			},
		},
		{
			// The default rule no longer exempts a federated login, so the
			// requirement policy enforces it; the challenge policy still lets it
			// through by its own federated rule, not by an exemption.
			name: "by default a federated login is not exempt from the requirement",
			kind: factor.OIDC,
			assert: func(t *testing.T, challenge, requirement policy.Decision) {
				assert.Equal(t, policy.Allow, challenge.Outcome)
				assert.Equal(t, policy.Challenge, requirement.Outcome,
					"the default exemption still exempts a federated login")
			},
		},
		{
			name:   "a consumer rule that exempts oidc restores the total exemption",
			kind:   factor.OIDC,
			opts:   []policy.MFAOption{policy.WithMFAExemption(exemptFederatedAndMachine)},
			reqOpt: policy.WithMFAExemption(exemptFederatedAndMachine),
			assert: func(t *testing.T, challenge, requirement policy.Decision) {
				assert.Equal(t, policy.Allow, challenge.Outcome)
				assert.Equal(t, policy.Allow, requirement.Outcome,
					"a consumer's exemption of oidc did not reach the requirement policy")
			},
		},
		{
			name: "by default a password login is enforced",
			kind: factor.Password,
			assert: func(t *testing.T, challenge, requirement policy.Decision) {
				assert.Equal(t, policy.Challenge, challenge.Outcome)
				assert.Equal(t, policy.Challenge, requirement.Outcome)
			},
		},
		{
			name:   "a consumer rule that exempts nothing enforces a normally exempt kind",
			kind:   factor.APIKey,
			opts:   []policy.MFAOption{policy.WithMFAExemption(enforceEverything)},
			reqOpt: policy.WithMFAExemption(enforceEverything),
			assert: func(t *testing.T, challenge, requirement policy.Decision) {
				assert.Equal(t, policy.Challenge, challenge.Outcome,
					"the override did not replace the exemption rule")
				assert.Equal(t, policy.Challenge, requirement.Outcome,
					"one override value did not reach both policies")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			method := mfaMethod(t, factor.AuthenticatorApp, true, nil)
			challenge := mfaPolicyFor(t, method, tc.opts...).
				Evaluate(t.Context(), mfaInput(tc.kind))

			reqOpts := []policy.MFARequirementOption{
				policy.WithMFARequirementLogger(mfaLogger(&bytes.Buffer{})),
				policy.WithMFARequiredForAll(),
			}
			if tc.reqOpt != nil {
				reqOpts = append(reqOpts, tc.reqOpt)
			}

			requirement := mfaRequirementPolicyFor(t, nil, method, reqOpts...).
				Evaluate(mfaPhaseContext(t, policy.PerRequest), mfaInput(tc.kind))

			tc.assert(t, challenge, requirement)
		})
	}
}
