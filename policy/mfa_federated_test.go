package policy_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/policy"
)

// TestMFAPolicy_Federated pins the second-factor challenge policy's decision
// for a login on the federated channel: allowed by default without asking
// anything, and judged on its provider assurance only when the consumer opts
// in with WithFederatedChallengeWhenUnmet.
func TestMFAPolicy_Federated(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		methods func(t *testing.T) []policy.MFAMethodLookup
		// source is the assurance source; nil wires none.
		source func(t *testing.T) policy.FederatedAssuranceSource
		opts   []policy.MFAOption
		in     func() *policy.Input
		// assert receives the Input after the evaluation, so a case can show
		// the policy wrote nothing to it.
		assert func(t *testing.T, d policy.Decision, err error, in *policy.Input)
	}

	enrolledTOTP := func(t *testing.T) []policy.MFAMethodLookup {
		return mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil))
	}
	unenrolledTOTP := func(t *testing.T) []policy.MFAMethodLookup {
		return mfaMethods(mfaMethod(t, factor.AuthenticatorApp, false, nil))
	}
	failingTOTP := func(t *testing.T) []policy.MFAMethodLookup {
		return mfaMethods(mfaMethod(t, factor.AuthenticatorApp, false, errEnrolmentStore))
	}
	// idleTOTP is a method no case expects to be asked about the user, so a
	// policy that asked it anyway fails the case.
	idleTOTP := func(t *testing.T) []policy.MFAMethodLookup {
		return mfaMethods(idleMFAMethod(t, mfaMethodName(factor.AuthenticatorApp)))
	}
	met := func(t *testing.T) policy.FederatedAssuranceSource { return assuranceSource(t, true, true, nil) }
	notMet := func(t *testing.T) policy.FederatedAssuranceSource { return assuranceSource(t, true, false, nil) }
	unasked := func(t *testing.T) policy.FederatedAssuranceSource { return assuranceSource(t, false, false, nil) }

	challengeUnmet := []policy.MFAOption{policy.WithFederatedChallengeWhenUnmet(true)}
	oidcLogin := func() *policy.Input { return federatedInput(factor.OIDC, federatedEvidence("pwd")) }

	allowed := func(t *testing.T, d policy.Decision, err error, _ *policy.Input) {
		t.Helper()

		require.NoError(t, err)
		assert.Equal(t, policy.Allow, d.Outcome)
		assert.NoError(t, d.Reason)
	}
	// allowedWithoutProof is an allow that left the login carrying no proof
	// that its second factor was met, and no satisfied second factor: the
	// provider's assurance is evidence, never the proof.
	allowedWithoutProof := func(t *testing.T, d policy.Decision, err error, in *policy.Input) {
		t.Helper()

		allowed(t, d, err, in)
		assert.False(t, in.SecondFactorAtLogin.Holds(), "federated evidence was turned into the proof")
		assert.False(t, in.MFASatisfied, "federated evidence marked the second factor satisfied")
	}
	challengedForMFA := func(t *testing.T, d policy.Decision, err error, _ *policy.Input) {
		t.Helper()

		require.NoError(t, err)
		require.Equal(t, policy.Challenge, d.Outcome, "an unmet federated login was let through")
		assert.Equal(t, policy.ChallengeMFA, d.Challenge)
		assert.NoError(t, d.Reason)
	}

	cases := []testCase{
		{
			name:    "default: an oidc login without accepted assurance is allowed for an enrolled user, asking no lookup",
			methods: idleTOTP,
			in:      oidcLogin, assert: allowedWithoutProof,
		},
		{
			name:    "default: a wired source is not asked",
			methods: idleTOTP, source: unasked,
			in: oidcLogin, assert: allowedWithoutProof,
		},
		{
			name:    "turned off explicitly, without a source: accepted, and allowed",
			methods: idleTOTP,
			opts:    []policy.MFAOption{policy.WithFederatedChallengeWhenUnmet(false)},
			in:      oidcLogin, assert: allowedWithoutProof,
		},
		{
			name:    "opted in, not met, enrolled on totp: challenged for mfa",
			methods: enrolledTOTP, source: notMet, opts: challengeUnmet,
			in: oidcLogin, assert: challengedForMFA,
		},
		{
			name:    "opted in, met, enrolled on totp: allowed without asking any lookup, and carries no proof",
			methods: idleTOTP, source: met, opts: challengeUnmet,
			in:     func() *policy.Input { return federatedInput(factor.OIDC, federatedEvidence("mfa")) },
			assert: allowedWithoutProof,
		},
		{
			name:    "opted in without a source: a configuration error",
			methods: idleTOTP, opts: challengeUnmet,
			in: oidcLogin,
			assert: func(t *testing.T, _ policy.Decision, err error, _ *policy.Input) {
				assert.ErrorIs(t, err, policy.ErrConfig)
			},
		},
		{
			name:    "opted in, a source error denies with that error as the reason",
			methods: idleTOTP, opts: challengeUnmet,
			source: func(t *testing.T) policy.FederatedAssuranceSource {
				return assuranceSource(t, true, true, errAssuranceSource)
			},
			in: oidcLogin,
			assert: func(t *testing.T, d policy.Decision, err error, _ *policy.Input) {
				require.NoError(t, err)
				require.Equal(t, policy.Deny, d.Outcome, "an undecidable assurance was read as met")
				require.ErrorIs(t, d.Reason, errAssuranceSource)
				assert.NotContains(t, d.Reason.Error(), errAssuranceSource.Error(),
					"the reason repeats the source's own text")
			},
		},
		{
			name:    "opted in, zero evidence: challenged without asking the source",
			methods: enrolledTOTP, source: unasked, opts: challengeUnmet,
			in:     func() *policy.Input { return federatedInput(factor.OIDC, policy.FederatedAssurance{}) },
			assert: challengedForMFA,
		},
		{
			// With the option an unmet login is judged like any other, and a
			// user enrolled on nothing has nothing to be challenged on.
			name:    "opted in, not met, enrolled on nothing: allowed",
			methods: unenrolledTOTP, source: notMet, opts: challengeUnmet,
			in: oidcLogin, assert: allowedWithoutProof,
		},
		{
			name:    "opted in, not met, the enrolment lookup fails: denied with a reason wrapping it",
			methods: failingTOTP, source: notMet, opts: challengeUnmet,
			in: oidcLogin,
			assert: func(t *testing.T, d policy.Decision, err error, _ *policy.Input) {
				require.NoError(t, err)
				require.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, errEnrolmentStore)
			},
		},
		{
			// Evidence placed on a login of another channel is not a federated
			// login, whatever it carries.
			name:    "opted in, a password login carrying evidence is judged by its enrolment, the source unasked",
			methods: enrolledTOTP, source: unasked, opts: challengeUnmet,
			in:     func() *policy.Input { return federatedInput(factor.Password, federatedEvidence("mfa")) },
			assert: challengedForMFA,
		},
		{
			name:    "opted in, a passkey proof decides before any evidence, the source unasked",
			methods: idleTOTP, source: unasked, opts: challengeUnmet,
			in: func() *policy.Input {
				in := federatedInput(factor.Passkey, federatedEvidence("mfa"))
				in.SecondFactorAtLogin = policy.MintProofForTest(factor.Passkey, mfaNow)

				return in
			},
			assert: allowed,
		},
		{
			name:    "opted in, a consumer rule exempting oidc allows before the source is asked",
			methods: idleTOTP, source: unasked,
			opts: []policy.MFAOption{
				policy.WithFederatedChallengeWhenUnmet(true),
				policy.WithMFAExemption(func(k factor.Kind) bool { return k == factor.OIDC || k.MFAExempt() }),
			},
			in: oidcLogin, assert: allowedWithoutProof,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := []policy.MFAOption{policy.WithMFAPolicyLogger(mfaLogger(&bytes.Buffer{}))}
			if tc.source != nil {
				opts = append(opts, policy.WithFederatedAssuranceSource(tc.source(t)))
			}
			opts = append(opts, tc.opts...)

			p, err := policy.NewMFAPolicy(tc.methods(t), opts...)
			if err != nil {
				tc.assert(t, policy.Decision{}, err, nil)

				return
			}

			in := tc.in()
			d := p.Evaluate(t.Context(), in)
			tc.assert(t, d, nil, in)
		})
	}
}

// TestWithFederatedChallengeWhenUnmet_ChallengePolicyOnly pins that the option
// is named for the second-factor challenge policy alone: the requirement
// policy decides a required user's federated login by its own mode, and does
// not accept this option.
func TestWithFederatedChallengeWhenUnmet_ChallengePolicyOnly(t *testing.T) {
	t.Parallel()

	_, governsRequirement := any(policy.WithFederatedChallengeWhenUnmet(true)).(policy.MFARequirementOption)

	assert.False(t, governsRequirement, "the challenge policy's option also configures the requirement policy")
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
					policy.WithFederatedChallengeWhenUnmet(true))
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
