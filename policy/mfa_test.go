package policy_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

// sequentialMethodLookup answers its first Enrolled call with (first,
// firstErr) and every call after with (false, err). It is how a case reaches
// the challenge policy's second walk over its methods (enrolledOnAny) with an
// error the first walk (UsableMFAMethods) never saw, because that walk already
// asked every method once and succeeded.
type sequentialMethodLookup struct {
	name     string
	channel  factor.Channel
	first    bool
	firstErr error
	err      error

	calls int
}

func (s *sequentialMethodLookup) Name() string { return s.name }

func (s *sequentialMethodLookup) Channel() factor.Channel { return s.channel }

func (s *sequentialMethodLookup) Enrolled(context.Context, identity.UserID) (bool, error) {
	s.calls++
	if s.calls == 1 {
		return s.first, s.firstErr
	}

	return false, s.err
}

func TestNewMFAPolicy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		methods []policy.MFAMethodLookup
		opts    []policy.MFAOption
		assert  func(t *testing.T, p policy.Policy, err error)
	}

	refused := func(t *testing.T, p policy.Policy, err error) {
		t.Helper()

		require.ErrorIs(t, err, policy.ErrConfig,
			"a policy that cannot work was accepted at wiring time")
		assert.Nil(t, p, "a refused constructor still handed back a policy")
	}

	// consumerClockAt is what a consumer's own read-only clock reports, and
	// consumerClockLogBuf captures what the policy writes under it, for the
	// "consumer clock" row below.
	consumerClockAt := time.Date(2033, time.May, 5, 5, 5, 5, 0, time.UTC)
	consumerClockLogBuf := &bytes.Buffer{}

	// mutableMFAMethods is the slice the "mutating the caller's slice" case
	// below hands the constructor and then overwrites, to show the policy
	// decided from its own copy of the set and not from whatever the caller
	// does to the slice afterward.
	mutableMFAMethods := mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil))

	cases := []testCase{
		{
			name: "no set of methods is refused",
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			name:    "an empty set of methods is refused",
			methods: mfaMethods(),
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			name:    "an absent method lookup is refused",
			methods: mfaMethods(nil),
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			// A nil *MockMFAMethodLookup is a non-nil interface holding a nil
			// pointer, which is what an unchecked constructor result hands
			// over. It would panic at the first login rather than here.
			name:    "a typed-nil method lookup is refused",
			methods: mfaMethods((*MockMFAMethodLookup)(nil)),
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			name:    "an absent method beside a present one is refused",
			methods: mfaMethods(idleMFAMethod(t, "totp"), nil),
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			name:    "a typed-nil method beside a present one is refused",
			methods: mfaMethods(idleMFAMethod(t, "totp"), (*MockMFAMethodLookup)(nil)),
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			// Nothing downstream could tell the two apart: a client naming
			// one would reach whichever came first.
			name:    "two methods of the same name are refused",
			methods: mfaMethods(idleMFAMethod(t, "totp"), idleMFAMethod(t, "totp")),
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			name:    "two methods of different names are accepted",
			methods: mfaMethods(idleMFAMethod(t, "totp"), idleMFAMethod(t, "email-code")),
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.NoError(t, err)
				assert.NotNil(t, p)
			},
		},
		{
			name:    "a nil exemption rule is refused",
			methods: mfaMethods(idleMFAMethod(t, "totp")),
			opts:    []policy.MFAOption{policy.WithMFAExemption(nil)},
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			name:    "a nil clock is refused",
			methods: mfaMethods(idleMFAMethod(t, "totp")),
			opts:    []policy.MFAOption{policy.WithMFAClock(nil)},
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			// *clockwork.FakeClock implements Now through a pointer receiver,
			// so a nil one is an interface holding a nil pointer: `== nil`
			// misses it, and only the reflect-based check the constructor now
			// uses catches it before the first sampled record reads from a nil
			// receiver.
			name:    "a typed-nil clock is refused",
			methods: mfaMethods(idleMFAMethod(t, "totp")),
			opts:    []policy.MFAOption{policy.WithMFAClock((*clockwork.FakeClock)(nil))},
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			// A Now-only consumer type: `time-source` "Read-only source for a
			// read-only component". Construction succeeds, and the policy
			// samples its same-channel records by the consumer's clock: since
			// fixedClock never advances, a one-millisecond sampling window
			// never appears to elapse, so two refusals a real sleep apart
			// still produce one record.
			name:    "a consumer's own read-only clock is accepted and used to sample records",
			methods: mfaMethods(mfaMethod(t, factor.Email, true, nil)),
			opts: []policy.MFAOption{
				policy.WithMFAClock(fixedClock{at: consumerClockAt}),
				policy.WithMFALogger(mfaLogger(consumerClockLogBuf)),
				policy.WithMFALogInterval(time.Millisecond),
			},
			assert: func(t *testing.T, p policy.Policy, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, p)

				in := &policy.Input{User: mfaUser, FirstFactor: factor.MagicLink}
				_ = p.Evaluate(t.Context(), in)
				time.Sleep(50 * time.Millisecond) // real time passes; the frozen clock does not
				_ = p.Evaluate(t.Context(), in)

				assert.Len(t, mfaRecordsOf(t, consumerClockLogBuf, logSameChannelRefused), 1,
					"a clock that never advances must keep the sampling window from ever elapsing")
			},
		},
		{
			name:    "a mode naming neither constant is refused",
			methods: mfaMethods(idleMFAMethod(t, "totp")),
			opts:    []policy.MFAOption{policy.WithMFASameChannelEnrolment(policy.SameChannelMode(7))},
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			name:    "the minimum wiring is a method lookup and nothing else",
			methods: mfaMethods(idleMFAMethod(t, "totp")),
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.NoError(t, err, "the documented minimum wiring was refused")
				require.NotNil(t, p)
				assert.Equal(t, []policy.Phase{policy.PostAuthentication}, p.Phases(),
					"the login challenge would be issued in the wrong phase")
				assert.NotEmpty(t, p.Name(), "the policy has no name to appear in logs under")
			},
		},
		{
			name:    "a nil logger is ignored rather than refused",
			methods: mfaMethods(idleMFAMethod(t, "totp")),
			opts:    []policy.MFAOption{policy.WithMFALogger(nil)},
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.NoError(t, err, "a nil logger made configuring logging mandatory")
				assert.NotNil(t, p)
			},
		},
		{
			// The godoc promises "the policy keeps its own copy of the set".
			// Overwriting the caller's slice after construction must not
			// change what an already-built policy consults.
			name:    "mutating the caller's slice after construction does not change what the policy decided from",
			methods: mutableMFAMethods,
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)

				in := mfaInput(factor.Password)

				before := p.Evaluate(t.Context(), in)
				require.Equal(t, policy.Challenge, before.Outcome,
					"the case's own setup was wrong before the mutation could prove anything")

				mutableMFAMethods[0] = mfaMethod(t, factor.AuthenticatorApp, false, nil)

				after := p.Evaluate(t.Context(), in)
				assert.Equal(t, policy.Challenge, after.Outcome,
					"the policy consulted the caller's slice instead of its own copy")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := policy.NewMFA(tc.methods, tc.opts...)
			tc.assert(t, p, err)
		})
	}
}

func TestMFAPolicyEvaluate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		methods []policy.MFAMethodLookup
		in      *policy.Input
		opts    []policy.MFAOption
		assert  func(t *testing.T, d policy.Decision)
	}

	allows := func(t *testing.T, d policy.Decision) {
		t.Helper()

		assert.Equal(t, policy.Allow, d.Outcome)
		assert.NoError(t, d.Reason, "an allow carried a refusal reason")
	}

	cases := []testCase{
		{
			name:    "a login that has already satisfied a second factor allows",
			methods: mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil)),
			in: &policy.Input{
				User: mfaUser, FirstFactor: factor.Password, MFASatisfied: true, Now: mfaNow,
			},
			assert: allows,
		},
		{
			name:    "an exempt first factor allows",
			methods: mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil)),
			in:      mfaInput(factor.APIKey),
			assert:  allows,
		},
		{
			// A federated login is not exempt by its kind, yet by default this
			// policy lets it through without asking whether the user is
			// enrolled: a user who is not required keeps the behaviour they had.
			name:    "a federated first factor allows by default without consulting a lookup",
			methods: mfaMethods(idleMFAMethod(t, mfaMethodName(factor.AuthenticatorApp))),
			in:      mfaInput(factor.OIDC),
			assert:  allows,
		},
		{
			name:    "a lookup error denies with a reason wrapping it",
			methods: mfaMethods(mfaMethod(t, factor.AuthenticatorApp, false, errEnrolmentStore)),
			in:      mfaInput(factor.Password),
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome,
					"an unreadable enrolment downgraded the user to one factor")
				assert.ErrorIs(t, d.Reason, errEnrolmentStore,
					"the caller cannot see what actually failed")
			},
		},
		{
			name:    "enrolled on a different channel challenges for a second factor",
			methods: mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil)),
			in:      mfaInput(factor.Password),
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Challenge, d.Outcome)
				assert.Equal(t, policy.ChallengeMFA, d.Challenge)
				assert.NoError(t, d.Reason, "a challenge refuses nothing and carries no reason")
			},
		},
		{
			name:    "a user who is not enrolled allows",
			methods: mfaMethods(mfaMethod(t, factor.AuthenticatorApp, false, nil)),
			in:      mfaInput(factor.Password),
			assert:  allows,
		},
		{
			// The empty kind is unknown, so it reports no channel and is never
			// exempt. It must not match an enrolled method either.
			name:    "a login with no recorded first factor is still challenged",
			methods: mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil)),
			in:      mfaInput(""),
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Challenge, d.Outcome)
				assert.Equal(t, policy.ChallengeMFA, d.Challenge)
			},
		},
		{
			name: "enrolled on the second of two methods challenges",
			methods: mfaMethods(
				mfaMethod(t, factor.AuthenticatorApp, false, nil),
				mfaMethod(t, factor.Email, true, nil)),
			in: mfaInput(factor.Password),
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Challenge, d.Outcome,
					"only the first configured method was consulted")
				assert.Equal(t, policy.ChallengeMFA, d.Challenge)
			},
		},
		{
			name: "one method's lookup failing denies, though another is enrolled",
			methods: mfaMethods(
				mfaMethod(t, factor.AuthenticatorApp, true, nil),
				mfaMethod(t, factor.Email, false, errEnrolmentStore)),
			in: mfaInput(factor.Password),
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome,
					"a lookup failure on one method was ignored because another answered")
				assert.ErrorIs(t, d.Reason, errEnrolmentStore)
			},
		},
		{
			name: "a lookup failing ahead of an enrolled method denies",
			methods: mfaMethods(
				mfaMethod(t, factor.Email, false, errEnrolmentStore),
				mfaMethod(t, factor.AuthenticatorApp, true, nil)),
			in: mfaInput(factor.Password),
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, errEnrolmentStore)
			},
		},
		{
			name: "a usable method alongside a same-channel one challenges",
			methods: mfaMethods(
				mfaMethod(t, factor.Email, true, nil),
				mfaMethod(t, factor.AuthenticatorApp, true, nil)),
			in: mfaInput(factor.MagicLink),
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Challenge, d.Outcome,
					"a user with a usable method was refused over a same-channel one")
				assert.Equal(t, policy.ChallengeMFA, d.Challenge)
			},
		},
		{
			name: "enrolled only on same-channel methods is refused by default",
			methods: mfaMethods(
				mfaMethod(t, factor.AuthenticatorApp, false, nil),
				mfaMethod(t, factor.Email, true, nil)),
			in: mfaInput(factor.MagicLink),
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome,
					"a same-channel enrolment on a later method completed silently")
				assert.ErrorIs(t, d.Reason, policy.ErrSecondFactorSameChannel)
			},
		},
		{
			name: "enrolled only on same-channel methods completes when the consumer chose it",
			methods: mfaMethods(
				mfaMethod(t, factor.AuthenticatorApp, false, nil),
				mfaMethod(t, factor.Email, true, nil)),
			in: mfaInput(factor.MagicLink),
			opts: []policy.MFAOption{
				policy.WithMFASameChannelEnrolment(policy.SameChannelCompleteOnFirstFactor),
			},
			assert: allows,
		},
		{
			name: "enrolled on none of several methods allows",
			methods: mfaMethods(
				mfaMethod(t, factor.AuthenticatorApp, false, nil),
				mfaMethod(t, factor.Email, false, nil)),
			in:     mfaInput(factor.Password),
			assert: allows,
		},
		{
			// The first walk (UsableMFAMethods) asks every method once and
			// finds none usable; the second walk (enrolledOnAny) then asks
			// again and this time fails. Only a stub that answers
			// differently by call count can put the two walks apart.
			name: "a lookup error in the second walk over the same set denies",
			methods: mfaMethods(&sequentialMethodLookup{
				name: mfaMethodName(factor.AuthenticatorApp), channel: factor.AuthenticatorApp,
				err: errEnrolmentStore,
			}),
			in: mfaInput(factor.Password),
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome,
					"an error from the second walk over the methods was not denied")
				assert.ErrorIs(t, d.Reason, errEnrolmentStore)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := mfaPolicyOver(t, tc.methods, tc.opts...)
			tc.assert(t, p.Evaluate(t.Context(), tc.in))
		})
	}
}

// TestMFAPolicy_Federated pins the second-factor challenge policy's decision
// for a login on the federated channel: allowed by default without asking
// anything, and judged on its provider assurance only when the consumer opts
// in with WithMFAFederatedChallengeWhenUnmet.
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

	challengeUnmet := []policy.MFAOption{policy.WithMFAFederatedChallengeWhenUnmet(true)}
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
			opts:    []policy.MFAOption{policy.WithMFAFederatedChallengeWhenUnmet(false)},
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
				policy.WithMFAFederatedChallengeWhenUnmet(true),
				policy.WithMFAExemption(func(k factor.Kind) bool { return k == factor.OIDC || k.MFAExempt() }),
			},
			in: oidcLogin, assert: allowedWithoutProof,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := []policy.MFAOption{policy.WithMFALogger(mfaLogger(&bytes.Buffer{}))}
			if tc.source != nil {
				opts = append(opts, policy.WithFederatedAssuranceSource(tc.source(t)))
			}
			opts = append(opts, tc.opts...)

			p, err := policy.NewMFA(tc.methods(t), opts...)
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

	_, governsRequirement := any(policy.WithMFAFederatedChallengeWhenUnmet(true)).(policy.MFARequirementOption)

	assert.False(t, governsRequirement, "the challenge policy's option also configures the requirement policy")
}

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
				policy.WithMFASameChannelEnrolment(policy.SameChannelCompleteOnFirstFactor),
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
			p, err := policy.NewMFA([]policy.MFAMethodLookup{mfaMethod(t, factor.Email, true, nil)},
				append([]policy.MFAOption{policy.WithMFALogger(mfaLogger(buf))}, tc.opts...)...)
			require.NoError(t, err)

			in := mfaInput(factor.MagicLink)
			tc.assert(t, p.Evaluate(t.Context(), in), in, buf)
		})
	}
}

// TestMFAMethodLookupContract drives a method lookup through each of the three
// answers its contract names — enrolled, not enrolled, and an error — and
// records what each of the two MFA policies does with it.
//
// The rows are the contract: a confirmed enrolment whose secret opens is
// enrolled; an enrolment that was started and never confirmed is not; a store
// failure and a secret that will not decrypt are errors. The assertions are
// what the contract is for: neither policy may read an error as "this user has
// no second factor", because that would let a lost row or an unreadable secret
// downgrade the users who had enrolled.
func TestMFAMethodLookupContract(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		enrolled  bool
		lookupErr error
		assert    func(t *testing.T, challenge, requirement policy.Decision)
	}

	refusesOnError := func(t *testing.T, challenge, requirement policy.Decision, cause error) {
		t.Helper()

		require.Equal(t, policy.Deny, challenge.Outcome,
			"the challenge policy read a failed lookup as a user with no second factor")
		assert.ErrorIs(t, challenge.Reason, cause,
			"the challenge policy's refusal does not say what failed")

		require.Equal(t, policy.Deny, requirement.Outcome,
			"the requirement policy read a failed lookup as a user with no second factor")
		assert.ErrorIs(t, requirement.Reason, cause,
			"the requirement policy's refusal does not say what failed")
	}

	cases := []testCase{
		{
			name:     "a confirmed enrolment whose secret opens is enrolled",
			enrolled: true,
			assert: func(t *testing.T, challenge, requirement policy.Decision) {
				assert.Equal(t, policy.Challenge, challenge.Outcome,
					"an enrolled user was not challenged at login")
				assert.Equal(t, policy.Challenge, requirement.Outcome,
					"a required, enrolled user was not challenged")
			},
		},
		{
			name:     "an enrolment that was never confirmed is not an enrolment",
			enrolled: false,
			assert: func(t *testing.T, challenge, requirement policy.Decision) {
				assert.Equal(t, policy.Allow, challenge.Outcome,
					"an unconfirmed enrolment was challenged for, which nobody could answer")
				require.Equal(t, policy.Deny, requirement.Outcome)
				assert.ErrorIs(t, requirement.Reason, policy.ErrMFAEnrolmentRequired,
					"a required user with no confirmed enrolment was not asked to enrol")
			},
		},
		{
			name:      "a store failure is an error, never a user with no second factor",
			lookupErr: errEnrolmentStore,
			assert: func(t *testing.T, challenge, requirement policy.Decision) {
				refusesOnError(t, challenge, requirement, errEnrolmentStore)
			},
		},
		{
			name:      "a secret that will not decrypt is an error, never a user with no second factor",
			lookupErr: errSecretUnreadable,
			assert: func(t *testing.T, challenge, requirement policy.Decision) {
				refusesOnError(t, challenge, requirement, errSecretUnreadable)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			method := mfaMethod(t, factor.AuthenticatorApp, tc.enrolled, tc.lookupErr)
			in := mfaInput(factor.Password)

			challenge := mfaPolicyFor(t, method).Evaluate(t.Context(), in)

			requirement := mfaRequirementPolicyFor(t,
				mfaRequirementLookup(t, true, true, nil), method).
				Evaluate(mfaPhaseContext(t, policy.PerRequest), in)

			tc.assert(t, challenge, requirement)
		})
	}
}

// lookupStub is a method lookup whose every answer is fixed at construction. It
// is a value type, so a case can build a set of several in one line.
//
// It answers a request whose context has ended with that context's error, as a
// store would, which is how a case shows the caller's context reaches it.
type lookupStub struct {
	name     string
	channel  factor.Channel
	enrolled bool
	err      error
}

func (s lookupStub) Name() string { return s.name }

func (s lookupStub) Channel() factor.Channel { return s.channel }

func (s lookupStub) Enrolled(ctx context.Context, _ identity.UserID) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	return s.enrolled, s.err
}

// lookupNames lists the names of methods, in order, so a case compares a
// result by what a reader recognises.
func lookupNames(methods []policy.MFAMethodLookup) []string {
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		out = append(out, m.Name())
	}

	return out
}

func TestUsableMFAMethods(t *testing.T) {
	t.Parallel()

	storeDown := errors.New("store down")
	totp := lookupStub{name: "totp", channel: factor.AuthenticatorApp, enrolled: true}
	email := lookupStub{name: "email-code", channel: factor.Email, enrolled: true}

	type testCase struct {
		name    string
		methods []policy.MFAMethodLookup
		first   factor.Kind
		ctx     func(ctx context.Context) context.Context
		assert  func(t *testing.T, got []policy.MFAMethodLookup, err error)
	}

	cases := []testCase{
		{
			name:    "usable methods in configuration order",
			methods: []policy.MFAMethodLookup{totp, email},
			first:   factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"totp", "email-code"}, lookupNames(got))
			},
		},
		{
			name:    "the configuration order is kept when it is reversed",
			methods: []policy.MFAMethodLookup{email, totp},
			first:   factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"email-code", "totp"}, lookupNames(got))
			},
		},
		{
			name:    "a method on the first factor's channel is not usable",
			methods: []policy.MFAMethodLookup{totp, email},
			first:   factor.MagicLink,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"totp"}, lookupNames(got))
			},
		},
		{
			name: "a failed lookup is an error, not a shorter list",
			methods: []policy.MFAMethodLookup{
				totp, lookupStub{name: "email-code", channel: factor.Email, err: storeDown},
			},
			first: factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.ErrorIs(t, err, storeDown,
					"a lost enrolment read as a shorter list would downgrade the user")
				assert.Nil(t, got)
			},
		},
		{
			name: "a failed lookup ahead of a usable method is an error too",
			methods: []policy.MFAMethodLookup{
				lookupStub{name: "email-code", channel: factor.Email, err: storeDown}, totp,
			},
			first: factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.ErrorIs(t, err, storeDown)
				assert.Nil(t, got)
			},
		},
		{
			name:    "not enrolled anywhere is an empty list, not an error",
			methods: []policy.MFAMethodLookup{lookupStub{name: "totp", channel: factor.AuthenticatorApp}},
			first:   factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
		{
			name:  "no methods at all is an empty list, not an error",
			first: factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
		{
			name:    "the caller's context reaches every lookup",
			methods: []policy.MFAMethodLookup{totp, email},
			first:   factor.Password,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, got)
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

			got, err := policy.UsableMFAMethods(ctx, tc.methods, mfaUser, tc.first)
			tc.assert(t, got, err)
		})
	}
}
