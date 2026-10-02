package policy_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

// TestMFARequirementPolicy_Federated pins the requirement policy's decision for
// a login on the federated channel at login and in the phases that refuse it,
// under each federated-assurance mode.
func TestMFARequirementPolicy_Federated(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// required is the per-user lookup; nil requires a second factor of
		// everyone without one.
		required func(t *testing.T) identity.MFARequirementLookup
		methods  func(t *testing.T) []policy.MFAMethodLookup
		// source is the assurance source; nil wires none.
		source func(t *testing.T) policy.FederatedAssuranceSource
		opts   []policy.MFARequirementOption
		phase  policy.Phase
		in     func() *policy.Input
		assert func(t *testing.T, d policy.Decision, err error)
	}

	// The lookups a case never expects to be asked carry no expectation, so a
	// policy that asked them anyway fails the case.
	requiredUser := func(t *testing.T) identity.MFARequirementLookup {
		return mfaRequirementLookup(t, true, true, nil)
	}
	enrolledTOTP := func(t *testing.T) []policy.MFAMethodLookup {
		return mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil))
	}
	unenrolledTOTP := func(t *testing.T) []policy.MFAMethodLookup {
		return mfaMethods(mfaMethod(t, factor.AuthenticatorApp, false, nil))
	}
	unenrolledEnrollable := func(t *testing.T) []policy.MFAMethodLookup {
		return mfaMethods(canEnrol(mfaMethod(t, factor.AuthenticatorApp, false, nil)))
	}
	idleTOTP := func(t *testing.T) []policy.MFAMethodLookup {
		return mfaMethods(idleMFAMethod(t, mfaMethodName(factor.AuthenticatorApp)))
	}
	met := func(t *testing.T) policy.FederatedAssuranceSource { return assuranceSource(t, true, true, nil) }
	notMet := func(t *testing.T) policy.FederatedAssuranceSource { return assuranceSource(t, true, false, nil) }
	unasked := func(t *testing.T) policy.FederatedAssuranceSource { return assuranceSource(t, false, false, nil) }

	oidcLogin := func() *policy.Input { return federatedInput(factor.OIDC, federatedEvidence("pwd")) }
	exemptOIDC := policy.WithMFAExemption(func(k factor.Kind) bool { return k == factor.OIDC || k.MFAExempt() })

	allowed := func(t *testing.T, d policy.Decision, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.Equal(t, policy.Allow, d.Outcome)
		assert.NoError(t, d.Reason)
	}
	challengedForMFA := func(t *testing.T, d policy.Decision, err error) {
		t.Helper()

		require.NoError(t, err)
		require.Equal(t, policy.Challenge, d.Outcome)
		assert.Equal(t, policy.ChallengeMFA, d.Challenge)
		assert.NoError(t, d.Reason)
	}
	denied := func(reason error) func(t *testing.T, d policy.Decision, err error) {
		return func(t *testing.T, d policy.Decision, err error) {
			t.Helper()

			require.NoError(t, err)
			deniedWith(reason)(t, d)
		}
	}

	cases := []testCase{
		{
			name:     "assurance met allows a required user enrolled on nothing",
			required: requiredUser, methods: idleTOTP, source: met,
			phase: policy.PostAuthentication, in: oidcLogin, assert: allowed,
		},
		{
			name:     "not met, enrolled, default mode challenges for mfa",
			required: requiredUser, methods: enrolledTOTP, source: notMet,
			phase: policy.PostAuthentication, in: oidcLogin, assert: challengedForMFA,
		},
		{
			name:    "not met, not enrolled, required for all, default mode denies for enrolment",
			methods: unenrolledTOTP, source: notMet,
			phase: policy.PostAuthentication, in: oidcLogin,
			assert: denied(policy.ErrMFAEnrollmentRequired),
		},
		{
			name:     "refuse mode denies an unmet login with the assurance-not-met reason",
			required: requiredUser, methods: idleTOTP, source: notMet,
			opts:  []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceRefuse)},
			phase: policy.PostAuthentication, in: oidcLogin,
			assert: denied(policy.ErrFederatedAssuranceNotMet),
		},
		{
			name:     "refuse mode allows a met login",
			required: requiredUser, methods: idleTOTP, source: met,
			opts:  []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceRefuse)},
			phase: policy.PostAuthentication, in: oidcLogin, assert: allowed,
		},
		{
			// The proof is decided before the refusal, as the order states.
			name:     "refuse mode honours the library's proof before refusing",
			required: requiredUser, methods: idleTOTP, source: notMet,
			opts:  []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceRefuse)},
			phase: policy.PostAuthentication,
			in: func() *policy.Input {
				in := oidcLogin()
				in.SecondFactorAtLogin = policy.MintProofForTest(factor.OIDC, mfaNow)

				return in
			},
			assert: allowed,
		},
		{
			// Exempt mode is decided before the requirement is looked up: a
			// lookup that would fail is never called, and nothing else is.
			name: "exempt mode allows without consulting any lookup or source",
			required: func(t *testing.T) identity.MFARequirementLookup {
				m := NewMockMFARequirementLookup(gomock.NewController(t))
				m.EXPECT().Required(gomock.Any(), gomock.Any()).Return(false, errRequirementStore).Times(0)

				return m
			},
			methods: idleTOTP, source: unasked,
			opts:  []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceExempt)},
			phase: policy.PostAuthentication, in: oidcLogin, assert: allowed,
		},
		{
			name:     "exempt mode allows a federated session per request",
			required: func(t *testing.T) identity.MFARequirementLookup { return mfaRequirementLookup(t, false, true, nil) },
			methods:  idleTOTP, source: unasked,
			opts:  []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceExempt)},
			phase: policy.PerRequest, in: oidcLogin, assert: allowed,
		},
		{
			name:    "exempt mode does not exempt a login off the federated channel",
			methods: unenrolledTOTP,
			opts:    []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceExempt)},
			phase:   policy.PostAuthentication,
			in:      func() *policy.Input { return mfaInput(factor.Password) },
			assert:  denied(policy.ErrMFAEnrollmentRequired),
		},
		{
			name:    "a consumer exemption rule marking oidc exempt is a total exemption",
			methods: idleTOTP, source: unasked,
			opts:  []policy.MFARequirementOption{exemptOIDC},
			phase: policy.PostAuthentication, in: oidcLogin, assert: allowed,
		},
		{
			name:     "a source error denies with that error as the reason",
			required: requiredUser, methods: idleTOTP,
			source: func(t *testing.T) policy.FederatedAssuranceSource {
				return assuranceSource(t, true, true, errAssuranceSource)
			},
			phase: policy.PostAuthentication, in: oidcLogin,
			assert: func(t *testing.T, d policy.Decision, err error) {
				require.NoError(t, err)
				require.Equal(t, policy.Deny, d.Outcome)
				require.ErrorIs(t, d.Reason, errAssuranceSource)
				assert.NotContains(t, d.Reason.Error(), errAssuranceSource.Error(),
					"the reason repeats the source's own text")
			},
		},
		{
			name:     "refuse mode with a source error denies with that error as the reason",
			required: requiredUser, methods: idleTOTP,
			source: func(t *testing.T) policy.FederatedAssuranceSource {
				return assuranceSource(t, true, true, errAssuranceSource)
			},
			opts:  []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceRefuse)},
			phase: policy.PostAuthentication, in: oidcLogin,
			assert: func(t *testing.T, d policy.Decision, err error) {
				require.NoError(t, err)
				require.Equal(t, policy.Deny, d.Outcome)
				require.ErrorIs(t, d.Reason, errAssuranceSource)
				assert.NotErrorIs(t, d.Reason, policy.ErrFederatedAssuranceNotMet)
			},
		},
		{
			name:     "refuse mode in a stateless phase is refused before the source is asked",
			required: requiredUser, methods: idleTOTP, source: unasked,
			opts:  []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceRefuse)},
			phase: policy.StatelessAuthentication, in: oidcLogin,
			assert: denied(policy.ErrMFARequired),
		},
		{
			name:     "refuse mode in an undeclared phase is refused before the source is asked",
			required: requiredUser, methods: enrolledTOTP, source: unasked,
			opts:  []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceRefuse)},
			phase: policy.PreAuthentication, in: oidcLogin,
			assert: denied(policy.ErrMFARequired),
		},
		{
			name:     "zero evidence is challenged for mfa without asking the source",
			required: requiredUser, methods: enrolledTOTP, source: unasked,
			phase:  policy.PostAuthentication,
			in:     func() *policy.Input { return federatedInput(factor.OIDC, policy.FederatedAssurance{}) },
			assert: challengedForMFA,
		},
		{
			name:     "no source wired is challenged for mfa, whatever the evidence asserts",
			required: requiredUser, methods: enrolledTOTP,
			phase:  policy.PostAuthentication,
			in:     func() *policy.Input { return federatedInput(factor.OIDC, federatedEvidence("mfa")) },
			assert: challengedForMFA,
		},
		{
			name:    "a consumer path admitting oidc sends an unmet, unenrolled user to enrol",
			methods: unenrolledEnrollable, source: notMet,
			opts: []policy.MFARequirementOption{policy.WithMFAEnrolmentPath(
				policy.WithEnrolmentFirstFactors(factor.Password, factor.MagicLink, factor.OIDC))},
			phase: policy.PostAuthentication, in: oidcLogin,
			assert: func(t *testing.T, d policy.Decision, err error) {
				require.NoError(t, err)
				challengedForEnrolment(t, d)
			},
		},
		{
			name:    "oidc is off the path's default list",
			methods: unenrolledEnrollable, source: notMet,
			opts:  []policy.MFARequirementOption{policy.WithMFAEnrolmentPath()},
			phase: policy.PostAuthentication, in: oidcLogin,
			assert: denied(policy.ErrMFAEnrollmentRequired),
		},
		{
			name:     "met assurance is decided before an empty set of methods",
			required: requiredUser,
			methods:  func(*testing.T) []policy.MFAMethodLookup { return nil },
			source:   met,
			phase:    policy.PostAuthentication, in: oidcLogin, assert: allowed,
		},
		{
			name:     "unmet assurance with no method configured denies mfa-required",
			required: requiredUser,
			methods:  func(*testing.T) []policy.MFAMethodLookup { return nil },
			source:   notMet,
			phase:    policy.PostAuthentication, in: oidcLogin,
			assert: denied(policy.ErrMFARequired),
		},
		{
			name:     "a stateless federated request is refused before the source is asked",
			required: requiredUser, methods: idleTOTP, source: unasked,
			phase: policy.StatelessAuthentication, in: oidcLogin,
			assert: denied(policy.ErrMFARequired),
		},
		{
			name:     "an undeclared phase is refused before the source is asked",
			required: requiredUser, methods: enrolledTOTP, source: unasked,
			phase: policy.PreAuthentication, in: oidcLogin,
			assert: denied(policy.ErrMFARequired),
		},
		{
			name:     "a user who is not required is allowed without asking the source",
			required: func(t *testing.T) identity.MFARequirementLookup { return mfaRequirementLookup(t, true, false, nil) },
			methods:  idleTOTP, source: unasked,
			phase: policy.PostAuthentication, in: oidcLogin, assert: allowed,
		},
		{
			name:    "an unknown mode is a configuration error",
			methods: idleTOTP,
			opts:    []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceMode(9))},
			phase:   policy.PostAuthentication, in: oidcLogin,
			assert: func(t *testing.T, _ policy.Decision, err error) {
				assert.ErrorIs(t, err, policy.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := []policy.MFARequirementOption{policy.WithMFARequirementLogger(mfaLogger(&bytes.Buffer{}))}

			var required identity.MFARequirementLookup
			if tc.required != nil {
				required = tc.required(t)
			} else {
				opts = append(opts, policy.WithMFARequiredForAll())
			}
			if tc.source != nil {
				opts = append(opts, policy.WithFederatedAssuranceSource(tc.source(t)))
			}
			opts = append(opts, tc.opts...)

			p, err := policy.NewMFARequirementPolicy(required, tc.methods(t), opts...)
			if err != nil {
				tc.assert(t, policy.Decision{}, err)

				return
			}

			tc.assert(t, p.Evaluate(mfaPhaseContext(t, tc.phase), tc.in()), nil)
		})
	}
}

// TestMFARequirementPolicy_FederatedPerRequest pins that a federated session's
// stored assurance is matched again, through the source, on every per-request
// evaluation, and that a decision made at login is never trusted in its place.
func TestMFARequirementPolicy_FederatedPerRequest(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// required is the per-user lookup; nil requires a second factor of
		// everyone without one.
		required func(t *testing.T) identity.MFARequirementLookup
		methods  func(t *testing.T) []policy.MFAMethodLookup
		// source is the assurance source; nil wires none.
		source func(t *testing.T) policy.FederatedAssuranceSource
		opts   []policy.MFARequirementOption
		in     func() *policy.Input
		assert func(t *testing.T, d policy.Decision)
	}

	requiredUser := func(t *testing.T) identity.MFARequirementLookup {
		return mfaRequirementLookup(t, true, true, nil)
	}
	enrolledTOTP := func(t *testing.T) []policy.MFAMethodLookup {
		return mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil))
	}
	unenrolledTOTP := func(t *testing.T) []policy.MFAMethodLookup {
		return mfaMethods(mfaMethod(t, factor.AuthenticatorApp, false, nil))
	}
	unenrolledEnrollable := func(t *testing.T) []policy.MFAMethodLookup {
		return mfaMethods(canEnrol(mfaMethod(t, factor.AuthenticatorApp, false, nil)))
	}
	idleTOTP := func(t *testing.T) []policy.MFAMethodLookup {
		return mfaMethods(idleMFAMethod(t, mfaMethodName(factor.AuthenticatorApp)))
	}

	// rematched is a source asked exactly once, about this session's own
	// evidence, which answers met and err. It is how a case shows the decision came
	// from matching the stored evidence now, not from anything recorded at
	// login.
	rematched := func(met bool, err error) func(t *testing.T) policy.FederatedAssuranceSource {
		return func(t *testing.T) policy.FederatedAssuranceSource {
			m := NewMockFederatedAssuranceSource(gomock.NewController(t))
			m.EXPECT().MeetsAssurance(gomock.Any(), identity.UserID(mfaUser), gomock.Any()).
				DoAndReturn(func(_ context.Context, _ identity.UserID, ev policy.FederatedAssurance) (bool, error) {
					assert.Equal(t, "corp", ev.Provider(), "the source was not handed the session's evidence")
					assert.Equal(t, []string{"mfa"}, ev.AMR(), "the source was not handed the session's evidence")

					return met, err
				}).
				Times(1)

			return m
		}
	}
	// registeredOnly is a source that knows only the provider named, as a
	// manager rebuilt without the others: evidence from any other provider
	// is never met, whatever its amr, and that of the one it knows is.
	registeredOnly := func(known string) func(t *testing.T) policy.FederatedAssuranceSource {
		return func(t *testing.T) policy.FederatedAssuranceSource {
			m := NewMockFederatedAssuranceSource(gomock.NewController(t))
			m.EXPECT().MeetsAssurance(gomock.Any(), identity.UserID(mfaUser), gomock.Any()).
				DoAndReturn(func(_ context.Context, _ identity.UserID, ev policy.FederatedAssurance) (bool, error) {
					return ev.Provider() == known, nil
				}).
				Times(1)

			return m
		}
	}
	sessionOf := func(provider string) func() *policy.Input {
		return func() *policy.Input {
			return federatedInput(factor.OIDC, policy.MintFederatedForTest(provider, "https://idp.example", []string{"mfa"}, ""))
		}
	}
	unasked := func(t *testing.T) policy.FederatedAssuranceSource { return assuranceSource(t, false, false, nil) }

	// session is a federated session whose login asserted amr ["mfa"], which
	// the provider accepted at the time.
	session := func() *policy.Input { return federatedInput(factor.OIDC, federatedEvidence("mfa")) }
	satisfiedSession := func() *policy.Input {
		in := session()
		in.MFASatisfied = true

		return in
	}

	allowed := func(t *testing.T, d policy.Decision) {
		t.Helper()

		assert.Equal(t, policy.Allow, d.Outcome)
		assert.NoError(t, d.Reason)
	}
	challengedForMFA := func(t *testing.T, d policy.Decision) {
		t.Helper()

		require.Equal(t, policy.Challenge, d.Outcome, "the session was let through on its login")
		assert.Equal(t, policy.ChallengeMFA, d.Challenge)
		assert.NoError(t, d.Reason)
	}
	// deniedForEnrolment is Review Focus 1: a tightened provider, no usable
	// enrolment and the path off. The stale login must not let the session
	// through; the user is told what they are missing.
	deniedForEnrolment := func(t *testing.T, d policy.Decision) {
		t.Helper()

		require.NotEqual(t, policy.Allow, d.Outcome, "the session was allowed on its stale login")
		deniedWith(policy.ErrMFAEnrollmentRequired)(t, d)
	}

	cases := []testCase{
		{
			name:     "provider tightened: an enrolled user's session is challenged for mfa",
			required: requiredUser, methods: enrolledTOTP, source: rematched(false, nil),
			in: session, assert: challengedForMFA,
		},
		{
			// The source no longer knows the session's provider, so the same
			// amr that was met before is not met now.
			name:     "provider removed: an enrolled user's session is challenged for mfa",
			required: requiredUser, methods: enrolledTOTP, source: registeredOnly("corp"),
			in: sessionOf("gone"), assert: challengedForMFA,
		},
		{
			name:     "another provider's session is still met when one provider is removed",
			required: requiredUser, methods: idleTOTP, source: registeredOnly("corp"),
			in: sessionOf("corp"), assert: allowed,
		},
		{
			name:     "assurance still met: the session is allowed",
			required: requiredUser, methods: idleTOTP, source: rematched(true, nil),
			in: session, assert: allowed,
		},
		{
			name:     "a session satisfied by the library's verification is allowed without asking the source",
			required: requiredUser, methods: idleTOTP, source: unasked,
			in: satisfiedSession, assert: allowed,
		},
		{
			name:     "a locally satisfied session is allowed in refuse mode too",
			required: requiredUser, methods: idleTOTP, source: unasked,
			opts: []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceRefuse)},
			in:   satisfiedSession, assert: allowed,
		},
		{
			name:     "provider tightened in refuse mode: the session is denied with assurance-not-met",
			required: requiredUser, methods: idleTOTP, source: rematched(false, nil),
			opts:   []policy.MFARequirementOption{policy.WithFederatedAssurance(policy.FederatedAssuranceRefuse)},
			in:     session,
			assert: deniedWith(policy.ErrFederatedAssuranceNotMet),
		},
		{
			name:     "a source error per request denies with that error as the reason",
			required: requiredUser, methods: idleTOTP, source: rematched(true, errAssuranceSource),
			in: session,
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome)
				require.ErrorIs(t, d.Reason, errAssuranceSource)
				assert.NotContains(t, d.Reason.Error(), errAssuranceSource.Error(),
					"the reason repeats the source's own text")
			},
		},
		{
			name:     "no source wired: an enrolled user's session is challenged, whatever its login asserted",
			required: requiredUser, methods: enrolledTOTP,
			in: session, assert: challengedForMFA,
		},
		{
			name:     "provider tightened, no usable enrolment, path off: denied for enrolment",
			required: requiredUser, methods: unenrolledTOTP, source: rematched(false, nil),
			in: session, assert: deniedForEnrolment,
		},
		{
			name:    "provider tightened, no usable enrolment, required for all, path off: denied for enrolment",
			methods: unenrolledTOTP, source: rematched(false, nil),
			in: session, assert: deniedForEnrolment,
		},
		{
			name:     "provider tightened, no usable enrolment, path on without oidc: denied for enrolment",
			required: requiredUser, methods: unenrolledEnrollable, source: rematched(false, nil),
			opts: []policy.MFARequirementOption{policy.WithMFAEnrolmentPath()},
			in:   session, assert: deniedForEnrolment,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := []policy.MFARequirementOption{policy.WithMFARequirementLogger(mfaLogger(&bytes.Buffer{}))}

			var required identity.MFARequirementLookup
			if tc.required != nil {
				required = tc.required(t)
			} else {
				opts = append(opts, policy.WithMFARequiredForAll())
			}
			if tc.source != nil {
				opts = append(opts, policy.WithFederatedAssuranceSource(tc.source(t)))
			}
			opts = append(opts, tc.opts...)

			p := mfaRequirementPolicyOver(t, required, tc.methods(t), opts...)
			tc.assert(t, p.Evaluate(mfaPhaseContext(t, policy.PerRequest), tc.in()))
		})
	}
}

// TestMFARequirementPolicy_FederatedRematchedEachRequest pins that one policy
// asks the source again for every request, so a provider tightened between two
// requests of one session decides the second. It stands apart from the table
// above because it evaluates one policy twice against a source whose answer
// changes.
func TestMFARequirementPolicy_FederatedRematchedEachRequest(t *testing.T) {
	t.Parallel()

	src := NewMockFederatedAssuranceSource(gomock.NewController(t))
	gomock.InOrder(
		src.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil).Times(1),
		src.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil).Times(1),
	)

	p := mfaRequirementPolicyFor(t,
		mfaRequirementLookup(t, true, true, nil),
		mfaMethod(t, factor.AuthenticatorApp, true, nil),
		policy.WithFederatedAssuranceSource(src))
	ctx := mfaPhaseContext(t, policy.PerRequest)

	before := p.Evaluate(ctx, federatedInput(factor.OIDC, federatedEvidence("mfa")))
	after := p.Evaluate(ctx, federatedInput(factor.OIDC, federatedEvidence("mfa")))

	assert.Equal(t, policy.Allow, before.Outcome, "the session was not allowed while its assurance was met")
	require.Equal(t, policy.Challenge, after.Outcome,
		"the session was let through on an answer the source no longer gives")
	assert.Equal(t, policy.ChallengeMFA, after.Challenge)
}

func TestMFARequirementPolicy_FederatedRefusalRecord(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	p := mfaRequirementPolicyFor(t,
		mfaRequirementLookup(t, true, true, nil),
		mfaMethod(t, factor.AuthenticatorApp, true, nil),
		policy.WithFederatedAssuranceSource(assuranceSource(t, true, false, nil)),
		policy.WithFederatedAssurance(policy.FederatedAssuranceRefuse),
		policy.WithMFARequirementLogger(mfaLogger(buf)))

	in := federatedInput(factor.OIDC,
		policy.MintFederatedForTest("corp", "https://idp.example", []string{"pwd"}, "gold"))
	d := p.Evaluate(mfaPhaseContext(t, policy.PostAuthentication), in)

	require.Equal(t, policy.Deny, d.Outcome)
	require.ErrorIs(t, d.Reason, policy.ErrFederatedAssuranceNotMet)

	records := mfaRecords(t, buf)
	require.Len(t, records, 1, "the refusal wrote other than exactly one record")
	assert.Equal(t, logAssuranceNotMet, records[0]["msg"])
	assert.Equal(t, "corp", records[0]["provider"])

	for _, v := range []string{"pwd", "gold"} {
		assert.NotContains(t, buf.String(), v, "the record carried a value the provider asserted")
	}
}

func TestFederatedAssuranceModeString(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		mode   policy.FederatedAssuranceMode
		assert func(t *testing.T, s string)
	}

	named := func(want string) func(t *testing.T, s string) {
		return func(t *testing.T, s string) { assert.Equal(t, want, s) }
	}

	cases := []testCase{
		{name: "challenge", mode: policy.FederatedAssuranceChallenge, assert: named("FederatedAssuranceChallenge")},
		{name: "refuse", mode: policy.FederatedAssuranceRefuse, assert: named("FederatedAssuranceRefuse")},
		{name: "exempt", mode: policy.FederatedAssuranceExempt, assert: named("FederatedAssuranceExempt")},
		{
			name: "an unnamed value is printed as a number, never as a mode",
			mode: policy.FederatedAssuranceMode(9), assert: named("FederatedAssuranceMode(9)"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.mode.String())
		})
	}
}
