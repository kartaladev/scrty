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
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

// errRequirementStore stands for a requirement lookup that could not answer.
var errRequirementStore = errors.New("the requirement store refused the connection")

func TestNewMFARequirementPolicy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		lookup  identity.MFARequirementLookup
		methods []policy.MFAMethodLookup
		opts    []policy.MFARequirementOption
		assert  func(t *testing.T, p policy.Policy, err error)
	}

	// consumerRequirementClockAt is what a consumer's own read-only clock
	// reports, and consumerRequirementClockLogBuf captures what the policy
	// writes under it, for the "consumer clock" row below.
	consumerRequirementClockAt := time.Date(2034, time.June, 6, 6, 6, 6, 0, time.UTC)
	consumerRequirementClockLogBuf := &bytes.Buffer{}

	// mutableRequirementMethods is the slice the "mutating the caller's
	// slice" case below hands the constructor and then overwrites, to show
	// the policy decided from its own copy of the set and not from whatever
	// the caller does to the slice afterward.
	mutableRequirementMethods := mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil))

	cases := []testCase{
		{
			name:    "a policy with no lookup and no requirement for all can answer nothing",
			methods: mfaMethods(idleMFAMethod(t, "totp")),
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.ErrorIs(t, err, policy.ErrMFARequirementLookupMissing)
				assert.ErrorIs(t, err, policy.ErrConfig,
					"a wiring mistake was not reported as one")
				assert.Nil(t, p)
			},
		},
		{
			// A nil *MockMFARequirementLookup is a non-nil interface holding a
			// nil pointer, which is what an unchecked constructor result hands
			// over.
			name:    "a typed-nil lookup is as absent as a nil one",
			lookup:  (*MockMFARequirementLookup)(nil),
			methods: mfaMethods(idleMFAMethod(t, "totp")),
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.ErrorIs(t, err, policy.ErrMFARequirementLookupMissing)
				assert.Nil(t, p)
			},
		},
		{
			name: "requiring a second factor of everyone with no method to present is unsatisfiable",
			opts: []policy.MFARequirementOption{policy.WithMFARequiredForAll()},
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.ErrorIs(t, err, policy.ErrMFARequirementUnsatisfiable)
				assert.ErrorIs(t, err, policy.ErrConfig,
					"a wiring mistake was not reported as one")
				assert.Nil(t, p)
			},
		},
		{
			name:    "requiring a second factor of everyone with an empty set of methods is unsatisfiable",
			methods: mfaMethods(),
			opts:    []policy.MFARequirementOption{policy.WithMFARequiredForAll()},
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.ErrorIs(t, err, policy.ErrMFARequirementUnsatisfiable)
				assert.ErrorIs(t, err, policy.ErrConfig)
				assert.Nil(t, p)
			},
		},
		{
			name:    "a typed-nil method is refused",
			methods: mfaMethods((*MockMFAMethodLookup)(nil)),
			opts:    []policy.MFARequirementOption{policy.WithMFARequiredForAll()},
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.ErrorIs(t, err, policy.ErrConfig)
				assert.Nil(t, p)
			},
		},
		{
			name:    "an absent method beside a present one is refused",
			lookup:  NewMockMFARequirementLookup(gomock.NewController(t)),
			methods: mfaMethods(idleMFAMethod(t, "totp"), nil),
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.ErrorIs(t, err, policy.ErrConfig,
					"a set holding an absent method was accepted, to panic at the first login")
				assert.Nil(t, p)
			},
		},
		{
			name:    "a typed-nil method beside a present one is refused",
			lookup:  NewMockMFARequirementLookup(gomock.NewController(t)),
			methods: mfaMethods(idleMFAMethod(t, "totp"), (*MockMFAMethodLookup)(nil)),
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.ErrorIs(t, err, policy.ErrConfig)
				assert.Nil(t, p)
			},
		},
		{
			name:    "two methods of the same name are refused",
			lookup:  NewMockMFARequirementLookup(gomock.NewController(t)),
			methods: mfaMethods(idleMFAMethod(t, "totp"), idleMFAMethod(t, "totp")),
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.ErrorIs(t, err, policy.ErrConfig,
					"two methods nothing could tell apart were accepted")
				assert.Nil(t, p)
			},
		},
		{
			// An empty set means no method is configured, which a per-user
			// lookup can live with: a required user is refused.
			name:    "an empty set with a per-user lookup is accepted, and refuses a required user",
			lookup:  mfaRequirementLookup(t, true, true, nil),
			methods: mfaMethods(),
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)

				d := p.Evaluate(mfaPhaseContext(t, policy.PerRequest), mfaInput(factor.Password))
				require.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, policy.ErrMFARequired)
			},
		},
		{
			name:    "requiring a second factor of everyone needs no lookup",
			methods: mfaMethods(idleMFAMethod(t, "totp")),
			opts:    []policy.MFARequirementOption{policy.WithMFARequiredForAll()},
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t,
					[]policy.Phase{
						policy.PostAuthentication,
						policy.PerRequest,
						policy.StatelessAuthentication,
					},
					p.Phases(), "the requirement would not be enforced in every phase it covers")
			},
		},
		{
			name:   "a per-user lookup needs no method, because an unenrolled user is refused",
			lookup: NewMockMFARequirementLookup(gomock.NewController(t)),
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.NoError(t, err)
				assert.NotNil(t, p)
			},
		},
		{
			name:   "a nil exemption rule is refused",
			lookup: NewMockMFARequirementLookup(gomock.NewController(t)),
			opts:   []policy.MFARequirementOption{policy.WithMFAExemption(nil)},
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.ErrorIs(t, err, policy.ErrConfig)
				assert.Nil(t, p)
			},
		},
		{
			name:   "a nil clock is refused",
			lookup: NewMockMFARequirementLookup(gomock.NewController(t)),
			opts:   []policy.MFARequirementOption{policy.WithMFARequirementClock(nil)},
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.ErrorIs(t, err, policy.ErrConfig)
				assert.Nil(t, p)
			},
		},
		{
			// *clockwork.FakeClock implements Now through a pointer receiver,
			// so a nil one is an interface holding a nil pointer: `== nil`
			// misses it, and only the reflect-based check the constructor now
			// uses catches it before the first sampled record reads from a nil
			// receiver.
			name:   "a typed-nil clock is refused",
			lookup: NewMockMFARequirementLookup(gomock.NewController(t)),
			opts:   []policy.MFARequirementOption{policy.WithMFARequirementClock((*clockwork.FakeClock)(nil))},
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.ErrorIs(t, err, policy.ErrConfig)
				assert.Nil(t, p)
			},
		},
		{
			// A Now-only consumer type: `time-source` "Read-only source for a
			// read-only component". Construction succeeds, and the policy
			// samples its refusal records by the consumer's clock: since
			// fixedClock never advances, a one-millisecond sampling window
			// never appears to elapse, so two refusals a real sleep apart
			// still produce one record.
			name:    "a consumer's own read-only clock is accepted and used to sample records",
			methods: mfaMethods(mfaMethod(t, factor.Email, false, nil)),
			opts: []policy.MFARequirementOption{
				policy.WithMFARequiredForAll(),
				policy.WithMFARequirementClock(fixedClock{at: consumerRequirementClockAt}),
				policy.WithMFARequirementLogger(mfaLogger(consumerRequirementClockLogBuf)),
				policy.WithMFARequirementLogInterval(time.Millisecond),
			},
			assert: func(t *testing.T, p policy.Policy, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, p)

				in := &policy.Input{User: mfaUser, FirstFactor: factor.MagicLink}
				ctx := mfaPhaseContext(t, policy.PerRequest)
				_ = p.Evaluate(ctx, in)
				time.Sleep(50 * time.Millisecond) // real time passes; the frozen clock does not
				_ = p.Evaluate(ctx, in)

				assert.Len(t, mfaRecordsOf(t, consumerRequirementClockLogBuf, logMFAEnrollmentRequired), 1,
					"a clock that never advances must keep the sampling window from ever elapsing")
			},
		},
		{
			// The godoc promises "the policy keeps its own copy of the set".
			// Overwriting the caller's slice after construction must not
			// change what an already-built policy consults.
			name:    "mutating the caller's slice after construction does not change what the policy decided from",
			lookup:  mfaRequirementLookup(t, true, true, nil),
			methods: mutableRequirementMethods,
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)

				in := &policy.Input{User: mfaUser, FirstFactor: factor.Password, Now: mfaNow}
				ctx := mfaPhaseContext(t, policy.PerRequest)

				before := p.Evaluate(ctx, in)
				require.Equal(t, policy.Challenge, before.Outcome,
					"the case's own setup was wrong before the mutation could prove anything")

				mutableRequirementMethods[0] = mfaMethod(t, factor.AuthenticatorApp, false, nil)

				after := p.Evaluate(ctx, in)
				assert.Equal(t, policy.Challenge, after.Outcome,
					"the policy consulted the caller's slice instead of its own copy")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := policy.NewMFARequirement(tc.lookup, tc.methods, tc.opts...)
			tc.assert(t, p, err)
		})
	}
}

func TestMFARequirementEvaluationOrder(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name         string
		kind         factor.Kind
		phase        policy.Phase
		withoutPhase bool
		satisfied    bool
		forAll       bool
		consulted    bool
		required     bool
		requiredErr  error
		omitMethod   bool
		channel      factor.Channel
		enrolled     bool
		assert       func(t *testing.T, d policy.Decision)
	}

	allows := func(t *testing.T, d policy.Decision) {
		t.Helper()

		assert.Equal(t, policy.Allow, d.Outcome)
		assert.NoError(t, d.Reason, "an allow carried a refusal reason")
	}
	denies := func(target error, why string) func(t *testing.T, d policy.Decision) {
		return func(t *testing.T, d policy.Decision) {
			t.Helper()

			require.Equal(t, policy.Deny, d.Outcome, why)
			assert.ErrorIs(t, d.Reason, target)
		}
	}

	cases := []testCase{
		{
			name: "1 an exempt first factor allows before anything is looked up",
			kind: factor.APIKey, phase: policy.StatelessAuthentication,
			channel: factor.AuthenticatorApp,
			assert:  allows,
		},
		{
			// The empty kind is unknown, and an unknown kind is enforced. A
			// caller that forgot to record the first factor must not be waved
			// through as if it had been a federated login.
			name: "1 a request with no recorded first factor is enforced rather than exempt",
			kind: "", phase: policy.PerRequest,
			consulted: true, required: true,
			channel: factor.AuthenticatorApp, enrolled: true,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Challenge, d.Outcome,
					"a request with no first factor was treated as exempt")
			},
		},
		{
			name: "2 requiring a second factor of everyone answers without consulting the lookup",
			kind: factor.Password, phase: policy.PerRequest, forAll: true,
			channel: factor.AuthenticatorApp, enrolled: true,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Challenge, d.Outcome)
			},
		},
		{
			name: "2 a lookup error denies with the error, and never allows",
			kind: factor.Password, phase: policy.PerRequest,
			consulted: true, requiredErr: errRequirementStore,
			channel: factor.AuthenticatorApp, enrolled: true,
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome,
					"a requirement that could not be read was read as absent")
				assert.ErrorIs(t, d.Reason, errRequirementStore)
			},
		},
		{
			name: "3 a user who is not required allows",
			kind: factor.Password, phase: policy.PerRequest,
			consulted: true, required: false,
			channel: factor.AuthenticatorApp,
			assert:  allows,
		},
		{
			name: "4 the stateless phase denies, whatever the user's enrolment",
			kind: factor.Basic, phase: policy.StatelessAuthentication,
			consulted: true, required: true,
			channel: factor.AuthenticatorApp, enrolled: true,
			assert: denies(policy.ErrMFARequired,
				"a stateless request that can never answer a challenge was let through"),
		},
		{
			name: "4 a policy with no method to challenge against denies",
			kind: factor.Password, phase: policy.PerRequest,
			consulted: true, required: true, omitMethod: true,
			assert: denies(policy.ErrMFARequired, "a required user was let through unchallenged"),
		},
		{
			name: "5 a per-request evaluation whose second factor is satisfied allows",
			kind: factor.Password, phase: policy.PerRequest, satisfied: true,
			consulted: true, required: true,
			channel: factor.AuthenticatorApp, enrolled: true,
			assert: allows,
		},
		{
			name: "6 a user who is not enrolled denies with the enrolment reason",
			kind: factor.Password, phase: policy.PerRequest,
			consulted: true, required: true,
			channel: factor.AuthenticatorApp, enrolled: false,
			assert: denies(policy.ErrMFAEnrolmentRequired,
				"a required user with nothing to be challenged on was let through"),
		},
		{
			name: "6 an enrolment on the first factor's own channel is no usable enrolment",
			kind: factor.MagicLink, phase: policy.PostAuthentication,
			consulted: true, required: true,
			channel: factor.Email, enrolled: true,
			assert: denies(policy.ErrMFAEnrolmentRequired,
				"one factor counted twice because it arrived under two names"),
		},
		{
			name: "6 a login claiming a satisfied second factor is not honoured in post-authentication",
			kind: factor.Password, phase: policy.PostAuthentication, satisfied: true,
			consulted: true, required: true,
			channel: factor.AuthenticatorApp, enrolled: false,
			assert: denies(policy.ErrMFAEnrolmentRequired,
				"the login talked the policy out of its requirement"),
		},
		{
			name: "7 a per-request evaluation with a usable enrolment challenges",
			kind: factor.Password, phase: policy.PerRequest,
			consulted: true, required: true,
			channel: factor.AuthenticatorApp, enrolled: true,
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Challenge, d.Outcome)
				assert.Equal(t, policy.ChallengeMFA, d.Challenge)
			},
		},
		{
			name: "8 post-authentication allows, leaving the login challenge to the challenge policy",
			kind: factor.Password, phase: policy.PostAuthentication,
			consulted: true, required: true,
			channel: factor.AuthenticatorApp, enrolled: true,
			assert: allows,
		},
		{
			name: "9 an evaluation in the pre-authentication phase denies",
			kind: factor.Password, phase: policy.PreAuthentication,
			consulted: true, required: true,
			channel: factor.AuthenticatorApp, enrolled: true,
			assert: denies(policy.ErrMFARequired,
				"a phase the policy never declared was answered as if it had"),
		},
		{
			name: "9 an evaluation after the handler denies",
			kind: factor.Password, phase: policy.PostHandler,
			consulted: true, required: true,
			channel: factor.AuthenticatorApp, enrolled: true,
			assert: denies(policy.ErrMFARequired,
				"a phase the policy never declared was answered as if it had"),
		},
		{
			name: "9 an evaluation that names no phase at all denies",
			kind: factor.Password, withoutPhase: true,
			consulted: true, required: true,
			channel: factor.AuthenticatorApp, enrolled: true,
			assert: denies(policy.ErrMFARequired,
				"a phase the policy could not identify was guessed at"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var methods []policy.MFAMethodLookup
			if !tc.omitMethod {
				methods = mfaMethods(mfaMethod(t, tc.channel, tc.enrolled, nil))
			}

			opts := []policy.MFARequirementOption{
				policy.WithMFARequirementLogger(mfaLogger(&bytes.Buffer{})),
			}
			if tc.forAll {
				opts = append(opts, policy.WithMFARequiredForAll())
			}

			p := mfaRequirementPolicyOver(t,
				mfaRequirementLookup(t, tc.consulted, tc.required, tc.requiredErr), methods, opts...)

			ctx := t.Context()
			if !tc.withoutPhase {
				ctx = policy.ContextWithPhase(ctx, tc.phase)
			}

			in := &policy.Input{
				User: mfaUser, FirstFactor: tc.kind, MFASatisfied: tc.satisfied, Now: mfaNow,
			}
			tc.assert(t, p.Evaluate(ctx, in))
		})
	}
}

func TestMFARequirementLookupFailureLogging(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		users  []identity.UserID
		assert func(t *testing.T, buf *bytes.Buffer, ds []policy.Decision)
	}

	cases := []testCase{
		{
			name: "a request that ended under the lookup is a debug record, not an outage",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			users: []identity.UserID{"u-1", "u-1"},
			assert: func(t *testing.T, buf *bytes.Buffer, ds []policy.Decision) {
				records := mfaRecordsOf(t, buf, logRequirementLookupEnded)
				require.Len(t, records, 2,
					"a caller hanging up was sampled, so it can hide a real outage")
				assert.Equal(t, "DEBUG", records[0]["level"],
					"an ordinary disconnection was written at an alerting level")
				assert.Empty(t,
					mfaRecordsOf(t, buf, logRequirementLookupFailed),
					"a cancelled request was also reported as an outage")

				for _, d := range ds {
					assert.Equal(t, policy.Deny, d.Outcome, "a cancelled lookup was read as not required")
				}
			},
		},
		{
			name:  "an outage is one error record for the window, however many users hit it",
			users: []identity.UserID{"u-1", "u-2", "u-3"},
			assert: func(t *testing.T, buf *bytes.Buffer, ds []policy.Decision) {
				records := mfaRecordsOf(t, buf, logRequirementLookupFailed)
				require.Len(t, records, 1,
					"the outage was keyed per user, so one outage writes one record per user")
				assert.Equal(t, "ERROR", records[0]["level"])

				for _, d := range ds {
					assert.Equal(t, policy.Deny, d.Outcome)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			buf := &bytes.Buffer{}
			p, err := policy.NewMFARequirement(
				mfaRequirementLookup(t, true, false, errRequirementStore),
				mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil)),
				policy.WithMFARequirementLogger(mfaLogger(buf)))
			require.NoError(t, err)

			ctx := policy.ContextWithPhase(t.Context(), policy.PerRequest)
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			ds := make([]policy.Decision, 0, len(tc.users))
			for _, user := range tc.users {
				ds = append(ds, p.Evaluate(ctx, &policy.Input{
					User: user, FirstFactor: factor.Password, Now: mfaNow,
				}))
			}

			tc.assert(t, buf, ds)
		})
	}
}

func TestMFARequirementLookupFailureKeyIsSharedByEveryUser(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	p, err := policy.NewMFARequirement(
		mfaRequirementLookup(t, true, false, errRequirementStore),
		mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil)),
		policy.WithMFARequirementLogger(mfaLogger(buf)))
	require.NoError(t, err)

	ctx := policy.ContextWithPhase(t.Context(), policy.PerRequest)
	for _, user := range []identity.UserID{"u-1", "u-2", "u-3"} {
		p.Evaluate(ctx, &policy.Input{User: user, FirstFactor: factor.Password, Now: mfaNow})
	}

	require.NoError(t, p.FlushRefusalLogs())

	records := mfaRecordsOf(t, buf, logRequirementSuppressed)
	require.Len(t, records, 1, "the suppressed failures were reported under more than one key")
	assert.Equal(t, "lookup-failed", records[0]["key"],
		"the outage was not sampled under the single key every user shares")
	assert.Equal(t, float64(2), records[0]["suppressed"],
		"the failures held back were not reported in full")
}

// Standalone: its policy, phase and input differ from TestMFARequirementLookupFailureKeyIsSharedByEveryUser.
func TestMFARequirementAssuranceSourceFailureKeyIsSharedByEveryUser(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	p := mfaRequirementPolicyFor(t,
		mfaRequirementLookup(t, true, true, nil),
		mfaMethod(t, factor.AuthenticatorApp, true, nil),
		policy.WithFederatedAssuranceSource(assuranceSource(t, true, false, errAssuranceSource)),
		policy.WithMFARequirementLogger(mfaLogger(buf)))

	ctx := policy.ContextWithPhase(t.Context(), policy.PostAuthentication)
	for _, user := range []identity.UserID{"u-1", "u-2"} {
		in := federatedInput(factor.OIDC, federatedEvidence("pwd"))
		in.User = user
		p.Evaluate(ctx, in)
	}

	require.NoError(t, p.FlushRefusalLogs())

	records := mfaRecordsOf(t, buf, logRequirementSuppressed)
	require.Len(t, records, 1, "the suppressed failures were reported under more than one key")
	assert.Equal(t, "assurance-source-failed", records[0]["key"],
		"the outage was not sampled under the single key every user shares")
	assert.Equal(t, float64(1), records[0]["suppressed"])
}

// TestMFARequirementPhaseSourceOverride covers the override point for how the
// policy learns its phase. The default reads the context; a consumer whose call
// path cannot reach it supplies a rule of their own.
func TestMFARequirementPhaseSourceOverride(t *testing.T) {
	t.Parallel()

	method := mfaMethod(t, factor.AuthenticatorApp, true, nil)
	in := &policy.Input{User: mfaUser, FirstFactor: factor.Password, Now: mfaNow}

	t.Run("with nothing configured a context carrying no phase is refused", func(t *testing.T) {
		t.Parallel()

		d := mfaRequirementPolicyFor(t, mfaRequirementLookup(t, true, true, nil), method).
			Evaluate(t.Context(), in)

		require.Equal(t, policy.Deny, d.Outcome,
			"a phase the policy could not identify was guessed at")
		assert.ErrorIs(t, d.Reason, policy.ErrMFARequired)
	})

	t.Run("a consumer rule decides the phase instead", func(t *testing.T) {
		t.Parallel()

		d := mfaRequirementPolicyFor(t, mfaRequirementLookup(t, true, true, nil), method,
			policy.WithMFARequirementPhaseSource(
				func(context.Context, *policy.Input) (policy.Phase, bool) {
					return policy.PerRequest, true
				})).
			Evaluate(t.Context(), in)

		require.Equal(t, policy.Challenge, d.Outcome,
			"the consumer's rule did not replace the default source of the phase")
		assert.Equal(t, policy.ChallengeMFA, d.Challenge)
	})
}

// TestMFARequirementChallenges pins what the requirement policy declares it can
// raise. The enrolment challenge is declared only when the path is on, so a
// chain without the enrolment interceptor keeps assembling until a consumer
// opts in, and refuses to assemble once they do.
func TestMFARequirementChallenges(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []policy.MFARequirementOption
		assert func(t *testing.T, kinds []policy.ChallengeKind)
	}

	cases := []testCase{
		{
			name: "path off declares the second-factor challenge only",
			assert: func(t *testing.T, kinds []policy.ChallengeKind) {
				assert.Equal(t, []policy.ChallengeKind{policy.ChallengeMFA}, kinds)
			},
		},
		{
			name: "path on also declares the enrolment challenge",
			opts: []policy.MFARequirementOption{policy.WithMFAEnrolmentPath()},
			assert: func(t *testing.T, kinds []policy.ChallengeKind) {
				assert.ElementsMatch(t,
					[]policy.ChallengeKind{policy.ChallengeMFA, policy.ChallengeMFAEnrolment}, kinds,
					"a chain could assemble without the enforcer of a challenge this policy raises")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := mfaRequirementPolicyFor(t, nil, mfaMethod(t, factor.AuthenticatorApp, false, nil),
				append([]policy.MFARequirementOption{policy.WithMFARequiredForAll()}, tc.opts...)...)

			tc.assert(t, p.Challenges())
		})
	}
}

// TestMFARequirementMidSessionEnrolment covers a user who becomes required
// during a password session and has no enrolment. The next per-request
// evaluation sends them to enrol with the path on, and refuses them with it
// off, as before the path existed.
func TestMFARequirementMidSessionEnrolment(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		pathOn bool
		assert func(t *testing.T, d policy.Decision)
	}

	cases := []testCase{
		{name: "path on challenges for enrolment", pathOn: true, assert: challengedForEnrolment},
		{name: "path off refuses as before", assert: deniedForEnrolment},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opts []policy.MFARequirementOption
			if tc.pathOn {
				opts = append(opts, policy.WithMFAEnrolmentPath())
			}

			// The lookup is what a mid-session flag changes: it now answers
			// "required" for a session that never satisfied a second factor.
			p := mfaRequirementPolicyFor(t, mfaRequirementLookup(t, true, true, nil),
				canEnrol(mfaMethod(t, factor.AuthenticatorApp, false, nil)), opts...)

			in := &policy.Input{User: mfaUser, FirstFactor: factor.Password, Now: mfaNow}
			tc.assert(t, p.Evaluate(mfaPhaseContext(t, policy.PerRequest), in))
		})
	}
}

// TestMFARequirementPolicyOverASet covers the requirement policy over more than
// one method: usability is decided across the whole set, any lookup failure
// refuses, and the enrolment path is entered only through a method that
// supports it on another channel. It is a table of its own because each row
// builds its own set, where the tables above configure one method by fields.
func TestMFARequirementPolicyOverASet(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		methods func(t *testing.T) []policy.MFAMethodLookup
		pathOn  bool
		phase   policy.Phase
		first   factor.Kind
		assert  func(t *testing.T, d policy.Decision)
	}

	cases := []testCase{
		{
			name: "usable on the second method, flagged mid-session, is challenged per request",
			methods: func(t *testing.T) []policy.MFAMethodLookup {
				return mfaMethods(
					mfaMethod(t, factor.AuthenticatorApp, false, nil),
					mfaMethod(t, factor.Email, true, nil))
			},
			phase: policy.PerRequest, first: factor.Password,
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Challenge, d.Outcome,
					"only the first configured method was consulted")
				assert.Equal(t, policy.ChallengeMFA, d.Challenge)
			},
		},
		{
			name: "any lookup failure denies, though another method is usable",
			methods: func(t *testing.T) []policy.MFAMethodLookup {
				return mfaMethods(
					mfaMethod(t, factor.AuthenticatorApp, true, nil),
					mfaMethod(t, factor.Email, false, errEnrolmentStore))
			},
			phase: policy.PerRequest, first: factor.Password,
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome,
					"a lookup failure on one method was ignored because another answered")
				assert.ErrorIs(t, d.Reason, errEnrolmentStore)
			},
		},
		{
			name: "any lookup failure denies with the path on",
			methods: func(t *testing.T) []policy.MFAMethodLookup {
				return mfaMethods(
					canEnrol(mfaMethod(t, factor.AuthenticatorApp, false, nil)),
					mfaMethod(t, factor.Email, false, errEnrolmentStore))
			},
			pathOn: true, phase: policy.PostAuthentication, first: factor.Password,
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, errEnrolmentStore)
				assert.NotErrorIs(t, d.Reason, policy.ErrMFAEnrolmentRequired)
			},
		},
		{
			name: "enrolled only on the first factor's channel, with another method unenrolled, is refused",
			methods: func(t *testing.T) []policy.MFAMethodLookup {
				return mfaMethods(
					mfaMethod(t, factor.AuthenticatorApp, false, nil),
					mfaMethod(t, factor.Email, true, nil))
			},
			phase: policy.PostAuthentication, first: factor.MagicLink,
			assert: deniedForEnrolment,
		},
		{
			// The consumer's authenticator method is listed first, so a policy
			// that looked at one method only, or ignored whether it can enrol,
			// would admit the login.
			name: "only a method that cannot enrol on another channel is refused (it listed first)",
			methods: func(t *testing.T) []policy.MFAMethodLookup {
				return mfaMethods(
					cannotEnrol(mfaMethod(t, factor.AuthenticatorApp, false, nil)),
					canEnrol(mfaMethod(t, factor.Email, false, nil)))
			},
			pathOn: true, phase: policy.PostAuthentication, first: factor.MagicLink,
			assert: deniedForEnrolment,
		},
		{
			name: "only a method that cannot enrol on another channel is refused (it listed second)",
			methods: func(t *testing.T) []policy.MFAMethodLookup {
				return mfaMethods(
					canEnrol(mfaMethod(t, factor.Email, false, nil)),
					cannotEnrol(mfaMethod(t, factor.AuthenticatorApp, false, nil)))
			},
			pathOn: true, phase: policy.PostAuthentication, first: factor.MagicLink,
			assert: deniedForEnrolment,
		},
		{
			// A method that does not declare SupportsEnrolmentPath at all is
			// one that cannot enrol.
			name: "a method that does not say whether it can enrol cannot",
			methods: func(t *testing.T) []policy.MFAMethodLookup {
				return mfaMethods(mfaMethod(t, factor.AuthenticatorApp, false, nil))
			},
			pathOn: true, phase: policy.PostAuthentication, first: factor.Password,
			assert: deniedForEnrolment,
		},
		{
			name: "only method on the first factor's channel is refused",
			methods: func(t *testing.T) []policy.MFAMethodLookup {
				return mfaMethods(canEnrol(mfaMethod(t, factor.Email, false, nil)))
			},
			pathOn: true, phase: policy.PostAuthentication, first: factor.MagicLink,
			assert: deniedForEnrolment,
		},
		{
			name: "a method that can enrol on another channel admits the login, wherever it is listed",
			methods: func(t *testing.T) []policy.MFAMethodLookup {
				return mfaMethods(
					cannotEnrol(mfaMethod(t, factor.AuthenticatorApp, false, nil)),
					canEnrol(mfaMethod(t, factor.Email, false, nil)))
			},
			pathOn: true, phase: policy.PostAuthentication, first: factor.Password,
			assert: challengedForEnrolment,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opts []policy.MFARequirementOption
			if tc.pathOn {
				opts = append(opts, policy.WithMFAEnrolmentPath())
			}

			p := mfaRequirementPolicyOver(t, mfaRequirementLookup(t, true, true, nil),
				tc.methods(t), opts...)

			in := &policy.Input{User: mfaUser, FirstFactor: tc.first, Now: mfaNow}
			tc.assert(t, p.Evaluate(mfaPhaseContext(t, tc.phase), in))
		})
	}
}

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
			assert: denied(policy.ErrMFAEnrolmentRequired),
		},
		{
			name:     "refuse mode denies an unmet login with the assurance-not-met reason",
			required: requiredUser, methods: idleTOTP, source: notMet,
			opts:  []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceRefuse)},
			phase: policy.PostAuthentication, in: oidcLogin,
			assert: denied(policy.ErrFederatedAssuranceNotMet),
		},
		{
			name:     "refuse mode allows a met login",
			required: requiredUser, methods: idleTOTP, source: met,
			opts:  []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceRefuse)},
			phase: policy.PostAuthentication, in: oidcLogin, assert: allowed,
		},
		{
			// The proof is decided before the refusal, as the order states.
			name:     "refuse mode honours the library's proof before refusing",
			required: requiredUser, methods: idleTOTP, source: notMet,
			opts:  []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceRefuse)},
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
			opts:  []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceExempt)},
			phase: policy.PostAuthentication, in: oidcLogin, assert: allowed,
		},
		{
			name:     "exempt mode allows a federated session per request",
			required: func(t *testing.T) identity.MFARequirementLookup { return mfaRequirementLookup(t, false, true, nil) },
			methods:  idleTOTP, source: unasked,
			opts:  []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceExempt)},
			phase: policy.PerRequest, in: oidcLogin, assert: allowed,
		},
		{
			name:    "exempt mode does not exempt a login off the federated channel",
			methods: unenrolledTOTP,
			opts:    []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceExempt)},
			phase:   policy.PostAuthentication,
			in:      func() *policy.Input { return mfaInput(factor.Password) },
			assert:  denied(policy.ErrMFAEnrolmentRequired),
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
			opts:  []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceRefuse)},
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
			opts:  []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceRefuse)},
			phase: policy.StatelessAuthentication, in: oidcLogin,
			assert: denied(policy.ErrMFARequired),
		},
		{
			name:     "refuse mode in an undeclared phase is refused before the source is asked",
			required: requiredUser, methods: enrolledTOTP, source: unasked,
			opts:  []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceRefuse)},
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
			assert: denied(policy.ErrMFAEnrolmentRequired),
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
			opts:    []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceMode(9))},
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

			p, err := policy.NewMFARequirement(required, tc.methods(t), opts...)
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
		deniedWith(policy.ErrMFAEnrolmentRequired)(t, d)
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
			opts: []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceRefuse)},
			in:   satisfiedSession, assert: allowed,
		},
		{
			name:     "provider tightened in refuse mode: the session is denied with assurance-not-met",
			required: requiredUser, methods: idleTOTP, source: rematched(false, nil),
			opts:   []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceRefuse)},
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
		policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceRefuse),
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
			opts:     []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceExempt)},
			kind:     factor.OIDC,
			assert:   admits,
		},
		{
			name:   "exempt mode admits even when everyone is required",
			opts:   []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceExempt)},
			kind:   factor.OIDC,
			assert: admits,
		},
		{
			name:     "exempt mode does not cover a kind off the federated channel",
			required: required,
			opts:     []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceExempt)},
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
			opts:     []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceRefuse)},
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

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			got, err := p.AdmitsWithoutLocalSecondFactor(ctx, user, tc.kind)
			tc.assert(t, got, err)
		})
	}
}
