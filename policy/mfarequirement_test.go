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

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

// errRequirementStore stands for a requirement lookup that could not answer.
var errRequirementStore = errors.New("the requirement store refused the connection")

// mfaRequirementLookup returns a per-user requirement lookup. A lookup that is
// not expected to be consulted carries no expectation at all, so a policy that
// consulted it anyway fails the case rather than passing quietly.
func mfaRequirementLookup(t *testing.T, consulted, required bool, err error) *MockMFARequirementLookup {
	t.Helper()

	m := NewMockMFARequirementLookup(gomock.NewController(t))
	if consulted {
		m.EXPECT().Required(gomock.Any(), gomock.Any()).Return(required, err).AnyTimes()
	}

	return m
}

// mfaRequirementPolicyFor builds the requirement policy over a set of one
// method, writing its records nowhere unless a case replaces the logger.
func mfaRequirementPolicyFor(
	t *testing.T,
	required identity.MFARequirementLookup,
	method policy.MFAMethodLookup,
	opts ...policy.MFARequirementOption,
) policy.Policy {
	t.Helper()

	return mfaRequirementPolicyOver(t, required, mfaMethods(method), opts...)
}

// mfaRequirementPolicyOver builds the requirement policy over methods, which may
// be empty, writing its records nowhere unless a case replaces the logger.
func mfaRequirementPolicyOver(
	t *testing.T,
	required identity.MFARequirementLookup,
	methods []policy.MFAMethodLookup,
	opts ...policy.MFARequirementOption,
) policy.Policy {
	t.Helper()

	p, err := policy.NewMFARequirementPolicy(required, methods,
		append([]policy.MFARequirementOption{
			policy.WithMFARequirementLogger(mfaLogger(&bytes.Buffer{})),
		}, opts...)...)
	require.NoError(t, err, "the policy under test could not be built")

	return p
}

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

			p, err := policy.NewMFARequirementPolicy(tc.lookup, tc.methods, tc.opts...)
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
			assert: denies(policy.ErrMFAEnrollmentRequired,
				"a required user with nothing to be challenged on was let through"),
		},
		{
			name: "6 an enrolment on the first factor's own channel is no usable enrolment",
			kind: factor.MagicLink, phase: policy.PostAuthentication,
			consulted: true, required: true,
			channel: factor.Email, enrolled: true,
			assert: denies(policy.ErrMFAEnrollmentRequired,
				"one factor counted twice because it arrived under two names"),
		},
		{
			name: "6 a login claiming a satisfied second factor is not honoured in post-authentication",
			kind: factor.Password, phase: policy.PostAuthentication, satisfied: true,
			consulted: true, required: true,
			channel: factor.AuthenticatorApp, enrolled: false,
			assert: denies(policy.ErrMFAEnrollmentRequired,
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
			p, err := policy.NewMFARequirementPolicy(
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
	p, err := policy.NewMFARequirementPolicy(
		mfaRequirementLookup(t, true, false, errRequirementStore),
		mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil)),
		policy.WithMFARequirementLogger(mfaLogger(buf)))
	require.NoError(t, err)

	ctx := policy.ContextWithPhase(t.Context(), policy.PerRequest)
	for _, user := range []identity.UserID{"u-1", "u-2", "u-3"} {
		p.Evaluate(ctx, &policy.Input{User: user, FirstFactor: factor.Password, Now: mfaNow})
	}

	flusher, ok := p.(policy.RefusalLogFlusher)
	require.True(t, ok, "the policy offers no way to report what it suppressed")
	require.NoError(t, flusher.FlushRefusalLogs())

	records := mfaRecordsOf(t, buf, logRequirementSuppressed)
	require.Len(t, records, 1, "the suppressed failures were reported under more than one key")
	assert.Equal(t, "lookup-failed", records[0]["key"],
		"the outage was not sampled under the single key every user shares")
	assert.Equal(t, float64(2), records[0]["suppressed"],
		"the failures held back were not reported in full")
}

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

	flusher, ok := p.(policy.RefusalLogFlusher)
	require.True(t, ok, "the policy offers no way to report what it suppressed")
	require.NoError(t, flusher.FlushRefusalLogs())

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

			challenger, ok := p.(policy.Challenger)
			require.True(t, ok, "the requirement policy no longer declares its challenges")
			tc.assert(t, challenger.Challenges())
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
				assert.NotErrorIs(t, d.Reason, policy.ErrMFAEnrollmentRequired)
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
