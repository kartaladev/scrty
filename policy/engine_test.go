package policy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// errDenied is the reason a denying stub gives, so a test can tell the policy's
// own reason apart from the one the engine substitutes.
var errDenied = errors.New("the stub policy refused")

// stubPolicy is a policy whose answer is fixed by the test that builds it. It
// stands in where a mock's call expectations are not the assertion, which is
// most of the precedence table: the interesting part there is what the engine
// does with the answers, not that it asked.
type stubPolicy struct {
	name     string
	phases   []policy.Phase
	decision policy.Decision
	observe  func(in *policy.Input)
}

func (s stubPolicy) Name() string {
	if s.name == "" {
		return "stub"
	}

	return s.name
}

func (s stubPolicy) Phases() []policy.Phase { return s.phases }

func (s stubPolicy) Evaluate(_ context.Context, in *policy.Input) policy.Decision {
	if s.observe != nil {
		s.observe(in)
	}

	return s.decision
}

// pointerPolicy implements Policy on a pointer receiver, so a nil
// *pointerPolicy is a non-nil interface holding a nil pointer — what an
// unchecked constructor result hands over. Its methods dereference, so an
// engine that registered one would panic at the first evaluation rather than at
// the line of wiring that was wrong.
type pointerPolicy struct {
	name     string
	phases   []policy.Phase
	decision policy.Decision
}

func (p *pointerPolicy) Name() string { return p.name }

func (p *pointerPolicy) Phases() []policy.Phase { return p.phases }

func (p *pointerPolicy) Evaluate(_ context.Context, _ *policy.Input) policy.Decision {
	return p.decision
}

func TestEngineRunsOnlyDeclaredPhases(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	p := NewMockPolicy(ctrl)
	p.EXPECT().Name().Return("per-request only").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.PerRequest}).AnyTimes()
	// Deliberately no EXPECT for Evaluate: being asked in a phase it did not
	// declare is itself the failure. A rule written for one point in a request
	// must not quietly start running at another.

	e, err := policy.NewEngine(p)
	require.NoError(t, err)

	d := e.EvaluatePhase(t.Context(), policy.PreAuthentication, &policy.Input{})
	assert.Equal(t, policy.Allow, d.Outcome, "a phase with no declaring policy must allow")
	assert.NoError(t, d.Reason)
}

func TestEnginePrecedence(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		policies []policy.Policy
		assert   func(t *testing.T, d policy.Decision)
	}

	allowing := stubPolicy{name: "allowing", phases: []policy.Phase{policy.PerRequest}}
	denying := stubPolicy{
		name:     "denying",
		phases:   []policy.Phase{policy.PerRequest},
		decision: policy.Decision{Outcome: policy.Deny, Reason: errDenied},
	}
	challengingMFA := stubPolicy{
		name:     "challenging for mfa",
		phases:   []policy.Phase{policy.PerRequest},
		decision: policy.Decision{Outcome: policy.Challenge, Challenge: policy.ChallengeMFA},
	}
	challengingPassword := stubPolicy{
		name:     "challenging for a password change",
		phases:   []policy.Phase{policy.PerRequest},
		decision: policy.Decision{Outcome: policy.Challenge, Challenge: policy.ChallengePasswordChange},
	}

	allows := func(t *testing.T, d policy.Decision) {
		t.Helper()

		assert.Equal(t, policy.Allow, d.Outcome)
		assert.NoError(t, d.Reason, "an allow explains nothing, because it refused nothing")
		assert.Equal(t, policy.ChallengeNone, d.Challenge)
	}
	denies := func(t *testing.T, d policy.Decision) {
		t.Helper()

		require.Equal(t, policy.Deny, d.Outcome)
		assert.ErrorIs(t, d.Reason, errDenied, "the denying policy's own reason was lost")
	}

	cases := []testCase{
		{
			name:     "an empty phase allows",
			policies: nil,
			assert:   allows,
		},
		{
			name:     "a single allow allows",
			policies: []policy.Policy{allowing},
			assert:   allows,
		},
		{
			name:     "deny outranks allow",
			policies: []policy.Policy{allowing, denying},
			assert:   denies,
		},
		{
			name:     "deny outranks a challenge registered before it",
			policies: []policy.Policy{challengingMFA, denying},
			assert:   denies,
		},
		{
			name:     "deny outranks a challenge registered after it",
			policies: []policy.Policy{denying, challengingMFA},
			assert:   denies,
		},
		{
			name:     "challenge outranks allow",
			policies: []policy.Policy{allowing, challengingMFA},
			assert: func(t *testing.T, d policy.Decision) {
				t.Helper()

				assert.Equal(t, policy.Challenge, d.Outcome)
				assert.Equal(t, policy.ChallengeMFA, d.Challenge)
			},
		},
		{
			// Two challenges and no deny: the first registered is the one the
			// caller is asked to satisfy, so registration order decides which
			// challenge a user meets and not the order the policies happened
			// to answer in.
			name:     "the first held challenge is the one returned",
			policies: []policy.Policy{challengingMFA, challengingPassword},
			assert: func(t *testing.T, d policy.Decision) {
				t.Helper()

				assert.Equal(t, policy.Challenge, d.Outcome)
				assert.Equal(t, policy.ChallengeMFA, d.Challenge,
					"the later challenge overwrote the first one held")
			},
		},
		{
			name:     "a challenge held across a later allow survives",
			policies: []policy.Policy{challengingPassword, allowing},
			assert: func(t *testing.T, d policy.Decision) {
				t.Helper()

				assert.Equal(t, policy.Challenge, d.Outcome)
				assert.Equal(t, policy.ChallengePasswordChange, d.Challenge,
					"a later allow overruled another policy's challenge")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, err := policy.NewEngine(tc.policies...)
			require.NoError(t, err)

			tc.assert(t, e.EvaluatePhase(t.Context(), policy.PerRequest, &policy.Input{}))
		})
	}
}

func TestEngineStopsAtTheFirstDeny(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	later := NewMockPolicy(ctrl)
	later.EXPECT().Name().Return("later").AnyTimes()
	later.EXPECT().Phases().Return([]policy.Phase{policy.PerRequest}).AnyTimes()
	// No EXPECT for Evaluate: a deny ends the phase, so nothing registered
	// after it is asked. A policy that still ran could log, count or charge for
	// a request that was already refused.

	denying := stubPolicy{
		phases:   []policy.Phase{policy.PerRequest},
		decision: policy.Decision{Outcome: policy.Deny, Reason: errDenied},
	}

	e, err := policy.NewEngine(denying, later)
	require.NoError(t, err)

	d := e.EvaluatePhase(t.Context(), policy.PerRequest, &policy.Input{})
	require.Equal(t, policy.Deny, d.Outcome)
	assert.ErrorIs(t, d.Reason, errDenied)
}

func TestEngineRefusesAbsentPolicies(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T, ctrl *gomock.Controller) error
		assert func(t *testing.T, err error)
	}

	configError := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, policy.ErrConfig,
			"an absent policy was accepted, so the engine makes fewer checks than the consumer wrote")
	}

	cases := []testCase{
		{
			name: "a live policy constructs",
			build: func(t *testing.T, ctrl *gomock.Controller) error {
				t.Helper()

				p := NewMockPolicy(ctrl)
				p.EXPECT().Name().Return("live").AnyTimes()
				p.EXPECT().Phases().Return([]policy.Phase{policy.PerRequest}).AnyTimes()

				e, err := policy.NewEngine(p)
				if err == nil {
					assert.NotNil(t, e)
				}

				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			name: "NewEngine refuses a nil policy",
			build: func(t *testing.T, _ *gomock.Controller) error {
				t.Helper()

				e, err := policy.NewEngine(nil)
				assert.Nil(t, e, "a refused configuration still produced an engine")

				return err
			},
			assert: configError,
		},
		{
			name: "NewEngine refuses an interface holding a nil pointer",
			build: func(t *testing.T, _ *gomock.Controller) error {
				t.Helper()

				var unchecked *pointerPolicy

				e, err := policy.NewEngine(unchecked)
				assert.Nil(t, e, "a refused configuration still produced an engine")

				return err
			},
			assert: configError,
		},
		{
			name: "Add refuses a nil policy",
			build: func(t *testing.T, _ *gomock.Controller) error {
				t.Helper()

				e, err := policy.NewEngine()
				require.NoError(t, err)

				return e.Add(nil)
			},
			assert: configError,
		},
		{
			name: "Add refuses an interface holding a nil pointer",
			build: func(t *testing.T, _ *gomock.Controller) error {
				t.Helper()

				e, err := policy.NewEngine()
				require.NoError(t, err)

				var unchecked *pointerPolicy

				return e.Add(unchecked)
			},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			tc.assert(t, tc.build(t, ctrl))
		})
	}
}

func TestEngineAddRegistersForLaterEvaluation(t *testing.T) {
	t.Parallel()

	e, err := policy.NewEngine()
	require.NoError(t, err)

	require.NoError(t, e.Add(stubPolicy{
		phases:   []policy.Phase{policy.PostHandler},
		decision: policy.Decision{Outcome: policy.Deny, Reason: errDenied},
	}))

	d := e.EvaluatePhase(t.Context(), policy.PostHandler, &policy.Input{})
	require.Equal(t, policy.Deny, d.Outcome, "a policy added after construction was never asked")
	assert.ErrorIs(t, d.Reason, errDenied)
}

func TestEnginePassesTheInputIntact(t *testing.T) {
	t.Parallel()

	principal := &identity.Principal{ID: "u-1"}
	sess := &session.Session{ID: "s-1", UserID: "u-1"}
	changed := time.Date(2024, time.March, 1, 9, 0, 0, 0, time.UTC)
	now := time.Date(2024, time.June, 1, 9, 0, 0, 0, time.UTC)

	in := &policy.Input{
		User:              "u-1",
		Username:          "ada",
		Principal:         principal,
		Session:           sess,
		FirstFactor:       factor.Password,
		PasswordChangedAt: changed,
		MFASatisfied:      true,
		Now:               now,
	}

	var seen *policy.Input
	recorder := stubPolicy{
		phases:  []policy.Phase{policy.PostAuthentication},
		observe: func(got *policy.Input) { seen = got },
	}

	e, err := policy.NewEngine(recorder)
	require.NoError(t, err)

	e.EvaluatePhase(t.Context(), policy.PostAuthentication, in)

	require.NotNil(t, seen, "the policy was never handed an input")
	assert.Equal(t, identity.UserID("u-1"), seen.User)
	assert.Equal(t, "ada", seen.Username)
	assert.Same(t, principal, seen.Principal, "the principal was copied or replaced")
	assert.Same(t, sess, seen.Session, "the session was copied or replaced")
	assert.Equal(t, factor.Password, seen.FirstFactor)
	assert.Equal(t, changed, seen.PasswordChangedAt)
	assert.True(t, seen.MFASatisfied)
	assert.Equal(t, now, seen.Now)
}
