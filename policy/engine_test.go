package policy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
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

func TestEngineDeniesAnUnrecognisedOutcome(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		policies []policy.Policy
		assert   func(t *testing.T, d policy.Decision)
	}

	// Outcome(9) names no constant of the enumeration. It stands for the
	// outcome a later constant would be: one this engine's switch has no case
	// for, which the compiler does not report because Outcome is an integer.
	unrecognised := stubPolicy{
		name:     "unrecognised",
		phases:   []policy.Phase{policy.PerRequest},
		decision: policy.Decision{Outcome: policy.Outcome(9)},
	}
	challenging := stubPolicy{
		name:     "challenging for mfa",
		phases:   []policy.Phase{policy.PerRequest},
		decision: policy.Decision{Outcome: policy.Challenge, Challenge: policy.ChallengeMFA},
	}
	denying := stubPolicy{
		name:     "denying",
		phases:   []policy.Phase{policy.PerRequest},
		decision: policy.Decision{Outcome: policy.Deny, Reason: errDenied},
	}

	deniesUninterpreted := func(t *testing.T, d policy.Decision) {
		t.Helper()

		require.Equal(t, policy.Deny, d.Outcome,
			"an outcome the engine cannot interpret was passed over, and the phase allowed")
		assert.ErrorIs(t, d.Reason, policy.ErrDenied)
	}

	cases := []testCase{
		{
			name:     "an unrecognised outcome alone in a phase denies",
			policies: []policy.Policy{unrecognised},
			assert:   deniesUninterpreted,
		},
		{
			// A held challenge is not an answer that survives an
			// uninterpretable one: the engine still cannot say the request is
			// safe to continue, so the deny outranks it exactly as a policy's
			// own deny would.
			name:     "an unrecognised outcome after a held challenge still denies",
			policies: []policy.Policy{challenging, unrecognised},
			assert: func(t *testing.T, d policy.Decision) {
				t.Helper()

				deniesUninterpreted(t, d)
				assert.Equal(t, policy.ChallengeNone, d.Challenge,
					"a deny carried the challenge it outranked")
			},
		},
		{
			name:     "an unrecognised outcome does not disturb an earlier deny",
			policies: []policy.Policy{denying, unrecognised},
			assert: func(t *testing.T, d policy.Decision) {
				t.Helper()

				require.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, errDenied,
					"the first deny's own reason was replaced by a later policy's outcome")
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

// TestEngineDeclaredChallenges pins the list a chain checks its enforcers
// against: every kind a registered policy declares, once, in the order it was
// first declared, and nothing from a policy that declares nothing or is asked
// in no phase.
func TestEngineDeclaredChallenges(t *testing.T) {
	t.Parallel()

	const terms policy.ChallengeKind = 100

	both := []policy.Phase{policy.PostAuthentication, policy.PerRequest}

	type testCase struct {
		name     string
		policies []policy.Policy
		assert   func(t *testing.T, got []policy.ChallengeKind)
	}

	cases := []testCase{
		{
			name: "no policies declares nothing",
			assert: func(t *testing.T, got []policy.ChallengeKind) {
				assert.Empty(t, got)
			},
		},
		{
			name:     "a policy that does not declare is read as raising nothing",
			policies: []policy.Policy{stubPolicy{phases: both}},
			assert: func(t *testing.T, got []policy.ChallengeKind) {
				assert.Empty(t, got)
			},
		},
		{
			name: "every declared kind once, in first-declared order",
			policies: []policy.Policy{
				challengingStub{stubPolicy: stubPolicy{phases: both},
					kinds: []policy.ChallengeKind{policy.ChallengePasswordChange, terms}},
				challengingStub{stubPolicy: stubPolicy{phases: both},
					kinds: []policy.ChallengeKind{terms, policy.ChallengeMFA, policy.ChallengePasswordChange}},
			},
			assert: func(t *testing.T, got []policy.ChallengeKind) {
				assert.Equal(t,
					[]policy.ChallengeKind{policy.ChallengePasswordChange, terms, policy.ChallengeMFA}, got)
			},
		},
		{
			name: "a policy asked in no phase raises nothing whatever it declares",
			policies: []policy.Policy{
				challengingStub{kinds: []policy.ChallengeKind{policy.ChallengeMFA}},
			},
			assert: func(t *testing.T, got []policy.ChallengeKind) {
				assert.Empty(t, got)
			},
		},
		{
			name: "ChallengeNone is not a challenge",
			policies: []policy.Policy{
				challengingStub{stubPolicy: stubPolicy{phases: both},
					kinds: []policy.ChallengeKind{policy.ChallengeNone, policy.ChallengeMFA}},
			},
			assert: func(t *testing.T, got []policy.ChallengeKind) {
				assert.Equal(t, []policy.ChallengeKind{policy.ChallengeMFA}, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, err := policy.NewEngine(tc.policies...)
			require.NoError(t, err)

			tc.assert(t, e.DeclaredChallenges())
		})
	}
}

// viewRequirerStub is a consumer's own policy requiring its own view, so the
// engine is shown to ask the interface rather than the lockout type.
type viewRequirerStub struct {
	stubPolicy
	view     policy.AttemptStore
	required bool
}

func (s viewRequirerStub) RequiredAttemptView() (policy.AttemptStore, bool) {
	return s.view, s.required
}

// TestRequiredAttemptViews pins the wiring-time question a chain asks before
// it lets a password login record failures: which registered policies only
// count failures recorded through their own view, and which view that is.
func TestRequiredAttemptViews(t *testing.T) {
	t.Parallel()

	newLockout := func(t *testing.T, opts ...lockout.Option) *lockout.Policy {
		t.Helper()

		p, err := lockout.New(opts...)
		require.NoError(t, err)

		return p
	}

	pre := []policy.Phase{policy.PreAuthentication}

	type testCase struct {
		name   string
		build  func(t *testing.T) ([]policy.Policy, []policy.RequiredAttemptView)
		assert func(t *testing.T, want, got []policy.RequiredAttemptView)
	}

	sameViews := func(t *testing.T, want, got []policy.RequiredAttemptView) {
		t.Helper()

		require.Len(t, got, len(want))

		for i := range want {
			assert.Equal(t, want[i].Policy, got[i].Policy, "entry %d", i)
			assert.Same(t, want[i].View, got[i].View, "entry %d", i)
		}
	}

	none := func(t *testing.T, _, got []policy.RequiredAttemptView) {
		t.Helper()

		assert.Nil(t, got)
	}

	cases := []testCase{
		{
			name: "a capped lockout policy requires its view",
			build: func(t *testing.T) ([]policy.Policy, []policy.RequiredAttemptView) {
				p := newLockout(t, lockout.WithCap(20))

				return []policy.Policy{p}, []policy.RequiredAttemptView{{Policy: p.Name(), View: p.Attempts()}}
			},
			assert: sameViews,
		},
		{
			name: "an uncapped lockout policy requires nothing",
			build: func(t *testing.T) ([]policy.Policy, []policy.RequiredAttemptView) {
				return []policy.Policy{newLockout(t)}, nil
			},
			assert: none,
		},
		{
			name: "an engine with no lockout policy requires nothing",
			build: func(*testing.T) ([]policy.Policy, []policy.RequiredAttemptView) {
				return []policy.Policy{stubPolicy{phases: pre}}, nil
			},
			assert: none,
		},
		{
			name: "every requirer, in registration order",
			build: func(t *testing.T) ([]policy.Policy, []policy.RequiredAttemptView) {
				own := viewRequirerStub{
					stubPolicy: stubPolicy{name: "own", phases: pre},
					view:       lockout.NewMemoryAttemptStore(),
					required:   true,
				}
				p := newLockout(t, lockout.WithCap(20))

				return []policy.Policy{own, newLockout(t), p}, []policy.RequiredAttemptView{
					{Policy: "own", View: own.view},
					{Policy: p.Name(), View: p.Attempts()},
				}
			},
			assert: sameViews,
		},
		{
			name: "a requirer that does not require is left out",
			build: func(*testing.T) ([]policy.Policy, []policy.RequiredAttemptView) {
				return []policy.Policy{viewRequirerStub{
					stubPolicy: stubPolicy{phases: pre},
					view:       lockout.NewMemoryAttemptStore(),
				}}, nil
			},
			assert: none,
		},
		{
			name: "a requirer asked in no phase is never reported",
			build: func(*testing.T) ([]policy.Policy, []policy.RequiredAttemptView) {
				return []policy.Policy{viewRequirerStub{
					view:     lockout.NewMemoryAttemptStore(),
					required: true,
				}}, nil
			},
			assert: none,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			policies, want := tc.build(t)

			e, err := policy.NewEngine(policies...)
			require.NoError(t, err)

			tc.assert(t, want, e.RequiredAttemptViews())
		})
	}
}

// idleStub is a policy that reports an idle timeout through the optional
// IdleTimeout method, as a consumer's own policy may.
type idleStub struct {
	stubPolicy
	idle time.Duration
}

func (s idleStub) IdleTimeout() time.Duration { return s.idle }

func TestEngineIdleTimeouts(t *testing.T) {
	t.Parallel()

	pre := []policy.Phase{policy.PerRequest}

	idlePolicy := func(t *testing.T, d time.Duration) *policy.IdleTimeout {
		t.Helper()

		p, err := policy.NewIdleTimeout(policy.WithIdleTimeout(d))
		require.NoError(t, err)

		return p
	}

	type testCase struct {
		name   string
		build  func(t *testing.T) []policy.Policy
		assert func(t *testing.T, got []time.Duration)
	}

	cases := []testCase{
		{
			name: "an idle-timeout policy reports its timeout",
			build: func(t *testing.T) []policy.Policy {
				return []policy.Policy{idlePolicy(t, 5*time.Minute)}
			},
			assert: func(t *testing.T, got []time.Duration) { assert.Equal(t, []time.Duration{5 * time.Minute}, got) },
		},
		{
			name: "every reporter, in registration order, others left out",
			build: func(t *testing.T) []policy.Policy {
				return []policy.Policy{
					idlePolicy(t, time.Hour),
					stubPolicy{phases: pre},
					idleStub{stubPolicy: stubPolicy{phases: pre}, idle: time.Minute},
				}
			},
			assert: func(t *testing.T, got []time.Duration) {
				assert.Equal(t, []time.Duration{time.Hour, time.Minute}, got)
			},
		},
		{
			name: "a reporter asked in no phase is never reported",
			build: func(*testing.T) []policy.Policy {
				return []policy.Policy{idleStub{idle: time.Minute}}
			},
			assert: func(t *testing.T, got []time.Duration) { assert.Nil(t, got) },
		},
		{
			name:   "an engine with no policies reports nothing",
			build:  func(*testing.T) []policy.Policy { return nil },
			assert: func(t *testing.T, got []time.Duration) { assert.Nil(t, got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, err := policy.NewEngine(tc.build(t)...)
			require.NoError(t, err)

			tc.assert(t, e.IdleTimeouts())
		})
	}
}

// TestEngine_NilInputDeniesRatherThanPanics pins that a phase evaluated with
// no input is refused by the engine itself, before any policy can either
// dereference it or allow it.
func TestEngine_NilInputDeniesRatherThanPanics(t *testing.T) {
	t.Parallel()

	called := false
	allowing := stubPolicy{
		phases:  []policy.Phase{policy.PerRequest},
		observe: func(*policy.Input) { called = true },
	}
	e, err := policy.NewEngine(allowing)
	require.NoError(t, err)

	var d policy.Decision
	require.NotPanics(t, func() { d = e.EvaluatePhase(t.Context(), policy.PerRequest, nil) })
	require.Equal(t, policy.Deny, d.Outcome, "a phase with no input was allowed")
	require.ErrorIs(t, d.Reason, policy.ErrDenied)
	assert.False(t, called, "a policy was handed a nil input")
}

// challengingStub is a policy that declares the challenges it can raise. It
// stands in for a consumer's own rule, which is the case the optional interface
// exists for.
type challengingStub struct {
	stubPolicy

	kinds []policy.ChallengeKind
}

func (c challengingStub) Challenges() []policy.ChallengeKind { return c.kinds }

// TestEngineCanChallenge pins what an engine will say about the challenges its
// policies can raise, which is what a chain checks its own wiring against: a
// challenge nothing enforces is a session marked pending forever and a caller
// served anyway.
func TestEngineCanChallenge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		policies func(t *testing.T) []policy.Policy
		assert   func(t *testing.T, e *policy.Engine)
	}

	secondFactor := func(t *testing.T) policy.Policy {
		t.Helper()

		p, err := policy.NewMFA([]policy.MFAMethodLookup{idleMFAMethod(t, "totp")})
		require.NoError(t, err)

		return p
	}

	requirement := func(t *testing.T) policy.Policy {
		t.Helper()

		ctrl := gomock.NewController(t)

		p, err := policy.NewMFARequirement(
			NewMockMFARequirementLookup(ctrl), mfaMethods(idleMFAMethod(t, "totp")))
		require.NoError(t, err)

		return p
	}

	passwordAge := func(t *testing.T) policy.Policy {
		t.Helper()

		p, err := policy.NewPasswordAge()
		require.NoError(t, err)

		return p
	}

	cases := []testCase{
		{
			name:     "an engine with no policies",
			policies: func(*testing.T) []policy.Policy { return nil },
			assert: func(t *testing.T, e *policy.Engine) {
				assert.False(t, e.CanChallenge(policy.ChallengeMFA))
				assert.False(t, e.CanChallenge(policy.ChallengePasswordChange))
			},
		},
		{
			name: "the second-factor challenge policy",
			policies: func(t *testing.T) []policy.Policy {
				t.Helper()

				return []policy.Policy{secondFactor(t)}
			},
			assert: func(t *testing.T, e *policy.Engine) {
				assert.True(t, e.CanChallenge(policy.ChallengeMFA))
				assert.False(t, e.CanChallenge(policy.ChallengePasswordChange),
					"it raises one kind, and says so")
			},
		},
		{
			name: "the requirement policy",
			policies: func(t *testing.T) []policy.Policy {
				t.Helper()

				return []policy.Policy{requirement(t)}
			},
			assert: func(t *testing.T, e *policy.Engine) {
				assert.True(t, e.CanChallenge(policy.ChallengeMFA))
				assert.False(t, e.CanChallenge(policy.ChallengePasswordChange))
			},
		},
		{
			name: "the password-age policy",
			policies: func(t *testing.T) []policy.Policy {
				t.Helper()

				return []policy.Policy{passwordAge(t)}
			},
			assert: func(t *testing.T, e *policy.Engine) {
				assert.True(t, e.CanChallenge(policy.ChallengePasswordChange))
				assert.False(t, e.CanChallenge(policy.ChallengeMFA),
					"a password change is not a second factor")
			},
		},
		{
			name: "several policies, one of which challenges for a second factor",
			policies: func(t *testing.T) []policy.Policy {
				t.Helper()

				return []policy.Policy{passwordAge(t), secondFactor(t)}
			},
			assert: func(t *testing.T, e *policy.Engine) {
				assert.True(t, e.CanChallenge(policy.ChallengeMFA))
				assert.True(t, e.CanChallenge(policy.ChallengePasswordChange))
			},
		},
		{
			name: "a consumer's policy that declares the challenges it raises",
			policies: func(*testing.T) []policy.Policy {
				return []policy.Policy{challengingStub{
					stubPolicy: stubPolicy{
						name:     "consumer rule",
						phases:   []policy.Phase{policy.PostAuthentication},
						decision: policy.Decision{Outcome: policy.Allow},
					},
					kinds: []policy.ChallengeKind{
						policy.ChallengePasswordChange,
						policy.ChallengeMFA,
					},
				}}
			},
			assert: func(t *testing.T, e *policy.Engine) {
				assert.True(t, e.CanChallenge(policy.ChallengeMFA))
				assert.True(t, e.CanChallenge(policy.ChallengePasswordChange))
			},
		},
		{
			// The documented limit of the answer: a policy that does not
			// declare its challenges is taken to raise none, so a consumer
			// whose own rule challenges has to implement Challenger for a
			// chain to be able to check their wiring.
			name: "a policy that challenges without declaring it",
			policies: func(*testing.T) []policy.Policy {
				return []policy.Policy{stubPolicy{
					name:   "undeclared",
					phases: []policy.Phase{policy.PostAuthentication},
					decision: policy.Decision{
						Outcome:   policy.Challenge,
						Challenge: policy.ChallengeMFA,
					},
				}}
			},
			assert: func(t *testing.T, e *policy.Engine) {
				assert.False(t, e.CanChallenge(policy.ChallengeMFA),
					"silence is read as raising nothing, not as raising anything")
			},
		},
		{
			name: "a policy registered in no phase at all",
			policies: func(*testing.T) []policy.Policy {
				return []policy.Policy{challengingStub{
					stubPolicy: stubPolicy{name: "never asked"},
					kinds:      []policy.ChallengeKind{policy.ChallengeMFA},
				}}
			},
			assert: func(t *testing.T, e *policy.Engine) {
				assert.False(t, e.CanChallenge(policy.ChallengeMFA),
					"a policy no phase asks cannot raise anything")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, err := policy.NewEngine(tc.policies(t)...)
			require.NoError(t, err)

			tc.assert(t, e)
		})
	}
}

// Compile-time proof that the stub satisfies both ports it stands in for.
var (
	_ policy.Policy     = challengingStub{}
	_ policy.Challenger = challengingStub{}
)

// flushablePolicy is a stubPolicy that also implements
// policy.RefusalLogFlusher, counting how many times FlushRefusalLogs was
// called on it. It shares stubPolicy's value semantics, so it registers on
// the engine exactly as any other policy in this file's tests does.
type flushablePolicy struct {
	stubPolicy
	flushes *int
}

func (p flushablePolicy) FlushRefusalLogs() error {
	*p.flushes++

	return nil
}

var _ policy.RefusalLogFlusher = flushablePolicy{}

// newFlushablePolicy returns a flushable policy registered for phases and a
// pointer to its own flush counter.
func newFlushablePolicy(name string, phases ...policy.Phase) (flushablePolicy, *int) {
	n := 0

	return flushablePolicy{stubPolicy: stubPolicy{name: name, phases: phases}, flushes: &n}, &n
}

// TestEngineFlushRefusalLogs pins spec http-security-chain scenario
// "Registered policy flushed": the engine reaches every registered policy
// that can flush, once each, skips one that cannot without panicking, and
// flushes a policy registered for more than one phase only once.
func TestEngineFlushRefusalLogs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) (e *policy.Engine, counts []*int)
		assert func(t *testing.T, counts []*int)
	}

	cases := []testCase{
		{
			name: "two flushable policies are each flushed once",
			build: func(t *testing.T) (*policy.Engine, []*int) {
				t.Helper()

				a, countA := newFlushablePolicy("a", policy.PerRequest)
				b, countB := newFlushablePolicy("b", policy.PerRequest)

				e, err := policy.NewEngine(a, b)
				require.NoError(t, err)

				return e, []*int{countA, countB}
			},
			assert: func(t *testing.T, counts []*int) {
				require.Len(t, counts, 2)
				assert.Equal(t, 1, *counts[0])
				assert.Equal(t, 1, *counts[1])
			},
		},
		{
			name: "a policy without a flush is skipped without a panic",
			build: func(t *testing.T) (*policy.Engine, []*int) {
				t.Helper()

				e, err := policy.NewEngine(stubPolicy{name: "no flush", phases: []policy.Phase{policy.PerRequest}})
				require.NoError(t, err)

				return e, nil
			},
			assert: func(t *testing.T, _ []*int) {
				t.Helper()
				// Reaching this closure at all is the assertion: a policy
				// with no RefusalLogFlusher must not panic the flush.
			},
		},
		{
			name: "a policy registered for two phases is flushed once",
			build: func(t *testing.T) (*policy.Engine, []*int) {
				t.Helper()

				p, count := newFlushablePolicy("both-phases", policy.PreAuthentication, policy.PostAuthentication)

				e, err := policy.NewEngine(p)
				require.NoError(t, err)

				return e, []*int{count}
			},
			assert: func(t *testing.T, counts []*int) {
				require.Len(t, counts, 1)
				assert.Equal(t, 1, *counts[0],
					"a policy registered for two phases must be flushed once, from asked, not once per phase")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, counts := tc.build(t)
			e.FlushRefusalLogs()
			tc.assert(t, counts)
		})
	}

	t.Run("a policy added after a first flush is flushed by the next", func(t *testing.T) {
		t.Parallel()

		e, err := policy.NewEngine()
		require.NoError(t, err)

		e.FlushRefusalLogs() // nothing registered yet; must not panic

		p, count := newFlushablePolicy("added-later", policy.PerRequest)
		require.NoError(t, e.Add(p))

		e.FlushRefusalLogs()
		assert.Equal(t, 1, *count, "the policy added after construction was never flushed")

		e.FlushRefusalLogs()
		assert.Equal(t, 2, *count, "a second flush must reach the same policy again")
	})
}

// TestEngineTellsPolicyItsPhase pins that a policy whose answer depends on the
// phase learns the phase from the engine that is asking, with nothing added to
// the context by the consumer.
//
// The real MFA requirement policy is driven through a real Engine here, rather
// than evaluated directly as the requirement policy's own table does, because
// what is under test is the engine's side of the arrangement: Input carries no
// phase, so an engine that passed its context through unchanged would leave
// every phase-sensitive policy unable to tell a login from a stateless request
// — and that policy fails closed, refusing users the phase says to challenge or
// allow.
func TestEngineTellsPolicyItsPhase(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		phase  policy.Phase
		assert func(t *testing.T, d policy.Decision)
	}

	cases := []testCase{
		{
			// The "Flagged mid-session" scenario: a user becomes required
			// during a session that has not satisfied a second factor, and is
			// enrolled on a usable method.
			name:  "a required, enrolled user is challenged in the per-request phase",
			phase: policy.PerRequest,
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Challenge, d.Outcome,
					"a required user the engine could have challenged answered %v (%v)",
					d.Outcome, d.Reason)
				assert.Equal(t, policy.ChallengeMFA, d.Challenge)
			},
		},
		{
			// Post-authentication leaves the login challenge to the
			// second-factor challenge policy, so this one raises no objection.
			name:  "a required, enrolled user is allowed in the post-authentication phase",
			phase: policy.PostAuthentication,
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Allow, d.Outcome,
					"a login the challenge policy owns answered %v (%v)", d.Outcome, d.Reason)
				assert.NoError(t, d.Reason)
				assert.Equal(t, policy.ChallengeNone, d.Challenge)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := mfaRequirementPolicyFor(t,
				mfaRequirementLookup(t, true, true, nil),
				mfaMethod(t, factor.AuthenticatorApp, true, nil))

			e, err := policy.NewEngine(p)
			require.NoError(t, err)

			in := &policy.Input{
				User:         mfaUser,
				Session:      &session.Session{ID: "s-1", UserID: mfaUser},
				FirstFactor:  factor.Password,
				MFASatisfied: false,
				Now:          mfaNow,
			}

			// A plain context: a consumer that registered the policy with an
			// engine has said which phase it is evaluating by calling
			// EvaluatePhase, and should not have to say it twice.
			tc.assert(t, e.EvaluatePhase(t.Context(), tc.phase, in))
		})
	}
}

// TestEngine_UnwiredFederatedAssurance pins which registered policies report
// that they decide federated logins on provider assurance with no source to
// decide by: the requirement policy, unless it is given a source or exempts
// federated logins outright, and never a policy that decides nothing on it.
func TestEngine_UnwiredFederatedAssurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		policies func(t *testing.T) []policy.Policy
		assert   func(t *testing.T, unwired []string)
	}

	requirement := func(opts ...policy.MFARequirementOption) func(t *testing.T) []policy.Policy {
		return func(t *testing.T) []policy.Policy {
			p, err := policy.NewMFARequirement(nil,
				mfaMethods(idleMFAMethod(t, mfaMethodName(factor.AuthenticatorApp))),
				append([]policy.MFARequirementOption{policy.WithMFARequiredForAll()}, opts...)...)
			require.NoError(t, err)

			return []policy.Policy{p}
		}
	}

	unwired := func(t *testing.T, got []string) {
		t.Helper()
		assert.Equal(t, []string{"mfa-requirement"}, got)
	}
	wired := func(t *testing.T, got []string) {
		t.Helper()
		assert.Empty(t, got)
	}

	cases := []testCase{
		{
			name:     "the requirement policy in the default mode without a source",
			policies: requirement(),
			assert:   unwired,
		},
		{
			name:     "the requirement policy in refuse mode without a source",
			policies: requirement(policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceRefuse)),
			assert:   unwired,
		},
		{
			name: "the requirement policy with a source",
			policies: func(t *testing.T) []policy.Policy {
				return requirement(policy.WithFederatedAssuranceSource(assuranceSource(t, false, false, nil)))(t)
			},
			assert: wired,
		},
		{
			name:     "the requirement policy in exempt mode needs no source",
			policies: requirement(policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceExempt)),
			assert:   wired,
		},
		{
			name: "the requirement policy under an exemption rule exempting oidc needs no source",
			policies: requirement(policy.WithMFAExemption(func(k factor.Kind) bool {
				return k == factor.OIDC || k.MFAExempt()
			})),
			assert: wired,
		},
		{
			name: "the challenge policy without its opt-in needs no source",
			policies: func(t *testing.T) []policy.Policy {
				p, err := policy.NewMFA(mfaMethods(idleMFAMethod(t, mfaMethodName(factor.AuthenticatorApp))))
				require.NoError(t, err)

				return []policy.Policy{p}
			},
			assert: wired,
		},
		{
			name: "every unwired registration is reported, in registration order",
			policies: func(t *testing.T) []policy.Policy {
				return append(requirement()(t), requirement()(t)...)
			},
			assert: func(t *testing.T, got []string) {
				assert.Equal(t, []string{"mfa-requirement", "mfa-requirement"}, got,
					"one entry per registered policy, so two registrations are both reported")
			},
		},
		{
			name:     "an engine with no policies reports none",
			policies: func(*testing.T) []policy.Policy { return nil },
			assert:   wired,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, err := policy.NewEngine(tc.policies(t)...)
			require.NoError(t, err)

			tc.assert(t, e.UnwiredFederatedAssurance())
		})
	}
}

// TestADeny pins that the engine never hands back a deny without a reason, and
// never replaces a reason a policy gave.
func TestADeny(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		policy stubPolicy
		assert func(t *testing.T, d policy.Decision)
	}

	cases := []testCase{
		{
			// A stateless first factor has no later phase to refuse in: it turns the
			// phase's decision into its own error and returns that. A deny carrying no
			// reason therefore hands it nil, which every caller in Go reads as success, and
			// the request the policy meant to refuse is served.
			//
			// The engine substitutes ErrDenied so that this cannot happen, whichever
			// policy did the denying — closing it once here rather than asking every policy
			// that will ever be written to remember.
			name: "always carries a reason",
			policy: stubPolicy{
				name:     "reasonless",
				phases:   []policy.Phase{policy.StatelessAuthentication},
				decision: policy.Decision{Outcome: policy.Deny}, // Reason left nil.
			},
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome)
				require.Error(t, d.Reason,
					"a deny with no reason is indistinguishable from success to the caller that reports it")
				assert.ErrorIs(t, d.Reason, policy.ErrDenied)
			},
		},
		{
			// The other half: the substitution is a floor, not a replacement. A
			// policy that explained its refusal keeps that explanation, or a consumer
			// could no longer tell an account lockout from a failed second factor.
			name: "carries its own reason unchanged",
			policy: stubPolicy{
				name:     "explained",
				phases:   []policy.Phase{policy.StatelessAuthentication},
				decision: policy.Decision{Outcome: policy.Deny, Reason: errDenied},
			},
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, errDenied, "the policy's own reason was replaced")
				assert.NotErrorIs(t, d.Reason, policy.ErrDenied,
					"a policy that explained itself was reported as an unexplained refusal")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, err := policy.NewEngine(tc.policy)
			require.NoError(t, err)

			d := e.EvaluatePhase(t.Context(), policy.StatelessAuthentication, &policy.Input{})
			tc.assert(t, d)
		})
	}
}
