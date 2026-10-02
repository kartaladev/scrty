package policy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
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

// mfaUser is the user every MFA case is about. The policies match it
// byte-for-byte and never parse it, so one opaque value is enough.
const mfaUser = identity.UserID("u-1")

// mfaNow is the instant the MFA cases are judged at. The policies read it from
// the Input rather than from a clock of their own, so it only has to be the
// same in every case.
var mfaNow = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// errEnrolmentStore stands for a store that could not answer, and
// errSecretUnreadable for a stored secret that would not decrypt. They are two
// errors rather than one because the lookup contract names both, and a test
// that used one for both could not show that either reaches the caller.
var (
	errEnrolmentStore   = errors.New("the enrolment store refused the connection")
	errSecretUnreadable = errors.New("the enrolment secret could not be decrypted")
)

// The messages the two MFA policies write. A case names the record it is
// counting through one of these, so a change to the text is a change to one
// line rather than to every case that reads the log.
const (
	logSameChannelRefused = "policy: refusing a login whose second factor is same-channel with its first"
	logSameChannelAllowed = "policy: completing a login on its first factor, its second factor being same-channel"
	logMFASuppressed      = "policy: second-factor records suppressed"

	logMFARequired             = "policy: refusing a request that is required to present a second factor"
	logMFAEnrollmentRequired   = "policy: refusing a required user with no usable second-factor enrolment"
	logRequirementLookupFailed = "policy: the mfa requirement lookup failed"
	logRequirementLookupEnded  = "policy: the mfa requirement lookup ended with its request"
	logRequirementSuppressed   = "policy: mfa requirement records suppressed"
)

// mfaMethod returns a method lookup on ch that answers every enrolment
// question with (enrolled, err). It is named after its channel by
// mfaMethodName, so a case that needs two methods on one channel names them
// itself with namedMFAMethod. Every method is optional: a policy that allows
// before it looks asks none.
func mfaMethod(t *testing.T, ch factor.Channel, enrolled bool, err error) *MockMFAMethodLookup {
	t.Helper()

	return namedMFAMethod(t, mfaMethodName(ch), ch, enrolled, err)
}

// namedMFAMethod is mfaMethod under a name the case chooses.
func namedMFAMethod(t *testing.T, name string, ch factor.Channel, enrolled bool, err error) *MockMFAMethodLookup {
	t.Helper()

	m := NewMockMFAMethodLookup(gomock.NewController(t))
	m.EXPECT().Name().Return(name).AnyTimes()
	m.EXPECT().Channel().Return(ch).AnyTimes()
	m.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(enrolled, err).AnyTimes()

	return m
}

// idleMFAMethod returns a method lookup a case never expects to be asked about
// a user: only its name may be read, which is what a constructor does.
func idleMFAMethod(t *testing.T, name string) *MockMFAMethodLookup {
	t.Helper()

	m := NewMockMFAMethodLookup(gomock.NewController(t))
	m.EXPECT().Name().Return(name).AnyTimes()

	return m
}

// mfaMethodName is the name mfaMethod gives a method on ch: the name scrty's
// own methods on that channel carry, or the channel itself.
func mfaMethodName(ch factor.Channel) string {
	switch ch {
	case factor.AuthenticatorApp:
		return "totp"
	case factor.Email:
		return "email-code"
	default:
		return string(ch)
	}
}

// mfaMethods is the set of methods a case lists, typed as the constructors
// take it.
func mfaMethods(methods ...policy.MFAMethodLookup) []policy.MFAMethodLookup {
	return methods
}

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

// mfaInput is a login by kind, for the user the MFA cases are about.
func mfaInput(kind factor.Kind) *policy.Input {
	return &policy.Input{User: mfaUser, FirstFactor: kind, Now: mfaNow}
}

// mfaPolicyFor builds the second-factor challenge policy over a set of one
// method, writing its records nowhere unless a case replaces the logger.
func mfaPolicyFor(t *testing.T, method policy.MFAMethodLookup, opts ...policy.MFAOption) policy.Policy {
	t.Helper()

	return mfaPolicyOver(t, mfaMethods(method), opts...)
}

// mfaPolicyOver builds the second-factor challenge policy over methods,
// writing its records nowhere unless a case replaces the logger.
func mfaPolicyOver(t *testing.T, methods []policy.MFAMethodLookup, opts ...policy.MFAOption) policy.Policy {
	t.Helper()

	p, err := policy.NewMFAPolicy(methods,
		append([]policy.MFAOption{policy.WithMFAPolicyLogger(mfaLogger(&bytes.Buffer{}))}, opts...)...)
	require.NoError(t, err, "the policy under test could not be built")

	return p
}

// mfaLogger writes JSON records of every level to buf, so a case can see the
// debug records a production handler would drop.
func mfaLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// mfaRecords decodes the records written to buf, in the order they were
// written.
func mfaRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()

	var records []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}

		record := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(line), &record), "a written record was not JSON")
		records = append(records, record)
	}

	return records
}

// mfaRecordsOf returns the records in buf whose message is msg.
func mfaRecordsOf(t *testing.T, buf *bytes.Buffer, msg string) []map[string]any {
	t.Helper()

	var matching []map[string]any
	for _, record := range mfaRecords(t, buf) {
		if record["msg"] == msg {
			matching = append(matching, record)
		}
	}

	return matching
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
			opts:    []policy.MFAOption{policy.WithMFAPolicyClock(nil)},
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
			opts:    []policy.MFAOption{policy.WithMFAPolicyClock((*clockwork.FakeClock)(nil))},
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
				policy.WithMFAPolicyClock(fixedClock{at: consumerClockAt}),
				policy.WithMFAPolicyLogger(mfaLogger(consumerClockLogBuf)),
				policy.WithMFAPolicyLogInterval(time.Millisecond),
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
			opts:    []policy.MFAOption{policy.WithSameChannelEnrolment(policy.SameChannelMode(7))},
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
			opts:    []policy.MFAOption{policy.WithMFAPolicyLogger(nil)},
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

			p, err := policy.NewMFAPolicy(tc.methods, tc.opts...)
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
				policy.WithSameChannelEnrolment(policy.SameChannelCompleteOnFirstFactor),
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

// mfaPhaseContext returns a context carrying phase, which is how the
// requirement policy learns which phase it is being asked in.
func mfaPhaseContext(t *testing.T, phase policy.Phase) context.Context {
	t.Helper()

	return policy.ContextWithPhase(t.Context(), phase)
}
