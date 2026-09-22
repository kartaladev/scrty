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
// question with (enrolled, err). Both methods are optional: a policy that
// allows before it looks asks neither.
func mfaMethod(t *testing.T, ch factor.Channel, enrolled bool, err error) *MockMFAMethodLookup {
	t.Helper()

	m := NewMockMFAMethodLookup(gomock.NewController(t))
	m.EXPECT().Channel().Return(ch).AnyTimes()
	m.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(enrolled, err).AnyTimes()

	return m
}

// mfaInput is a login by kind, for the user the MFA cases are about.
func mfaInput(kind factor.Kind) *policy.Input {
	return &policy.Input{User: mfaUser, FirstFactor: kind, Now: mfaNow}
}

// mfaPolicyFor builds the second-factor challenge policy over method, writing
// its records nowhere unless a case replaces the logger.
func mfaPolicyFor(t *testing.T, method policy.MFAMethodLookup, opts ...policy.MFAOption) policy.Policy {
	t.Helper()

	p, err := policy.NewMFAPolicy(method,
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
		name   string
		method policy.MFAMethodLookup
		opts   []policy.MFAOption
		assert func(t *testing.T, p policy.Policy, err error)
	}

	refused := func(t *testing.T, p policy.Policy, err error) {
		t.Helper()

		require.ErrorIs(t, err, policy.ErrConfig,
			"a policy that cannot work was accepted at wiring time")
		assert.Nil(t, p, "a refused constructor still handed back a policy")
	}

	cases := []testCase{
		{
			name: "an absent method lookup is refused",
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			// A nil *MockMFAMethodLookup is a non-nil interface holding a nil
			// pointer, which is what an unchecked constructor result hands
			// over. It would panic at the first login rather than here.
			name:   "a typed-nil method lookup is refused",
			method: (*MockMFAMethodLookup)(nil),
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			name:   "a nil exemption rule is refused",
			method: NewMockMFAMethodLookup(gomock.NewController(t)),
			opts:   []policy.MFAOption{policy.WithMFAExemption(nil)},
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			name:   "a nil clock is refused",
			method: NewMockMFAMethodLookup(gomock.NewController(t)),
			opts:   []policy.MFAOption{policy.WithMFAPolicyClock(nil)},
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			name:   "a mode naming neither constant is refused",
			method: NewMockMFAMethodLookup(gomock.NewController(t)),
			opts:   []policy.MFAOption{policy.WithSameChannelEnrolment(policy.SameChannelMode(7))},
			assert: func(t *testing.T, p policy.Policy, err error) {
				refused(t, p, err)
			},
		},
		{
			name:   "the minimum wiring is a method lookup and nothing else",
			method: NewMockMFAMethodLookup(gomock.NewController(t)),
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.NoError(t, err, "the documented minimum wiring was refused")
				require.NotNil(t, p)
				assert.Equal(t, []policy.Phase{policy.PostAuthentication}, p.Phases(),
					"the login challenge would be issued in the wrong phase")
				assert.NotEmpty(t, p.Name(), "the policy has no name to appear in logs under")
			},
		},
		{
			name:   "a nil logger is ignored rather than refused",
			method: NewMockMFAMethodLookup(gomock.NewController(t)),
			opts:   []policy.MFAOption{policy.WithMFAPolicyLogger(nil)},
			assert: func(t *testing.T, p policy.Policy, err error) {
				require.NoError(t, err, "a nil logger made configuring logging mandatory")
				assert.NotNil(t, p)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := policy.NewMFAPolicy(tc.method, tc.opts...)
			tc.assert(t, p, err)
		})
	}
}

func TestMFAPolicyEvaluate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		method *MockMFAMethodLookup
		in     *policy.Input
		opts   []policy.MFAOption
		assert func(t *testing.T, d policy.Decision)
	}

	allows := func(t *testing.T, d policy.Decision) {
		t.Helper()

		assert.Equal(t, policy.Allow, d.Outcome)
		assert.NoError(t, d.Reason, "an allow carried a refusal reason")
	}

	cases := []testCase{
		{
			name:   "a login that has already satisfied a second factor allows",
			method: mfaMethod(t, factor.AuthenticatorApp, true, nil),
			in: &policy.Input{
				User: mfaUser, FirstFactor: factor.Password, MFASatisfied: true, Now: mfaNow,
			},
			assert: allows,
		},
		{
			name:   "an exempt first factor allows",
			method: mfaMethod(t, factor.AuthenticatorApp, true, nil),
			in:     mfaInput(factor.OIDC),
			assert: allows,
		},
		{
			name:   "a lookup error denies with a reason wrapping it",
			method: mfaMethod(t, factor.AuthenticatorApp, false, errEnrolmentStore),
			in:     mfaInput(factor.Password),
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome,
					"an unreadable enrolment downgraded the user to one factor")
				assert.ErrorIs(t, d.Reason, errEnrolmentStore,
					"the caller cannot see what actually failed")
			},
		},
		{
			name:   "enrolled on a different channel challenges for a second factor",
			method: mfaMethod(t, factor.AuthenticatorApp, true, nil),
			in:     mfaInput(factor.Password),
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Challenge, d.Outcome)
				assert.Equal(t, policy.ChallengeMFA, d.Challenge)
				assert.NoError(t, d.Reason, "a challenge refuses nothing and carries no reason")
			},
		},
		{
			name:   "a user who is not enrolled allows",
			method: mfaMethod(t, factor.AuthenticatorApp, false, nil),
			in:     mfaInput(factor.Password),
			assert: allows,
		},
		{
			// The empty kind is unknown, so it reports no channel and is never
			// exempt. It must not match an enrolled method either.
			name:   "a login with no recorded first factor is still challenged",
			method: mfaMethod(t, factor.AuthenticatorApp, true, nil),
			in:     mfaInput(""),
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Challenge, d.Outcome)
				assert.Equal(t, policy.ChallengeMFA, d.Challenge)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := mfaPolicyFor(t, tc.method, tc.opts...)
			tc.assert(t, p.Evaluate(t.Context(), tc.in))
		})
	}
}

func TestMFAExemptionRule(t *testing.T) {
	t.Parallel()

	enforceEverything := func(factor.Kind) bool { return false }

	type testCase struct {
		name   string
		kind   factor.Kind
		opts   []policy.MFAOption
		reqOpt policy.MFARequirementOption
		assert func(t *testing.T, challenge, requirement policy.Decision)
	}

	cases := []testCase{
		{
			name: "by default the identity model's own rule decides, and exempts a federated login",
			kind: factor.OIDC,
			assert: func(t *testing.T, challenge, requirement policy.Decision) {
				assert.Equal(t, policy.Allow, challenge.Outcome,
					"the default exemption stopped exempting a federated login")
				assert.Equal(t, policy.Allow, requirement.Outcome)
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
			kind:   factor.OIDC,
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
