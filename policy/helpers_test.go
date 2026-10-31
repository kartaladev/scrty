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

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

// fixedClock is a consumer's own read-only clock: the "Read-only source for a
// read-only component" scenario (time-source spec). It carries only Now.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

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

// mfaInput is a login by kind, for the user the MFA cases are about.
func mfaInput(kind factor.Kind) *policy.Input {
	return &policy.Input{User: mfaUser, FirstFactor: kind, Now: mfaNow}
}

// mfaPolicyFor builds the second-factor challenge policy over a set of one
// method, writing its records nowhere unless a case replaces the logger.
func mfaPolicyFor(t *testing.T, method policy.MFAMethodLookup, opts ...policy.MFAOption) *policy.MFA {
	t.Helper()

	return mfaPolicyOver(t, mfaMethods(method), opts...)
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

// mfaPhaseContext returns a context carrying phase, which is how the
// requirement policy learns which phase it is being asked in.
func mfaPhaseContext(t *testing.T, phase policy.Phase) context.Context {
	t.Helper()

	return policy.ContextWithPhase(t.Context(), phase)
}

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
) *policy.MFARequirement {
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
) *policy.MFARequirement {
	t.Helper()

	p, err := policy.NewMFARequirement(required, methods,
		append([]policy.MFARequirementOption{
			policy.WithMFARequirementLogger(mfaLogger(&bytes.Buffer{})),
		}, opts...)...)
	require.NoError(t, err, "the policy under test could not be built")

	return p
}

// challengedForEnrolment asserts the decision the enrolment path exists to
// produce: a challenge of the enrolment kind, refusing nothing.
func challengedForEnrolment(t *testing.T, d policy.Decision) {
	t.Helper()

	require.Equal(t, policy.Challenge, d.Outcome, "the user was not sent down the enrolment path")
	assert.Equal(t, policy.ChallengeMFAEnrolment, d.Challenge)
	assert.NoError(t, d.Reason, "a challenge carried a refusal reason")
}

// deniedWith asserts a refusal for the given reason.
func deniedWith(reason error) func(t *testing.T, d policy.Decision) {
	return func(t *testing.T, d policy.Decision) {
		t.Helper()

		require.Equal(t, policy.Deny, d.Outcome)
		assert.ErrorIs(t, d.Reason, reason)
		assert.Equal(t, policy.ChallengeNone, d.Challenge, "a denial carried a challenge")
	}
}

// enrollable is a method lookup that says whether it supports the enrolment
// path, which the requirement policy learns by asking for exactly this method.
// A bare MockMFAMethodLookup, which has no such method, stands for a method
// that does not.
type enrollable struct {
	policy.MFAMethodLookup

	supports bool
}

func (e enrollable) SupportsEnrolmentPath() bool { return e.supports }

// canEnrol is m, reporting that it supports the enrolment path.
func canEnrol(m policy.MFAMethodLookup) policy.MFAMethodLookup {
	return enrollable{MFAMethodLookup: m, supports: true}
}

// cannotEnrol is m, reporting that it does not support the enrolment path.
func cannotEnrol(m policy.MFAMethodLookup) policy.MFAMethodLookup {
	return enrollable{MFAMethodLookup: m, supports: false}
}

// deniedForEnrolment is the refusal every login the path does not admit gets:
// the one it got before the path existed.
var deniedForEnrolment = deniedWith(policy.ErrMFAEnrolmentRequired)

// errAssuranceSource stands for an assurance source that could not answer.
var errAssuranceSource = errors.New("the assurance evaluator could not reach its rules")

// federatedEvidence is evidence from provider corp that asserted amr, minted
// the way only library code can.
func federatedEvidence(amr ...string) policy.FederatedAssurance {
	return policy.MintFederatedForTest("corp", "https://idp.example", amr, "")
}

// federatedInput is a login of kind carrying ev.
func federatedInput(kind factor.Kind, ev policy.FederatedAssurance) *policy.Input {
	in := mfaInput(kind)
	in.FederatedAssurance = ev

	return in
}

// assuranceSource returns a source that answers met and err for every
// question. A source not expected to be asked carries no expectation, so a
// rule that asked it anyway fails the case.
func assuranceSource(t *testing.T, asked, met bool, err error) *MockFederatedAssuranceSource {
	t.Helper()

	m := NewMockFederatedAssuranceSource(gomock.NewController(t))
	if asked {
		m.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any(), gomock.Any()).Return(met, err).AnyTimes()
	}

	return m
}

const (
	logAssuranceSourceFailed = "policy: the federated assurance source failed"
	logAssuranceNotMet       = "policy: refusing a federated login whose provider assurance is not met"
)

// mfaPolicyOver builds the second-factor challenge policy over methods,
// writing its records nowhere unless a case replaces the logger.
func mfaPolicyOver(t *testing.T, methods []policy.MFAMethodLookup, opts ...policy.MFAOption) *policy.MFA {
	t.Helper()

	p, err := policy.NewMFA(methods,
		append([]policy.MFAOption{policy.WithMFALogger(mfaLogger(&bytes.Buffer{}))}, opts...)...)
	require.NoError(t, err, "the policy under test could not be built")

	return p
}
