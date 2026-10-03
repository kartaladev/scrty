package policy_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/policy"
)

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
var deniedForEnrolment = deniedWith(policy.ErrMFAEnrollmentRequired)

// TestMFARequirementEnrolmentPath runs every case of the no-usable-enrolment
// branch with the path off and on. The path-off rows pin today's outcome, so
// turning the path off must leave every decision exactly as it was.
func TestMFARequirementEnrolmentPath(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		pathOn     bool
		phase      policy.Phase
		first      factor.Kind
		satisfied  bool
		omitMethod bool
		channel    factor.Channel
		enrolled   bool
		lookupErr  error
		assert     func(t *testing.T, d policy.Decision)
	}

	allowed := func(t *testing.T, d policy.Decision) {
		t.Helper()

		assert.Equal(t, policy.Allow, d.Outcome)
		assert.NoError(t, d.Reason)
	}
	challengedForMFA := func(t *testing.T, d policy.Decision) {
		t.Helper()

		require.Equal(t, policy.Challenge, d.Outcome)
		assert.Equal(t, policy.ChallengeMFA, d.Challenge)
	}
	deniedForLookup := func(t *testing.T, d policy.Decision) {
		t.Helper()

		require.Equal(t, policy.Deny, d.Outcome, "an unreadable enrolment let the user through")
		assert.ErrorIs(t, d.Reason, errEnrolmentStore)
		assert.NotErrorIs(t, d.Reason, policy.ErrMFAEnrollmentRequired,
			"a lookup failure was reported as a missing enrolment")
	}

	cases := []testCase{
		{
			name: "off, not enrolled, at login", phase: policy.PostAuthentication,
			first: factor.Password, channel: factor.AuthenticatorApp, assert: deniedForEnrolment,
		},
		{
			name: "on, not enrolled, at login", pathOn: true, phase: policy.PostAuthentication,
			first: factor.Password, channel: factor.AuthenticatorApp, assert: challengedForEnrolment,
		},
		{
			name: "off, not enrolled, per request", phase: policy.PerRequest,
			first: factor.Password, channel: factor.AuthenticatorApp, assert: deniedForEnrolment,
		},
		{
			name: "on, not enrolled, per request", pathOn: true, phase: policy.PerRequest,
			first: factor.Password, channel: factor.AuthenticatorApp, assert: challengedForEnrolment,
		},
		{
			// The path belongs to post-authentication and per-request only; a phase
			// the policy does not declare must not reach it.
			name: "on, not enrolled, an undeclared phase", pathOn: true, phase: policy.PreAuthentication,
			first: factor.Password, channel: factor.AuthenticatorApp, assert: deniedForEnrolment,
		},
		{
			// The login's claim is not honoured at login, so it cannot talk the
			// policy past the enrolment path either.
			name:  "off, not enrolled, a login claiming a satisfied second factor",
			phase: policy.PostAuthentication, first: factor.Password, satisfied: true,
			channel: factor.AuthenticatorApp, assert: deniedForEnrolment,
		},
		{
			name: "on, not enrolled, a login claiming a satisfied second factor", pathOn: true,
			phase: policy.PostAuthentication, first: factor.Password, satisfied: true,
			channel: factor.AuthenticatorApp, assert: challengedForEnrolment,
		},
		{
			name: "off, enrolled only on the first factor's channel", phase: policy.PostAuthentication,
			first: factor.MagicLink, channel: factor.Email, enrolled: true, assert: deniedForEnrolment,
		},
		{
			// Enrolling again on the same channel would leave the user as
			// unusable as before, so the path is never entered.
			name: "on, enrolled only on the first factor's channel", pathOn: true,
			phase: policy.PostAuthentication, first: factor.MagicLink, channel: factor.Email,
			enrolled: true, assert: deniedForEnrolment,
		},
		{
			name:  "off, not enrolled, the method shares the first factor's channel",
			phase: policy.PostAuthentication, first: factor.MagicLink, channel: factor.Email,
			assert: deniedForEnrolment,
		},
		{
			name: "on, not enrolled, the method shares the first factor's channel", pathOn: true,
			phase: policy.PostAuthentication, first: factor.MagicLink, channel: factor.Email,
			assert: deniedForEnrolment,
		},
		{
			name: "off, the enrolment lookup fails", phase: policy.PostAuthentication,
			first: factor.Password, channel: factor.AuthenticatorApp, lookupErr: errEnrolmentStore,
			assert: deniedForLookup,
		},
		{
			name: "on, the enrolment lookup fails", pathOn: true, phase: policy.PostAuthentication,
			first: factor.Password, channel: factor.AuthenticatorApp, lookupErr: errEnrolmentStore,
			assert: deniedForLookup,
		},
		{
			name: "off, stateless authentication", phase: policy.StatelessAuthentication,
			first: factor.Basic, channel: factor.AuthenticatorApp,
			assert: deniedWith(policy.ErrMFARequired),
		},
		{
			name: "on, stateless authentication", pathOn: true, phase: policy.StatelessAuthentication,
			first: factor.Basic, channel: factor.AuthenticatorApp,
			assert: deniedWith(policy.ErrMFARequired),
		},
		{
			name: "off, no method configured", phase: policy.PostAuthentication,
			first: factor.Password, omitMethod: true, assert: deniedWith(policy.ErrMFARequired),
		},
		{
			name: "on, no method configured", pathOn: true, phase: policy.PostAuthentication,
			first: factor.Password, omitMethod: true, assert: deniedWith(policy.ErrMFARequired),
		},
		{
			name: "off, a satisfied session", phase: policy.PerRequest, first: factor.Password,
			satisfied: true, channel: factor.AuthenticatorApp, assert: allowed,
		},
		{
			name: "on, a satisfied session", pathOn: true, phase: policy.PerRequest,
			first: factor.Password, satisfied: true, channel: factor.AuthenticatorApp,
			assert: allowed,
		},
		{
			name: "off, a usable enrolment at login", phase: policy.PostAuthentication,
			first: factor.Password, channel: factor.AuthenticatorApp, enrolled: true, assert: allowed,
		},
		{
			name: "on, a usable enrolment at login", pathOn: true, phase: policy.PostAuthentication,
			first: factor.Password, channel: factor.AuthenticatorApp, enrolled: true, assert: allowed,
		},
		{
			name: "off, a usable enrolment per request", phase: policy.PerRequest,
			first: factor.Password, channel: factor.AuthenticatorApp, enrolled: true,
			assert: challengedForMFA,
		},
		{
			name: "on, a usable enrolment per request", pathOn: true, phase: policy.PerRequest,
			first: factor.Password, channel: factor.AuthenticatorApp, enrolled: true,
			assert: challengedForMFA,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// A per-user lookup that answers "required", so the policy can be
			// built with no method as well as with one.
			required := mfaRequirementLookup(t, true, true, nil)

			// The method supports the enrolment path, as the library's own TOTP
			// does, so every refusal below is the one its row names.
			var methods []policy.MFAMethodLookup
			if !tc.omitMethod {
				methods = mfaMethods(canEnrol(mfaMethod(t, tc.channel, tc.enrolled, tc.lookupErr)))
			}

			var opts []policy.MFARequirementOption
			if tc.pathOn {
				opts = append(opts, policy.WithMFAEnrolmentPath())
			}

			p := mfaRequirementPolicyOver(t, required, methods, opts...)

			in := &policy.Input{
				User: mfaUser, FirstFactor: tc.first, MFASatisfied: tc.satisfied, Now: mfaNow,
			}
			tc.assert(t, p.Evaluate(mfaPhaseContext(t, tc.phase), in))
		})
	}
}

// TestPasskeyRegistrationServesEnrolmentPath pins the passkey method on the
// enrolment path: the only configured method is a passkey method, on the
// public-key channel, and a required, unenrolled user logs in by password.
// Whether the path is entered turns on the method's own declaration that
// passkey registration serves the path.
func TestPasskeyRegistrationServesEnrolmentPath(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		serves bool
		assert func(t *testing.T, d policy.Decision)
	}

	cases := []testCase{
		{name: "passkey registration serves the path", serves: true, assert: challengedForEnrolment},
		{name: "nothing serves the path", serves: false, assert: deniedForEnrolment},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			passkeyMethod := enrollable{
				MFAMethodLookup: namedMFAMethod(t, "passkey", factor.PublicKey, false, nil),
				supports:        tc.serves,
			}

			p := mfaRequirementPolicyOver(t, mfaRequirementLookup(t, true, true, nil),
				mfaMethods(passkeyMethod), policy.WithMFAEnrolmentPath())

			in := &policy.Input{User: mfaUser, FirstFactor: factor.Password, Now: mfaNow}
			tc.assert(t, p.Evaluate(mfaPhaseContext(t, policy.PostAuthentication), in))
		})
	}
}

// TestEnrolmentFirstFactors pins the path's allowlist of first-factor kinds: its
// default, a consumer's replacement of it, and the kinds that can never be on
// it.
func TestEnrolmentFirstFactors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// list replaces the default allowlist; nil keeps the default.
		list []factor.Kind
		// exemption replaces the library's exemption rule; nil keeps it. The
		// library's rule does not exempt an OIDC login, so the default lets one
		// reach the path.
		exemption func(factor.Kind) bool
		first     factor.Kind
		assert    func(t *testing.T, d policy.Decision, err error)
	}

	challenged := func(t *testing.T, d policy.Decision, err error) {
		t.Helper()

		require.NoError(t, err)
		challengedForEnrolment(t, d)
	}
	denied := func(t *testing.T, d policy.Decision, err error) {
		t.Helper()

		require.NoError(t, err)
		deniedForEnrolment(t, d)
	}
	refusedAtConstruction := func(t *testing.T, _ policy.Decision, err error) {
		t.Helper()

		assert.ErrorIs(t, err, policy.ErrConfig, "a path that cannot work was built")
	}

	cases := []testCase{
		{name: "password is on the default list", first: factor.Password, assert: challenged},
		{name: "magic link is on the default list", first: factor.MagicLink, assert: challenged},
		{name: "an unrecorded first factor is on the default list", first: "", assert: challenged},
		{
			// A recovery session rests on two proofs of different kinds and
			// exists to bind a new authenticator, so a required user left with no
			// usable second factor is challenged for enrolment rather than denied
			// outright.
			name: "recovery is on the default list", first: factor.Recovery, assert: challenged,
		},
		{name: "oidc is off the default list", first: factor.OIDC, assert: denied},
		{
			name:  "a consumer list admits oidc",
			list:  []factor.Kind{factor.Password, factor.MagicLink, factor.OIDC},
			first: factor.OIDC, assert: challenged,
		},
		{
			name: "a consumer list replaces the default rather than adding to it",
			list: []factor.Kind{factor.Password}, first: factor.MagicLink, assert: denied,
		},
		{
			name: "a consumer list admits what it names",
			list: []factor.Kind{factor.Password}, first: factor.Password, assert: challenged,
		},
		{
			// The list governs entry to the path, not the exemption rule: a
			// consumer rule that exempts an OIDC login still exempts it.
			name:      "listing oidc does not take away a consumer's exemption of it",
			list:      []factor.Kind{factor.OIDC},
			exemption: func(k factor.Kind) bool { return k == factor.OIDC || k == factor.APIKey },
			first:     factor.OIDC,
			assert: func(t *testing.T, d policy.Decision, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, policy.Allow, d.Outcome,
					"the allowlist changed which first factors are exempt")
			},
		},
		{
			name: "the api-key first factor cannot be listed", list: []factor.Kind{factor.APIKey},
			first: factor.Password, assert: refusedAtConstruction,
		},
		{
			name:  "the basic first factor cannot be listed",
			list:  []factor.Kind{factor.Password, factor.Basic},
			first: factor.Password, assert: refusedAtConstruction,
		},
		{
			// A path on that admits nothing declares a challenge it can never
			// raise, which makes the chain demand an interceptor nobody reaches.
			name: "an empty list is refused", list: []factor.Kind{},
			first: factor.Password, assert: refusedAtConstruction,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var pathOpts []policy.EnrolmentPathOption
			if tc.list != nil {
				pathOpts = append(pathOpts, policy.WithEnrolmentFirstFactors(tc.list...))
			}

			opts := []policy.MFARequirementOption{
				policy.WithMFARequirementLogger(mfaLogger(&bytes.Buffer{})),
				policy.WithMFARequiredForAll(),
				policy.WithMFAEnrolmentPath(pathOpts...),
			}
			if tc.exemption != nil {
				opts = append(opts, policy.WithMFAExemption(tc.exemption))
			}

			p, err := policy.NewMFARequirementPolicy(nil,
				mfaMethods(canEnrol(mfaMethod(t, factor.AuthenticatorApp, false, nil))), opts...)
			if err != nil {
				tc.assert(t, policy.Decision{}, err)

				return
			}

			in := &policy.Input{User: mfaUser, FirstFactor: tc.first, Now: mfaNow}
			tc.assert(t, p.Evaluate(mfaPhaseContext(t, policy.PostAuthentication), in), nil)
		})
	}
}

// TestDefaultEnrolmentFirstFactorsExactly pins the enrolment path's default
// allowlist as an exact set: a password, a magic link, a recovery and the
// unrecorded kind, and nothing else. TestEnrolmentFirstFactors pins how each
// kind it names is treated; this pins that no kind it does not name was added.
func TestDefaultEnrolmentFirstFactorsExactly(t *testing.T) {
	t.Parallel()

	assert.Equal(t, map[factor.Kind]bool{
		factor.Password:  true,
		factor.MagicLink: true,
		factor.Recovery:  true,
		"":               true,
	}, policy.DefaultEnrolmentFirstFactors())
}

// TestEnrolmentPathUntil pins the instant after which the path is closed. The
// instant is compared with Input.Now, the one every policy in the phase judges
// against, not with the policy's own sampling clock.
func TestEnrolmentPathUntil(t *testing.T) {
	t.Parallel()

	closesAt := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		until  *time.Time
		now    time.Time
		assert func(t *testing.T, d policy.Decision)
	}

	cases := []testCase{
		{
			name: "a login before the instant is challenged", until: &closesAt,
			now: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC), assert: challengedForEnrolment,
		},
		{
			name: "a login after the instant is refused as before the path", until: &closesAt,
			now: time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC), assert: deniedForEnrolment,
		},
		{
			name: "a login at the instant is refused", until: &closesAt,
			now: closesAt, assert: deniedForEnrolment,
		},
		{
			name: "with no instant the path stays open",
			now:  time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), assert: challengedForEnrolment,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var pathOpts []policy.EnrolmentPathOption
			if tc.until != nil {
				pathOpts = append(pathOpts, policy.WithEnrolmentPathUntil(*tc.until))
			}

			// The sampling clock is pinned before the instant, so a policy that
			// read it instead of Input.Now would keep the path open.
			p := mfaRequirementPolicyFor(t, nil, canEnrol(mfaMethod(t, factor.AuthenticatorApp, false, nil)),
				policy.WithMFARequiredForAll(),
				policy.WithMFARequirementClock(clockwork.NewFakeClockAt(closesAt.Add(-time.Hour))),
				policy.WithMFAEnrolmentPath(pathOpts...))

			in := &policy.Input{User: mfaUser, FirstFactor: factor.Password, Now: tc.now}
			tc.assert(t, p.Evaluate(mfaPhaseContext(t, policy.PostAuthentication), in))
		})
	}
}
