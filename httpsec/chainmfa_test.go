package httpsec_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// mfaChallengingEngine is an engine holding the library's own second-factor
// policy, which declares that it can raise the challenge.
func mfaChallengingEngine(t *testing.T) *policy.Engine {
	t.Helper()

	p, err := policy.NewMFAPolicy([]policy.MFAMethodLookup{idleLookup(t)})
	require.NoError(t, err)

	return engineOf(t, p)
}

// enrollableLookup is a method lookup that reports it supports the enrolment
// path, as the library's own TOTP does over a store that can hold its proofs.
// The requirement policy admits a login to the path only over such a method.
type enrollableLookup struct{ policy.MFAMethodLookup }

func (enrollableLookup) SupportsEnrolmentPath() bool { return true }

// idleLookup is a method lookup no case expects to be asked about a user: only
// its name may be read, which is what a policy constructor does.
func idleLookup(t *testing.T) *MockMFAMethodLookup {
	t.Helper()

	lookup := NewMockMFAMethodLookup(gomock.NewController(t))
	lookup.EXPECT().Name().Return("totp").AnyTimes()

	return lookup
}

// passwordChangeChallengingEngine holds a policy that can challenge, but for
// something the MFA interceptor has nothing to do with.
func passwordChangeChallengingEngine(t *testing.T) *policy.Engine {
	t.Helper()

	p, err := policy.NewPasswordAgePolicy()
	require.NoError(t, err)

	return engineOf(t, p)
}

// passwordChangeGateFor is the password-change gate wired to a session manager
// of its own, which is what a chain registering the password-age policy must
// also enable for that policy's challenge to be enforced.
func passwordChangeGateFor(t *testing.T) httpsec.Option {
	t.Helper()

	m, err := session.NewManager()
	require.NoError(t, err)

	return httpsec.EnablePasswordChangeGate(m)
}

// chainSessions is a session manager for a chain that needs one, supplied
// through a built-in as a deployment would.
func chainSessions(t *testing.T) httpsec.Option {
	t.Helper()

	m, err := session.NewManager()
	require.NoError(t, err)

	return httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: m})
}

// enableMFAFor is EnableMFA wired to everything it needs, so a case that is
// about the assembly check is not about the MFA options.
func enableMFAFor(t *testing.T) httpsec.Option {
	t.Helper()

	ctrl := gomock.NewController(t)

	method := NewMockMethod(ctrl)
	method.EXPECT().Name().Return("totp").AnyTimes()
	method.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
	method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
	method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

	return httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(NewMockGenerator(ctrl)))
}

// TestChainRefusesUnenforcedMFAChallenge pins the refusal http-security
// flagged and could not enforce itself.
//
// The per-request phase marks a second-factor challenge pending and continues,
// because the gate is what enforces it and the verify endpoint must stay
// reachable. With no gate, every challenged session is marked and served
// anyway: the caller goes on with an unsatisfied second factor and nothing in
// the request path says so. That silence is why this is a construction error.
func TestChainRefusesUnenforcedMFAChallenge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	assembles := func(t *testing.T, c *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	cases := []testCase{
		{
			name: "a policy that can challenge for MFA with no interceptor",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.WithPolicyEngine(mfaChallengingEngine(t))}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, strings.ToLower(err.Error()), "enablemfa",
					"the error names what is missing")
			},
		},
		{
			name: "the same policy with EnableMFA",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					httpsec.WithPolicyEngine(mfaChallengingEngine(t)),
					enableMFAFor(t),
				}
			},
			assert: assembles,
		},
		{
			// Occupying the slot is not enforcing the challenge: the chain
			// cannot tell what a consumer's interceptor does there, so only
			// the built-in gate counts.
			name: "the same policy with a consumer's own interceptor at the slot",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				passes := httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error { return next(ex) })

				return []httpsec.Option{
					httpsec.WithPolicyEngine(mfaChallengingEngine(t)),
					httpsec.RegisterInterceptor(passes, httpsec.OrderMFAChallenge),
				}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, strings.ToLower(err.Error()), "enablemfa",
					"the error names the gate that would enforce it")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(append([]httpsec.Option{chainSessions(t)}, tc.opts(t)...)...)
			tc.assert(t, c, err)
		})
	}
}

// TestChainMFAChallengeRefusalScope pins that the refusal does not fire where
// it should not. A check that refuses working deployments is one consumers
// learn to route around.
func TestChainMFAChallengeRefusalScope(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts func(t *testing.T) []httpsec.Option
	}

	cases := []testCase{
		{
			// Its own gate is enabled, because a chain that raises a password
			// change nothing enforces is refused on that account; what is
			// pinned here is that the second-factor refusal does not fire too.
			name: "a policy that can only challenge for a password change",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					httpsec.WithPolicyEngine(passwordChangeChallengingEngine(t)),
					passwordChangeGateFor(t),
				}
			},
		},
		{
			name: "no policy at all",
			opts: func(*testing.T) []httpsec.Option { return nil },
		},
		{
			name: "an engine holding no policies",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.WithPolicyEngine(engineOf(t))}
			},
		},
		{
			// Enforcing a challenge nothing raises is harmless: the gate never
			// fires. Only the other direction is a hole.
			name: "EnableMFA without an MFA policy",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{enableMFAFor(t)}
			},
		},
		{
			name: "a policy that challenges for a password change, with EnableMFA",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					httpsec.WithPolicyEngine(passwordChangeChallengingEngine(t)),
					passwordChangeGateFor(t),
					enableMFAFor(t),
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(append([]httpsec.Option{chainSessions(t)}, tc.opts(t)...)...)

			require.NoError(t, err)
			assert.NotNil(t, c)
		})
	}
}

// compile-time proof that the method double these cases use is a real method.
var _ mfa.Method = (*MockMethod)(nil)
