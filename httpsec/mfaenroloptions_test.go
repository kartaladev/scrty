package httpsec_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
)

// singleCallStore is an enrolment store offering only the single-call
// confirmation: embedding the interface promotes its methods and nothing
// else, so the device-proof port the memory store also implements is hidden.
type singleCallStore struct{ mfa.EnrolmentStore }

// TestEnableMFAEnrolmentConstruction pins what the enrolment path refuses to be
// built with. Each is a wiring mistake that would otherwise surface as a
// session confined to a path that cannot complete, or as a path nobody can
// reach — both far from their cause.
func TestEnableMFAEnrolmentConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// options builds the chain's options from the harness; nil means
		// the harness's own, unchanged.
		options func(t *testing.T, h *enrolHarness) []httpsec.Option

		// prepare changes the harness before the options are built.
		prepare func(t *testing.T, h *enrolHarness)

		assert func(t *testing.T, h *enrolHarness, c *httpsec.Chain, err error)
	}

	refused := func(names ...string) func(*testing.T, *enrolHarness, *httpsec.Chain, error) {
		return func(t *testing.T, _ *enrolHarness, c *httpsec.Chain, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, c)

			for _, n := range names {
				assert.ErrorContains(t, err, n, "the error names what is at fault")
			}
		}
	}

	assembles := func(t *testing.T, _ *enrolHarness, c *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	// without drops the option at index i of the harness's own options: 0
	// the engine, 2 EnableMFA, 3 EnableMFAEnrolment.
	without := func(i int) func(t *testing.T, h *enrolHarness) []httpsec.Option {
		return func(t *testing.T, h *enrolHarness) []httpsec.Option {
			t.Helper()

			opts := h.options(t, nil)

			return append(opts[:i:i], opts[i+1:]...)
		}
	}

	cases := []testCase{
		{
			name:   "every default satisfied",
			assert: assembles,
		},
		{
			name: "no registered policy can raise the enrolment challenge",
			options: func(t *testing.T, h *enrolHarness) []httpsec.Option {
				t.Helper()

				return append(without(0)(t, h), httpsec.WithPolicyEngine(engineOf(t)))
			},
			assert: refused("EnableMFAEnrolment", "ChallengeMFAEnrolment", "WithMFAEnrolmentPath"),
		},
		{
			name:    "no policy engine at all",
			options: without(0),
			assert:  refused("EnableMFAEnrolment", "ChallengeMFAEnrolment"),
		},
		{
			// The requirement policy also declares the second-factor
			// challenge, so it is replaced by one declaring only the
			// enrolment challenge: what is pinned is this option's own check.
			name: "no MFA method enabled",
			options: func(t *testing.T, h *enrolHarness) []httpsec.Option {
				t.Helper()

				opts := without(2)(t, h)
				opts[0] = httpsec.WithPolicyEngine(engineOf(t,
					raisingDeclared{kind: policy.ChallengeMFAEnrolment, phase: policy.PerRequest}))

				return opts
			},
			assert: refused("EnableMFAEnrolment", "EnableMFA"),
		},
		{
			name: "an MFA method that cannot enrol",
			prepare: func(t *testing.T, h *enrolHarness) {
				t.Helper()

				h.method = mfaMethod(t, factor.AuthenticatorApp)
			},
			assert: refused("EnableMFAEnrolment", "mfa.Enroller"),
		},
		{
			name: "a TOTP method whose store cannot record a device proof",
			prepare: func(t *testing.T, h *enrolHarness) {
				t.Helper()

				m, err := mfa.NewTOTP(singleCallStore{h.store}, enrolIssuer,
					mfa.WithClock(h.clock))
				require.NoError(t, err)

				h.totp, h.method = m, m
			},
			assert: func(t *testing.T, h *enrolHarness, c *httpsec.Chain, err error) {
				t.Helper()

				refused("EnableMFAEnrolment", "DeviceProofStore")(t, h, c, err)

				// The same store keeps serving out-of-band enrolment.
				p, err := h.totp.BeginEnrolment(t.Context(), testMFAUser, enrolUsername)
				require.NoError(t, err)
				require.NoError(t, h.totp.ConfirmEnrolment(t.Context(), testMFAUser, h.codeFor(t, p.Secret)))

				enrolled, err := h.totp.Enrolled(t.Context(), testMFAUser)
				require.NoError(t, err)
				assert.True(t, enrolled)
			},
		},
		{
			name: "a nil begin limiter",
			prepare: func(_ *testing.T, h *enrolHarness) {
				h.enrolOpts = []httpsec.EnrolmentOption{httpsec.WithEnrolmentBeginLimiter(nil)}
			},
			assert: refused("WithEnrolmentBeginLimiter"),
		},
		{
			name: "a typed-nil confirmation limiter",
			prepare: func(_ *testing.T, h *enrolHarness) {
				h.enrolOpts = []httpsec.EnrolmentOption{
					httpsec.WithEnrolmentConfirmLimiter((*ratelimit.MemoryLimiter)(nil)),
				}
			},
			assert: refused("WithEnrolmentConfirmLimiter"),
		},
		{
			name: "no sender with the defaults on",
			options: func(t *testing.T, h *enrolHarness) []httpsec.Option {
				t.Helper()

				return append(without(3)(t, h),
					httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: h.users}))
			},
			assert: refused("EnableMFAEnrolment", "Sender"),
		},
		{
			name: "no sender with email confirmation alone off",
			options: func(t *testing.T, h *enrolHarness) []httpsec.Option {
				t.Helper()

				return append(without(3)(t, h),
					httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: h.users},
						httpsec.WithoutEmailConfirmation()))
			},
			assert: refused("EnableMFAEnrolment", "Sender", "WithoutEnrolmentNotification"),
		},
		{
			name: "no sender with both email confirmation and notification off",
			options: func(t *testing.T, h *enrolHarness) []httpsec.Option {
				t.Helper()

				return append(without(3)(t, h),
					httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: h.users},
						httpsec.WithoutEmailConfirmation(), httpsec.WithoutEnrolmentNotification()))
			},
			assert: assembles,
		},
		{
			name: "a synchronous sender without accepting it",
			options: func(t *testing.T, h *enrolHarness) []httpsec.Option {
				t.Helper()

				return append(without(3)(t, h),
					httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: h.users, Sender: h.sender}))
			},
			assert: refused("EnableMFAEnrolment", "WithEnrolmentSynchronousDelivery"),
		},
		{
			name: "a synchronous sender, accepted",
			options: func(t *testing.T, h *enrolHarness) []httpsec.Option {
				t.Helper()

				return append(without(3)(t, h),
					httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: h.users, Sender: h.sender},
						httpsec.WithEnrolmentSynchronousDelivery()))
			},
			assert: assembles,
		},
		{
			name: "a lifetime of zero",
			prepare: func(_ *testing.T, h *enrolHarness) {
				h.enrolOpts = []httpsec.EnrolmentOption{httpsec.WithEnrolmentSessionTTL(0)}
			},
			assert: refused("WithEnrolmentSessionTTL"),
		},
		{
			name: "a lifetime longer than the session manager's absolute timeout",
			prepare: func(_ *testing.T, h *enrolHarness) {
				h.enrolOpts = []httpsec.EnrolmentOption{
					httpsec.WithEnrolmentSessionTTL(h.sessions.AbsoluteTimeout() + time.Minute),
				}
			},
			assert: refused("WithEnrolmentSessionTTL", "absolute timeout"),
		},
		{
			name: "a lifetime equal to the absolute timeout",
			prepare: func(_ *testing.T, h *enrolHarness) {
				h.enrolOpts = []httpsec.EnrolmentOption{
					httpsec.WithEnrolmentSessionTTL(h.sessions.AbsoluteTimeout()),
				}
			},
			assert: assembles,
		},
		{
			name: "no user loader",
			options: func(t *testing.T, h *enrolHarness) []httpsec.Option {
				t.Helper()

				return append(without(3)(t, h),
					httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Sender: queuedSender{h.sender}}))
			},
			assert: refused("EnableMFAEnrolment", "user loader"),
		},
		{
			name: "an empty begin path",
			prepare: func(_ *testing.T, h *enrolHarness) {
				h.enrolOpts = []httpsec.EnrolmentOption{httpsec.WithEnrolmentBeginPath("")}
			},
			assert: refused("WithEnrolmentBeginPath"),
		},
		{
			name: "two enrolment endpoints on one path",
			prepare: func(_ *testing.T, h *enrolHarness) {
				h.enrolOpts = []httpsec.EnrolmentOption{
					httpsec.WithEnrolmentConfirmPath(httpsec.DefaultEnrolmentBeginPath),
				}
			},
			assert: refused("EnableMFAEnrolment", httpsec.DefaultEnrolmentBeginPath),
		},
		{
			name: "an enrolment endpoint on the logout path",
			prepare: func(_ *testing.T, h *enrolHarness) {
				h.enrolOpts = []httpsec.EnrolmentOption{
					httpsec.WithEnrolmentEmailConfirmPath(httpsec.DefaultLogoutPath),
				}
			},
			assert: refused("EnableMFAEnrolment", httpsec.DefaultLogoutPath),
		},
		{
			name: "the path enabled twice",
			options: func(t *testing.T, h *enrolHarness) []httpsec.Option {
				t.Helper()

				return append(h.options(t, nil), httpsec.EnableMFAEnrolment(h.deps()))
			},
			assert: refused("EnableMFAEnrolment", "twice"),
		},
		{
			// The other half of the pairing is not a check of this option's:
			// the requirement policy declares the enrolment challenge, and the
			// chain's enforcer check refuses it with nothing to enforce it.
			name:    "the policy side on and no enrolment path",
			options: without(3),
			assert:  refused("ChallengeMFAEnrolment", "EnableMFAEnrolment"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

			if tc.prepare != nil {
				tc.prepare(t, h)
			}

			opts := h.options(t, nil)
			if tc.options != nil {
				opts = tc.options(t, h)
			}

			c, err := httpsec.New(opts...)
			tc.assert(t, h, c, err)
		})
	}
}

// compile-time proof that the doubles are what the path is wired to.
var (
	_ mfa.Enroller = (*MockEnroller)(nil)
	_ mfa.Enroller = (*mfa.TOTP)(nil)
)
