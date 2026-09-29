package httpsec_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// TestEnrolmentSessionTTLOption pins that WithEnrolmentSessionTTL's value is
// what a real login actually lowers an enrolment-only session's deadline to,
// not only what enrolmentInterceptor.lifetime holds in memory. EnableMFAEnrolment
// carries the option into the chain's shared enrolment lifetime
// (config.enrolmentLifetime), which the login tail reads when it marks a
// session enrolment-pending; a chain built without that wiring would silently
// keep every session on the 15-minute default regardless of the option.
//
// Each case drives a real magic-link login through a fully assembled chain,
// then loads the session the login tail saved at a later instant, moving only
// the session manager's injected clock between the two steps.
func TestEnrolmentSessionTTLOption(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)

	type testCase struct {
		name      string
		enrolOpts []httpsec.EnrolmentOption
		at        time.Time
		assert    func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:      "default lifetime: no longer loads at 09:16",
			enrolOpts: nil,
			at:        start.Add(16 * time.Minute),
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, session.ErrSessionExpired)
			},
		},
		{
			name:      "consumer lifetime: still loads at 09:20",
			enrolOpts: []httpsec.EnrolmentOption{httpsec.WithEnrolmentSessionTTL(30 * time.Minute)},
			at:        start.Add(20 * time.Minute),
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(start)

			h := newMagicLinkHarness(t)

			store := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
			mgr, err := session.NewManager(
				session.WithStore(store),
				session.WithClock(clk))
			require.NoError(t, err)
			h.sessions = mgr

			enrolStore := mfa.NewMemoryEnrolmentStore()
			totp, err := mfa.NewTOTP(enrolStore, enrolIssuer, mfa.WithClock(clk))
			require.NoError(t, err)

			ctrl := gomock.NewController(t)
			lookup := NewMockMFAMethodLookup(ctrl)
			lookup.EXPECT().Name().Return("totp").AnyTimes()
			lookup.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
			lookup.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()

			requirement, err := policy.NewMFARequirementPolicy(everyoneRequired{}, []policy.MFAMethodLookup{enrollableLookup{lookup}},
				policy.WithMFAEnrolmentPath())
			require.NoError(t, err)

			mfaTokens := NewMockGenerator(ctrl)

			chain, err := httpsec.New(
				httpsec.EnableMagicLink(h.manager, h.options()...),
				httpsec.WithPolicyEngine(engineOf(t, requirement)),
				httpsec.EnableMFA([]mfa.Method{totp}, httpsec.WithMFATokens(mfaTokens)),
				httpsec.EnableMFAEnrolment(
					httpsec.EnrolmentDeps{Users: h.users, Sender: h.sender}, tc.enrolOpts...),
			)
			require.NoError(t, err)

			tok, nonce := h.link(t, chain)
			out := h.redeem(t, chain, tok, nonce)

			var ch *httpsec.ChallengeError
			require.ErrorAs(t, out.err, &ch)
			require.Equal(t, policy.ChallengeMFAEnrolment, ch.Kind)

			id, ok := h.sessionID.Load().(string)
			require.True(t, ok, "no access token was issued for the enrolment-only session")
			require.NotEmpty(t, id)

			clk.Advance(tc.at.Sub(clk.Now()))

			_, err = mgr.Load(t.Context(), id)
			tc.assert(t, err)
		})
	}
}
