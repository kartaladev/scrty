package httpsec_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// TestCompleteLogin_Proof pins that the login tail records a second factor met
// at the first factor: a login carrying the library's holding proof creates
// its session satisfied, in the creating write, and still owes any other
// challenge the phase raises; a login carrying none behaves as it always did.
func TestCompleteLogin_Proof(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

	type written struct {
		created *session.Session
		saved   *session.Session
	}

	type testCase struct {
		name string
		// proof is whether the input carries a holding proof.
		proof bool
		// passwordAge adds the password-age policy and a stale password.
		passwordAge bool
		// totpEnrolled enrols the user on TOTP besides their passkey.
		totpEnrolled bool
		assert       func(t *testing.T, tok string, err error, w written)
	}

	cases := []testCase{
		{
			name:  "satisfied at creation",
			proof: true,
			assert: func(t *testing.T, tok string, err error, w written) {
				require.NoError(t, err, "the second factor was met at the first, so no challenge is owed")
				assert.Equal(t, "issued-token", tok)

				require.NotNil(t, w.created)
				assert.Equal(t, session.MFASatisfied, w.created.MFA,
					"satisfied in the creating write, never briefly unsatisfied")
				assert.True(t, w.created.MFAAtFirstFactor)
				assert.True(t, w.created.MFASatisfiedAt.Equal(w.created.CreatedAt))
				assert.Equal(t, factor.Passkey, w.created.FirstFactor)
				assert.Nil(t, w.saved, "nothing is saved after the creating write")
			},
		},
		{
			name:        "password-change still challenges",
			proof:       true,
			passwordAge: true,
			assert: func(t *testing.T, tok string, err error, w written) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, err, &ch)
				assert.Equal(t, policy.ChallengePasswordChange, ch.Kind)
				assert.Equal(t, "issued-token", tok)

				require.NotNil(t, w.created)
				assert.Equal(t, session.MFASatisfied, w.created.MFA)

				require.NotNil(t, w.saved, "the challenge is marked and saved")
				assert.Equal(t, session.MFASatisfied, w.saved.MFA)
				assert.True(t, w.saved.MFAAtFirstFactor)
				assert.True(t, w.saved.PasswordChangePending)
			},
		},
		{
			name:         "zero proof unchanged",
			totpEnrolled: true,
			assert: func(t *testing.T, tok string, err error, w written) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, err, &ch)
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				assert.Equal(t, "issued-token", tok)

				require.NotNil(t, w.created)
				assert.Equal(t, session.MFANone, w.created.MFA)
				assert.False(t, w.created.MFAAtFirstFactor)

				require.NotNil(t, w.saved)
				assert.Equal(t, session.MFAPending, w.saved.MFA)
				assert.False(t, w.saved.MFAAtFirstFactor)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			passkey := NewMockMFAMethodLookup(ctrl)
			passkey.EXPECT().Name().Return("passkey").AnyTimes()
			passkey.EXPECT().Channel().Return(factor.PublicKey).AnyTimes()
			passkey.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

			totp := NewMockMFAMethodLookup(ctrl)
			totp.EXPECT().Name().Return("totp").AnyTimes()
			totp.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
			totp.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(tc.totpEnrolled, nil).AnyTimes()

			lookups := []policy.MFAMethodLookup{passkey, totp}

			requirement, err := policy.NewMFARequirementPolicy(nil, lookups, policy.WithMFARequiredForAll())
			require.NoError(t, err)

			challenge, err := policy.NewMFAPolicy(lookups)
			require.NoError(t, err)

			policies := []policy.Policy{requirement, challenge}
			passwordChangedAt := start.Add(-time.Hour)

			if tc.passwordAge {
				age, err := policy.NewPasswordAgePolicy(policy.WithMaxPasswordAge(maxPasswordAge))
				require.NoError(t, err)

				policies = append(policies, age)
				passwordChangedAt = start.Add(-2 * maxPasswordAge)
			}

			store := NewMockStore(ctrl)
			tokens := NewMockGenerator(ctrl)

			sessions, err := session.NewManager(session.WithStore(store),
				session.WithClock(clockwork.NewFakeClockAt(start)))
			require.NoError(t, err)

			var w written

			store.EXPECT().Create(gomock.Any(), gomock.Any()).Times(1).
				DoAndReturn(func(_ context.Context, s *session.Session) error {
					c := *s
					w.created = &c

					return nil
				})
			store.EXPECT().Save(gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, s *session.Session) error {
					c := *s
					w.saved = &c

					return nil
				})
			tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("issued-token", nil)

			in := httpsec.PostAuthenticationInputForTest(
				testPrincipal(), factor.Passkey, "ada", passwordChangedAt, start)
			if tc.proof {
				in.SecondFactorAtLogin = httpsec.MintProofForTest(factor.Passkey, start)
			}

			tok, err := httpsec.CompleteLoginForTest(newExchange(t),
				httpsec.LoginTailDepsForTest(engineOf(t, policies...), sessions, tokens), in)

			tc.assert(t, tok, err, w)
		})
	}
}
