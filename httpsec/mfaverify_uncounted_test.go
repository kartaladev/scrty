package httpsec_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/session"
)

// TestMFAVerify_AuthenticatorRefusedUncounted pins that a method refusing the
// authenticator itself — a suspected clone, a suspended credential — is not a
// wrong guess: the refusal comes back unchanged and nothing is counted against
// the user. Every other refusal still is. Either way the challenge stays
// pending and the handle does not move.
func TestMFAVerify_AuthenticatorRefusedUncounted(t *testing.T) {
	t.Parallel()

	errClone := fmt.Errorf("%w: suspected clone", mfa.ErrAuthenticatorRefused)

	type testCase struct {
		name      string
		verifyErr error
		// failures is how many failed verifications the limiter must record.
		failures int
		assert   func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:      "a refused authenticator is returned unchanged and not counted",
			verifyErr: errClone,
			failures:  0,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, mfa.ErrAuthenticatorRefused)
				require.ErrorIs(t, err, errClone, "the method's refusal is returned as it was")
				assert.NotErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(err))
			},
		},
		{
			name:      "an invalid response is still counted",
			verifyErr: mfa.ErrInvalidCode,
			failures:  1,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(err))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).neverVerifies()
			h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
				Return(false, nil).AnyTimes()
			h.limiter.EXPECT().RecordFailure(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
				Return(nil).Times(tc.failures)

			stub := newChallengeStub()
			stub.verifyErr = tc.verifyErr
			h.extra = []mfa.Method{stub}

			s := h.pendingSession(t, factor.Password)
			c := h.bearerChain(t)

			begun := serve(t, c, bearerPost(t.Context(), testMFABeginPath, mfaTokenFor(s.ID)))
			require.NoError(t, begun.err, "the begin succeeds")

			out := serve(t, c, bearerJSON(t.Context(), testPasskeyVerifyPath, mfaTokenFor(s.ID),
				answer(issuedChallenge(t, begun))))

			require.Equal(t, int32(1), stub.verifyCalls.Load(), "the method is asked to verify")
			assert.False(t, out.handlerRan)
			tc.assert(t, out.err)

			still := h.stored(t, s.ID)
			assert.Equal(t, s.ID, still.ID, "the handle is unchanged")
			assert.Equal(t, session.MFAPending, still.MFA, "the challenge stays pending")
			assert.True(t, still.MFASatisfiedAt.IsZero())
		})
	}
}
