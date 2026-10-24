package recovery_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/recovery"
)

// TestRecoverer_ProofChannels pins that the two proofs of a recovery never
// share a delivery channel: an issued code arrives by email, so it does not
// pair with an MFA method whose codes arrive by email, while a saved code does.
func TestRecoverer_ProofChannels(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(e *recoverEnv, email *MockMethod)
		req    func(e *recoverEnv) recovery.Request
		assert func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, v *recovery.Verified, err error)
	}

	cases := []testCase{
		{
			// The email method mock has no Enrolled or Verify expectation, so
			// a check of the MFA proof would fail the test on its own.
			name: "an issued code with an emailed MFA code is malformed, and nothing is checked or spent",
			req: func(e *recoverEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Issued: e.issued, MFAMethod: "email-code", MFACode: "123456"}
			},
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.ErrorIs(t, err, recovery.ErrMalformed, "an emailed recovery code plus an emailed MFA code recovered the account")
				assert.False(t, recovery.RefusedAfterValidCode(err))
				assert.True(t, e.issuedUsable(t.Context(), t, r, anaID, e.issued), "the issued code stays redeemable")
				assert.Zero(t, e.failures.Load(), "a malformed recovery counts nothing")
			},
		},
		{
			name: "saved code with an emailed MFA code still recovers",
			setup: func(_ *recoverEnv, email *MockMethod) {
				email.EXPECT().Enrolled(gomock.Any(), anaID).Return(true, nil)
				email.EXPECT().Verify(gomock.Any(), anaID, []byte("123456")).Return(nil)
			},
			req: func(e *recoverEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Saved: e.saved[0], MFAMethod: "email-code", MFACode: "123456"}
			},
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, v *recovery.Verified, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.ProofKind{recovery.ProofSaved, recovery.ProofMFA}, v.Proofs())
				assert.Equal(t, []recovery.AuthenticatorRef{refEmail}, v.Proven())
				assert.False(t, e.savedUsable(t.Context(), t, e.saved[0]), "the saved code is spent")
			},
		},
		{
			name: "an issued code with TOTP still recovers",
			setup: func(e *recoverEnv, _ *MockMethod) {
				e.totp.EXPECT().Enrolled(gomock.Any(), anaID).Return(true, nil)
				e.totp.EXPECT().Verify(gomock.Any(), anaID, []byte("123456")).Return(nil)
			},
			req: func(e *recoverEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Issued: e.issued, MFAMethod: "totp", MFACode: "123456"}
			},
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, v *recovery.Verified, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.ProofKind{recovery.ProofIssued, recovery.ProofMFA}, v.Proofs())
				assert.False(t, e.issuedUsable(t.Context(), t, r, anaID, e.issued), "the issued code is spent")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newRecoverEnv(t)
			email := declaredMethod(e.ctrl, "email-code", factor.Email)
			if tc.setup != nil {
				tc.setup(e, email)
			}
			e.defaults()

			r, err := recovery.NewRecoverer(e.deps(), e.opts(recovery.WithMFAMethods(e.totp, email))...)
			require.NoError(t, err)

			v, err := recoverOnce(t.Context(), r, tc.req(e))
			tc.assert(t, e, r, v, err)
		})
	}
}
