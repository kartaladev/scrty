package recovery_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/recovery"
)

// TestHasWayBack_IssuedCodePairing pins that the way-back check counts only
// the pairings a recovery accepts, over the library's own MFA kind: an MFA
// method delivered by email does not pair with an issued code, which arrives
// by email too, and a loader that finds no user is a user with nothing.
func TestHasWayBack_IssuedCodePairing(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")
	withoutPassword := &identity.Details{ID: user, Username: "alice", Active: true}

	type testCase struct {
		name   string
		setup  func(set mfaMethods, users *MockUserLoader)
		assert func(t *testing.T, ok bool, err error)
	}

	cases := []testCase{
		{
			name: "only an emailed MFA method with issued codes is no way back",
			setup: func(set mfaMethods, users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), user).Return(withoutPassword, nil)
				set.methods["totp"].EXPECT().Enrolled(gomock.Any(), user).Return(false, nil)
				set.methods["email-code"].EXPECT().Enrolled(gomock.Any(), user).Return(true, nil)
			},
			assert: func(t *testing.T, ok bool, err error) {
				require.NoError(t, err)
				assert.False(t, ok, "an emailed MFA method was counted as pairing with an emailed issued code")
			},
		},
		{
			name: "TOTP with issued codes is a way back",
			setup: func(set mfaMethods, users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), user).Return(withoutPassword, nil)
				set.methods["totp"].EXPECT().Enrolled(gomock.Any(), user).Return(true, nil)
				set.methods["email-code"].EXPECT().Enrolled(gomock.Any(), user).Return(true, nil).AnyTimes()
			},
			assert: func(t *testing.T, ok bool, err error) {
				require.NoError(t, err)
				assert.True(t, ok)
			},
		},
		{
			name: "a loader with no details does not panic, and the kinds still count",
			setup: func(set mfaMethods, users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), user).Return(nil, nil)
				set.methods["totp"].EXPECT().Enrolled(gomock.Any(), user).Return(true, nil)
				set.methods["email-code"].EXPECT().Enrolled(gomock.Any(), user).Return(false, nil).AnyTimes()
			},
			assert: func(t *testing.T, ok bool, err error) {
				require.NoError(t, err)
				assert.True(t, ok)
			},
		},
		{
			name: "a loader with no details and nothing held is no way back",
			setup: func(set mfaMethods, users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), user).Return(nil, nil)
				set.methods["totp"].EXPECT().Enrolled(gomock.Any(), user).Return(false, nil)
				set.methods["email-code"].EXPECT().Enrolled(gomock.Any(), user).Return(false, nil)
			},
			assert: func(t *testing.T, ok bool, err error) {
				require.NoError(t, err)
				assert.False(t, ok)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			set, methods := removableMethods(ctrl)
			users := NewMockUserLoader(ctrl)
			codes := NewMockCodeStore(ctrl)
			codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
			tc.setup(set, users)

			kind, err := recovery.MFAEnrolments(methods...)
			require.NoError(t, err)

			c, err := recovery.NewWayBackCheck(recovery.WayBackDeps{
				Users:       users,
				Codes:       newCodes(t, recovery.WithCodesStore(codes)),
				Kinds:       []recovery.AuthenticatorKind{kind},
				IssuedCodes: true,
			})
			require.NoError(t, err)

			ok, err := c.HasWayBack(t.Context(), user)
			tc.assert(t, ok, err)
		})
	}
}
