package authenticate_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/token"
)

// errRedactionFixture is the dependency error every diagnostic-redaction
// reproduction in this change quotes: a username and a user reference the
// library never saw, which no returned error's text may carry.
var errRedactionFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// TestAuthenticateReturnedErrors pins task 5.7 for this package: an error
// caused by a consumer-supplied dependency at construction or at
// authentication carries the library's own fixed text, with the cause and any
// sentinel it already matched still reachable by identity.
//
// The password authenticator's credential cleanup
// (identity.UsernamePassword.Cleanup) is not a row here: that concrete type's
// Cleanup always returns nil, so the branch that would wrap its error is
// unreachable from the public API and there is nothing a test can make fail.
func TestAuthenticateReturnedErrors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T, ctrl *gomock.Controller) error
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "the password authenticator's reference-hash encoder probe fails",
			run: func(t *testing.T, ctrl *gomock.Controller) error {
				t.Helper()

				enc := NewMockEncoder(ctrl)
				enc.EXPECT().Encode(gomock.Any()).Return(nil, errRedactionFixture)

				_, err := authenticate.NewUsernamePasswordAuthenticator(
					NewMockUserLoader(ctrl), authenticate.WithPasswordEncoder(enc))
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.NotContains(t, err.Error(), "alice@example.com")
				assert.NotContains(t, err.Error(), "u-123")
				assert.ErrorIs(t, err, authenticate.ErrConfig,
					"the outer config sentinel already matched regardless of cause before this change")
				assert.ErrorIs(t, err, errRedactionFixture, "the encoder's own error is still reachable")
			},
		},
		{
			name: "the jwt authenticator's credential cleanup fails",
			run: func(t *testing.T, ctrl *gomock.Controller) error {
				t.Helper()

				v := NewMockVerifier(ctrl)
				v.EXPECT().Verify(gomock.Any(), gomock.Any()).Return(token.NewClaims("ada", tokenID.String()), nil)

				auth, err := authenticate.NewJwtAuthenticator(authenticate.WithJwtVerifier(v))
				require.NoError(t, err)

				creds := NewMockBearerCredentials(ctrl)
				creds.EXPECT().Token().Return(presentedToken)
				creds.EXPECT().Cleanup().Return(errRedactionFixture)

				_, err = auth.Authenticate(t.Context(), creds)
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.NotContains(t, err.Error(), "alice@example.com")
				assert.NotContains(t, err.Error(), "u-123")
				assert.ErrorIs(t, err, errRedactionFixture)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			tc.assert(t, tc.run(t, ctrl))
		})
	}
}
