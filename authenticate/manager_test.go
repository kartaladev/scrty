package authenticate_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
)

func TestManagerAuthenticate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		delegates func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator
		assert    func(t *testing.T, got *authenticate.Authentication, err error)
	}

	cases := []testCase{
		{
			name: "the first delegate that answers decides, and later ones are never asked",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				first := NewMockAuthenticator(ctrl)
				first.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(&authenticate.Authentication{Principal: principal(t)}, nil)

				// No EXPECT: asking it at all is the failure.
				second := NewMockAuthenticator(ctrl)

				return []authenticate.Authenticator{first, second}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, "ada", got.Principal.Username)
			},
		},
		{
			name: "ErrUnsupportedCredentials skips to the next delegate",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				first := NewMockAuthenticator(ctrl)
				first.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(nil, authenticate.ErrUnsupportedCredentials)
				second := NewMockAuthenticator(ctrl)
				second.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(&authenticate.Authentication{Principal: principal(t)}, nil)

				return []authenticate.Authenticator{first, second}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, got)
			},
		},
		{
			name: "any other error is returned unchanged, and stops the manager",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				first := NewMockAuthenticator(ctrl)
				first.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(nil, errBackendDown)

				// No EXPECT: a failure must not be retried by a later delegate.
				second := NewMockAuthenticator(ctrl)

				return []authenticate.Authenticator{first, second}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, errBackendDown)
				assert.Nil(t, got)
			},
		},
		{
			name: "every delegate skipping is reported as such",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				first := NewMockAuthenticator(ctrl)
				first.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(nil, authenticate.ErrUnsupportedCredentials)
				second := NewMockAuthenticator(ctrl)
				second.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(nil, authenticate.ErrUnsupportedCredentials)

				return []authenticate.Authenticator{first, second}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrNoEligibleAuthenticator)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed,
					"skipped credentials were reported as a judged refusal")
				assert.Nil(t, got)
			},
		},
		{
			name: "a nil result becomes a failure, not a nil-principal success",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				only := NewMockAuthenticator(ctrl)
				only.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Return(nil, nil)

				return []authenticate.Authenticator{only}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, got)
			},
		},
		{
			name: "a result with a nil principal becomes a failure",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				only := NewMockAuthenticator(ctrl)
				only.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(&authenticate.Authentication{Principal: nil}, nil)

				return []authenticate.Authenticator{only}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, got,
					"a caller reading Principal after a nil error would dereference nothing")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			m, err := authenticate.NewManager(tc.delegates(t, ctrl)...)
			require.NoError(t, err)

			got, err := m.Authenticate(t.Context(), credentials(t))
			tc.assert(t, got, err)
		})
	}
}

// principal returns the resolved caller a delegate reports on success.
func principal(t *testing.T) *identity.Principal {
	t.Helper()

	return &identity.Principal{ID: identity.UserID("u1"), Username: "ada"}
}

// credentials returns credentials to present to a manager. The manager itself
// never reads them, so any kind will do.
func credentials(t *testing.T) identity.Credentials {
	t.Helper()

	return identity.NewUsernamePassword("ada", []byte("correct-horse"))
}

// errBackendDown stands for a failure of something a delegate depends on,
// rather than a decision about the caller. The manager must pass it through
// unchanged so a caller can tell an outage from a refusal.
var errBackendDown = errors.New("the user store is unreachable")
