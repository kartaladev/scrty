package authenticate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
)

func TestManager_NestedManagerThatSkipsLetsOuterTryNextDelegate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator
		assert func(t *testing.T, got *authenticate.Authentication, err error)
	}

	// skipping returns a manager whose only provider skips every credential, so
	// its own answer is ErrNoEligibleAuthenticator.
	skipping := func(t *testing.T, ctrl *gomock.Controller) *authenticate.FirstOf {
		t.Helper()

		inner := NewMockAuthenticator(ctrl)
		inner.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Return(nil, authenticate.ErrUnsupportedCredentials)

		nested, err := authenticate.NewFirstOf(inner)
		require.NoError(t, err)

		return nested
	}

	cases := []testCase{
		{
			name: "the next delegate authenticates what the nested manager skipped",
			build: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				next := NewMockAuthenticator(ctrl)
				next.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(&authenticate.Authentication{Principal: principal(t)}, nil)

				return []authenticate.Authenticator{skipping(t, ctrl), next}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.NoError(t, err, "a nested manager that skipped is a skip, not an answer")
				require.NotNil(t, got)
				assert.Equal(t, "ada", got.Principal.Username)
			},
		},
		{
			name: "every delegate being a skipping manager is still no eligible authenticator",
			build: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				return []authenticate.Authenticator{skipping(t, ctrl), skipping(t, ctrl)}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrNoEligibleAuthenticator)
				assert.Nil(t, got)
			},
		},
		{
			name: "an outage inside a nested manager still stops the walk",
			build: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				inner := NewMockAuthenticator(ctrl)
				inner.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Return(nil, errBackendDown)

				nested, err := authenticate.NewFirstOf(inner)
				require.NoError(t, err)

				// No EXPECT: an outage must not be retried by a later delegate.
				return []authenticate.Authenticator{nested, NewMockAuthenticator(ctrl)}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, errBackendDown)
				assert.Nil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			outer, err := authenticate.NewFirstOf(tc.build(t, ctrl)...)
			require.NoError(t, err)

			got, err := outer.Authenticate(t.Context(), credentials(t))
			tc.assert(t, got, err)
		})
	}
}

func TestPasswordProvider_TypedNilCredentialsRefusedWithoutPanic(t *testing.T) {
	t.Parallel()

	var typedNil *identity.UsernamePassword

	type testCase struct {
		name string
		run  func(t *testing.T, p authenticate.Authenticator)
	}

	cases := []testCase{
		{
			name: "Authenticate reports unsupported credentials",
			run: func(t *testing.T, p authenticate.Authenticator) {
				t.Helper()

				got, err := p.Authenticate(t.Context(), typedNil)

				require.ErrorIs(t, err, authenticate.ErrUnsupportedCredentials)
				assert.Nil(t, got)
			},
		},
		{
			name: "VerifyDecoy declines them without hashing",
			run: func(t *testing.T, p authenticate.Authenticator) {
				t.Helper()

				v, ok := p.(authenticate.DecoyVerifier)
				require.True(t, ok, "the password provider must implement DecoyVerifier")

				assert.False(t, v.VerifyDecoy(t.Context(), typedNil))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			enc := NewMockEncoder(ctrl)
			// Only the construction-time reference: any Match call is a failure.
			enc.EXPECT().Encode(gomock.Any()).Return([]byte("reference-hash"), nil).Times(1)
			// No expectations: loading a user for no one is a failure.
			users := NewMockUserLoader(ctrl)

			p, err := authenticate.NewUsernamePasswordAuthenticator(users, authenticate.WithPasswordEncoder(enc))
			require.NoError(t, err)

			tc.run(t, p)
		})
	}
}
