package authenticate_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/password"
)

func TestPasswordAuthenticatorSuccess(t *testing.T) {
	t.Parallel()

	t.Run("presented secrets are wiped", func(t *testing.T) {
		t.Parallel()

		secret := []byte(storedPassword)
		creds := identity.NewUsernamePassword("ada", secret)

		auth, _ := authenticatorFor(t, cheapEncoder(t))

		got, err := auth.Authenticate(t.Context(), creds)
		require.NoError(t, err)

		assert.NotContains(t, string(secret), storedPassword,
			"the presented password survived in the caller's own buffer")
		assert.Equal(t, make([]byte, len(secret)), secret,
			"the buffer was released rather than overwritten, so the secret is still resident")
		assert.Same(t, creds, got.Credentials,
			"the result carries credentials other than the ones presented")
	})

	t.Run("the result describes the authentication", func(t *testing.T) {
		t.Parallel()

		auth, _ := authenticatorFor(t, cheapEncoder(t))

		before := time.Now()
		got, err := auth.Authenticate(t.Context(),
			identity.NewUsernamePassword("ada", []byte(storedPassword)))
		require.NoError(t, err)
		require.NotNil(t, got)

		require.NotNil(t, got.Principal)
		assert.Equal(t, identity.UserID("u1"), got.Principal.ID)
		assert.Equal(t, "ada", got.Principal.Username)
		assert.Equal(t, passwordChangedAt, got.PasswordChangedAt)
		assert.False(t, got.Time.Before(before), "the result is dated before the request that produced it")
		assert.Equal(t, identity.CredentialsUsernamePassword, got.Credentials.Type())
	})

	t.Run("the default encoder verifies hashes the default encoder produced", func(t *testing.T) {
		t.Parallel()

		// The point of the default is that a consumer who configures nothing
		// can still verify what scrty's own encoder wrote. A default that were
		// a no-op, or another algorithm, would refuse this.
		enc, err := password.NewArgon2idEncoder()
		require.NoError(t, err)

		ctrl := gomock.NewController(t)
		users := NewMockUserLoader(ctrl)
		users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).Return(storedUser(t, enc, true), nil)

		auth, err := authenticate.NewUsernamePasswordAuthenticator(users)
		require.NoError(t, err)

		got, err := auth.Authenticate(t.Context(),
			identity.NewUsernamePassword("ada", []byte(storedPassword)))
		require.NoError(t, err)
		assert.NotNil(t, got)
	})
}

// authenticatorFor returns a provider over one active user whose password is
// storedPassword, hashed by enc, and the loader behind it.
func authenticatorFor(t *testing.T, enc password.Encoder, opts ...authenticate.PasswordOption) (authenticate.Authenticator, *MockUserLoader) {
	t.Helper()

	ctrl := gomock.NewController(t)
	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
		Return(storedUser(t, enc, true), nil).AnyTimes()

	auth, err := authenticate.NewUsernamePasswordAuthenticator(users,
		append([]authenticate.PasswordOption{authenticate.WithPasswordEncoder(enc)}, opts...)...)
	require.NoError(t, err)

	return auth, users
}
