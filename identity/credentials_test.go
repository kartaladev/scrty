package identity_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

func TestCredentialsType(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		credentials identity.Credentials
		assert      func(t *testing.T, kind identity.CredentialsType)
	}

	cases := []testCase{
		{
			name:        "a username and password reports its type",
			credentials: identity.NewUsernamePassword("alice", []byte("hunter2")),
			assert: func(t *testing.T, kind identity.CredentialsType) {
				// The wire value is pinned once, by TestCredentialsTypesAreNamed.
				assert.Equal(t, identity.CredentialsUsernamePassword, kind)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.credentials.Type())
		})
	}
}

func TestCredentialsTypesAreNamed(t *testing.T) {
	t.Parallel()

	assert.Equal(t, identity.CredentialsType("username-password"), identity.CredentialsUsernamePassword)
	assert.Equal(t, identity.CredentialsType("jwt"), identity.CredentialsJWT)
}

// TestUsernamePasswordCleanupWipesTheBuffer asserts on the caller's own buffer,
// not on the credential's field. A Cleanup that assigned a fresh slice, or set
// the field to nil, would leave the caller's bytes sitting in memory and still
// pass a test that only read the credential back.
func TestUsernamePasswordCleanupWipesTheBuffer(t *testing.T) {
	t.Parallel()

	secret := []byte("hunter2")
	creds := identity.NewUsernamePassword("alice", secret)

	require.NoError(t, creds.Cleanup())

	assert.Equal(t, make([]byte, len("hunter2")), secret,
		"cleanup overwrites the caller's buffer in place, it does not just drop the reference")
}
