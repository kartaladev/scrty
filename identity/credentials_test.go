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

// TestUsernamePasswordCleanup asserts on the caller's own buffer, never on the
// credential's field. A Cleanup that assigned a fresh slice, or set the field to
// nil, would leave the caller's bytes sitting in memory and still pass a test
// that only read the credential back.
//
// Every case goes through the Credentials interface and through NotPanics,
// because that is how a provider uses one: it defers Cleanup on the credential
// it was handed, whatever came back.
func TestUsernamePasswordCleanup(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// build returns the credential to clean up and the caller's own buffer,
		// which is what the assertions read.
		build  func(t *testing.T) (*identity.UsernamePassword, []byte)
		assert func(t *testing.T, secret []byte, err error)
	}

	cases := []testCase{
		{
			name: "the caller's buffer is overwritten in place",
			build: func(t *testing.T) (*identity.UsernamePassword, []byte) {
				t.Helper()

				secret := []byte("hunter2")

				return identity.NewUsernamePassword("alice", secret), secret
			},
			assert: func(t *testing.T, secret []byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, make([]byte, len("hunter2")), secret,
					"cleanup overwrites the caller's buffer in place, it does not just drop "+
						"the reference")
			},
		},
		{
			name: "the buffer the credential was built over is wiped after the field is reassigned",
			build: func(t *testing.T) (*identity.UsernamePassword, []byte) {
				t.Helper()

				secret := make([]byte, len("hunter2"))
				copy(secret, "hunter2")

				creds := identity.NewUsernamePassword("alice", secret)

				// Any use of the exported field that reallocates — normalising,
				// padding, appending a terminator — leaves the field pointing at a
				// new array while the secret stays in the old one.
				creds.Password = append(creds.Password, '!')

				return creds, secret
			},
			assert: func(t *testing.T, secret []byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, make([]byte, len("hunter2")), secret,
					"the secret is still resident in the buffer the credential was built over: "+
						"wiping only what the field points at now orphans the array holding it")
			},
		},
		{
			name: "an absent credential reports rather than panics",
			build: func(t *testing.T) (*identity.UsernamePassword, []byte) {
				t.Helper()

				// A provider that produced no credential still runs its deferred
				// cleanup, and a typed nil inside the interface is not nil, so the
				// caller cannot guard against it.
				return nil, nil
			},
			assert: func(t *testing.T, _ []byte, err error) {
				assert.NoError(t, err, "there is nothing to wipe, which is not a failure")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			creds, secret := tc.build(t)

			var presented identity.Credentials = creds

			var err error

			require.NotPanics(t, func() { err = presented.Cleanup() },
				"a deferred Cleanup must not take the process down")

			tc.assert(t, secret, err)
		})
	}
}
