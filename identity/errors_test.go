package identity_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

func TestMissingPort(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		port   string
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "the error names the port the component needs",
			port: "user loader",
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "user loader",
					"the consumer has to learn which port to wire")
			},
		},
		{
			name: "every missing port matches one sentinel",
			port: "role loader",
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, identity.ErrMissingPort,
					"a caller checks for a wiring mistake without naming each port")
			},
		},
		{
			name: "the port is readable from the error, not only from its text",
			port: "mfa requirement lookup",
			assert: func(t *testing.T, err error) {
				var missing *identity.MissingPortError
				require.ErrorAs(t, err, &missing)
				assert.Equal(t, "mfa requirement lookup", missing.Port)
			},
		},
		{
			name: "a missing port is not mistaken for a missing user",
			port: "user provisioner",
			assert: func(t *testing.T, err error) {
				assert.NotErrorIs(t, err, identity.ErrUserNotFound,
					"a wiring mistake is a configuration error, not a lookup miss")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, identity.MissingPort(tc.port))
		})
	}
}

func TestSentinelsAreDistinct(t *testing.T) {
	t.Parallel()

	sentinels := map[string]error{
		"ErrUserNotFound":       identity.ErrUserNotFound,
		"ErrUserExists":         identity.ErrUserExists,
		"ErrPrivilegesNotFound": identity.ErrPrivilegesNotFound,
		"ErrNoPrincipal":        identity.ErrNoPrincipal,
		"ErrMissingPort":        identity.ErrMissingPort,
	}

	for name, err := range sentinels {
		require.Error(t, err, "%s must be a real error", name)
		assert.Contains(t, err.Error(), "identity: ",
			"%s must name its package, so a wrapped error says where it came from", name)

		for otherName, other := range sentinels {
			if name == otherName {
				continue
			}

			assert.False(t, errors.Is(err, other),
				"%s must not match %s, or callers cannot tell the two apart", name, otherName)
		}
	}
}
