// This is the reproduction for task 5.8: the library's PrivilegeAuthorizer
// returns a failing RoleLoader's error behind fixed text, its cause still
// reachable, and matching no authorize sentinel the unwrapped error did not
// already match.
package authorize_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
)

// errFixture is the dependency error the role loader fails with: its text
// quotes an address and a user reference that the returned error must never
// carry.
var errFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// authorizeSentinelsNotMatched are this package's own sentinels. The
// unwrapped role-loader failure at HEAD matches none of them (it is neither
// ErrAccessDenied nor a configuration error), so the wrapped error must not
// newly match any of them either.
var authorizeSentinelsNotMatched = []error{
	authorize.ErrConfig,
	authorize.ErrUnsupportedAttributes,
	authorize.ErrInvalidAttributes,
	authorize.ErrAccessDenied,
	authorize.ErrAuthenticationRequired,
}

func TestAuthorizeReturnedErrors(t *testing.T) {
	t.Parallel()

	roles := NewMockRoleLoader(gomock.NewController(t))
	roles.EXPECT().LoadPrivileges(gomock.Any(), "editor").Return(nil, errFixture)

	authorizer, err := authorize.NewPrivilegeAuthorizer(roles)
	require.NoError(t, err)

	authErr := authorizer.Authorize(withRole(t.Context(), "editor"), authorize.PrivilegeAttributes{
		Group:    "billing",
		Resource: "invoice",
		Required: []string{"read"},
		Mode:     authorize.MatchAnyOf,
	})

	require.Error(t, authErr)

	text := authErr.Error()
	assert.NotContains(t, text, "alice@example.com", "the returned error quotes the dependency")
	assert.NotContains(t, text, "u-123", "the returned error quotes the dependency")
	require.ErrorIs(t, authErr, errFixture, "the dependency's error is no longer reachable")

	for _, sentinel := range authorizeSentinelsNotMatched {
		assert.NotErrorIs(t, authErr, sentinel, "the refusal newly matches %v", sentinel)
	}
}
