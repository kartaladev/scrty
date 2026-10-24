package authorize_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
)

func TestPrivilegeAuthorizer_DefaultComparerDoesNotFoldDistinctUnicodeNames(t *testing.T) {
	t.Parallel()

	// names is the group, resource and privilege of one side of a comparison.
	type names struct{ group, resource, privilege string }

	type testCase struct {
		name    string
		granted names // what the role holds
		asked   names // what the attempt requires
		assert  func(t *testing.T, err error)
	}

	allowed := func(t *testing.T, err error) { require.NoError(t, err) }
	denied := func(t *testing.T, err error) { require.ErrorIs(t, err, authorize.ErrAccessDenied) }

	cases := []testCase{
		{
			name:    "the Kelvin sign is not a k in a privilege name",
			granted: names{"billing", "invoice", "Kill"}, asked: names{"billing", "invoice", "kill"},
			assert: denied,
		},
		{
			name:    "the long s is not an s in a group name",
			granted: names{"ſales", "invoice", "read"}, asked: names{"sales", "invoice", "read"},
			assert: denied,
		},
		{
			name:    "the Kelvin sign is not a k in a resource name",
			granted: names{"billing", "Kiosk", "read"}, asked: names{"billing", "kiosk", "read"},
			assert: denied,
		},
		{
			name:    "a no-break space around a required privilege name is not trimmed",
			granted: names{"billing", "invoice", "write"}, asked: names{"billing", "invoice", " write"},
			assert: denied,
		},
		{
			name:    "a no-break space around a granted privilege name is not trimmed",
			granted: names{"billing", "invoice", "write "}, asked: names{"billing", "invoice", "write"},
			assert: denied,
		},
		{
			name:    "a no-break space around a group name is not trimmed",
			granted: names{" billing", "invoice", "write"}, asked: names{"billing", "invoice", "write"},
			assert: denied,
		},
		{
			name:    "ASCII case and ASCII whitespace are still ignored",
			granted: names{" Billing ", "\tInvoice\n", " WRITE "}, asked: names{"billing", "invoice", "write"},
			assert: allowed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			roles := NewMockRoleLoader(ctrl)
			roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").
				Return(grantOn(tc.granted.group, tc.granted.resource,
					map[string]bool{tc.granted.privilege: true}), nil)

			authorizer, err := authorize.NewPrivilegeAuthorizer(roles)
			require.NoError(t, err)

			tc.assert(t, authorizer.Authorize(withRole(t.Context(), "clerk"), authorize.PrivilegeAttributes{
				Group:    tc.asked.group,
				Resource: tc.asked.resource,
				Required: []string{tc.asked.privilege},
				Mode:     authorize.MatchAnyOf,
			}))
		})
	}
}
