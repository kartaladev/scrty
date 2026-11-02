package password_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
)

func TestConditionalProvisionerRehash(t *testing.T) {
	t.Parallel()

	replaced := []byte("old-64-mib-hash")
	upgraded := []byte("new-128-mib-hash")
	user := &identity.Details{ID: "u1", Username: "ada", Password: replaced}

	errDown := errors.New("store down")

	// conditionalWrite checks the one call the write makes: the upgraded hash,
	// conditional on the replaced one, and nothing else.
	conditionalWrite := func(t *testing.T, ret error) func(context.Context, string, ...identity.UserOption) (*identity.Details, error) {
		return func(_ context.Context, _ string, opts ...identity.UserOption) (*identity.Details, error) {
			change := identity.ApplyUserOptions(opts...)
			expected, conditional := change.ExpectedPassword()
			assert.True(t, conditional,
				"the write must be conditional on the replaced hash, decided by the store in the write itself")
			assert.Equal(t, replaced, expected)
			assert.True(t, change.IsSet(identity.FieldPassword))
			assert.Equal(t, upgraded, change.Password)
			assert.False(t, change.IsSet(identity.FieldPasswordChangedAt),
				"a rehash is not a password change and must not move the password's age")

			if ret != nil {
				return nil, ret
			}

			return &identity.Details{}, nil
		}
	}

	type testCase struct {
		name   string
		setup  func(t *testing.T, prov *MockUserProvisioner)
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "the replaced hash is still stored, so the store writes the upgraded one",
			setup: func(t *testing.T, prov *MockUserProvisioner) {
				prov.EXPECT().Update(gomock.Any(), "ada", gomock.Any()).DoAndReturn(conditionalWrite(t, nil))
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "a password change stored a new hash meanwhile, so the store writes nothing and that is no failure",
			setup: func(t *testing.T, prov *MockUserProvisioner) {
				prov.EXPECT().Update(gomock.Any(), "ada", gomock.Any()).
					DoAndReturn(conditionalWrite(t, fmt.Errorf("somestore: update user: %w", identity.ErrNotUpdated)))
			},
			assert: func(t *testing.T, err error) {
				require.NoError(t, err, "a concurrent change wins; the next login upgrades the new hash")
			},
		},
		{
			name: "the user is gone, so nothing is written and that is no failure",
			setup: func(t *testing.T, prov *MockUserProvisioner) {
				prov.EXPECT().Update(gomock.Any(), "ada", gomock.Any()).
					DoAndReturn(conditionalWrite(t, identity.ErrUserNotFound))
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "a write that fails is reported",
			setup: func(t *testing.T, prov *MockUserProvisioner) {
				prov.EXPECT().Update(gomock.Any(), "ada", gomock.Any()).DoAndReturn(conditionalWrite(t, errDown))
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, errDown) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			prov := NewMockUserProvisioner(gomock.NewController(t))
			tc.setup(t, prov)

			write := password.ConditionalProvisionerRehash(prov)
			tc.assert(t, write(t.Context(), user, replaced, upgraded))
		})
	}
}
