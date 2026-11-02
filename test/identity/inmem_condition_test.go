package identitytest_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	identitytest "github.com/kartaladev/scrty/test/identity"
)

// TestInMemoryStore_PasswordConditionRefusals pins where the in-memory store
// refuses a password condition: where it has no stored hash to compare, and
// where no new password is named for it to guard.
func TestInMemoryStore_PasswordConditionRefusals(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		call   func(t *testing.T, s *identitytest.InMemoryStore) error
		assert func(t *testing.T, s *identitytest.InMemoryStore, err error)
	}

	cases := []testCase{
		{
			name: "a provision cannot be conditional on a stored hash",
			call: func(t *testing.T, s *identitytest.InMemoryStore) error {
				_, err := s.Provision(t.Context(), "new",
					identity.WithUserPasswordIf([]byte("H1")), identity.WithUserPassword([]byte("H2")))
				return err
			},
			assert: func(t *testing.T, s *identitytest.InMemoryStore, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, identity.ErrNotUpdated)
				_, err = s.LoadByUsername(t.Context(), "new")
				assert.ErrorIs(t, err, identity.ErrUserNotFound, "a refused provision creates nothing")
			},
		},
		{
			name: "an update conditional on the hash must name a new password",
			call: func(t *testing.T, s *identitytest.InMemoryStore) error {
				_, err := s.Update(t.Context(), "target",
					identity.WithUserPasswordIf([]byte("H1")), identity.WithUserName("After"))
				return err
			},
			assert: func(t *testing.T, s *identitytest.InMemoryStore, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, identity.ErrNotUpdated)
				d, err := s.LoadByUsername(t.Context(), "target")
				require.NoError(t, err)
				assert.Empty(t, d.Name, "a refused update writes nothing")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := identitytest.NewInMemoryStore()
			_, err := s.Provision(t.Context(), "target", identity.WithUserPassword([]byte("H1")))
			require.NoError(t, err)

			tc.assert(t, s, tc.call(t, s))
		})
	}
}
