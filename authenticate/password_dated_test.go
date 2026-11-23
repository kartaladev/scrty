package authenticate_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
)

// TestPassword_DatedPrincipal pins that the principal a password login builds
// keeps only the grants in force when it authenticates: an expired or future
// primary grant leaves no active role, and no other grant is promoted.
func TestPassword_DatedPrincipal(t *testing.T) {
	t.Parallel()

	past := time.Now().Add(-48 * time.Hour)
	future := time.Now().Add(48 * time.Hour)

	type testCase struct {
		name   string
		roles  []*identity.AssignedRole
		assert func(t *testing.T, p *identity.Principal)
	}

	cases := []testCase{
		{
			name: "an expired primary grant leaves no active role",
			roles: []*identity.AssignedRole{
				{ID: "r-sales", Name: "sales", Primary: true, ValidUntil: past},
				{ID: "r-audit", Name: "audit"},
			},
			assert: func(t *testing.T, p *identity.Principal) {
				assert.Nil(t, p.ActiveRole, "no other grant is promoted in place of the expired primary")
				require.Len(t, p.Roles, 1)
				assert.Equal(t, "audit", p.Roles[0].Name)
			},
		},
		{
			name: "a primary grant that has not started leaves no active role",
			roles: []*identity.AssignedRole{
				{ID: "r-sales", Name: "sales", Primary: true, StartDate: future},
			},
			assert: func(t *testing.T, p *identity.Principal) {
				assert.Nil(t, p.ActiveRole)
				assert.Empty(t, p.Roles)
			},
		},
		{
			name: "a primary grant in force is active",
			roles: []*identity.AssignedRole{
				{ID: "r-sales", Name: "sales", Primary: true, StartDate: past, ValidUntil: future},
			},
			assert: func(t *testing.T, p *identity.Principal) {
				require.NotNil(t, p.ActiveRole)
				assert.Equal(t, "sales", p.ActiveRole.Name)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUsername(gomock.Any(), "ada").Return(&identity.Details{
				ID: "u1", Username: "ada", Active: true, Password: stubHash, Roles: tc.roles,
			}, nil).Times(1)

			enc := NewMockEncoder(ctrl)
			enc.EXPECT().Encode(gomock.Any()).Return([]byte("$fake$reference"), nil)
			enc.EXPECT().Match(gomock.Any(), stubHash).Return(true).Times(1)

			auth, err := authenticate.NewUsernamePasswordAuthenticator(users, authenticate.WithPasswordEncoder(enc))
			require.NoError(t, err)

			result, err := auth.Authenticate(t.Context(), identity.NewUsernamePassword("ada", []byte(presentedPassword)))
			require.NoError(t, err)
			require.NotNil(t, result.Principal)
			tc.assert(t, result.Principal)
		})
	}
}
