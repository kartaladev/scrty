package sqlstore_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// TestSessionStore_EndSignInOwnership pins, through the session manager over
// the durable store, that ending a sign-in by handle ends only the caller's
// own: another user's handle is not found and revokes nothing in the table.
func TestSessionStore_EndSignInOwnership(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB

	type testCase struct {
		name   string
		handle func(own, foreign *session.Session) string
		assert func(t *testing.T, err error, ownLoads, foreignLoads bool)
	}

	cases := []testCase{
		{
			name:   "another user's handle is not found and revokes nothing",
			handle: func(_, foreign *session.Session) string { return foreign.FamilyID.String() },
			assert: func(t *testing.T, err error, ownLoads, foreignLoads bool) {
				assert.True(t, foreignLoads, "the other user's sign-in is untouched")
				assert.True(t, ownLoads, "the caller's sign-in is untouched")
				assert.ErrorIs(t, err, session.ErrNotFound)
			},
		},
		{
			name:   "the caller's own handle ends the caller's sign-in only",
			handle: func(own, _ *session.Session) string { return own.FamilyID.String() },
			assert: func(t *testing.T, err error, ownLoads, foreignLoads bool) {
				require.NoError(t, err)
				assert.False(t, ownLoads, "the caller's sign-in is ended")
				assert.True(t, foreignLoads, "the other user's sign-in is untouched")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := session.New(session.WithStore(newSessionStore(t, db, storefix.TestCipher(t))))
			require.NoError(t, err)

			// Users of their own per case, so the parallel cases share the
			// table without seeing each other's rows.
			caller := identity.UserID("u-end-" + t.Name())
			other := identity.UserID("u-other-" + t.Name())

			own, err := m.Create(t.Context(), caller)
			require.NoError(t, err)
			foreign, err := m.Create(t.Context(), other)
			require.NoError(t, err)

			endErr := m.EndSignIn(t.Context(), caller, tc.handle(own, foreign))

			_, ownErr := m.Load(t.Context(), own.ID)
			_, foreignErr := m.Load(t.Context(), foreign.ID)
			tc.assert(t, endErr, ownErr == nil, foreignErr == nil)
		})
	}
}
