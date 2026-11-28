package sqlstore_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/session"
)

// TestRename_RevokesSessionsWhenOptedIn renames a user, over the database/sql
// identity store, whose two sessions are live, with the session manager given
// as the revoker, and asserts both sessions are gone afterwards.
func TestRename_RevokesSessionsWhenOptedIn(t *testing.T) {
	t.Parallel()

	ctx := admin.WithSystemActor(t.Context(), "rename-test")

	conn := migratedIdentityDB(t)
	identityStore := newIdentityStore(t, conn.DB)

	memory, err := session.NewMemoryStore()
	require.NoError(t, err)

	sessions, err := session.New(session.WithStore(memory))
	require.NoError(t, err)

	users, err := admin.NewUsers(identityStore, admin.WithSessionRevocation(sessions))
	require.NoError(t, err)

	ada, err := users.Create(ctx, admin.NewUser{Username: "ada", Name: "Ada"})
	require.NoError(t, err)

	laptop, err := sessions.Create(ctx, ada.ID)
	require.NoError(t, err)

	phone, err := sessions.Create(ctx, ada.ID)
	require.NoError(t, err)

	for _, s := range []*session.Session{laptop, phone} {
		_, err := sessions.Load(ctx, s.ID)
		require.NoError(t, err, "the session must load before the rename")
	}

	newName := "ada.lovelace"

	renamed, err := users.Update(ctx, ada.ID, ada.Version, admin.UserChange{Username: &newName})
	require.NoError(t, err)
	require.Equal(t, newName, renamed.Username)

	for _, s := range []*session.Session{laptop, phone} {
		_, err := sessions.Load(ctx, s.ID)
		require.ErrorIs(t, err, session.ErrNotFound)
	}
}
