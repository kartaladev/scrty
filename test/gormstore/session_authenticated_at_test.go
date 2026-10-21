package gormstore_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// TestSessionStore_AuthenticatedAt pins that the authentication time is
// stored on create and read back apart from the creation time, and that a
// save never moves it.
func TestSessionStore_AuthenticatedAt(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	c := storefix.TestCipher(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	signedIn := now.Add(-2 * time.Hour)
	s := newSessionStore(t, emptied(t, d, "sessions"), c)

	sess := &session.Session{
		ID: "sess-auth-at", UserID: "u-1",
		CreatedAt: now, LastAccessedAt: now,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
		AuthenticatedAt: signedIn, Data: map[string]string{},
	}
	require.NoError(t, s.Create(t.Context(), sess))

	got, err := s.Load(t.Context(), sess.ID)
	require.NoError(t, err)
	assert.True(t, signedIn.Equal(got.AuthenticatedAt), "read back %s, want %s", got.AuthenticatedAt, signedIn)

	got.AuthenticatedAt = now
	require.NoError(t, s.Save(t.Context(), got))

	again, err := s.Load(t.Context(), sess.ID)
	require.NoError(t, err)
	assert.True(t, signedIn.Equal(again.AuthenticatedAt), "a save moved it to %s", again.AuthenticatedAt)
}
