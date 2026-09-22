package session_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

func TestSaveNeverRecreatesADeletedSession(t *testing.T) {
	t.Parallel()

	clk := newTestClock(createdAt)
	m, _ := managerOnClock(t, clk)
	ctx := t.Context()

	s, err := m.Create(ctx, testUser)
	require.NoError(t, err)

	// The revocation a concurrent request races: a logout, a forced sign-out,
	// an administrator ending a session.
	require.NoError(t, m.Delete(ctx, s.ID))

	// Touch is load-then-save: exactly the path a live request takes, and the
	// request holding this session has no way to know it was just revoked.
	require.ErrorIs(t, m.Touch(ctx, s), session.ErrSessionNotFound,
		"recording activity on a revoked session succeeded, so it wrote the session back")

	_, err = m.Load(ctx, s.ID)
	require.ErrorIs(t, err, session.ErrSessionNotFound,
		"a revoked session came back to life through Touch")
}
