package session_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCountActive_RenewedSignInCountsOnce(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)
	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	for range 3 {
		clk.Advance(time.Minute)
		s, _, err = m.RotateWithGrace(t.Context(), s, 30*time.Second)
		require.NoError(t, err)
	}
	clk.Advance(time.Minute) // every superseded window has ended

	n, err := m.CountActiveByUser(t.Context(), testUser)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "one sign-in renewed three times holds one live session")
}

func TestTouch_StaleCopyNeverLeavesIdleAfterAbsolute(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)
	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	stale, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	other, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	m.MarkEnrolmentPending(other, 15*time.Minute)
	require.NoError(t, m.Save(t.Context(), other))
	clk.Advance(time.Minute)

	require.NoError(t, m.Touch(t.Context(), stale))

	got, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.False(t, got.IdleExpiresAt.After(got.AbsoluteExpiresAt),
		"stored idle %s is after stored absolute %s", got.IdleExpiresAt, got.AbsoluteExpiresAt)
}
