package session_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

// A touch exactly one interval after the last recorded activity writes: the
// manager and the store must agree that an age equal to the interval is old
// enough.
func TestTouch_WritesExactlyOneIntervalAfterTheLastAccess(t *testing.T) {
	t.Parallel()

	const interval = time.Minute

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk, session.WithTouchInterval(interval))

	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	clk.Advance(interval)
	now := clk.Now()
	require.NoError(t, m.Touch(t.Context(), s))

	got, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.Equal(t, now, got.LastAccessedAt, "the store kept the write")
	assert.Equal(t, now.Add(30*time.Minute), got.IdleExpiresAt, "the idle deadline moved with it")
}
