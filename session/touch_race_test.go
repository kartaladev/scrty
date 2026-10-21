package session_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

// A request that loaded a session before another request confined it must not
// undo the confinement when it records its own activity.
func TestTouch_KeepsAConcurrentlyLoweredDeadline(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)

	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	// Request A loads its copy.
	a, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)

	// Request B, on the same session, confines it to enrolment and saves.
	b, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	m.MarkEnrolmentPending(b, 15*time.Minute)
	require.NoError(t, m.Save(t.Context(), b))
	require.False(t, b.EnrolmentOriginDeadline.IsZero())

	// Request A finishes with its stale copy.
	clk.Advance(time.Minute)
	require.NoError(t, m.Touch(t.Context(), a))

	got, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.Equal(t, b.AbsoluteExpiresAt, got.AbsoluteExpiresAt, "absolute deadline")
	assert.Equal(t, b.EnrolmentOriginDeadline, got.EnrolmentOriginDeadline, "enrolment-origin marker")
	assert.Equal(t, session.MFAEnrolmentPending, got.MFA, "second-factor state")
}
