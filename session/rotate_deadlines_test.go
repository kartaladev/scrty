package session_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// A caller may have restored the deadlines of the session it hands Rotate (as
// RestoreEnrolmentDeadlines does after an enrolment), so the successor carries
// the deadlines of the session it is given. Only the family fields come from
// storage.
func TestRotate_CarriesTheDeadlinesOfTheSessionItIsGiven(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)

	// The stored session is confined: its absolute deadline is 09:15.
	stored, err := m.Create(t.Context(), testUser, session.WithAbsoluteLifetime(15*time.Minute))
	require.NoError(t, err)
	require.Equal(t, createdAt.Add(15*time.Minute), stored.AbsoluteExpiresAt)

	// The caller's copy has had its deadlines restored to 21:00, and carries a
	// family of its own that storage must override.
	restored := *stored
	restored.AbsoluteExpiresAt = createdAt.Add(12 * time.Hour)
	restored.IdleExpiresAt = createdAt.Add(12 * time.Hour)
	restored.FamilyID = id.MustParse("01926a4e-0000-7000-8000-0000000000bb")
	restored.FamilyCreatedAt = createdAt.Add(-time.Hour)

	clk.Advance(5 * time.Minute)
	successor, err := m.Rotate(t.Context(), &restored)

	require.NoError(t, err)
	assert.Equal(t, createdAt.Add(12*time.Hour), successor.AbsoluteExpiresAt,
		"the successor took the stored record's deadlines, not those of the session it was given")
	assert.Equal(t, createdAt.Add(12*time.Hour), successor.IdleExpiresAt)
	assert.Equal(t, stored.FamilyID, successor.FamilyID, "the family comes from storage")
	assert.Equal(t, stored.FamilyCreatedAt, successor.FamilyCreatedAt)
}
