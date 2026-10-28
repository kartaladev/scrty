package session_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// supersessionLog is a memory store that records every supersession it is
// handed.
type supersessionLog struct {
	*session.MemoryStore

	mu  sync.Mutex
	ops []session.Supersession
}

func (s *supersessionLog) Supersede(ctx context.Context, op session.Supersession) error {
	s.mu.Lock()
	s.ops = append(s.ops, op)
	s.mu.Unlock()

	return s.MemoryStore.Supersede(ctx, op)
}

func (s *supersessionLog) last(t *testing.T) session.Supersession {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.ops, "no supersession reached the store")

	return s.ops[len(s.ops)-1]
}

// TestSupersession_RetainUntilIsTheFamilyDeadline pins that every
// supersession the manager makes carries the family's start plus the family
// maximum as its retention deadline, whichever renewal made it: a session
// created at 09:00 with a 12-hour lifetime and a 48-hour family maximum
// retains to 09:00 two days later.
func TestSupersession_RetainUntilIsTheFamilyDeadline(t *testing.T) {
	t.Parallel()

	const familyMax = 48 * time.Hour

	type testCase struct {
		name   string
		renew  func(ctx context.Context, t *testing.T, m *session.Sessions, s *session.Session)
		assert func(t *testing.T, s *session.Session, op session.Supersession)
	}

	retainsFamilyDeadline := func(t *testing.T, s *session.Session, op session.Supersession) {
		t.Helper()

		assert.Equal(t, s.FamilyCreatedAt.Add(familyMax), op.RetainUntil,
			"the retention deadline is the family's start plus the family maximum")
	}

	cases := []testCase{
		{
			name: "a strict rotation",
			renew: func(ctx context.Context, t *testing.T, m *session.Sessions, s *session.Session) {
				_, err := m.Rotate(ctx, s)
				require.NoError(t, err)
			},
			assert: retainsFamilyDeadline,
		},
		{
			name: "a fresh renewal",
			renew: func(ctx context.Context, t *testing.T, m *session.Sessions, s *session.Session) {
				_, _, err := m.RotateWithGrace(ctx, s, 30*time.Second)
				require.NoError(t, err)
			},
			assert: retainsFamilyDeadline,
		},
		{
			name: "a renewal with a successor lifetime",
			renew: func(ctx context.Context, t *testing.T, m *session.Sessions, s *session.Session) {
				_, _, err := m.RotateWithGrace(ctx, s, 30*time.Second, session.WithSuccessorLifetime(12*time.Hour))
				require.NoError(t, err)
			},
			assert: retainsFamilyDeadline,
		},
		{
			name: "a re-rotation inside the window",
			renew: func(ctx context.Context, t *testing.T, m *session.Sessions, s *session.Session) {
				_, _, err := m.RotateWithGrace(ctx, s, 30*time.Second)
				require.NoError(t, err)
				_, kind, err := m.RotateWithGrace(ctx, s, 30*time.Second)
				require.NoError(t, err)
				require.Equal(t, session.RenewalReRotation, kind)
			},
			assert: retainsFamilyDeadline,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			store := &supersessionLog{MemoryStore: session.NewMemoryStore(session.WithMemoryStoreClock(clk))}
			m := managerFor(t,
				session.WithStore(store),
				session.WithClock(clk),
				session.WithAbsoluteTimeout(12*time.Hour),
				session.WithMaxAbsoluteLifetime(12*time.Hour),
				session.WithMaxFamilyLifetime(familyMax),
			)
			s, err := m.Create(t.Context(), testUser)
			require.NoError(t, err)
			clk.Advance(10 * time.Minute)

			tc.renew(t.Context(), t, m, s)

			tc.assert(t, s, store.last(t))
		})
	}
}

// twoDeploys returns two managers over one memory store and clock, as a
// rolling deploy that changes the family maximum leaves them: the first
// manager's lifetimes and family maximum are first, the second's are second.
func twoDeploys(t *testing.T, clk *clockwork.FakeClock, first, second time.Duration) (before, after *session.Sessions, store *session.MemoryStore) {
	t.Helper()

	store = session.NewMemoryStore(session.WithMemoryStoreClock(clk))
	build := func(lifetime time.Duration, family time.Duration) *session.Sessions {
		return managerFor(t,
			session.WithStore(store),
			session.WithClock(clk),
			session.WithIdleTimeout(lifetime),
			session.WithAbsoluteTimeout(lifetime),
			session.WithMaxAbsoluteLifetime(lifetime),
			session.WithMaxFamilyLifetime(family),
		)
	}

	return build(first, first), build(second, second), store
}

// TestRotateWithGrace_LoweredFamilyMaximum pins that a deploy which lowers
// the family maximum never shortens a record already issued: a record
// renewed just before the new family end keeps its original deadline, so it
// is still judged inside its window, and a renewal past the new family end
// is refused.
func TestRotateWithGrace_LoweredFamilyMaximum(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		renew  time.Duration
		assert func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock, old, next *session.Session, err error)
	}

	cases := []testCase{
		{
			name:  "the grace window of a record renewed before the new family end is kept",
			renew: 5*time.Hour + 59*time.Minute + 50*time.Second,
			assert: func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock, old, next *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, old.FamilyCreatedAt.Add(6*time.Hour), next.AbsoluteExpiresAt,
					"the successor is cut at the family's end under the lowered maximum")

				clk.Advance(10 * time.Second) // 15:00:00, inside the 30 s window
				loaded, err := m.Load(t.Context(), old.ID)
				require.NoError(t, err, "the old record is still inside its window")
				assert.Equal(t, old.ID, loaded.ID)
			},
		},
		{
			name:  "a renewal past the new family end is refused as expired",
			renew: 6*time.Hour + 30*time.Minute,
			assert: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock, old, next *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
				assert.NotErrorIs(t, err, session.ErrReused)
				assert.Nil(t, next)

				loaded, err := m.Load(t.Context(), old.ID)
				require.NoError(t, err, "nothing was written: the old record is not superseded")
				assert.True(t, loaded.SupersededAt.IsZero())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			before, after, _ := twoDeploys(t, clk, 12*time.Hour, 6*time.Hour)
			s, err := before.Create(t.Context(), testUser)
			require.NoError(t, err)
			clk.Advance(tc.renew)

			next, _, err := after.RotateWithGrace(t.Context(), s, 30*time.Second)

			tc.assert(t, before, clk, s, next, err)
		})
	}
}

// TestRotateWithGrace_RaisedFamilyMaximumReadsAsExpired pins the documented
// limit of raising the family maximum: a record superseded under the old
// maximum keeps the retention it was given, so presented after that while
// the family lives on under the new maximum, it is refused as expired and
// the family is not revoked.
func TestRotateWithGrace_RaisedFamilyMaximumReadsAsExpired(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	before, after, _ := twoDeploys(t, clk, 12*time.Hour, 48*time.Hour)
	s, err := before.Create(t.Context(), testUser)
	require.NoError(t, err)
	clk.Advance(time.Hour)

	// Superseded by a deploy still on the old maximum: retained to 21:00.
	next, _, err := before.RotateWithGrace(t.Context(), s, 30*time.Second)
	require.NoError(t, err)

	// The family is extended under the new maximum before the old record's
	// retention (21:00) ends.
	clk.Advance(10 * time.Hour) // 20:00
	head, _, err := after.RotateWithGrace(t.Context(), next, 30*time.Second, session.WithSuccessorLifetime(12*time.Hour))
	require.NoError(t, err)

	clk.Advance(3 * time.Hour) // 23:00, past the old record's retention
	_, err = after.Load(t.Context(), s.ID)
	require.ErrorIs(t, err, session.ErrExpired)
	assert.NotErrorIs(t, err, session.ErrReused, "the limit: reuse is not detected past the old retention")

	_, err = after.Load(t.Context(), head.ID)
	require.NoError(t, err, "the family was not revoked: its head still loads")
}

// TestRotate_TakesTheFamilyFromTheStoredRecord pins that a successor stays in
// the family the store holds, whatever family the caller's copy of the
// session carries.
func TestRotate_TakesTheFamilyFromTheStoredRecord(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, store := managerOnClock(t, clk)
	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	clk.Advance(time.Minute)

	stale := *s
	stale.FamilyID = id.Nil
	stale.FamilyCreatedAt = time.Time{}

	rotated, err := m.Rotate(t.Context(), &stale)

	require.NoError(t, err)
	assert.Equal(t, s.FamilyID, rotated.FamilyID)
	assert.Equal(t, s.FamilyCreatedAt, rotated.FamilyCreatedAt)
	stored, err := store.Load(t.Context(), rotated.ID)
	require.NoError(t, err)
	assert.Equal(t, s.FamilyID, stored.FamilyID)
}
