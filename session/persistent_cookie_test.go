package session_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

func TestSessions_CreatePersistentCookie(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.CreateOption
		assert func(t *testing.T, loaded *session.Session, writes storeWrites)
	}

	cases := []testCase{
		{
			name: "created with the mark, in the one creating write",
			opts: []session.CreateOption{session.WithPersistentCookie()},
			assert: func(t *testing.T, loaded *session.Session, writes storeWrites) {
				assert.True(t, loaded.PersistentCookie)
				assert.Equal(t, int32(1), writes.creates)
				assert.Zero(t, writes.saves, "the mark is not a second write")
			},
		},
		{
			name: "created without the mark reports it unset",
			assert: func(t *testing.T, loaded *session.Session, writes storeWrites) {
				assert.False(t, loaded.PersistentCookie)
				assert.Equal(t, int32(1), writes.creates)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			store := &writeCountingStore{Store: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))}
			m := managerFor(t, session.WithStore(store), session.WithClock(clk))

			s, err := m.Create(t.Context(), testUser, tc.opts...)
			require.NoError(t, err)
			loaded, err := m.Load(t.Context(), s.ID)
			require.NoError(t, err)

			tc.assert(t, loaded, storeWrites{creates: store.creates.Load(), saves: store.saves.Load()})
		})
	}
}

func TestSessions_PersistentCookieNotFromData(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
	m := managerFor(t, session.WithStore(store), session.WithClock(clk))

	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	data := map[string]string{"persistent_cookie": "true", "PersistentCookie": "true"}
	s.Data = data
	require.NoError(t, m.Save(t.Context(), s))

	loaded, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.False(t, loaded.PersistentCookie)
	assert.Equal(t, data, loaded.Data, "consumer data is returned unchanged")
}

func TestSessions_RotationsCarryPersistentCookie(t *testing.T) {
	t.Parallel()

	type outcome struct {
		successor *session.Session
		seen      *session.Session
	}

	type testCase struct {
		name   string
		rotate func(t *testing.T, m *session.Sessions, s *session.Session) outcome
		assert func(t *testing.T, o outcome)
	}

	step := func(seen **session.Session) func(*session.Session) (string, error) {
		return func(next *session.Session) (string, error) {
			c := *next
			*seen = &c

			return "credential", nil
		}
	}

	cases := []testCase{
		{
			name: "Rotate",
			rotate: func(t *testing.T, m *session.Sessions, s *session.Session) outcome {
				next, err := m.Rotate(t.Context(), s)
				require.NoError(t, err)

				return outcome{successor: next}
			},
			assert: func(t *testing.T, o outcome) { assert.True(t, o.successor.PersistentCookie) },
		},
		{
			name: "RotateIssuing, visible to the issuing step",
			rotate: func(t *testing.T, m *session.Sessions, s *session.Session) outcome {
				var seen *session.Session
				next, _, err := m.RotateIssuing(t.Context(), s, step(&seen))
				require.NoError(t, err)

				return outcome{successor: next, seen: seen}
			},
			assert: func(t *testing.T, o outcome) {
				assert.True(t, o.successor.PersistentCookie)
				require.NotNil(t, o.seen)
				assert.True(t, o.seen.PersistentCookie)
			},
		},
		{
			name: "RotateWithGrace",
			rotate: func(t *testing.T, m *session.Sessions, s *session.Session) outcome {
				next, _, err := m.RotateWithGrace(t.Context(), s, 10*time.Second)
				require.NoError(t, err)

				return outcome{successor: next}
			},
			assert: func(t *testing.T, o outcome) { assert.True(t, o.successor.PersistentCookie) },
		},
		{
			name: "RotateWithGraceIssuing, visible to the issuing step",
			rotate: func(t *testing.T, m *session.Sessions, s *session.Session) outcome {
				var seen *session.Session
				next, _, _, err := m.RotateWithGraceIssuing(t.Context(), s, 10*time.Second, step(&seen))
				require.NoError(t, err)

				return outcome{successor: next, seen: seen}
			},
			assert: func(t *testing.T, o outcome) {
				assert.True(t, o.successor.PersistentCookie)
				require.NotNil(t, o.seen)
				assert.True(t, o.seen.PersistentCookie)
			},
		},
		{
			name: "Rotate of a copy with the mark cleared still carries the stored mark",
			rotate: func(t *testing.T, m *session.Sessions, s *session.Session) outcome {
				cp := *s
				cp.PersistentCookie = false
				next, err := m.Rotate(t.Context(), &cp)
				require.NoError(t, err)

				return outcome{successor: next}
			},
			assert: func(t *testing.T, o outcome) { assert.True(t, o.successor.PersistentCookie) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
			m := managerFor(t, session.WithStore(store), session.WithClock(clk))

			s, err := m.Create(t.Context(), testUser, session.WithPersistentCookie())
			require.NoError(t, err)

			o := tc.rotate(t, m, s)
			tc.assert(t, o)

			stored, err := m.Load(t.Context(), o.successor.ID)
			require.NoError(t, err)
			assert.True(t, stored.PersistentCookie, "the stored successor carries the mark")
		})
	}
}

func TestSessions_RotateOfAnUnmarkedSessionStaysUnmarked(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
	m := managerFor(t, session.WithStore(store), session.WithClock(clk))

	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	cp := *s
	cp.PersistentCookie = true
	next, err := m.Rotate(t.Context(), &cp)
	require.NoError(t, err)
	assert.False(t, next.PersistentCookie, "a copy cannot set the mark through a rotation")
}

func TestSessions_SaveKeepsPersistentCookie(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		created []session.CreateOption
		flipTo  bool
	}

	cases := []testCase{
		{name: "save cannot set the mark", flipTo: true},
		{name: "save cannot clear the mark", created: []session.CreateOption{session.WithPersistentCookie()}, flipTo: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
			m := managerFor(t, session.WithStore(store), session.WithClock(clk))

			s, err := m.Create(t.Context(), testUser, tc.created...)
			require.NoError(t, err)
			want := s.PersistentCookie

			s.PersistentCookie = tc.flipTo
			require.NoError(t, m.Save(t.Context(), s))

			loaded, err := m.Load(t.Context(), s.ID)
			require.NoError(t, err)
			assert.Equal(t, want, loaded.PersistentCookie)
		})
	}
}
