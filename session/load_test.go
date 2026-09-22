package session_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

func TestManagerLoad(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// at is when the load happens, relative to the session's creation.
		at time.Duration
		// id, when non-empty, is loaded instead of the created session's.
		id     string
		opts   []session.ManagerOption
		assert func(t *testing.T, s *session.Session, err error)
	}

	cases := []testCase{
		{
			name: "a live session loads",
			at:   10 * time.Minute,
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				require.NotNil(t, s)
				assert.Equal(t, testUser, s.UserID)
			},
		},
		{
			name: "an identifier that was never issued is not found",
			id:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			assert: func(t *testing.T, s *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrSessionNotFound)
				assert.Nil(t, s)
			},
		},
		{
			// 09:00 + 30m idle, loaded at 09:31 without activity.
			name: "a session past its idle deadline is expired, not missing",
			at:   31 * time.Minute,
			assert: func(t *testing.T, s *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrSessionExpired)
				assert.NotErrorIs(t, err, session.ErrSessionNotFound,
					"an expired session was reported as one that never existed, so the caller cannot tell 'log in again' from 'no such session'")
				assert.Nil(t, s, "an expired session was served")
			},
		},
		{
			// The idle deadline is still ahead; only the absolute one has
			// passed, so this row fails unless both are enforced.
			name: "a session past its absolute deadline is expired",
			at:   13 * time.Hour,
			opts: []session.ManagerOption{session.WithIdleTimeout(24 * time.Hour)},
			assert: func(t *testing.T, s *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrSessionExpired)
				assert.Nil(t, s, "an expired session was served")
			},
		},
		{
			// A deadline is the first moment the session is no longer valid,
			// not the last moment it is.
			name: "a session exactly at its idle deadline is expired",
			at:   30 * time.Minute,
			assert: func(t *testing.T, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrSessionExpired)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := newTestClock(createdAt)
			m, _ := managerOnClock(t, clk, tc.opts...)

			created, err := m.Create(t.Context(), testUser)
			require.NoError(t, err)

			id := created.ID
			if tc.id != "" {
				id = tc.id
			}
			clk.Set(createdAt.Add(tc.at))

			loaded, err := m.Load(t.Context(), id)
			tc.assert(t, loaded, err)
		})
	}
}
