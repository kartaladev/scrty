package session_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// testGeneration is the enrolment generation the fixtures record. Its value
// means nothing; it only has to survive a store round trip unchanged.
var testGeneration = id.MustParse("0192f0a0-0000-7000-8000-000000000001")

// TestMFAState pins the ordinals and names of the second-factor states. The
// ordinals are what a durable store keeps, so a new state is appended and an
// existing one never moves.
func TestMFAState(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		state session.MFAState
		value int
		text  string
	}

	cases := []testCase{
		{name: "none", state: session.MFANone, value: 0, text: "none"},
		{name: "pending", state: session.MFAPending, value: 1, text: "pending"},
		{name: "satisfied", state: session.MFASatisfied, value: 2, text: "satisfied"},
		{name: "enrolment pending is appended", state: session.MFAEnrolmentPending, value: 3, text: "enrolment-pending"},
		{name: "unnamed prints its number", state: session.MFAState(4), value: 4, text: "MFAState(4)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.value, int(tc.state))
			assert.Equal(t, tc.text, tc.state.String())
		})
	}
}

// TestEnrolmentStateRoundTrip pins the enrolment-pending state, the
// enrolment-origin marker with the deadline it records, and the enrolment
// generation as library-owned fields the memory store keeps.
func TestEnrolmentStateRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	m := managerFor(t)
	s, err := m.Create(ctx, testUser, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	origin := s.AbsoluteExpiresAt
	s.MFA = session.MFAEnrolmentPending
	s.EnrolmentOriginDeadline = origin
	s.EnrolmentGeneration = testGeneration
	require.NoError(t, m.Save(ctx, s))

	loaded, err := m.Load(ctx, s.ID)
	require.NoError(t, err)
	assert.Equal(t, session.MFAEnrolmentPending, loaded.MFA)
	assert.True(t, origin.Equal(loaded.EnrolmentOriginDeadline), "the recorded deadline survives the round trip")
	assert.Equal(t, testGeneration, loaded.EnrolmentGeneration)
}

// TestConsumerDataCannotClearEnrolment shows that no consumer data entry
// reaches the enrolment state: one that claims the state is gone leaves it in
// place, and one that claims it is set does not set it.
func TestConsumerDataCannotClearEnrolment(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		mutate func(s *session.Session)
		assert func(t *testing.T, loaded *session.Session)
	}

	cases := []testCase{
		{
			name: "an entry claiming none does not clear the state",
			mutate: func(s *session.Session) {
				s.MFA = session.MFAEnrolmentPending
				s.EnrolmentOriginDeadline = at(21, 0)
				s.EnrolmentGeneration = testGeneration
				s.Data = map[string]string{"mfa": "none", "EnrolmentOriginDeadline": "", "EnrolmentGeneration": ""}
			},
			assert: func(t *testing.T, loaded *session.Session) {
				assert.Equal(t, session.MFAEnrolmentPending, loaded.MFA)
				assert.True(t, at(21, 0).Equal(loaded.EnrolmentOriginDeadline))
				assert.Equal(t, testGeneration, loaded.EnrolmentGeneration)
				assert.Equal(t, map[string]string{"mfa": "none", "EnrolmentOriginDeadline": "", "EnrolmentGeneration": ""},
					loaded.Data, "consumer data is returned unchanged")
			},
		},
		{
			name: "an entry claiming the state does not forge it",
			mutate: func(s *session.Session) {
				s.Data = map[string]string{
					"mfa":                     "enrolment-pending",
					"EnrolmentOriginDeadline": at(21, 0).Format(time.RFC3339),
					"EnrolmentGeneration":     testGeneration.String(),
				}
			},
			assert: func(t *testing.T, loaded *session.Session) {
				assert.Equal(t, session.MFANone, loaded.MFA)
				assert.True(t, loaded.EnrolmentOriginDeadline.IsZero())
				assert.True(t, loaded.EnrolmentGeneration.IsZero())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			m := managerFor(t)
			s, err := m.Create(ctx, testUser, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			tc.mutate(s)
			require.NoError(t, m.Save(ctx, s))

			loaded, err := m.Load(ctx, s.ID)
			require.NoError(t, err)
			tc.assert(t, loaded)
		})
	}
}

// at returns the given wall-clock time on the fixtures' day.
func at(hour, minute int) time.Time {
	return time.Date(createdAt.Year(), createdAt.Month(), createdAt.Day(), hour, minute, 0, 0, time.UTC)
}

// enrolmentLifetime is the default enrolment lifetime the spec's scenarios use.
const enrolmentLifetime = 15 * time.Minute

// TestMarkEnrolmentPending pins how marking a session enrolment-pending
// lowers its deadlines: the absolute deadline becomes the earlier of its own
// and now plus the lifetime, the idle deadline never outlives it, the marker
// records the absolute deadline held before the mark, and the change is
// persisted by one save. Every assertion is on the session as reloaded from
// the store.
func TestMarkEnrolmentPending(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []session.ManagerOption
		created time.Time
		// prepare adjusts the created session before the mark. nil does
		// nothing.
		prepare func(s *session.Session)
		markAt  time.Time
		// remarkAt, when non-zero, marks the saved session a second time.
		remarkAt time.Time
		// touchAt, when non-zero, records activity on the saved session.
		touchAt time.Time
		// loadAt, when non-zero, is when the session is reloaded for the
		// assertion; zero reloads at the last time the clock was set to.
		loadAt time.Time
		assert func(t *testing.T, s *session.Session, err error)
	}

	cases := []testCase{
		{
			name:    "at login both deadlines move to the end of the lifetime",
			created: at(9, 0),
			markAt:  at(9, 0),
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, at(9, 15), s.AbsoluteExpiresAt)
				assert.Equal(t, at(9, 15), s.IdleExpiresAt)
				assert.Equal(t, session.MFAEnrolmentPending, s.MFA)
				assert.Equal(t, at(21, 0), s.EnrolmentOriginDeadline, "the marker records the deadline held before the mark")
			},
		},
		{
			name:    "mid-session the lifetime counts from the mark",
			created: at(8, 0),
			prepare: func(s *session.Session) {
				// Activity at 09:50 kept it alive until 10:20.
				s.LastAccessedAt, s.IdleExpiresAt = at(9, 50), at(10, 20)
			},
			markAt: at(10, 0),
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, at(10, 15), s.AbsoluteExpiresAt)
				assert.Equal(t, at(10, 15), s.IdleExpiresAt)
				assert.Equal(t, at(20, 0), s.EnrolmentOriginDeadline)
			},
		},
		{
			name:    "near the end the earlier absolute deadline stays",
			created: at(9, 0),
			prepare: func(s *session.Session) {
				// Activity at 20:50 kept it alive until its absolute deadline.
				s.LastAccessedAt, s.IdleExpiresAt = at(20, 50), at(21, 0)
			},
			markAt: at(20, 55),
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, at(21, 0), s.AbsoluteExpiresAt)
				assert.Equal(t, at(21, 0), s.IdleExpiresAt)
				assert.Equal(t, session.MFAEnrolmentPending, s.MFA)
				assert.Equal(t, at(21, 0), s.EnrolmentOriginDeadline)
			},
		},
		{
			name:    "an idle deadline already earlier is not raised",
			opts:    []session.ManagerOption{session.WithIdleTimeout(10 * time.Minute)},
			created: at(9, 0),
			markAt:  at(9, 0),
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, at(9, 15), s.AbsoluteExpiresAt)
				assert.Equal(t, at(9, 10), s.IdleExpiresAt)
			},
		},
		{
			name:     "marking twice keeps the deadline recorded by the first mark",
			created:  at(9, 0),
			markAt:   at(9, 0),
			remarkAt: at(9, 5),
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, at(9, 15), s.AbsoluteExpiresAt)
				assert.Equal(t, at(21, 0), s.EnrolmentOriginDeadline, "not the already-lowered 09:15")
			},
		},
		{
			name:    "activity cannot extend the state",
			created: at(9, 0),
			markAt:  at(9, 0),
			touchAt: at(9, 14),
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, at(9, 14), s.LastAccessedAt, "the touch was persisted")
				assert.Equal(t, at(9, 15), s.IdleExpiresAt)
				assert.Equal(t, at(9, 15), s.AbsoluteExpiresAt)
			},
		},
		{
			name:    "the session is gone at the lowered deadline",
			created: at(9, 0),
			markAt:  at(9, 0),
			loadAt:  at(9, 15),
			assert: func(t *testing.T, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrSessionExpired)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			clk := clockwork.NewFakeClockAt(tc.created)
			m, _ := managerOnClock(t, clk, tc.opts...)
			s, err := m.Create(ctx, testUser, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			if tc.prepare != nil {
				tc.prepare(s)
			}

			clk.Advance(tc.markAt.Sub(clk.Now()))
			m.MarkEnrolmentPending(s, enrolmentLifetime)
			require.NoError(t, m.Save(ctx, s), "the mark is persisted by one save")

			if !tc.remarkAt.IsZero() {
				clk.Advance(tc.remarkAt.Sub(clk.Now()))
				m.MarkEnrolmentPending(s, enrolmentLifetime)
				require.NoError(t, m.Save(ctx, s))
			}

			if !tc.touchAt.IsZero() {
				clk.Advance(tc.touchAt.Sub(clk.Now()))
				live, err := m.Load(ctx, s.ID)
				require.NoError(t, err)
				require.NoError(t, m.Touch(ctx, live))
			}

			if !tc.loadAt.IsZero() {
				clk.Advance(tc.loadAt.Sub(clk.Now()))
			}

			loaded, err := m.Load(ctx, s.ID)
			tc.assert(t, loaded, err)
		})
	}
}

// TestSatisfyRestoresEnrolmentDeadline pins the upgrade of an enrolment-only
// session: the absolute deadline goes back to the earlier of creation plus the
// absolute timeout and the deadline the marker recorded before the mark, the
// idle deadline to the earlier of now plus the idle timeout and that deadline,
// and the marker and generation are cleared. A session already past its
// lowered deadline is refused and left unchanged, a session without the marker
// is left alone, and a rotation after the restore carries the restored
// deadlines as a plain copy.
func TestSatisfyRestoresEnrolmentDeadline(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		created time.Time
		// markAt is when the session is marked enrolment-pending; zero leaves
		// it unmarked.
		markAt    time.Time
		prepare   func(s *session.Session)
		restoreAt time.Time
		// restorerOpts, when set, restores through a second manager over the
		// same store and clock, configured with these options.
		restorerOpts []session.ManagerOption
		rotate       bool
		// assert receives the persisted session when the restore succeeded,
		// and the in-memory session when it failed.
		assert func(t *testing.T, s *session.Session, err error)
	}

	cases := []testCase{
		{
			name:      "marked at login and upgraded nine minutes later",
			created:   at(9, 0),
			markAt:    at(9, 0),
			restoreAt: at(9, 9),
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, at(21, 0), s.AbsoluteExpiresAt)
				assert.Equal(t, at(9, 39), s.IdleExpiresAt)
				assert.True(t, s.EnrolmentOriginDeadline.IsZero())
				assert.True(t, s.EnrolmentGeneration.IsZero())
				assert.Equal(t, session.MFAPending, s.MFA, "the restore leaves the second-factor state to its caller")
			},
		},
		{
			name:    "marked mid-session gets back the deadline it held before",
			created: at(8, 0),
			prepare: func(s *session.Session) {
				// Activity at 09:50 kept it alive until 10:20.
				s.LastAccessedAt, s.IdleExpiresAt = at(9, 50), at(10, 20)
			},
			markAt:    at(10, 0),
			restoreAt: at(10, 10),
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, at(20, 0), s.AbsoluteExpiresAt)
				assert.Equal(t, at(10, 40), s.IdleExpiresAt)
				assert.True(t, s.EnrolmentOriginDeadline.IsZero())
			},
		},
		{
			name:    "a deadline lowered before the mark is not raised by the restore",
			created: at(9, 0),
			prepare: func(s *session.Session) {
				// Something lowered the absolute deadline to 10:00; activity
				// at 09:25 kept it alive until 09:55.
				s.AbsoluteExpiresAt = at(10, 0)
				s.LastAccessedAt, s.IdleExpiresAt = at(9, 25), at(9, 55)
			},
			markAt:    at(9, 30),
			restoreAt: at(9, 35),
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, at(10, 0), s.AbsoluteExpiresAt, "the deadline held before the mark, not creation plus the timeout")
				assert.Equal(t, at(10, 0), s.IdleExpiresAt)
			},
		},
		{
			name:         "a raised absolute timeout is capped by the recorded deadline",
			created:      at(9, 0),
			markAt:       at(9, 0),
			restoreAt:    at(9, 9),
			restorerOpts: []session.ManagerOption{session.WithAbsoluteTimeout(24 * time.Hour)},
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, at(21, 0), s.AbsoluteExpiresAt, "the deadline held before the mark, not creation plus 24 hours")
				assert.Equal(t, at(9, 39), s.IdleExpiresAt)
			},
		},
		{
			name:      "an expired enrolment-only session is not revived",
			created:   at(9, 0),
			markAt:    at(9, 0),
			restoreAt: at(9, 20),
			assert: func(t *testing.T, s *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrSessionExpired)
				assert.Equal(t, at(9, 15), s.AbsoluteExpiresAt)
				assert.Equal(t, at(9, 15), s.IdleExpiresAt)
				assert.Equal(t, at(21, 0), s.EnrolmentOriginDeadline)
				assert.Equal(t, testGeneration, s.EnrolmentGeneration)
			},
		},
		{
			name:    "an enrolment-only session past only its idle deadline is not revived",
			created: at(9, 0),
			prepare: func(s *session.Session) {
				s.IdleExpiresAt = at(9, 10)
			},
			markAt:    at(9, 0),
			restoreAt: at(9, 12),
			assert: func(t *testing.T, s *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrSessionExpired)
				assert.Equal(t, at(9, 15), s.AbsoluteExpiresAt)
				assert.Equal(t, at(9, 10), s.IdleExpiresAt)
			},
		},
		{
			name:      "a session without the marker keeps its deadlines",
			created:   at(9, 0),
			restoreAt: at(9, 9),
			prepare: func(s *session.Session) {
				s.EnrolmentGeneration = testGeneration
			},
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, at(21, 0), s.AbsoluteExpiresAt)
				assert.Equal(t, at(9, 30), s.IdleExpiresAt)
				assert.Equal(t, testGeneration, s.EnrolmentGeneration, "nothing is touched without the marker")
			},
		},
		{
			name:      "a rotation after the restore carries the restored deadlines",
			created:   at(9, 0),
			markAt:    at(9, 0),
			restoreAt: at(9, 9),
			rotate:    true,
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, at(21, 0), s.AbsoluteExpiresAt)
				assert.Equal(t, at(9, 39), s.IdleExpiresAt)
				assert.True(t, s.EnrolmentOriginDeadline.IsZero())
				assert.True(t, s.EnrolmentGeneration.IsZero())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			clk := clockwork.NewFakeClockAt(tc.created)
			m, store := managerOnClock(t, clk)
			s, err := m.Create(ctx, testUser, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			if tc.prepare != nil {
				tc.prepare(s)
			}

			if !tc.markAt.IsZero() {
				clk.Advance(tc.markAt.Sub(clk.Now()))
				m.MarkEnrolmentPending(s, enrolmentLifetime)
				s.EnrolmentGeneration = testGeneration
			}

			// By the upgrade the enrolment is confirmed and the session is
			// waiting for its second factor.
			s.MFA = session.MFAPending
			require.NoError(t, m.Save(ctx, s))

			restorer := m
			if tc.restorerOpts != nil {
				restorer = managerFor(t, append([]session.ManagerOption{
					session.WithStore(store),
					session.WithClock(clk),
				}, tc.restorerOpts...)...)
			}

			clk.Advance(tc.restoreAt.Sub(clk.Now()))
			if err := restorer.RestoreEnrolmentDeadlines(s); err != nil {
				tc.assert(t, s, err)
				return
			}

			if tc.rotate {
				s, err = restorer.Rotate(ctx, s)
				require.NoError(t, err)
			} else {
				require.NoError(t, restorer.Save(ctx, s))
			}

			loaded, err := restorer.Load(ctx, s.ID)
			tc.assert(t, loaded, err)
		})
	}
}

// TestEnrolmentSessionCountsUntilExpiry shows that an enrolment-only session
// counts towards the user's active sessions until its lowered deadline and not
// after. The count itself knows nothing of enrolment: it holds because marking
// lowers the absolute deadline every store already enforces.
func TestEnrolmentSessionCountsUntilExpiry(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		countAt time.Time
		assert  func(t *testing.T, n int, err error)
	}

	cases := []testCase{
		{
			name:    "counted before the lowered deadline",
			countAt: at(9, 10),
			assert: func(t *testing.T, n int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, n)
			},
		},
		{
			name:    "not counted after the lowered deadline",
			countAt: at(9, 16),
			assert: func(t *testing.T, n int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 0, n)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			clk := clockwork.NewFakeClockAt(at(9, 0))
			m, _ := managerOnClock(t, clk)
			s, err := m.Create(ctx, testUser, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			m.MarkEnrolmentPending(s, enrolmentLifetime)
			require.NoError(t, m.Save(ctx, s))

			clk.Advance(tc.countAt.Sub(clk.Now()))
			n, err := m.CountActiveByUser(ctx, testUser)
			tc.assert(t, n, err)
		})
	}
}
