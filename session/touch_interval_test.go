package session_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/session"
)

func TestTouch_Interval(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		interval time.Duration
		// elapsed is how long after creation Touch is called.
		elapsed time.Duration
		// expect sets the mock store's expectations for the Touch call.
		expect func(store *MockStore, id string)
		assert func(t *testing.T, s *session.Session, err error)
	}

	cases := []testCase{
		{
			name:    "the default interval persists every touch",
			elapsed: 10 * time.Second,
			expect: func(store *MockStore, id string) {
				store.EXPECT().RecordActivity(gomock.Any(), id,
					createdAt.Add(10*time.Second),
					createdAt.Add(10*time.Second+30*time.Minute),
					createdAt.Add(10*time.Second)).Return(nil).Times(1)
			},
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(10*time.Second), s.LastAccessedAt)
				assert.Equal(t, createdAt.Add(10*time.Second+30*time.Minute), s.IdleExpiresAt)
			},
		},
		{
			name:     "a touch inside the interval writes nothing",
			interval: time.Minute,
			elapsed:  30 * time.Second,
			expect:   func(*MockStore, string) {},
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt, s.LastAccessedAt, "the in-memory session moved though nothing was written")
				assert.Equal(t, createdAt.Add(30*time.Minute), s.IdleExpiresAt)
			},
		},
		{
			name:     "a touch at the interval persists with the interval as the threshold",
			interval: time.Minute,
			elapsed:  time.Minute,
			expect: func(store *MockStore, id string) {
				store.EXPECT().RecordActivity(gomock.Any(), id,
					createdAt.Add(time.Minute),
					createdAt.Add(31*time.Minute),
					createdAt).Return(nil).Times(1)
			},
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(time.Minute), s.LastAccessedAt)
			},
		},
		{
			name:     "a store failure leaves the session in memory untouched",
			interval: time.Minute,
			elapsed:  2 * time.Minute,
			expect: func(store *MockStore, id string) {
				store.EXPECT().RecordActivity(gomock.Any(), id, gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errStoreWrite).Times(1)
			},
			assert: func(t *testing.T, s *session.Session, err error) {
				require.ErrorIs(t, err, errStoreWrite)
				assert.Equal(t, createdAt, s.LastAccessedAt, "memory ran ahead of the store")
				assert.Equal(t, createdAt.Add(30*time.Minute), s.IdleExpiresAt)
			},
		},
		{
			name:     "an expired session is refused whatever the interval",
			interval: time.Hour / 3,
			elapsed:  31 * time.Minute,
			expect:   func(*MockStore, string) {},
			assert: func(t *testing.T, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrSessionExpired)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			store := NewMockStore(gomock.NewController(t))
			store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
			opts := []session.ManagerOption{session.WithStore(store), session.WithClock(clk)}
			if tc.interval != 0 {
				opts = append(opts, session.WithTouchInterval(tc.interval))
			}
			m := managerFor(t, opts...)

			s, err := m.Create(t.Context(), testUser)
			require.NoError(t, err)
			tc.expect(store, s.ID)

			clk.Advance(tc.elapsed)
			err = m.Touch(t.Context(), s)

			tc.assert(t, s, err)
		})
	}
}

// Skipping a write only ever brings expiry earlier: the stored deadline is
// the one from the last write, never a later one.
func TestTouch_SkippedWritesOnlyBringExpiryEarlier(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk, session.WithTouchInterval(time.Minute))

	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	require.NoError(t, m.Touch(t.Context(), s)) // 09:00, inside the interval of creation
	clk.Advance(50 * time.Second)
	require.NoError(t, m.Touch(t.Context(), s)) // 09:00:50, skipped

	clk.Advance(29*time.Minute + 10*time.Second) // 09:30:00
	_, err = m.Load(t.Context(), s.ID)

	require.ErrorIs(t, err, session.ErrSessionExpired)
}

func TestNewManager_TouchIntervalMustBeShorterThanIdleTimeout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		interval time.Duration
		assert   func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:     "negative",
			interval: -time.Second,
			assert:   func(t *testing.T, err error) { require.ErrorIs(t, err, session.ErrConfig) },
		},
		{
			name:     "equal to the idle timeout",
			interval: 30 * time.Minute,
			assert:   func(t *testing.T, err error) { require.ErrorIs(t, err, session.ErrConfig) },
		},
		{
			name:     "longer than the idle timeout",
			interval: 31 * time.Minute,
			assert:   func(t *testing.T, err error) { require.ErrorIs(t, err, session.ErrConfig) },
		},
		{
			name:     "just under the idle timeout",
			interval: 30*time.Minute - time.Nanosecond,
			assert:   func(t *testing.T, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := session.NewManager(session.WithTouchInterval(tc.interval))

			tc.assert(t, err)
		})
	}
}

// A session superseded by a rotation takes no activity: the store refuses the
// write, so the touch cannot move its deadlines.
func TestTouch_SupersededSessionWritesNothing(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, store := managerOnClock(t, clk)

	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	successor := *s
	successor.ID = "successor-id"
	require.NoError(t, store.Supersede(t.Context(), session.Supersession{
		Old: s.ID, AcceptUntil: createdAt.Add(30 * time.Second), RetainUntil: s.AbsoluteExpiresAt,
		Successor: &successor, Now: createdAt,
	}))
	before, err := store.Load(t.Context(), s.ID)
	require.NoError(t, err)

	clk.Advance(10 * time.Second)
	require.NoError(t, m.Touch(t.Context(), s))

	after, err := store.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.Equal(t, before.LastAccessedAt, after.LastAccessedAt)
	assert.Equal(t, before.IdleExpiresAt, after.IdleExpiresAt)
}
