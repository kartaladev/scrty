package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/session"
)

func TestCreateWritesEverythingInOneWrite(t *testing.T) {
	t.Parallel()

	t.Run("the first factor and the external session are in the creating write", func(t *testing.T) {
		t.Parallel()

		store := NewMockStore(gomock.NewController(t))
		// Exactly one write, and no EXPECT for Save: a second write is the
		// failure this pins. A crash between two writes would leave a live
		// session that had forgotten how it was established.
		store.EXPECT().Create(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, s *session.Session) error {
				assert.Equal(t, factor.Password, s.FirstFactor,
					"the first factor was applied after the create write, so a crash could lose it")
				assert.Equal(t, "okta", s.ExternalProvider)
				assert.Equal(t, "https://a", s.ExternalIssuer)
				assert.Equal(t, "s-1", s.ExternalSessionID)
				assert.Equal(t, "raw-id-token", s.ExternalIDToken)

				return nil
			}).
			Times(1)

		m := managerFor(t, session.WithStore(store))

		s, err := m.Create(t.Context(), testUser,
			session.WithFirstFactor(factor.Password),
			session.WithExternalSession("okta", "https://a", "s-1", "raw-id-token"))
		require.NoError(t, err)
		assert.Equal(t, factor.Password, s.FirstFactor)
	})

	t.Run("a session created without a first factor reports none", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, _ := managerOnClock(t, clk)

		s, err := m.Create(t.Context(), testUser)
		require.NoError(t, err)

		loaded, err := m.Load(t.Context(), s.ID)
		require.NoError(t, err)
		assert.Empty(t, loaded.FirstFactor, "a first factor appeared that no caller recorded")
		assert.Empty(t, loaded.ExternalIssuer)
	})

	t.Run("the deadlines are set from the manager's clock and timeouts", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, _ := managerOnClock(t, clk)

		s, err := m.Create(t.Context(), testUser)
		require.NoError(t, err)

		assert.Equal(t, createdAt, s.CreatedAt)
		assert.Equal(t, createdAt, s.LastAccessedAt)
		assert.Equal(t, createdAt.Add(30*time.Minute), s.IdleExpiresAt)
		assert.Equal(t, createdAt.Add(12*time.Hour), s.AbsoluteExpiresAt)
	})
}

// TestCreate_AuthenticationTime pins that a sign-in records when the user
// authenticated, and that a consumer's create option may still choose it.
func TestCreate_AuthenticationTime(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.CreateOption
		assert func(t *testing.T, created, loaded *session.Session)
	}

	cases := []testCase{
		{
			name: "a sign-in records its authentication time",
			assert: func(t *testing.T, created, loaded *session.Session) {
				assert.Equal(t, createdAt, created.AuthenticatedAt)
				assert.True(t, loaded.AuthenticatedAt.Equal(createdAt), "the store holds the authentication time")
			},
		},
		{
			name: "a consumer create option may set another authentication time",
			opts: []session.CreateOption{func(s *session.Session) {
				s.AuthenticatedAt = createdAt.Add(-5 * time.Minute)
			}},
			assert: func(t *testing.T, created, loaded *session.Session) {
				assert.Equal(t, createdAt.Add(-5*time.Minute), created.AuthenticatedAt)
				assert.True(t, loaded.AuthenticatedAt.Equal(createdAt.Add(-5*time.Minute)))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			m, _ := managerOnClock(t, clk)

			s, err := m.Create(t.Context(), testUser, tc.opts...)
			require.NoError(t, err)

			loaded, err := m.Load(t.Context(), s.ID)
			require.NoError(t, err)
			tc.assert(t, s, loaded)
		})
	}
}

func TestCreate_AbsoluteLifetime(t *testing.T) {
	t.Parallel()

	const thirtyDays = 30 * 24 * time.Hour

	type testCase struct {
		name   string
		opts   []session.ManagerOption
		create []session.CreateOption
		assert func(t *testing.T, s *session.Session, err error, stored int)
	}

	cases := []testCase{
		{
			name: "no option keeps the absolute timeout",
			assert: func(t *testing.T, s *session.Session, err error, _ int) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(12*time.Hour), s.AbsoluteExpiresAt)
			},
		},
		{
			name:   "the default maximum refuses a longer lifetime and stores nothing",
			create: []session.CreateOption{session.WithAbsoluteLifetime(thirtyDays)},
			assert: func(t *testing.T, s *session.Session, err error, stored int) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, s)
				assert.Zero(t, stored, "a refused lifetime still reached the store")
			},
		},
		{
			name:   "a lifetime up to the maximum is honoured",
			opts:   []session.ManagerOption{session.WithMaxAbsoluteLifetime(thirtyDays)},
			create: []session.CreateOption{session.WithAbsoluteLifetime(thirtyDays)},
			assert: func(t *testing.T, s *session.Session, err error, stored int) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(thirtyDays), s.AbsoluteExpiresAt)
				assert.Equal(t, createdAt.Add(30*time.Minute), s.IdleExpiresAt)
				assert.Equal(t, 1, stored)
			},
		},
		{
			name:   "a lifetime above the maximum is refused, not shortened",
			opts:   []session.ManagerOption{session.WithMaxAbsoluteLifetime(thirtyDays)},
			create: []session.CreateOption{session.WithAbsoluteLifetime(thirtyDays + time.Second)},
			assert: func(t *testing.T, s *session.Session, err error, stored int) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, s)
				assert.Zero(t, stored)
			},
		},
		{
			name:   "a zero lifetime is refused",
			create: []session.CreateOption{session.WithAbsoluteLifetime(0)},
			assert: func(t *testing.T, _ *session.Session, err error, stored int) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Zero(t, stored)
			},
		},
		{
			name:   "a negative lifetime is refused",
			create: []session.CreateOption{session.WithAbsoluteLifetime(-time.Hour)},
			assert: func(t *testing.T, _ *session.Session, err error, stored int) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Zero(t, stored)
			},
		},
		{
			name:   "a lifetime shorter than the idle timeout caps the idle deadline",
			create: []session.CreateOption{session.WithAbsoluteLifetime(10 * time.Minute)},
			assert: func(t *testing.T, s *session.Session, err error, _ int) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(10*time.Minute), s.AbsoluteExpiresAt)
				assert.Equal(t, createdAt.Add(10*time.Minute), s.IdleExpiresAt)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			ctrl := gomock.NewController(t)
			store := NewMockStore(ctrl)
			var stored int
			store.EXPECT().Create(gomock.Any(), gomock.Any()).
				DoAndReturn(func(context.Context, *session.Session) error { stored++; return nil }).
				AnyTimes()
			m := managerFor(t, append([]session.ManagerOption{session.WithStore(store), session.WithClock(clk)}, tc.opts...)...)

			s, err := m.Create(t.Context(), testUser, tc.create...)

			tc.assert(t, s, err, stored)
		})
	}
}

func TestNewManager_MaxAbsoluteLifetimeBelowTheTimeoutIsRefused(t *testing.T) {
	t.Parallel()

	_, err := session.NewManager(session.WithMaxAbsoluteLifetime(time.Hour))

	require.ErrorIs(t, err, session.ErrConfig)
}
