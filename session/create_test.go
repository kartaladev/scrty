package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
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

		clk := newTestClock(createdAt)
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

		clk := newTestClock(createdAt)
		m, _ := managerOnClock(t, clk)

		s, err := m.Create(t.Context(), testUser)
		require.NoError(t, err)

		assert.Equal(t, createdAt, s.CreatedAt)
		assert.Equal(t, createdAt, s.LastAccessedAt)
		assert.Equal(t, createdAt.Add(30*time.Minute), s.IdleExpiresAt)
		assert.Equal(t, createdAt.Add(12*time.Hour), s.AbsoluteExpiresAt)
	})
}
