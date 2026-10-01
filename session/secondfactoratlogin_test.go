package session_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/session"
)

// createCountingStore counts the creating writes that reach the store it
// wraps, so a case can pin that a session was created satisfied in one write.
type createCountingStore struct {
	session.Store

	creates atomic.Int32
}

func (s *createCountingStore) Create(ctx context.Context, sess *session.Session) error {
	s.creates.Add(1)

	return s.Store.Create(ctx, sess)
}

func TestSecondFactorAtLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// act drives the manager and returns the session as the store now
		// holds it.
		act    func(t *testing.T, m *session.Manager) *session.Session
		assert func(t *testing.T, got *session.Session, creates int32)
	}

	cases := []testCase{
		{
			name: "created satisfied in one write",
			act: func(t *testing.T, m *session.Manager) *session.Session {
				s, err := m.Create(t.Context(), testUser,
					session.WithFirstFactor(factor.Passkey), session.WithSecondFactorAtLogin())
				require.NoError(t, err)

				loaded, err := m.Load(t.Context(), s.ID)
				require.NoError(t, err)

				return loaded
			},
			assert: func(t *testing.T, got *session.Session, creates int32) {
				assert.Equal(t, session.MFASatisfied, got.MFA)
				assert.Equal(t, createdAt, got.MFASatisfiedAt, "satisfied at the creation time")
				assert.Equal(t, got.CreatedAt, got.MFASatisfiedAt)
				assert.True(t, got.MFAAtFirstFactor)
				assert.Equal(t, int32(1), creates, "the satisfied state is in the creating write")
			},
		},
		{
			name: "rotation keeps it",
			act: func(t *testing.T, m *session.Manager) *session.Session {
				s, err := m.Create(t.Context(), testUser,
					session.WithFirstFactor(factor.Passkey), session.WithSecondFactorAtLogin())
				require.NoError(t, err)

				rotated, err := m.Rotate(t.Context(), s)
				require.NoError(t, err)

				loaded, err := m.Load(t.Context(), rotated.ID)
				require.NoError(t, err)

				return loaded
			},
			assert: func(t *testing.T, got *session.Session, _ int32) {
				assert.Equal(t, session.MFASatisfied, got.MFA)
				assert.Equal(t, createdAt, got.MFASatisfiedAt)
				assert.True(t, got.MFAAtFirstFactor)
			},
		},
		{
			name: "consumer data cannot claim it",
			act: func(t *testing.T, m *session.Manager) *session.Session {
				s, err := m.Create(t.Context(), testUser, session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				s.Data = map[string]string{"mfa_at_first_factor": "true", "mfa": "satisfied"}
				require.NoError(t, m.Save(t.Context(), s))

				loaded, err := m.Load(t.Context(), s.ID)
				require.NoError(t, err)

				return loaded
			},
			assert: func(t *testing.T, got *session.Session, _ int32) {
				assert.False(t, got.MFAAtFirstFactor)
				assert.Equal(t, session.MFANone, got.MFA)
				assert.Equal(t, "true", got.Data["mfa_at_first_factor"], "consumer data is kept unchanged")
			},
		},
		{
			name: "verify-resolved sessions are not marked",
			act: func(t *testing.T, m *session.Manager) *session.Session {
				s, err := m.Create(t.Context(), testUser, session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				// The way the verify endpoint resolves a challenge.
				s.MFA = session.MFASatisfied
				s.MFASatisfiedAt = createdAt
				require.NoError(t, m.Save(t.Context(), s))

				loaded, err := m.Load(t.Context(), s.ID)
				require.NoError(t, err)

				return loaded
			},
			assert: func(t *testing.T, got *session.Session, _ int32) {
				assert.Equal(t, session.MFASatisfied, got.MFA)
				assert.False(t, got.MFAAtFirstFactor)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			store := &createCountingStore{Store: session.NewMemoryStore(session.WithMemoryStoreClock(clk))}
			m := managerFor(t, session.WithStore(store), session.WithClock(clk))

			got := tc.act(t, m)
			tc.assert(t, got, store.creates.Load())
		})
	}
}
