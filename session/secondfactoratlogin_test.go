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

// writeCountingStore counts the creating and updating writes that reach the
// store it wraps, so a case can pin that a session was created satisfied in
// one write and needed no later save.
type writeCountingStore struct {
	session.Store

	creates atomic.Int32
	saves   atomic.Int32
}

func (s *writeCountingStore) Create(ctx context.Context, sess *session.Session) error {
	s.creates.Add(1)

	return s.Store.Create(ctx, sess)
}

func (s *writeCountingStore) Save(ctx context.Context, sess *session.Session) error {
	s.saves.Add(1)

	return s.Store.Save(ctx, sess)
}

// storeWrites is how many writes of each kind reached the store.
type storeWrites struct {
	creates, saves int32
}

func TestSecondFactorAtLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// act drives the manager and returns the session as the store now
		// holds it.
		act    func(t *testing.T, m *session.Manager) *session.Session
		assert func(t *testing.T, got *session.Session, writes storeWrites)
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
			assert: func(t *testing.T, got *session.Session, writes storeWrites) {
				assert.Equal(t, session.MFASatisfied, got.MFA)
				assert.Equal(t, createdAt, got.MFASatisfiedAt, "satisfied at the creation time")
				assert.Equal(t, got.CreatedAt, got.MFASatisfiedAt)
				assert.True(t, got.MFAAtFirstFactor)
				assert.Equal(t, int32(1), writes.creates, "the satisfied state is in the creating write")
				assert.Zero(t, writes.saves, "no save follows the creating write")
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
			assert: func(t *testing.T, got *session.Session, _ storeWrites) {
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
			assert: func(t *testing.T, got *session.Session, _ storeWrites) {
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
			assert: func(t *testing.T, got *session.Session, _ storeWrites) {
				assert.Equal(t, session.MFASatisfied, got.MFA)
				assert.False(t, got.MFAAtFirstFactor)
			},
		},
		{
			name: "a later save cannot set the marker",
			act: func(t *testing.T, m *session.Manager) *session.Session {
				s, err := m.Create(t.Context(), testUser, session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				s.MFAAtFirstFactor = true
				require.NoError(t, m.Save(t.Context(), s))

				loaded, err := m.Load(t.Context(), s.ID)
				require.NoError(t, err)

				return loaded
			},
			assert: func(t *testing.T, got *session.Session, _ storeWrites) {
				assert.False(t, got.MFAAtFirstFactor, "only the creating write sets the marker")
			},
		},
		{
			name: "a later save cannot clear the marker",
			act: func(t *testing.T, m *session.Manager) *session.Session {
				s, err := m.Create(t.Context(), testUser,
					session.WithFirstFactor(factor.Passkey), session.WithSecondFactorAtLogin())
				require.NoError(t, err)

				s.MFAAtFirstFactor = false
				require.NoError(t, m.Save(t.Context(), s))

				loaded, err := m.Load(t.Context(), s.ID)
				require.NoError(t, err)

				return loaded
			},
			assert: func(t *testing.T, got *session.Session, _ storeWrites) {
				assert.True(t, got.MFAAtFirstFactor, "only the creating write sets the marker")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			store := &writeCountingStore{Store: session.NewMemoryStore(session.WithMemoryStoreClock(clk))}
			m := managerFor(t, session.WithStore(store), session.WithClock(clk))

			got := tc.act(t, m)
			tc.assert(t, got, storeWrites{creates: store.creates.Load(), saves: store.saves.Load()})
		})
	}
}
