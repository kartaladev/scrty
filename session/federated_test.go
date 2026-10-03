package session_test

import (
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/session"
)

func TestFederatedAssurance(t *testing.T) {
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
			name: "recorded at creation in one write",
			act: func(t *testing.T, m *session.Manager) *session.Session {
				s, err := m.Create(t.Context(), testUser,
					session.WithFirstFactor(factor.OIDC),
					session.WithFederatedAssurance([]string{"mfa"}, "urn:corp:loa:2"))
				require.NoError(t, err)

				loaded, err := m.Load(t.Context(), s.ID)
				require.NoError(t, err)

				return loaded
			},
			assert: func(t *testing.T, got *session.Session, writes storeWrites) {
				assert.Equal(t, []string{"mfa"}, got.FederatedAMR)
				assert.Equal(t, "urn:corp:loa:2", got.FederatedACR)
				assert.Equal(t, session.MFANone, got.MFA)
				assert.False(t, got.MFAAtFirstFactor)
				assert.Equal(t, int32(1), writes.creates, "the assurance is in the creating write")
				assert.Zero(t, writes.saves)
			},
		},
		{
			name: "rotation keeps it after the challenge resolves",
			act: func(t *testing.T, m *session.Manager) *session.Session {
				s, err := m.Create(t.Context(), testUser,
					session.WithFirstFactor(factor.OIDC),
					session.WithFederatedAssurance([]string{"pwd", "mfa"}, "urn:corp:loa:2"))
				require.NoError(t, err)

				s.MFA = session.MFASatisfied
				s.MFASatisfiedAt = createdAt
				require.NoError(t, m.Save(t.Context(), s))

				rotated, err := m.Rotate(t.Context(), s)
				require.NoError(t, err)

				loaded, err := m.Load(t.Context(), rotated.ID)
				require.NoError(t, err)

				return loaded
			},
			assert: func(t *testing.T, got *session.Session, _ storeWrites) {
				assert.Equal(t, []string{"pwd", "mfa"}, got.FederatedAMR)
				assert.Equal(t, "urn:corp:loa:2", got.FederatedACR)
				assert.Equal(t, session.MFASatisfied, got.MFA)
			},
		},
		{
			name: "a rotated copy shares no backing array with the original",
			act: func(t *testing.T, m *session.Manager) *session.Session {
				s, err := m.Create(t.Context(), testUser,
					session.WithFederatedAssurance([]string{"mfa"}, ""))
				require.NoError(t, err)

				rotated, err := m.Rotate(t.Context(), s)
				require.NoError(t, err)

				require.Len(t, rotated.FederatedAMR, 1)
				rotated.FederatedAMR[0] = "x"

				return s
			},
			assert: func(t *testing.T, got *session.Session, _ storeWrites) {
				assert.Equal(t, []string{"mfa"}, got.FederatedAMR)
			},
		},
		{
			name: "the stored copy is unreachable through a returned session",
			act: func(t *testing.T, m *session.Manager) *session.Session {
				s, err := m.Create(t.Context(), testUser,
					session.WithFederatedAssurance([]string{"mfa"}, ""))
				require.NoError(t, err)

				first, err := m.Load(t.Context(), s.ID)
				require.NoError(t, err)
				require.Len(t, first.FederatedAMR, 1)
				first.FederatedAMR[0] = "x"

				// The created session handed back is not the stored record either.
				require.Len(t, s.FederatedAMR, 1)
				s.FederatedAMR[0] = "y"

				loaded, err := m.Load(t.Context(), s.ID)
				require.NoError(t, err)

				return loaded
			},
			assert: func(t *testing.T, got *session.Session, _ storeWrites) {
				assert.Equal(t, []string{"mfa"}, got.FederatedAMR)
			},
		},
		{
			name: "the option copies the caller's slice",
			act: func(t *testing.T, m *session.Manager) *session.Session {
				amr := []string{"mfa"}
				s, err := m.Create(t.Context(), testUser, session.WithFederatedAssurance(amr, ""))
				require.NoError(t, err)

				amr[0] = "x"

				return s
			},
			assert: func(t *testing.T, got *session.Session, _ storeWrites) {
				assert.Equal(t, []string{"mfa"}, got.FederatedAMR)
			},
		},
		{
			name: "consumer data cannot forge it",
			act: func(t *testing.T, m *session.Manager) *session.Session {
				s, err := m.Create(t.Context(), testUser, session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				s.Data = map[string]string{"amr": "mfa", "acr": "urn:corp:loa:2", "federated_amr": "mfa"}
				require.NoError(t, m.Save(t.Context(), s))

				loaded, err := m.Load(t.Context(), s.ID)
				require.NoError(t, err)

				return loaded
			},
			assert: func(t *testing.T, got *session.Session, _ storeWrites) {
				assert.Empty(t, got.FederatedAMR)
				assert.Empty(t, got.FederatedACR)
				assert.Equal(t, "mfa", got.Data["amr"], "consumer data is kept unchanged")
			},
		},
		{
			name: "not recorded by default",
			act: func(t *testing.T, m *session.Manager) *session.Session {
				s, err := m.Create(t.Context(), testUser, session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				loaded, err := m.Load(t.Context(), s.ID)
				require.NoError(t, err)

				return loaded
			},
			assert: func(t *testing.T, got *session.Session, _ storeWrites) {
				assert.Empty(t, got.FederatedAMR)
				assert.Empty(t, got.FederatedACR)
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
