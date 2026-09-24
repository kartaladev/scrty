package session_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/session"
)

// TestSessionMFASatisfiedAt pins the second-factor-satisfied time as
// library-owned state: it survives a store round-trip, it is zero until a
// second factor is accepted, and no entry a consumer puts in Data can produce
// one.
func TestSessionMFASatisfiedAt(t *testing.T) {
	t.Parallel()

	satisfied := time.Date(2026, time.September, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		mutate func(s *session.Session)
		assert func(t *testing.T, loaded *session.Session)
	}

	cases := []testCase{
		{
			name: "round-trips through the store",
			mutate: func(s *session.Session) {
				s.MFA = session.MFASatisfied
				s.MFASatisfiedAt = satisfied
			},
			assert: func(t *testing.T, loaded *session.Session) {
				assert.Equal(t, session.MFASatisfied, loaded.MFA)
				assert.True(t, loaded.MFASatisfiedAt.Equal(satisfied),
					"want %s, got %s", satisfied, loaded.MFASatisfiedAt)
			},
		},
		{
			name:   "zero until a second factor is accepted",
			mutate: func(s *session.Session) { s.MFA = session.MFAPending },
			assert: func(t *testing.T, loaded *session.Session) {
				assert.True(t, loaded.MFASatisfiedAt.IsZero())
			},
		},
		{
			name: "a consumer data entry cannot forge it",
			mutate: func(s *session.Session) {
				s.MFA = session.MFAPending
				s.Data = map[string]string{"MFASatisfiedAt": satisfied.Format(time.RFC3339)}
			},
			assert: func(t *testing.T, loaded *session.Session) {
				assert.Equal(t, session.MFAPending, loaded.MFA)
				assert.True(t, loaded.MFASatisfiedAt.IsZero())
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
