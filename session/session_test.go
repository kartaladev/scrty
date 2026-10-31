package session_test

import (
	"math"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/internal/must"
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
		{name: "recovery pending is appended", state: session.MFARecoveryPending, value: 4, text: "recovery-pending"},
		{name: "unnamed prints its number", state: session.MFAState(5), value: 5, text: "MFAState(5)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.value, int(tc.state))
			assert.Equal(t, tc.text, tc.state.String())
		})
	}
}

func TestLibraryStateIsNotInConsumerData(t *testing.T) {
	t.Parallel()

	t.Run("the state the library owns lives in fields, not in the consumer's map", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, _ := managerOnClock(t, clk)

		s, err := m.Create(t.Context(), testUser, session.WithFirstFactor(factor.Password))
		require.NoError(t, err)

		s.MFA = session.MFAPending
		s.PasswordChangePending = true
		require.NoError(t, m.Save(t.Context(), s))

		loaded, err := m.Load(t.Context(), s.ID)
		require.NoError(t, err)

		assert.Equal(t, factor.Password, loaded.FirstFactor)
		assert.Equal(t, session.MFAPending, loaded.MFA)
		assert.True(t, loaded.PasswordChangePending)
		assert.Empty(t, loaded.Data,
			"library state was written into the consumer's map, where a key collision could forge it")
	})

	t.Run("a consumer key cannot forge a challenge state", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, _ := managerOnClock(t, clk)

		s, err := m.Create(t.Context(), testUser, session.WithFirstFactor(factor.Password))
		require.NoError(t, err)

		s.MFA = session.MFAPending
		// The most plausible reserved key a library would have used, written
		// by the consumer into the map that is theirs to write.
		s.Data = map[string]string{"mfa": "satisfied"}
		require.NoError(t, m.Save(t.Context(), s))

		loaded, err := m.Load(t.Context(), s.ID)
		require.NoError(t, err)

		assert.Equal(t, session.MFAPending, loaded.MFA,
			"a consumer's own map entry decided the second-factor state")
		assert.Equal(t, "satisfied", loaded.Data["mfa"],
			"the library rewrote an entry of the consumer's map")
	})

	t.Run("the second-factor state is persisted through pending to satisfied", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, _ := managerOnClock(t, clk)

		s, err := m.Create(t.Context(), testUser)
		require.NoError(t, err)
		assert.Equal(t, session.MFANone, s.MFA, "a new session already owed or had given a second factor")

		s.MFA = session.MFAPending
		require.NoError(t, m.Save(t.Context(), s))

		pending, err := m.Load(t.Context(), s.ID)
		require.NoError(t, err)
		require.Equal(t, session.MFAPending, pending.MFA)

		pending.MFA = session.MFASatisfied
		require.NoError(t, m.Save(t.Context(), pending))

		satisfied, err := m.Load(t.Context(), s.ID)
		require.NoError(t, err)
		assert.Equal(t, session.MFASatisfied, satisfied.MFA)
	})
}

// Standalone: it round-trips a whole consumer map rather than library-owned state.
func TestConsumerDataIsReturnedUnchanged(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)

	// Every row here is a value a map of arbitrary values would change on the
	// way through a durable store, which is why Data is map[string]string.
	data := map[string]string{
		"tenant":  "acme",
		"count":   "07",
		"empty":   "",
		"unicode": "héllo → 世界",
		"numeric": "0042",
		"float":   "1.0",
		"boolish": "true",
		"spaced":  "  padded  ",
	}

	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	s.Data = data
	require.NoError(t, m.Save(t.Context(), s))

	loaded, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.Equal(t, data, loaded.Data, "the library did not return the consumer's map byte-for-byte")
}

// TestAuthenticatedWithin pins the one freshness rule: no more than the window
// elapsed since the authentication time, inclusive of the window's end; a time
// ahead of the clock counts as none elapsed; a zero time is never within.
func TestAuthenticatedWithin(t *testing.T) {
	t.Parallel()

	at := func(hh, mm, ss int) time.Time { return time.Date(2026, 1, 2, hh, mm, ss, 0, time.UTC) }

	type testCase struct {
		name            string
		authenticatedAt time.Time
		now             time.Time
		window          time.Duration
		assert          func(t *testing.T, got bool)
	}

	cases := []testCase{
		{
			name:            "inside the window",
			authenticatedAt: at(9, 0, 0),
			now:             at(9, 10, 0),
			window:          15 * time.Minute,
			assert:          func(t *testing.T, got bool) { assert.True(t, got) },
		},
		{
			name:            "at the window's end",
			authenticatedAt: at(9, 0, 0),
			now:             at(9, 15, 0),
			window:          15 * time.Minute,
			assert:          func(t *testing.T, got bool) { assert.True(t, got) },
		},
		{
			name:            "past the window",
			authenticatedAt: at(9, 0, 0),
			now:             at(9, 15, 1),
			window:          15 * time.Minute,
			assert:          func(t *testing.T, got bool) { assert.False(t, got) },
		},
		{
			name:            "authentication time seconds ahead of the clock",
			authenticatedAt: at(9, 0, 5),
			now:             at(9, 0, 0),
			window:          15 * time.Minute,
			assert:          func(t *testing.T, got bool) { assert.True(t, got) },
		},
		{
			name:            "authentication time hours ahead of the clock",
			authenticatedAt: at(12, 0, 0),
			now:             at(9, 0, 0),
			window:          15 * time.Minute,
			assert:          func(t *testing.T, got bool) { assert.True(t, got) },
		},
		{
			name:            "no recorded authentication time",
			authenticatedAt: time.Time{},
			now:             at(9, 0, 0),
			window:          24 * time.Hour,
			assert:          func(t *testing.T, got bool) { assert.False(t, got) },
		},
		{
			name:            "no recorded authentication time against the largest window",
			authenticatedAt: time.Time{},
			now:             at(9, 0, 0),
			window:          time.Duration(math.MaxInt64),
			assert:          func(t *testing.T, got bool) { assert.False(t, got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := &session.Session{AuthenticatedAt: tc.authenticatedAt}
			tc.assert(t, s.AuthenticatedWithin(tc.now, tc.window))
		})
	}
}

// TestSave_KeepsAuthenticatedAt pins that saving cannot refresh the
// authentication time: it is library-owned, and Save keeps the stored value.
func TestSave_KeepsAuthenticatedAt(t *testing.T) {
	t.Parallel()

	store := must.Must(session.NewMemoryStore(
		session.WithMemoryStoreClock(clockwork.NewFakeClockAt(createdAt)),
	))
	s := storedSession("keeps-authenticated-at")
	s.AuthenticatedAt = createdAt
	require.NoError(t, store.Create(t.Context(), s))

	loaded, err := store.Load(t.Context(), s.ID)
	require.NoError(t, err)

	loaded.AuthenticatedAt = createdAt.Add(time.Hour)
	require.NoError(t, store.Save(t.Context(), loaded))

	reloaded, err := store.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.True(t, createdAt.Equal(reloaded.AuthenticatedAt),
		"Save changed the authentication time to %s", reloaded.AuthenticatedAt)
}
