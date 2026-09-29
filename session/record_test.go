package session_test

import (
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/session"
)

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
