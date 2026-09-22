package session_test

import (
	"encoding/base64"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

func TestSessionIdentifiers(t *testing.T) {
	t.Parallel()

	t.Run("are 32 random bytes, base64url encoded", func(t *testing.T) {
		t.Parallel()

		m := managerFor(t)
		s, err := m.Create(t.Context(), testUser)
		require.NoError(t, err)

		raw, err := base64.RawURLEncoding.DecodeString(s.ID)
		require.NoError(t, err, "the identifier is not unpadded base64url")
		assert.Len(t, raw, 32)
		assert.Len(t, s.ID, 43, "32 bytes of unpadded base64url are 43 characters")
	})

	t.Run("never repeat", func(t *testing.T) {
		t.Parallel()

		seen := make(map[string]struct{}, 1000)
		m := managerFor(t)
		for range 1000 {
			s, err := m.Create(t.Context(), testUser)
			require.NoError(t, err)
			_, duplicate := seen[s.ID]
			require.False(t, duplicate, "a session identifier repeated")
			seen[s.ID] = struct{}{}
		}
	})

	t.Run("a failing entropy source is an error, never a weak identifier", func(t *testing.T) {
		t.Parallel()

		store := session.NewMemoryStore()
		m := managerWithReader(t, store, iotest.ErrReader(errNoEntropy))

		s, err := m.Create(t.Context(), testUser)
		require.ErrorIs(t, err, errNoEntropy)
		assert.Nil(t, s, "a session came back alongside a failed identifier")
		assert.Zero(t, store.Len(), "a session was stored despite having no usable identifier")
	})
}
