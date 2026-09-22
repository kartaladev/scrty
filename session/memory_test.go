package session_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

// storedSession is one record as a store would receive it from a manager.
func storedSession(id string) *session.Session {
	return &session.Session{
		ID:                id,
		UserID:            testUser,
		CreatedAt:         createdAt,
		LastAccessedAt:    createdAt,
		IdleExpiresAt:     createdAt.Add(30 * time.Minute),
		AbsoluteExpiresAt: createdAt.Add(12 * time.Hour),
		Data:              map[string]string{"k": "v"},
	}
}

func TestMemoryStoreIsolatesRecords(t *testing.T) {
	t.Parallel()

	t.Run("a caller writing to what it created cannot change what was stored", func(t *testing.T) {
		t.Parallel()

		clk := newTestClock(createdAt)
		store := session.NewMemoryStore(session.WithMemoryStoreClock(clk.Now))

		s := storedSession("created")
		require.NoError(t, store.Create(t.Context(), s))

		// The caller keeps writing to the record it handed over, which is
		// ordinary: it is their struct and their map.
		s.Data["k"] = "mutated-after-store"
		s.MFA = session.MFASatisfied

		loaded, err := store.Load(t.Context(), s.ID)
		require.NoError(t, err)
		assert.Equal(t, "v", loaded.Data["k"], "the store aliased the caller's map on write")
		assert.Equal(t, session.MFANone, loaded.MFA, "the store aliased the caller's record on write")
	})

	t.Run("a caller writing to what it loaded cannot change what was stored", func(t *testing.T) {
		t.Parallel()

		clk := newTestClock(createdAt)
		store := session.NewMemoryStore(session.WithMemoryStoreClock(clk.Now))
		require.NoError(t, store.Create(t.Context(), storedSession("loaded")))

		first, err := store.Load(t.Context(), "loaded")
		require.NoError(t, err)
		first.Data["k"] = "mutated-after-load"
		first.MFA = session.MFASatisfied
		first.UserID = "mallory"

		again, err := store.Load(t.Context(), "loaded")
		require.NoError(t, err)
		assert.Equal(t, "v", again.Data["k"], "the store aliased its own record on read")
		assert.Equal(t, session.MFANone, again.MFA, "the store aliased its own record on read")
		assert.Equal(t, testUser, again.UserID)
	})

	t.Run("a caller writing to what it saved cannot change what was stored", func(t *testing.T) {
		t.Parallel()

		clk := newTestClock(createdAt)
		store := session.NewMemoryStore(session.WithMemoryStoreClock(clk.Now))
		require.NoError(t, store.Create(t.Context(), storedSession("saved")))

		s := storedSession("saved")
		s.Data = map[string]string{"k": "saved"}
		require.NoError(t, store.Save(t.Context(), s))

		s.Data["k"] = "mutated-after-save"

		loaded, err := store.Load(t.Context(), "saved")
		require.NoError(t, err)
		assert.Equal(t, "saved", loaded.Data["k"], "the store aliased the caller's map on save")
	})

	t.Run("a nil consumer map stays nil rather than becoming an empty one", func(t *testing.T) {
		t.Parallel()

		clk := newTestClock(createdAt)
		store := session.NewMemoryStore(session.WithMemoryStoreClock(clk.Now))

		s := storedSession("nil-data")
		s.Data = nil
		require.NoError(t, store.Create(t.Context(), s))

		loaded, err := store.Load(t.Context(), "nil-data")
		require.NoError(t, err)
		assert.Nil(t, loaded.Data, "the store invented a map the consumer never supplied")
	})

	t.Run("concurrent callers reading and writing do not race", func(t *testing.T) {
		t.Parallel()

		clk := newTestClock(createdAt)
		store := session.NewMemoryStore(session.WithMemoryStoreClock(clk.Now))
		require.NoError(t, store.Create(t.Context(), storedSession("shared")))

		var wg sync.WaitGroup
		for range 8 {
			wg.Add(2)
			go func() {
				defer wg.Done()

				loaded, err := store.Load(t.Context(), "shared")
				if assert.NoError(t, err) {
					// A reader writing to what it read is what the copy on
					// read exists for; under -race this is where an alias
					// shows up.
					loaded.Data["k"] = "reader"
				}
			}()
			go func() {
				defer wg.Done()

				s := storedSession("shared")
				assert.NoError(t, store.Save(t.Context(), s))
				s.Data["k"] = "writer"
			}()
		}
		wg.Wait()

		loaded, err := store.Load(t.Context(), "shared")
		require.NoError(t, err)
		assert.Equal(t, "v", loaded.Data["k"])
	})
}

func TestUnstartedMemoryStoreKeepsExpiredRecords(t *testing.T) {
	t.Parallel()

	clk := newTestClock(createdAt)
	store := session.NewMemoryStore(session.WithMemoryStoreClock(clk.Now))
	require.NoError(t, store.Create(t.Context(), storedSession("expiring")))

	clk.Set(createdAt.Add(time.Hour))

	_, err := store.Load(t.Context(), "expiring")
	require.ErrorIs(t, err, session.ErrSessionExpired, "an expired session was served by an unstarted store")

	// This is the documented limit of not calling Start, and the assertion
	// exists so that nobody later "fixes" it into a surprise purge: a caller
	// reading a session must not be the thing that deletes other people's.
	assert.Equal(t, 1, store.Len(),
		"the record is still held; that is the documented limit of not calling Start")

	// And it goes when something asks for it to go.
	removed, err := store.DeleteExpired(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, removed)
	assert.Zero(t, store.Len())
}
