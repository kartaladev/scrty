package session_test

import (
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
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

		clk := clockwork.NewFakeClockAt(createdAt)
		store := session.NewMemoryStore(session.WithMemoryStoreClock(clk))

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

		clk := clockwork.NewFakeClockAt(createdAt)
		store := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
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

		clk := clockwork.NewFakeClockAt(createdAt)
		store := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
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

		clk := clockwork.NewFakeClockAt(createdAt)
		store := session.NewMemoryStore(session.WithMemoryStoreClock(clk))

		s := storedSession("nil-data")
		s.Data = nil
		require.NoError(t, store.Create(t.Context(), s))

		loaded, err := store.Load(t.Context(), "nil-data")
		require.NoError(t, err)
		assert.Nil(t, loaded.Data, "the store invented a map the consumer never supplied")
	})

	t.Run("concurrent callers reading and writing do not race", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		store := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
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

	clk := clockwork.NewFakeClockAt(createdAt)
	store := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
	require.NoError(t, store.Create(t.Context(), storedSession("expiring")))

	clk.Advance(createdAt.Add(time.Hour).Sub(clk.Now()))

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

// nilTimed is a consumer's clock type that can also wait; (*nilTimed)(nil) is
// the typed nil an unchecked constructor error hands over.
type nilTimed struct{}

func (*nilTimed) Now() time.Time                       { return time.Time{} }
func (*nilTimed) After(time.Duration) <-chan time.Time { return nil }

// TestMemoryStoreClock covers the store's absent clock. Its constructor cannot
// fail, so nil and typed nil keep the system clock instead of being refused.
func TestMemoryStoreClock(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.MemoryStoreOption
		assert func(t *testing.T, store *session.MemoryStore)
	}

	// judgesBySystemTime asserts that the store read the system clock: a
	// session expired a second ago is refused, and one expiring in an hour is
	// served.
	judgesBySystemTime := func(t *testing.T, store *session.MemoryStore) {
		t.Helper()

		now := time.Now()
		require.NoError(t, store.Create(t.Context(), &session.Session{
			ID: "expired", UserID: testUser, CreatedAt: now.Add(-time.Hour),
			IdleExpiresAt: now.Add(-time.Second), AbsoluteExpiresAt: now.Add(time.Hour),
		}))
		require.NoError(t, store.Create(t.Context(), &session.Session{
			ID: "live", UserID: testUser, CreatedAt: now,
			IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
		}))

		_, err := store.Load(t.Context(), "expired")
		require.ErrorIs(t, err, session.ErrSessionExpired, "the store did not judge expiry by the system clock")
		_, err = store.Load(t.Context(), "live")
		require.NoError(t, err)
	}

	cases := []testCase{
		{name: "no clock option reads the system clock", assert: judgesBySystemTime},
		{
			name:   "an untyped nil clock keeps the system clock",
			opts:   []session.MemoryStoreOption{session.WithMemoryStoreClock(nil)},
			assert: judgesBySystemTime,
		},
		{
			name:   "a typed-nil clock keeps the system clock, rather than being read",
			opts:   []session.MemoryStoreOption{session.WithMemoryStoreClock((*nilTimed)(nil))},
			assert: judgesBySystemTime,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, session.NewMemoryStore(tc.opts...))
		})
	}
}
