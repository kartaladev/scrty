package session_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// listedIDs returns the identifiers of the listed sessions, for comparing a
// listing whose order is unspecified.
func listedIDs(listed []*session.Session) []string {
	ids := make([]string, 0, len(listed))
	for _, s := range listed {
		ids = append(ids, s.ID)
	}

	return ids
}

// seedListing stores, at createdAt:
//   - "Alice"'s family A: "a-old", superseded by "a-head" with a window still
//     open a minute later;
//   - "Alice"'s family B: "b-gone", whose own deadlines ended at createdAt;
//   - "alice"'s family C: "c-head", the same letters in another case;
//   - "u-2"'s family D: "d-head".
func seedListing(t *testing.T, store *session.MemoryStore) {
	t.Helper()

	ctx := t.Context()
	member := func(sessionID string, user identity.UserID, family string) *session.Session {
		s := familyOf(sessionID, id.MustParse(family))
		s.UserID = user

		return s
	}

	require.NoError(t, store.Create(ctx, member("a-old", "Alice", "01926a4e-0000-7000-8000-00000000000a")))
	require.NoError(t, store.Supersede(ctx, firstRotation("a-old",
		member("a-head", "Alice", "01926a4e-0000-7000-8000-00000000000a"))))

	gone := member("b-gone", "Alice", "01926a4e-0000-7000-8000-00000000000b")
	gone.CreatedAt = createdAt.Add(-time.Hour)
	gone.FamilyCreatedAt = gone.CreatedAt
	gone.IdleExpiresAt = createdAt
	require.NoError(t, store.Create(ctx, gone))

	require.NoError(t, store.Create(ctx, member("c-head", "alice", "01926a4e-0000-7000-8000-00000000000c")))
	require.NoError(t, store.Create(ctx, member("d-head", "u-2", "01926a4e-0000-7000-8000-00000000000d")))
}

func TestMemoryStore_ListByUser(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		user   identity.UserID
		now    time.Time
		assert func(t *testing.T, store *session.MemoryStore, listed []*session.Session, err error)
	}

	cases := []testCase{
		{
			name: "live heads only: the superseded predecessor and the expired family are left out",
			user: "Alice",
			now:  createdAt.Add(time.Second),
			assert: func(t *testing.T, _ *session.MemoryStore, listed []*session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"a-head"}, listedIDs(listed))
			},
		},
		{
			// The store's own clock still reads createdAt; the caller's time
			// is past the head's idle deadline.
			name: "liveness is judged at the time the caller passes",
			user: "Alice",
			now:  createdAt.Add(31 * time.Minute),
			assert: func(t *testing.T, _ *session.MemoryStore, listed []*session.Session, err error) {
				require.NoError(t, err)
				assert.Empty(t, listed)
			},
		},
		{
			name: "the caller's time is honoured backwards too",
			user: "Alice",
			now:  createdAt.Add(-time.Minute),
			assert: func(t *testing.T, _ *session.MemoryStore, listed []*session.Session, err error) {
				require.NoError(t, err)
				assert.ElementsMatch(t, []string{"a-head", "b-gone"}, listedIDs(listed))
			},
		},
		{
			name: "the reference is matched exactly: alice is not Alice",
			user: "alice",
			now:  createdAt.Add(time.Second),
			assert: func(t *testing.T, _ *session.MemoryStore, listed []*session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"c-head"}, listedIDs(listed))
			},
		},
		{
			name: "another user's sessions are never listed",
			user: "u-2",
			now:  createdAt.Add(time.Second),
			assert: func(t *testing.T, _ *session.MemoryStore, listed []*session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"d-head"}, listedIDs(listed))
			},
		},
		{
			name: "a user with no sessions is an empty listing, not an error",
			user: "u-unknown",
			now:  createdAt.Add(time.Second),
			assert: func(t *testing.T, _ *session.MemoryStore, listed []*session.Session, err error) {
				require.NoError(t, err)
				assert.Empty(t, listed)
			},
		},
		{
			name: "a listed session is the caller's own copy",
			user: "Alice",
			now:  createdAt.Add(time.Second),
			assert: func(t *testing.T, store *session.MemoryStore, listed []*session.Session, err error) {
				require.NoError(t, err)
				require.Len(t, listed, 1)
				listed[0].Data["k"] = "changed"
				listed[0].UserID = "mallory"

				again, err := store.Load(t.Context(), "a-head")
				require.NoError(t, err)
				assert.Equal(t, "v", again.Data["k"])
				assert.Equal(t, identity.UserID("Alice"), again.UserID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clockwork.NewFakeClockAt(createdAt))))
			seedListing(t, store)

			listed, err := store.ListByUser(t.Context(), tc.user, tc.now)
			tc.assert(t, store, listed, err)
		})
	}
}
