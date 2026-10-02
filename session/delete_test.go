package session_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// otherUser is the second user every per-user case needs: what is deleted for
// one user must not touch the other.
const otherUser = identity.UserID("u2")

func TestDeletingAndCounting(t *testing.T) {
	t.Parallel()

	t.Run("deleting one session leaves the rest", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, _ := managerOnClock(t, clk)
		ctx := t.Context()

		gone, err := m.Create(ctx, testUser)
		require.NoError(t, err)
		kept, err := m.Create(ctx, testUser)
		require.NoError(t, err)

		require.NoError(t, m.Delete(ctx, gone.ID))

		_, err = m.Load(ctx, gone.ID)
		require.ErrorIs(t, err, session.ErrSessionNotFound)
		_, err = m.Load(ctx, kept.ID)
		require.NoError(t, err)
	})

	t.Run("deleting a session that is not there is not an error", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, _ := managerOnClock(t, clk)

		// The caller asked for it to be gone, and it is. Reporting a failure
		// would make an idempotent logout look like a broken one.
		assert.NoError(t, m.Delete(t.Context(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	})

	t.Run("deleting a user's sessions spares every other user's", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, _ := managerOnClock(t, clk)
		ctx := t.Context()

		var mine []string
		for range 3 {
			s, err := m.Create(ctx, testUser)
			require.NoError(t, err)
			mine = append(mine, s.ID)
		}
		theirs, err := m.Create(ctx, otherUser)
		require.NoError(t, err)

		require.NoError(t, m.DeleteByUser(ctx, testUser))

		for _, id := range mine {
			_, err := m.Load(ctx, id)
			require.ErrorIs(t, err, session.ErrSessionNotFound, "a session of the deleted user still loads")
		}
		_, err = m.Load(ctx, theirs.ID)
		require.NoError(t, err, "another user's session was deleted")
	})

	t.Run("a user reference is matched exactly as the consumer supplied it", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, _ := managerOnClock(t, clk)
		ctx := t.Context()

		s, err := m.Create(ctx, identity.UserID("Ada"))
		require.NoError(t, err)

		// identity states a user reference is opaque: two references that
		// differ only in case are two different users.
		require.NoError(t, m.DeleteByUser(ctx, identity.UserID("ada")))

		_, err = m.Load(ctx, s.ID)
		require.NoError(t, err, "a user reference was case-folded, so one user's logout ended another's session")
	})

	t.Run("counting a user's active sessions excludes expired ones", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, _ := managerOnClock(t, clk)
		ctx := t.Context()

		// One session created early enough to be idle-expired by the time the
		// count is taken, two created just before it.
		_, err := m.Create(ctx, testUser)
		require.NoError(t, err)

		clk.Advance(createdAt.Add(time.Hour).Sub(clk.Now()))
		for range 2 {
			_, err := m.Create(ctx, testUser)
			require.NoError(t, err)
		}
		_, err = m.Create(ctx, otherUser)
		require.NoError(t, err)

		n, err := m.CountActiveByUser(ctx, testUser)
		require.NoError(t, err)
		assert.Equal(t, 2, n, "the count included a session that can never be served again")

		n, err = m.CountActiveByUser(ctx, otherUser)
		require.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("deleting expired sessions reports how many went and spares live ones", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, store := managerOnClock(t, clk)
		ctx := t.Context()

		for range 2 {
			_, err := m.Create(ctx, testUser)
			require.NoError(t, err)
		}

		clk.Advance(createdAt.Add(time.Hour).Sub(clk.Now()))
		live, err := m.Create(ctx, testUser)
		require.NoError(t, err)

		removed, err := m.DeleteExpired(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, removed)
		assert.Equal(t, 1, store.Len(), "a live session was swept, or an expired one was left")

		_, err = m.Load(ctx, live.ID)
		require.NoError(t, err)

		removed, err = m.DeleteExpired(ctx)
		require.NoError(t, err)
		assert.Zero(t, removed, "a second sweep reported removals it did not make")
	})
}

func TestDeletingByUserExceptOne(t *testing.T) {
	t.Parallel()

	// Every case starts from three sessions of testUser and one of otherUser.
	// keep picks the kept identifier from them; prepare runs before the call.
	type testCase struct {
		name    string
		prepare func(t *testing.T, m *session.Manager, clk *clockwork.FakeClock, ids exceptIDs) exceptIDs
		keep    func(ids exceptIDs) string
		assert  func(t *testing.T, removed int, err error, m *session.Manager, ids exceptIDs)
	}

	cases := []testCase{
		{
			name: "the kept session stays and the user's others go",
			keep: func(ids exceptIDs) string { return ids.mine[0] },
			assert: func(t *testing.T, removed int, err error, m *session.Manager, ids exceptIDs) {
				require.NoError(t, err)
				assert.Equal(t, 2, removed)
				assertLoads(t, m, ids.mine[0], ids.theirs)
				assertGone(t, m, ids.mine[1:]...)
			},
		},
		{
			name: "a kept session of another user is untouched and every session of the user goes",
			keep: func(ids exceptIDs) string { return ids.theirs },
			assert: func(t *testing.T, removed int, err error, m *session.Manager, ids exceptIDs) {
				require.NoError(t, err)
				assert.Equal(t, 3, removed)
				assertLoads(t, m, ids.theirs)
				assertGone(t, m, ids.mine...)
			},
		},
		{
			name: "a kept identifier no session holds deletes every session of the user",
			keep: func(exceptIDs) string { return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
			assert: func(t *testing.T, removed int, err error, m *session.Manager, ids exceptIDs) {
				require.NoError(t, err)
				assert.Equal(t, 3, removed)
				assertLoads(t, m, ids.theirs)
				assertGone(t, m, ids.mine...)
			},
		},
		{
			name: "an empty kept identifier deletes every session of the user",
			keep: func(exceptIDs) string { return "" },
			assert: func(t *testing.T, removed int, err error, m *session.Manager, ids exceptIDs) {
				require.NoError(t, err)
				assert.Equal(t, 3, removed, "an empty kept identifier was a no-op")
				assertLoads(t, m, ids.theirs)
				assertGone(t, m, ids.mine...)
			},
		},
		{
			name: "expired sessions of the user are deleted and counted",
			prepare: func(t *testing.T, m *session.Manager, clk *clockwork.FakeClock, ids exceptIDs) exceptIDs {
				t.Helper()

				// The seeded sessions idle out; a fresh one is created to keep.
				clk.Advance(createdAt.Add(time.Hour).Sub(clk.Now()))
				fresh, err := m.Create(t.Context(), testUser)
				require.NoError(t, err)
				ids.fresh = fresh.ID

				return ids
			},
			keep: func(ids exceptIDs) string { return ids.fresh },
			assert: func(t *testing.T, removed int, err error, m *session.Manager, ids exceptIDs) {
				require.NoError(t, err)
				assert.Equal(t, 3, removed, "expired sessions were left behind or not counted")
				assertLoads(t, m, ids.fresh)
				assertGone(t, m, ids.mine...)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			m, _ := managerOnClock(t, clk)
			ids := seedExcept(t, m)
			if tc.prepare != nil {
				ids = tc.prepare(t, m, clk, ids)
			}

			removed, err := m.DeleteByUserExcept(t.Context(), testUser, tc.keep(ids))
			tc.assert(t, removed, err, m, ids)
		})
	}
}

// exceptIDs names the sessions seedExcept creates, and the one a case may add.
type exceptIDs struct {
	mine   []string
	theirs string
	fresh  string
}

// seedExcept creates three sessions of testUser and one of otherUser.
func seedExcept(t *testing.T, m *session.Manager) exceptIDs {
	t.Helper()

	var ids exceptIDs
	for range 3 {
		s, err := m.Create(t.Context(), testUser)
		require.NoError(t, err)
		ids.mine = append(ids.mine, s.ID)
	}
	s, err := m.Create(t.Context(), otherUser)
	require.NoError(t, err)
	ids.theirs = s.ID

	return ids
}

// assertLoads asserts every session in ids still loads.
func assertLoads(t *testing.T, m *session.Manager, ids ...string) {
	t.Helper()

	for _, id := range ids {
		_, err := m.Load(t.Context(), id)
		assert.NoError(t, err, "a session that should have been kept does not load")
	}
}

// assertGone asserts no session in ids is stored any longer, expired or not.
func assertGone(t *testing.T, m *session.Manager, ids ...string) {
	t.Helper()

	for _, id := range ids {
		_, err := m.Load(t.Context(), id)
		assert.ErrorIs(t, err, session.ErrSessionNotFound, "a session that should have been deleted is still stored")
	}
}

func TestEndingFederatedSessions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		call   func(t *testing.T, m *session.Manager) (int, error)
		assert func(t *testing.T, removed int, err error, m *session.Manager, ids federatedIDs)
	}

	cases := []testCase{
		{
			name: "deleting by provider session is scoped to one issuer",
			call: func(t *testing.T, m *session.Manager) (int, error) {
				t.Helper()

				return m.DeleteByExternalSession(t.Context(), "https://a", "s-1")
			},
			assert: func(t *testing.T, removed int, err error, m *session.Manager, ids federatedIDs) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)

				_, err = m.Load(t.Context(), ids.issuerASession1)
				require.ErrorIs(t, err, session.ErrSessionNotFound)
				_, err = m.Load(t.Context(), ids.issuerBSession1)
				require.NoError(t, err, "one provider's logout ended a session established at another")
			},
		},
		{
			name: "an empty issuer deletes nothing and is not an error",
			call: func(t *testing.T, m *session.Manager) (int, error) {
				t.Helper()

				return m.DeleteByExternalSession(t.Context(), "", "s-1")
			},
			assert: func(t *testing.T, removed int, err error, m *session.Manager, ids federatedIDs) {
				require.NoError(t, err)
				assert.Zero(t, removed, "an empty issuer matched sessions, so any provider could end any other's")

				_, err = m.Load(t.Context(), ids.issuerASession1)
				require.NoError(t, err)
			},
		},
		{
			// Unguarded, this is the row that sweeps every password session:
			// they carry an empty issuer and an empty provider session
			// identifier, so an unguarded match would find all of them.
			name: "an empty issuer and an empty session identifier delete nothing",
			call: func(t *testing.T, m *session.Manager) (int, error) {
				t.Helper()

				return m.DeleteByExternalSession(t.Context(), "", "")
			},
			assert: func(t *testing.T, removed int, err error, m *session.Manager, ids federatedIDs) {
				require.NoError(t, err)
				assert.Zero(t, removed, "an empty issuer and session identifier swept the password sessions")

				_, err = m.Load(t.Context(), ids.password)
				require.NoError(t, err)
			},
		},
		{
			name: "an empty provider session identifier deletes nothing and is not an error",
			call: func(t *testing.T, m *session.Manager) (int, error) {
				t.Helper()

				return m.DeleteByExternalSession(t.Context(), "https://a", "")
			},
			assert: func(t *testing.T, removed int, err error, m *session.Manager, ids federatedIDs) {
				require.NoError(t, err)
				assert.Zero(t, removed,
					"an empty provider session identifier matched the sessions that recorded none")

				_, err = m.Load(t.Context(), ids.issuerANoSession)
				require.NoError(t, err)
			},
		},
		{
			name: "deleting by user and issuer spares that user's password sessions",
			call: func(t *testing.T, m *session.Manager) (int, error) {
				t.Helper()

				return m.DeleteByUserAndExternalIssuer(t.Context(), testUser, "https://a")
			},
			assert: func(t *testing.T, removed int, err error, m *session.Manager, ids federatedIDs) {
				require.NoError(t, err)
				assert.Equal(t, 2, removed)

				_, err = m.Load(t.Context(), ids.password)
				require.NoError(t, err, "a password session was ended by a federated logout")
				_, err = m.Load(t.Context(), ids.otherUserIssuerA)
				require.NoError(t, err, "another user's session at the same issuer was ended")
				_, err = m.Load(t.Context(), ids.issuerASession1)
				require.ErrorIs(t, err, session.ErrSessionNotFound)
			},
		},
		{
			name: "deleting by user and an empty issuer deletes nothing and is not an error",
			call: func(t *testing.T, m *session.Manager) (int, error) {
				t.Helper()

				return m.DeleteByUserAndExternalIssuer(t.Context(), testUser, "")
			},
			assert: func(t *testing.T, removed int, err error, m *session.Manager, ids federatedIDs) {
				require.NoError(t, err)
				assert.Zero(t, removed, "an empty issuer ended a user's password sessions")

				_, err = m.Load(t.Context(), ids.password)
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			m, _ := managerOnClock(t, clk)
			ids := seedFederated(t, m)

			removed, err := tc.call(t, m)
			tc.assert(t, removed, err, m, ids)
		})
	}
}

// federatedIDs names the sessions seedFederated creates, so a case can say
// which one it expects to survive.
type federatedIDs struct {
	issuerASession1  string
	issuerBSession1  string
	issuerANoSession string
	password         string
	otherUserIssuerA string
}

// seedFederated creates one session per shape the federated deletes have to
// tell apart.
func seedFederated(t *testing.T, m *session.Manager) federatedIDs {
	t.Helper()

	ctx := t.Context()
	create := func(user identity.UserID, opts ...session.CreateOption) string {
		t.Helper()

		s, err := m.Create(ctx, user, opts...)
		require.NoError(t, err)

		return s.ID
	}

	return federatedIDs{
		issuerASession1:  create(testUser, session.WithExternalSession("okta", "https://a", "s-1", "tok-a")),
		issuerBSession1:  create(testUser, session.WithExternalSession("entra", "https://b", "s-1", "tok-b")),
		issuerANoSession: create(testUser, session.WithExternalSession("okta", "https://a", "", "tok-c")),
		password:         create(testUser),
		otherUserIssuerA: create(otherUser, session.WithExternalSession("okta", "https://a", "s-9", "tok-d")),
	}
}
