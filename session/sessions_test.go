package session_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
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
		require.ErrorIs(t, err, session.ErrNotFound)
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
			require.ErrorIs(t, err, session.ErrNotFound, "a session of the deleted user still loads")
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
		prepare func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock, ids exceptIDs) exceptIDs
		keep    func(ids exceptIDs) string
		assert  func(t *testing.T, removed int, err error, m *session.Sessions, ids exceptIDs)
	}

	cases := []testCase{
		{
			name: "the kept session stays and the user's others go",
			keep: func(ids exceptIDs) string { return ids.mine[0] },
			assert: func(t *testing.T, removed int, err error, m *session.Sessions, ids exceptIDs) {
				require.NoError(t, err)
				assert.Equal(t, 2, removed)
				assertLoads(t, m, ids.mine[0], ids.theirs)
				assertGone(t, m, ids.mine[1:]...)
			},
		},
		{
			name: "a kept session of another user is untouched and every session of the user goes",
			keep: func(ids exceptIDs) string { return ids.theirs },
			assert: func(t *testing.T, removed int, err error, m *session.Sessions, ids exceptIDs) {
				require.NoError(t, err)
				assert.Equal(t, 3, removed)
				assertLoads(t, m, ids.theirs)
				assertGone(t, m, ids.mine...)
			},
		},
		{
			name: "a kept identifier no session holds deletes every session of the user",
			keep: func(exceptIDs) string { return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
			assert: func(t *testing.T, removed int, err error, m *session.Sessions, ids exceptIDs) {
				require.NoError(t, err)
				assert.Equal(t, 3, removed)
				assertLoads(t, m, ids.theirs)
				assertGone(t, m, ids.mine...)
			},
		},
		{
			name: "an empty kept identifier deletes every session of the user",
			keep: func(exceptIDs) string { return "" },
			assert: func(t *testing.T, removed int, err error, m *session.Sessions, ids exceptIDs) {
				require.NoError(t, err)
				assert.Equal(t, 3, removed, "an empty kept identifier was a no-op")
				assertLoads(t, m, ids.theirs)
				assertGone(t, m, ids.mine...)
			},
		},
		{
			name:    "named by a superseded session inside its window keeps it and its successor",
			prepare: renewFirstSession,
			keep:    func(ids exceptIDs) string { return ids.mine[0] },
			assert: func(t *testing.T, removed int, err error, m *session.Sessions, ids exceptIDs) {
				require.NoError(t, err)
				assert.Equal(t, 2, removed, "only the two unrelated sessions of the user go")
				assertLoads(t, m, ids.mine[0], ids.fresh, ids.theirs)
				assertGone(t, m, ids.mine[1:]...)
			},
		},
		{
			name:    "named by the successor ends the superseded session of its family",
			prepare: renewFirstSession,
			keep:    func(ids exceptIDs) string { return ids.fresh },
			assert: func(t *testing.T, removed int, err error, m *session.Sessions, ids exceptIDs) {
				require.NoError(t, err)
				assert.Equal(t, 3, removed, "the superseded session and the two unrelated sessions go")
				assertLoads(t, m, ids.fresh, ids.theirs)
				assertGone(t, m, ids.mine...)
			},
		},
		{
			name: "expired sessions of the user are deleted and counted",
			prepare: func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock, ids exceptIDs) exceptIDs {
				t.Helper()

				// The seeded sessions idle out; a fresh one is created to keep.
				clk.Advance(createdAt.Add(time.Hour).Sub(clk.Now()))
				fresh, err := m.Create(t.Context(), testUser)
				require.NoError(t, err)
				ids.fresh = fresh.ID

				return ids
			},
			keep: func(ids exceptIDs) string { return ids.fresh },
			assert: func(t *testing.T, removed int, err error, m *session.Sessions, ids exceptIDs) {
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
func seedExcept(t *testing.T, m *session.Sessions) exceptIDs {
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

// renewFirstSession renews the first seeded session with a grace window, so
// the family holds it superseded and its successor live; the successor's
// identifier goes in ids.fresh.
func renewFirstSession(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock, ids exceptIDs) exceptIDs {
	t.Helper()

	first, err := m.Load(t.Context(), ids.mine[0])
	require.NoError(t, err)
	successor, _, err := m.RotateWithGrace(t.Context(), first, 30*time.Second)
	require.NoError(t, err)
	ids.fresh = successor.ID

	return ids
}

// assertLoads asserts every session in ids still loads.
func assertLoads(t *testing.T, m *session.Sessions, ids ...string) {
	t.Helper()

	for _, id := range ids {
		_, err := m.Load(t.Context(), id)
		assert.NoError(t, err, "a session that should have been kept does not load")
	}
}

// assertGone asserts no session in ids is stored any longer, expired or not.
func assertGone(t *testing.T, m *session.Sessions, ids ...string) {
	t.Helper()

	for _, id := range ids {
		_, err := m.Load(t.Context(), id)
		assert.ErrorIs(t, err, session.ErrNotFound, "a session that should have been deleted is still stored")
	}
}

func TestEndingFederatedSessions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		call   func(t *testing.T, m *session.Sessions) (int, error)
		assert func(t *testing.T, removed int, err error, m *session.Sessions, ids federatedIDs)
	}

	cases := []testCase{
		{
			name: "deleting by provider session is scoped to one issuer",
			call: func(t *testing.T, m *session.Sessions) (int, error) {
				t.Helper()

				return m.DeleteByExternalSession(t.Context(), "https://a", "s-1")
			},
			assert: func(t *testing.T, removed int, err error, m *session.Sessions, ids federatedIDs) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)

				_, err = m.Load(t.Context(), ids.issuerASession1)
				require.ErrorIs(t, err, session.ErrNotFound)
				_, err = m.Load(t.Context(), ids.issuerBSession1)
				require.NoError(t, err, "one provider's logout ended a session established at another")
			},
		},
		{
			name: "an empty issuer deletes nothing and is not an error",
			call: func(t *testing.T, m *session.Sessions) (int, error) {
				t.Helper()

				return m.DeleteByExternalSession(t.Context(), "", "s-1")
			},
			assert: func(t *testing.T, removed int, err error, m *session.Sessions, ids federatedIDs) {
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
			call: func(t *testing.T, m *session.Sessions) (int, error) {
				t.Helper()

				return m.DeleteByExternalSession(t.Context(), "", "")
			},
			assert: func(t *testing.T, removed int, err error, m *session.Sessions, ids federatedIDs) {
				require.NoError(t, err)
				assert.Zero(t, removed, "an empty issuer and session identifier swept the password sessions")

				_, err = m.Load(t.Context(), ids.password)
				require.NoError(t, err)
			},
		},
		{
			name: "an empty provider session identifier deletes nothing and is not an error",
			call: func(t *testing.T, m *session.Sessions) (int, error) {
				t.Helper()

				return m.DeleteByExternalSession(t.Context(), "https://a", "")
			},
			assert: func(t *testing.T, removed int, err error, m *session.Sessions, ids federatedIDs) {
				require.NoError(t, err)
				assert.Zero(t, removed,
					"an empty provider session identifier matched the sessions that recorded none")

				_, err = m.Load(t.Context(), ids.issuerANoSession)
				require.NoError(t, err)
			},
		},
		{
			name: "deleting by user and issuer spares that user's password sessions",
			call: func(t *testing.T, m *session.Sessions) (int, error) {
				t.Helper()

				return m.DeleteByUserAndExternalIssuer(t.Context(), testUser, "https://a")
			},
			assert: func(t *testing.T, removed int, err error, m *session.Sessions, ids federatedIDs) {
				require.NoError(t, err)
				assert.Equal(t, 2, removed)

				_, err = m.Load(t.Context(), ids.password)
				require.NoError(t, err, "a password session was ended by a federated logout")
				_, err = m.Load(t.Context(), ids.otherUserIssuerA)
				require.NoError(t, err, "another user's session at the same issuer was ended")
				_, err = m.Load(t.Context(), ids.issuerASession1)
				require.ErrorIs(t, err, session.ErrNotFound)
			},
		},
		{
			name: "deleting by user and an empty issuer deletes nothing and is not an error",
			call: func(t *testing.T, m *session.Sessions) (int, error) {
				t.Helper()

				return m.DeleteByUserAndExternalIssuer(t.Context(), testUser, "")
			},
			assert: func(t *testing.T, removed int, err error, m *session.Sessions, ids federatedIDs) {
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
func seedFederated(t *testing.T, m *session.Sessions) federatedIDs {
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

// configError is the assertion every wiring mistake shares: construction
// fails, it fails as a configuration error, and nothing usable comes back.
func configError(t *testing.T, m *session.Sessions, err error) {
	t.Helper()

	require.ErrorIs(t, err, session.ErrConfig)
	assert.Nil(t, m, "a manager came back alongside a configuration error")
}

func TestManagerLogger(t *testing.T) {
	t.Parallel()

	t.Run("a supplied logger receives this component's records", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

		_, err := session.New(session.WithLogger(logger))
		require.NoError(t, err)

		// The stated limit of the default store, said out loud once: behind a
		// second replica, every other request looks logged out.
		assert.Contains(t, buf.String(), "in-memory store",
			"the supplied logger received nothing, so the per-process limit is never said out loud")
	})

	t.Run("a consumer store is not warned about", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

		_, err := session.New(
			session.WithStore(session.NewMemoryStore()),
			session.WithLogger(logger))
		require.NoError(t, err)

		assert.Empty(t, buf.String(), "a consumer who supplied their own store was warned about the default")
	})

	t.Run("a nil logger constructs and logs nowhere in particular", func(t *testing.T) {
		t.Parallel()

		// Refusing a nil logger would make logging mandatory; ignoring it
		// leaves the caller on slog.Default(), which is what "do not
		// configure this" reasonably means.
		m, err := session.New(session.WithLogger(nil))
		require.NoError(t, err)
		require.NotNil(t, m)

		_, err = m.Create(t.Context(), testUser)
		assert.NoError(t, err, "a nil logger reached a log call")
	})
}

func TestConsumerStoreServesEveryOperation(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	store := NewMockStore(ctrl)

	live := storedSession("consumer-store")
	store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil).Times(1)
	store.EXPECT().Load(gomock.Any(), "consumer-store").Return(live, nil).Times(1)
	store.EXPECT().MarkPresented(gomock.Any(), "consumer-store", createdAt).Return(nil).Times(1)
	store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(nil).Times(1)
	store.EXPECT().Delete(gomock.Any(), "consumer-store").Return(nil).Times(1)
	store.EXPECT().DeleteByUser(gomock.Any(), testUser).Return(nil).Times(1)
	store.EXPECT().DeleteByUserExcept(gomock.Any(), testUser, "consumer-store").Return(6, nil).Times(1)
	store.EXPECT().CountActiveByUser(gomock.Any(), testUser).Return(4, nil).Times(1)
	store.EXPECT().DeleteExpired(gomock.Any()).Return(5, nil).Times(1)
	store.EXPECT().DeleteByExternalSession(gomock.Any(), "https://a", "s-1").Return(1, nil).Times(1)
	store.EXPECT().DeleteByUserAndExternalIssuer(gomock.Any(), testUser, "https://a").Return(2, nil).Times(1)

	clk := clockwork.NewFakeClockAt(createdAt)
	m := managerFor(t, session.WithStore(store), session.WithClock(clk))
	ctx := t.Context()

	_, err := m.Create(ctx, testUser)
	require.NoError(t, err)

	loaded, err := m.Load(ctx, "consumer-store")
	require.NoError(t, err)
	require.NoError(t, m.Save(ctx, loaded))
	require.NoError(t, m.Delete(ctx, "consumer-store"))
	require.NoError(t, m.DeleteByUser(ctx, testUser))

	n, err := m.DeleteByUserExcept(ctx, testUser, "consumer-store")
	require.NoError(t, err)
	assert.Equal(t, 6, n)

	n, err = m.CountActiveByUser(ctx, testUser)
	require.NoError(t, err)
	assert.Equal(t, 4, n)

	n, err = m.DeleteExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, 5, n)

	n, err = m.DeleteByExternalSession(ctx, "https://a", "s-1")
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	n, err = m.DeleteByUserAndExternalIssuer(ctx, testUser, "https://a")
	require.NoError(t, err)
	assert.Equal(t, 2, n)
}

func TestNewManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.Option
		assert func(t *testing.T, m *session.Sessions, err error)
	}

	cases := []testCase{
		{
			name: "defaults to an in-memory store, 30m idle and 12h absolute",
			assert: func(t *testing.T, m *session.Sessions, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
				assert.Equal(t, 30*time.Minute, m.IdleTimeout())
				assert.Equal(t, 12*time.Hour, m.AbsoluteTimeout())
			},
		},
		{
			name: "consumer timeouts replace the defaults",
			opts: []session.Option{
				session.WithIdleTimeout(5 * time.Minute),
				session.WithAbsoluteTimeout(time.Hour),
			},
			assert: func(t *testing.T, m *session.Sessions, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
				assert.Equal(t, 5*time.Minute, m.IdleTimeout())
				assert.Equal(t, time.Hour, m.AbsoluteTimeout())
			},
		},
		{
			name:   "a zero idle timeout is refused, because it expires every session on creation",
			opts:   []session.Option{session.WithIdleTimeout(0)},
			assert: configError,
		},
		{
			name:   "a negative idle timeout is refused",
			opts:   []session.Option{session.WithIdleTimeout(-time.Second)},
			assert: configError,
		},
		{
			name:   "a zero absolute timeout is refused",
			opts:   []session.Option{session.WithAbsoluteTimeout(0)},
			assert: configError,
		},
		{
			name:   "a negative absolute timeout is refused",
			opts:   []session.Option{session.WithAbsoluteTimeout(-time.Second)},
			assert: configError,
		},
		{
			name:   "a nil store is refused rather than silently kept in memory",
			opts:   []session.Option{session.WithStore(nil)},
			assert: configError,
		},
		{
			// The asymmetry with the logger below is deliberate: a caller
			// passing a clock meant to inject one, and the wall clock would
			// make a test that never advances look like one that does.
			name:   "a nil clock is refused",
			opts:   []session.Option{session.WithClock(nil)},
			assert: configError,
		},
		{
			// time-source "Nil time source", typed nil included: a nil
			// pointer inside the interface would otherwise pass construction
			// and panic, or read nonsense, at the first Create.
			name:   "a typed-nil clock is refused like an untyped one",
			opts:   []session.Option{session.WithClock((*nilClock)(nil))},
			assert: configError,
		},
		{
			name: "a consumer clock with only Now is accepted",
			opts: []session.Option{session.WithClock(fixedClock{at: createdAt})},
			assert: func(t *testing.T, m *session.Sessions, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			},
		},
		{
			name:   "a nil random source is refused",
			opts:   []session.Option{session.WithRandom(nil)},
			assert: configError,
		},
		{
			// A nil logger has an obvious safe reading — do not log from this
			// component — and refusing it would make logging mandatory.
			name: "a nil logger is ignored rather than refused",
			opts: []session.Option{session.WithLogger(nil)},
			assert: func(t *testing.T, m *session.Sessions, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name: "max absolute lifetime below the timeout is refused",
			opts: []session.Option{session.WithMaxAbsoluteLifetime(time.Hour)},
			assert: func(t *testing.T, _ *session.Sessions, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := session.New(tc.opts...)
			tc.assert(t, m, err)
		})
	}
}

func TestCreateWritesEverythingInOneWrite(t *testing.T) {
	t.Parallel()

	t.Run("the first factor and the external session are in the creating write", func(t *testing.T) {
		t.Parallel()

		store := NewMockStore(gomock.NewController(t))
		// Exactly one write, and no EXPECT for Save: a second write is the
		// failure this pins. A crash between two writes would leave a live
		// session that had forgotten how it was established.
		store.EXPECT().Create(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, s *session.Session) error {
				assert.Equal(t, factor.Password, s.FirstFactor,
					"the first factor was applied after the create write, so a crash could lose it")
				assert.Equal(t, "okta", s.ExternalProvider)
				assert.Equal(t, "https://a", s.ExternalIssuer)
				assert.Equal(t, "s-1", s.ExternalSessionID)
				assert.Equal(t, "raw-id-token", s.ExternalIDToken)

				return nil
			}).
			Times(1)

		m := managerFor(t, session.WithStore(store))

		s, err := m.Create(t.Context(), testUser,
			session.WithFirstFactor(factor.Password),
			session.WithExternalSession("okta", "https://a", "s-1", "raw-id-token"))
		require.NoError(t, err)
		assert.Equal(t, factor.Password, s.FirstFactor)
	})

	t.Run("a session created without a first factor reports none", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, _ := managerOnClock(t, clk)

		s, err := m.Create(t.Context(), testUser)
		require.NoError(t, err)

		loaded, err := m.Load(t.Context(), s.ID)
		require.NoError(t, err)
		assert.Empty(t, loaded.FirstFactor, "a first factor appeared that no caller recorded")
		assert.Empty(t, loaded.ExternalIssuer)
	})

	t.Run("the deadlines are set from the manager's clock and timeouts", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, _ := managerOnClock(t, clk)

		s, err := m.Create(t.Context(), testUser)
		require.NoError(t, err)

		assert.Equal(t, createdAt, s.CreatedAt)
		assert.Equal(t, createdAt, s.LastAccessedAt)
		assert.Equal(t, createdAt.Add(30*time.Minute), s.IdleExpiresAt)
		assert.Equal(t, createdAt.Add(12*time.Hour), s.AbsoluteExpiresAt)
	})
}

// TestCreate_AuthenticationTime pins that a sign-in records when the user
// authenticated, and that a consumer's create option may still choose it.
func TestCreate_AuthenticationTime(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.CreateOption
		assert func(t *testing.T, created, loaded *session.Session)
	}

	cases := []testCase{
		{
			name: "a sign-in records its authentication time",
			assert: func(t *testing.T, created, loaded *session.Session) {
				assert.Equal(t, createdAt, created.AuthenticatedAt)
				assert.True(t, loaded.AuthenticatedAt.Equal(createdAt), "the store holds the authentication time")
			},
		},
		{
			name: "a consumer create option may set another authentication time",
			opts: []session.CreateOption{func(s *session.Session) {
				s.AuthenticatedAt = createdAt.Add(-5 * time.Minute)
			}},
			assert: func(t *testing.T, created, loaded *session.Session) {
				assert.Equal(t, createdAt.Add(-5*time.Minute), created.AuthenticatedAt)
				assert.True(t, loaded.AuthenticatedAt.Equal(createdAt.Add(-5*time.Minute)))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			m, _ := managerOnClock(t, clk)

			s, err := m.Create(t.Context(), testUser, tc.opts...)
			require.NoError(t, err)

			loaded, err := m.Load(t.Context(), s.ID)
			require.NoError(t, err)
			tc.assert(t, s, loaded)
		})
	}
}

func TestCreate_AbsoluteLifetime(t *testing.T) {
	t.Parallel()

	const thirtyDays = 30 * 24 * time.Hour

	type testCase struct {
		name   string
		opts   []session.Option
		create []session.CreateOption
		assert func(t *testing.T, s *session.Session, err error, stored int)
	}

	cases := []testCase{
		{
			name: "no option keeps the absolute timeout",
			assert: func(t *testing.T, s *session.Session, err error, _ int) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(12*time.Hour), s.AbsoluteExpiresAt)
			},
		},
		{
			name:   "the default maximum refuses a longer lifetime and stores nothing",
			create: []session.CreateOption{session.WithAbsoluteLifetime(thirtyDays)},
			assert: func(t *testing.T, s *session.Session, err error, stored int) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, s)
				assert.Zero(t, stored, "a refused lifetime still reached the store")
			},
		},
		{
			name:   "a lifetime up to the maximum is honoured",
			opts:   []session.Option{session.WithMaxAbsoluteLifetime(thirtyDays)},
			create: []session.CreateOption{session.WithAbsoluteLifetime(thirtyDays)},
			assert: func(t *testing.T, s *session.Session, err error, stored int) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(thirtyDays), s.AbsoluteExpiresAt)
				assert.Equal(t, createdAt.Add(30*time.Minute), s.IdleExpiresAt)
				assert.Equal(t, 1, stored)
			},
		},
		{
			name:   "a lifetime above the maximum is refused, not shortened",
			opts:   []session.Option{session.WithMaxAbsoluteLifetime(thirtyDays)},
			create: []session.CreateOption{session.WithAbsoluteLifetime(thirtyDays + time.Second)},
			assert: func(t *testing.T, s *session.Session, err error, stored int) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, s)
				assert.Zero(t, stored)
			},
		},
		{
			name:   "a zero lifetime is refused",
			create: []session.CreateOption{session.WithAbsoluteLifetime(0)},
			assert: func(t *testing.T, _ *session.Session, err error, stored int) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Zero(t, stored)
			},
		},
		{
			name:   "a negative lifetime is refused",
			create: []session.CreateOption{session.WithAbsoluteLifetime(-time.Hour)},
			assert: func(t *testing.T, _ *session.Session, err error, stored int) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Zero(t, stored)
			},
		},
		{
			name:   "a lifetime shorter than the idle timeout caps the idle deadline",
			create: []session.CreateOption{session.WithAbsoluteLifetime(10 * time.Minute)},
			assert: func(t *testing.T, s *session.Session, err error, _ int) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(10*time.Minute), s.AbsoluteExpiresAt)
				assert.Equal(t, createdAt.Add(10*time.Minute), s.IdleExpiresAt)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			ctrl := gomock.NewController(t)
			store := NewMockStore(ctrl)
			var stored int
			store.EXPECT().Create(gomock.Any(), gomock.Any()).
				DoAndReturn(func(context.Context, *session.Session) error { stored++; return nil }).
				AnyTimes()
			m := managerFor(t, append([]session.Option{session.WithStore(store), session.WithClock(clk)}, tc.opts...)...)

			s, err := m.Create(t.Context(), testUser, tc.create...)

			tc.assert(t, s, err, stored)
		})
	}
}

func TestManagerLoad(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// at is when the load happens, relative to the session's creation.
		at time.Duration
		// id, when non-empty, is loaded instead of the created session's.
		id     string
		opts   []session.Option
		assert func(t *testing.T, s *session.Session, err error)
	}

	cases := []testCase{
		{
			name: "a live session loads",
			at:   10 * time.Minute,
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				require.NotNil(t, s)
				assert.Equal(t, testUser, s.UserID)
			},
		},
		{
			name: "an identifier that was never issued is not found",
			id:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			assert: func(t *testing.T, s *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrNotFound)
				assert.Nil(t, s)
			},
		},
		{
			// 09:00 + 30m idle, loaded at 09:31 without activity.
			name: "a session past its idle deadline is expired, not missing",
			at:   31 * time.Minute,
			assert: func(t *testing.T, s *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
				assert.NotErrorIs(t, err, session.ErrNotFound,
					"an expired session was reported as one that never existed, so the caller cannot tell 'log in again' from 'no such session'")
				assert.Nil(t, s, "an expired session was served")
			},
		},
		{
			// The idle deadline is still ahead; only the absolute one has
			// passed, so this row fails unless both are enforced.
			name: "a session past its absolute deadline is expired",
			at:   13 * time.Hour,
			opts: []session.Option{session.WithIdleTimeout(24 * time.Hour)},
			assert: func(t *testing.T, s *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
				assert.Nil(t, s, "an expired session was served")
			},
		},
		{
			// A deadline is the first moment the session is no longer valid,
			// not the last moment it is.
			name: "a session exactly at its idle deadline is expired",
			at:   30 * time.Minute,
			assert: func(t *testing.T, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			m, _ := managerOnClock(t, clk, tc.opts...)

			created, err := m.Create(t.Context(), testUser)
			require.NoError(t, err)

			id := created.ID
			if tc.id != "" {
				id = tc.id
			}
			clk.Advance(createdAt.Add(tc.at).Sub(clk.Now()))

			loaded, err := m.Load(t.Context(), id)
			tc.assert(t, loaded, err)
		})
	}
}

// every returns the moments step, 2*step, ... up to and including last, for a
// case that keeps a session alive by using it.
func every(step, last time.Duration) []time.Duration {
	var moments []time.Duration
	for at := step; at <= last; at += step {
		moments = append(moments, at)
	}

	return moments
}

func TestManagerTouch(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// activity is every moment activity is recorded, relative to creation
		// at 09:00. The assertion sees the result of the last one.
		activity []time.Duration
		opts     []session.Option
		assert   func(t *testing.T, s *session.Session, err error)
	}

	cases := []testCase{
		{
			// 09:00 + 30m idle, activity at 09:20 → 09:50.
			name:     "activity moves the idle deadline to now plus the idle timeout",
			activity: []time.Duration{20 * time.Minute},
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(50*time.Minute), s.IdleExpiresAt)
				assert.Equal(t, createdAt.Add(20*time.Minute), s.LastAccessedAt)
			},
		},
		{
			// A session in constant use: activity every 20 minutes keeps it
			// alive to 20:50, where the absolute deadline is 21:00 and an
			// unclamped 30-minute extension would reach 21:20.
			name:     "the idle deadline never moves past the absolute one",
			activity: every(20*time.Minute, 11*time.Hour+50*time.Minute),
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, s.AbsoluteExpiresAt, s.IdleExpiresAt,
					"the idle deadline was allowed past the absolute one, so a session in constant use never ends")
				assert.Equal(t, createdAt.Add(12*time.Hour), s.IdleExpiresAt)
			},
		},
		{
			name:     "activity on a session past its idle deadline is refused",
			activity: []time.Duration{31 * time.Minute},
			assert: func(t *testing.T, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
			},
		},
		{
			name:     "activity on a session past its absolute deadline is refused",
			activity: []time.Duration{13 * time.Hour},
			opts:     []session.Option{session.WithIdleTimeout(24 * time.Hour)},
			assert: func(t *testing.T, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			m, _ := managerOnClock(t, clk, tc.opts...)

			s, err := m.Create(t.Context(), testUser)
			require.NoError(t, err)

			for _, at := range tc.activity {
				clk.Advance(createdAt.Add(at).Sub(clk.Now()))
				err = m.Touch(t.Context(), s)
			}
			tc.assert(t, s, err)
		})
	}

	t.Run("an unknown session is not found", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, _ := managerOnClock(t, clk)
		// Created through another manager, so the first one's store never held it.
		elsewhere, _ := managerOnClock(t, clk)
		stranger, err := elsewhere.Create(t.Context(), testUser)
		require.NoError(t, err)

		clk.Advance(10 * time.Minute)
		err = m.Touch(t.Context(), stranger)

		require.ErrorIs(t, err, session.ErrNotFound)
	})

	t.Run("the extension is persisted, not only applied in memory", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		m, _ := managerOnClock(t, clk)

		s, err := m.Create(t.Context(), testUser)
		require.NoError(t, err)

		clk.Advance(createdAt.Add(20 * time.Minute).Sub(clk.Now()))
		require.NoError(t, m.Touch(t.Context(), s))

		// Past the original 09:30 deadline: this loads only because the
		// extension reached the store.
		clk.Advance(createdAt.Add(40 * time.Minute).Sub(clk.Now()))
		loaded, err := m.Load(t.Context(), s.ID)
		require.NoError(t, err)
		assert.Equal(t, createdAt.Add(50*time.Minute), loaded.IdleExpiresAt)
	})
}

func TestTouch_Interval(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		interval time.Duration
		// elapsed is how long after creation Touch is called.
		elapsed time.Duration
		// expect sets the mock store's expectations for the Touch call.
		expect func(store *MockStore, id string)
		assert func(t *testing.T, s *session.Session, err error)
	}

	cases := []testCase{
		{
			name:    "the default interval persists every touch",
			elapsed: 10 * time.Second,
			expect: func(store *MockStore, id string) {
				store.EXPECT().RecordActivity(gomock.Any(), id,
					createdAt.Add(10*time.Second),
					createdAt.Add(10*time.Second+30*time.Minute),
					createdAt.Add(10*time.Second)).Return(nil).Times(1)
			},
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(10*time.Second), s.LastAccessedAt)
				assert.Equal(t, createdAt.Add(10*time.Second+30*time.Minute), s.IdleExpiresAt)
			},
		},
		{
			name:     "a touch inside the interval writes nothing",
			interval: time.Minute,
			elapsed:  30 * time.Second,
			expect:   func(*MockStore, string) {},
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt, s.LastAccessedAt, "the in-memory session moved though nothing was written")
				assert.Equal(t, createdAt.Add(30*time.Minute), s.IdleExpiresAt)
			},
		},
		{
			name:     "a touch at the interval persists with the interval as the threshold",
			interval: time.Minute,
			elapsed:  time.Minute,
			expect: func(store *MockStore, id string) {
				store.EXPECT().RecordActivity(gomock.Any(), id,
					createdAt.Add(time.Minute),
					createdAt.Add(31*time.Minute),
					createdAt).Return(nil).Times(1)
			},
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(time.Minute), s.LastAccessedAt)
			},
		},
		{
			name:     "a store failure leaves the session in memory untouched",
			interval: time.Minute,
			elapsed:  2 * time.Minute,
			expect: func(store *MockStore, id string) {
				store.EXPECT().RecordActivity(gomock.Any(), id, gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errStoreWrite).Times(1)
			},
			assert: func(t *testing.T, s *session.Session, err error) {
				require.ErrorIs(t, err, errStoreWrite)
				assert.Equal(t, createdAt, s.LastAccessedAt, "memory ran ahead of the store")
				assert.Equal(t, createdAt.Add(30*time.Minute), s.IdleExpiresAt)
			},
		},
		{
			name:     "an expired session is refused whatever the interval",
			interval: time.Hour / 3,
			elapsed:  31 * time.Minute,
			expect:   func(*MockStore, string) {},
			assert: func(t *testing.T, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			store := NewMockStore(gomock.NewController(t))
			store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
			opts := []session.Option{session.WithStore(store), session.WithClock(clk)}
			if tc.interval != 0 {
				opts = append(opts, session.WithTouchInterval(tc.interval))
			}
			m := managerFor(t, opts...)

			s, err := m.Create(t.Context(), testUser)
			require.NoError(t, err)
			tc.expect(store, s.ID)

			clk.Advance(tc.elapsed)
			err = m.Touch(t.Context(), s)

			tc.assert(t, s, err)
		})
	}
}

// The default has no interval: every activity is written, so two touches ten
// seconds apart leave the stored deadline at the second one's. This runs on the
// memory store rather than the mock table above, because it asserts what the
// store holds afterwards.
// Standalone: it touches twice on a real store and reads the stored deadline back.
func TestTouch_DefaultWritesOnEveryActivity(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)

	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	clk.Advance(20 * time.Minute)
	require.NoError(t, m.Touch(t.Context(), s))
	clk.Advance(10 * time.Second)
	require.NoError(t, m.Touch(t.Context(), s))

	stored, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.Equal(t, createdAt.Add(20*time.Minute+10*time.Second+30*time.Minute), stored.IdleExpiresAt,
		"the second touch was not written")
	assert.Equal(t, createdAt.Add(20*time.Minute+10*time.Second), stored.LastAccessedAt)
}

// Skipping a write only ever brings expiry earlier: the stored deadline is
// the one from the last write, never a later one.
// Standalone: it touches twice under an interval and then loads past the deadline.
func TestTouch_SkippedWritesOnlyBringExpiryEarlier(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk, session.WithTouchInterval(time.Minute))

	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	require.NoError(t, m.Touch(t.Context(), s)) // 09:00, inside the interval of creation
	clk.Advance(50 * time.Second)
	require.NoError(t, m.Touch(t.Context(), s)) // 09:00:50, skipped

	clk.Advance(29*time.Minute + 10*time.Second) // 09:30:00
	_, err = m.Load(t.Context(), s.ID)

	require.ErrorIs(t, err, session.ErrExpired)
}

// A session superseded by a rotation takes no activity: the store refuses the
// write, so the touch cannot move its deadlines.
// Standalone: it supersedes the session through the store before the touch.
func TestTouch_SupersededSessionWritesNothing(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, store := managerOnClock(t, clk)

	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	successor := *s
	successor.ID = "successor-id"
	require.NoError(t, store.Supersede(t.Context(), session.Supersession{
		Old: s.ID, AcceptUntil: createdAt.Add(30 * time.Second), RetainUntil: s.AbsoluteExpiresAt,
		Successor: &successor, Now: createdAt,
	}))
	before, err := store.Load(t.Context(), s.ID)
	require.NoError(t, err)

	clk.Advance(10 * time.Second)
	require.NoError(t, m.Touch(t.Context(), s))

	after, err := store.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.Equal(t, before.LastAccessedAt, after.LastAccessedAt)
	assert.Equal(t, before.IdleExpiresAt, after.IdleExpiresAt)
}

// A touch exactly one interval after the last recorded activity writes: the
// manager and the store must agree that an age equal to the interval is old
// enough.
// Standalone: it advances the clock by exactly the interval before the touch.
func TestTouch_WritesExactlyOneIntervalAfterTheLastAccess(t *testing.T) {
	t.Parallel()

	const interval = time.Minute

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk, session.WithTouchInterval(interval))

	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	clk.Advance(interval)
	now := clk.Now()
	require.NoError(t, m.Touch(t.Context(), s))

	got, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.Equal(t, now, got.LastAccessedAt, "the store kept the write")
	assert.Equal(t, now.Add(30*time.Minute), got.IdleExpiresAt, "the idle deadline moved with it")
}

// A request that loaded a session before another request confined it must not
// undo the confinement when it records its own activity.
// Standalone: it touches a stale copy after another copy was confined and saved.
func TestTouch_KeepsAConcurrentlyLoweredDeadline(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)

	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	// Request A loads its copy.
	a, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)

	// Request B, on the same session, confines it to enrolment and saves.
	b, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	m.MarkEnrolmentPending(b, 15*time.Minute)
	require.NoError(t, m.Save(t.Context(), b))
	require.False(t, b.EnrolmentOriginDeadline.IsZero())

	// Request A finishes with its stale copy.
	clk.Advance(time.Minute)
	require.NoError(t, m.Touch(t.Context(), a))

	got, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.Equal(t, b.AbsoluteExpiresAt, got.AbsoluteExpiresAt, "absolute deadline")
	assert.Equal(t, b.EnrolmentOriginDeadline, got.EnrolmentOriginDeadline, "enrolment-origin marker")
	assert.Equal(t, session.MFAEnrolmentPending, got.MFA, "second-factor state")
}

// Standalone: it renews one sign-in three times before counting.
func TestCountActive_RenewedSignInCountsOnce(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)
	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	for range 3 {
		clk.Advance(time.Minute)
		s, _, err = m.RotateWithGrace(t.Context(), s, 30*time.Second)
		require.NoError(t, err)
	}
	clk.Advance(time.Minute) // every superseded window has ended

	n, err := m.CountActiveByUser(t.Context(), testUser)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "one sign-in renewed three times holds one live session")
}

// Standalone: it touches a stale copy after another copy was confined and saved.
func TestTouch_StaleCopyNeverLeavesIdleAfterAbsolute(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)
	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	stale, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	other, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	m.MarkEnrolmentPending(other, 15*time.Minute)
	require.NoError(t, m.Save(t.Context(), other))
	clk.Advance(time.Minute)

	require.NoError(t, m.Touch(t.Context(), stale))

	got, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.False(t, got.IdleExpiresAt.After(got.AbsoluteExpiresAt),
		"stored idle %s is after stored absolute %s", got.IdleExpiresAt, got.AbsoluteExpiresAt)
}

func TestSaveNeverRecreatesADeletedSession(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)
	ctx := t.Context()

	s, err := m.Create(ctx, testUser)
	require.NoError(t, err)

	// The revocation a concurrent request races: a logout, a forced sign-out,
	// an administrator ending a session.
	require.NoError(t, m.Delete(ctx, s.ID))

	// Touch is load-then-save: exactly the path a live request takes, and the
	// request holding this session has no way to know it was just revoked.
	require.ErrorIs(t, m.Touch(ctx, s), session.ErrNotFound,
		"recording activity on a revoked session succeeded, so it wrote the session back")

	_, err = m.Load(ctx, s.ID)
	require.ErrorIs(t, err, session.ErrNotFound,
		"a revoked session came back to life through Touch")
}

// failingWriteStore is a real store that takes the first insert — the case's
// own fixture — and refuses every later one, along with every supersession,
// which is the write a rotation makes before it deletes anything.
type failingWriteStore struct {
	session.Store

	inserts atomic.Int64
}

func (s *failingWriteStore) Create(ctx context.Context, sess *session.Session) error {
	if s.inserts.Add(1) == 1 {
		return s.Store.Create(ctx, sess)
	}

	return errStoreWrite
}

func (*failingWriteStore) Supersede(context.Context, session.Supersession) error {
	return errStoreWrite
}

// snapshot copies the caller-visible state of s, so a case can compare what
// rotation returned against what the session held before it ran.
func snapshot(s *session.Session) *session.Session {
	out := *s
	out.Data = maps.Clone(s.Data)

	return &out
}

// TestManagerRotate pins what rotation is for: a handle obtained before a
// privilege change stops working, the new one carries everything else, and a
// store that refuses the write leaves the caller exactly where they were.
func TestManagerRotate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  func(t *testing.T) session.Store
		assert func(t *testing.T, m *session.Sessions, old, got *session.Session, err error)
	}

	cases := []testCase{
		{
			name:  "the old handle stops loading and the new one carries everything",
			store: func(*testing.T) session.Store { return session.NewMemoryStore() },
			assert: func(t *testing.T, m *session.Sessions, old, got *session.Session, err error) {
				require.NoError(t, err)
				assert.NotEqual(t, old.ID, got.ID)
				assert.Equal(t, old.UserID, got.UserID)
				assert.Equal(t, old.FirstFactor, got.FirstFactor)
				assert.Equal(t, old.Data, got.Data)
				assert.True(t, got.AuthenticatedAt.Equal(old.AuthenticatedAt), "the authentication time is carried over")
				assert.True(t, got.AbsoluteExpiresAt.Equal(old.AbsoluteExpiresAt))

				_, loadErr := m.Load(t.Context(), old.ID)
				assert.ErrorIs(t, loadErr, session.ErrNotFound)

				reloaded, loadErr := m.Load(t.Context(), got.ID)
				require.NoError(t, loadErr)
				assert.Equal(t, old.UserID, reloaded.UserID)
				assert.Equal(t, old.Data, reloaded.Data)
			},
		},
		{
			name: "a failed write leaves the old handle loadable",
			store: func(*testing.T) session.Store {
				return &failingWriteStore{Store: session.NewMemoryStore()}
			},
			assert: func(t *testing.T, m *session.Sessions, old, got *session.Session, err error) {
				require.ErrorIs(t, err, errStoreWrite)
				assert.Nil(t, got)

				reloaded, loadErr := m.Load(t.Context(), old.ID)
				require.NoError(t, loadErr)
				assert.Equal(t, old.ID, reloaded.ID)
			},
		},
		{
			name:  "a handle already rotated away cannot be rotated again",
			store: func(*testing.T) session.Store { return session.NewMemoryStore() },
			assert: func(t *testing.T, m *session.Sessions, old, got *session.Session, err error) {
				require.NoError(t, err)
				require.NotNil(t, got)

				again, againErr := m.Rotate(t.Context(), old)
				require.ErrorIs(t, againErr, session.ErrNotFound)
				assert.Nil(t, again)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			m := managerFor(t, session.WithStore(tc.store(t)))
			old, err := m.Create(ctx, testUser, session.WithFirstFactor(factor.MagicLink))
			require.NoError(t, err)

			old.Data = map[string]string{"tenant": "acme"}
			require.NoError(t, m.Save(ctx, old))

			before := snapshot(old)

			got, err := m.Rotate(ctx, old)
			tc.assert(t, m, before, got, err)
		})
	}
}

// TestManagerRotateConcurrent pins that rotation cannot be made to hand out
// two live handles for one session by racing it: exactly one caller wins, and
// the handle they all started from is gone either way.
// Standalone: it rotates one session from many goroutines.
func TestManagerRotateConcurrent(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	m := managerFor(t)
	s, err := m.Create(ctx, testUser, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	const goroutines = 16

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		ids   []string
		start = make(chan struct{})
	)

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-start

			rotated, rotErr := m.Rotate(ctx, s)
			if rotErr == nil {
				mu.Lock()
				ids = append(ids, rotated.ID)
				mu.Unlock()
			}
		}()
	}

	close(start)
	wg.Wait()

	live := 0
	for _, id := range ids {
		if _, loadErr := m.Load(ctx, id); loadErr == nil {
			live++
		}
	}

	assert.Equal(t, 1, live, "exactly one rotated handle may remain loadable")

	_, err = m.Load(ctx, s.ID)
	assert.ErrorIs(t, err, session.ErrNotFound, "the original handle must not survive")
}

// barrierWait is how long a barrier insert waits for its fellows before it
// gives up. It is long enough that a machine under load still clears the
// barrier, and short enough that a rotation lock which serialises unrelated
// sessions reports a failure rather than hanging the package.
const barrierWait = 2 * time.Second

// errBarrierTimeout is what a barrier insert reports when the rotations it was
// waiting for never arrived, which is what a lock held across every session
// looks like from inside the store.
var errBarrierTimeout = errors.New("insert waited alone: rotations of distinct sessions were serialised")

// barrierStore holds every insert until want of them are in flight at once, so
// a test can tell rotations that genuinely overlap from rotations that merely
// take turns.
//
// It passes inserts straight through until arm is called, so a case can build
// its fixtures through the same manager.
type barrierStore struct {
	session.Store

	want int

	armed   atomic.Bool
	mu      sync.Mutex
	arrived int
	open    chan struct{}
}

func newBarrierStore(inner session.Store, want int) *barrierStore {
	return &barrierStore{Store: inner, want: want, open: make(chan struct{})}
}

func (s *barrierStore) arm() { s.armed.Store(true) }

func (s *barrierStore) Create(ctx context.Context, sess *session.Session) error {
	if !s.armed.Load() {
		return s.Store.Create(ctx, sess)
	}

	s.mu.Lock()
	s.arrived++
	if s.arrived == s.want {
		close(s.open)
	}
	s.mu.Unlock()

	select {
	case <-s.open:
		return s.Store.Create(ctx, sess)
	case <-time.After(barrierWait):
		return errBarrierTimeout
	}
}

// TestManagerRotateConcurrentDistinctSessions pins that the lock rotation
// takes follows the session and not the manager: two users completing a second
// factor at the same moment must not take turns, least of all across the three
// store round-trips a rotation makes.
// Standalone: it rotates many sessions from many goroutines.
func TestManagerRotateConcurrentDistinctSessions(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	const sessions = 8

	store := newBarrierStore(session.NewMemoryStore(), sessions)
	m := managerFor(t, session.WithStore(store))

	originals := make([]*session.Session, 0, sessions)
	for range sessions {
		s, err := m.Create(ctx, testUser, session.WithFirstFactor(factor.Password))
		require.NoError(t, err)
		originals = append(originals, s)
	}

	store.arm()

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)

	wg.Add(sessions)
	for _, s := range originals {
		go func() {
			defer wg.Done()

			_, rotErr := m.Rotate(ctx, s)

			mu.Lock()
			errs = append(errs, rotErr)
			mu.Unlock()
		}()
	}

	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err, "rotations of distinct sessions must overlap")
	}
}

// A caller may have restored the deadlines of the session it hands Rotate (as
// RestoreEnrolmentDeadlines does after an enrolment), so the successor carries
// the deadlines of the session it is given. Only the family fields come from
// storage.
// Standalone: it rotates a caller's copy whose deadlines and family differ from the stored record.
func TestRotate_CarriesTheDeadlinesOfTheSessionItIsGiven(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)

	// The stored session is confined: its absolute deadline is 09:15.
	stored, err := m.Create(t.Context(), testUser, session.WithAbsoluteLifetime(15*time.Minute))
	require.NoError(t, err)
	require.Equal(t, createdAt.Add(15*time.Minute), stored.AbsoluteExpiresAt)

	// The caller's copy has had its deadlines restored to 21:00, and carries a
	// family of its own that storage must override.
	restored := *stored
	restored.AbsoluteExpiresAt = createdAt.Add(12 * time.Hour)
	restored.IdleExpiresAt = createdAt.Add(12 * time.Hour)
	restored.FamilyID = id.MustParse("01926a4e-0000-7000-8000-0000000000bb")
	restored.FamilyCreatedAt = createdAt.Add(-time.Hour)

	clk.Advance(5 * time.Minute)
	successor, err := m.Rotate(t.Context(), &restored)

	require.NoError(t, err)
	assert.Equal(t, createdAt.Add(12*time.Hour), successor.AbsoluteExpiresAt,
		"the successor took the stored record's deadlines, not those of the session it was given")
	assert.Equal(t, createdAt.Add(12*time.Hour), successor.IdleExpiresAt)
	assert.Equal(t, stored.FamilyID, successor.FamilyID, "the family comes from storage")
	assert.Equal(t, stored.FamilyCreatedAt, successor.FamilyCreatedAt)
}

func newGate() *gate { return &gate{arrived: make(chan struct{}), open: make(chan struct{})} }

// gatedStore holds chosen calls once armed: the n-th armed Load (counted
// from 1) after it has read, and the first armed Delete before it deletes.
// Every other call passes straight through.
type gatedStore struct {
	*session.MemoryStore

	armed   atomic.Bool
	loads   atomic.Int32
	deletes atomic.Int32

	loadGates map[int32]*gate
	delete    *gate
}

func (s *gatedStore) Load(ctx context.Context, id string) (*session.Session, error) {
	got, err := s.MemoryStore.Load(ctx, id)
	if s.armed.Load() {
		if g, ok := s.loadGates[s.loads.Add(1)]; ok {
			g.pass()
		}
	}

	return got, err
}

func (s *gatedStore) Delete(ctx context.Context, id string) error {
	if s.armed.Load() && s.delete != nil && s.deletes.Add(1) == 1 {
		s.delete.pass()
	}

	return s.MemoryStore.Delete(ctx, id)
}

// rotations are the two racing calls' results.
type rotations struct {
	strict, grace       *session.Session
	strictErr, graceErr error
}

// TestRotate_RacingAGraceRotationLeavesOneLiveHead pins that a strict
// rotation (second-factor verification) and a grace rotation (renewal) of
// one session cannot both produce a successor, through one manager or two
// sharing a store. Whichever supersedes second is refused by the store's
// condition with ErrRenewalConflict and stores nothing; a grace
// rotation that reads the session only after the strict one superseded it
// finds it inside the in-flight window and re-rotates it, which knocks the
// strict successor out.
func TestRotate_RacingAGraceRotationLeavesOneLiveHead(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// managers is how many managers share the store; the strict
		// rotation runs on the first and the grace rotation on the last.
		managers int
		// drive runs the two rotations in one interleaving. strict and
		// grace start them; each returns a channel closed when it is done.
		drive  func(store *gatedStore, strict, grace func() <-chan struct{})
		gates  func(store *gatedStore)
		live   int
		assert func(t *testing.T, r rotations)
	}

	interleavings := []testCase{
		{
			name: "strict read first, grace superseded in between",
			gates: func(s *gatedStore) {
				s.loadGates = map[int32]*gate{1: newGate()}
			},
			drive: func(s *gatedStore, strict, grace func() <-chan struct{}) {
				strictDone := strict()
				<-s.loadGates[1].arrived
				<-grace()
				close(s.loadGates[1].open)
				<-strictDone
			},
			live: 1,
			assert: func(t *testing.T, r rotations) {
				require.NoError(t, r.graceErr)
				require.ErrorIs(t, r.strictErr, session.ErrRenewalConflict)
				assert.Nil(t, r.strict)
			},
		},
		{
			name: "grace read first, strict superseded in between",
			gates: func(s *gatedStore) {
				s.loadGates = map[int32]*gate{1: newGate()}
				s.delete = newGate()
			},
			drive: func(s *gatedStore, strict, grace func() <-chan struct{}) {
				graceDone := grace()
				<-s.loadGates[1].arrived
				strictDone := strict()
				<-s.delete.arrived
				close(s.loadGates[1].open)
				<-graceDone
				close(s.delete.open)
				<-strictDone
			},
			live: 1,
			assert: func(t *testing.T, r rotations) {
				require.NoError(t, r.strictErr)
				require.ErrorIs(t, r.graceErr, session.ErrRenewalConflict)
				assert.Nil(t, r.grace)
			},
		},
		{
			// The strict rotation's in-flight window is open, so the grace
			// rotation is a re-rotation: it knocks the strict successor out,
			// and the family keeps one live head.
			name: "grace read after strict superseded, before its delete",
			gates: func(s *gatedStore) {
				s.delete = newGate()
			},
			drive: func(s *gatedStore, strict, grace func() <-chan struct{}) {
				strictDone := strict()
				<-s.delete.arrived
				<-grace()
				close(s.delete.open)
				<-strictDone
			},
			live: 1,
			assert: func(t *testing.T, r rotations) {
				require.NoError(t, r.strictErr)
				require.NoError(t, r.graceErr)
				require.NotNil(t, r.grace)
			},
		},
	}

	var cases []testCase
	for _, managers := range []int{1, 2} {
		for _, tc := range interleavings {
			tc.managers = managers
			tc.name += map[int]string{1: ", one manager", 2: ", two managers sharing one store"}[managers]
			cases = append(cases, tc)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			inner := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
			store := &gatedStore{MemoryStore: inner}
			tc.gates(store)
			ms := make([]*session.Sessions, tc.managers)
			for i := range ms {
				ms[i] = managerFor(t, session.WithStore(store), session.WithClock(clk))
			}
			s, err := ms[0].Create(t.Context(), testUser)
			require.NoError(t, err)
			store.armed.Store(true)

			var r rotations
			strict := func() <-chan struct{} {
				done := make(chan struct{})
				go func() {
					defer close(done)
					r.strict, r.strictErr = ms[0].Rotate(t.Context(), s)
				}()

				return done
			}
			grace := func() <-chan struct{} {
				done := make(chan struct{})
				go func() {
					defer close(done)
					r.grace, _, r.graceErr = ms[tc.managers-1].RotateWithGrace(t.Context(), s, 30*time.Second)
				}()

				return done
			}
			tc.drive(store, strict, grace)

			live := 0
			for _, got := range []*session.Session{r.strict, r.grace} {
				if got == nil {
					continue
				}
				stored, loadErr := inner.Load(t.Context(), got.ID)
				if loadErr == nil && stored.SupersededAt.IsZero() {
					live++
				}
			}
			assert.Equal(t, tc.live, live, "live heads left in the family")
			tc.assert(t, r)
		})
	}
}

// inFlightFixture is a session still owing its second factor, the copy the
// verification endpoint rotates once the factor is satisfied, and what they
// run on.
type inFlightFixture struct {
	clk   *clockwork.FakeClock
	inner *session.MemoryStore
	store *inFlightStore
	m     *session.Sessions
	logs  *bytes.Buffer

	// pending is the stored session; satisfied is the caller's copy with the
	// second factor met, which is what Rotate is given.
	pending, satisfied *session.Session
}

// TestRotate_OldIdentifierInFlight pins that rotation at second-factor
// verification serves the old identifier only in flight: a request that
// loads it between the supersession and the delete gets the old session as it
// was, not a reuse verdict, and a delete that fails does not fail the
// rotation. In both, the old identifier stops answering once the in-flight
// window, session.DefaultRenewalGrace, ends.
func TestRotate_OldIdentifierInFlight(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		store func(inner *session.MemoryStore) *inFlightStore
		run   func(t *testing.T, f *inFlightFixture)
	}

	cases := []testCase{
		{
			name: "a load between the writes returns the old session",
			store: func(inner *session.MemoryStore) *inFlightStore {
				return &inFlightStore{MemoryStore: inner, afterSupersede: newGate()}
			},
			run: func(t *testing.T, f *inFlightFixture) {
				type result struct {
					s   *session.Session
					err error
				}
				done := make(chan result, 1)
				go func() {
					rotated, err := f.m.Rotate(t.Context(), f.satisfied)
					done <- result{rotated, err}
				}()
				<-f.store.afterSupersede.arrived

				got, err := f.m.Load(t.Context(), f.pending.ID)
				require.NoError(t, err, "a request in flight between the writes is not reuse")
				assert.Equal(t, testUser, got.UserID)
				assert.Equal(t, session.MFAPending, got.MFA, "the old session still owes its second factor")
				assert.Equal(t, 2, f.inner.Len(), "the family was not revoked")

				close(f.store.afterSupersede.open)
				r := <-done
				require.NoError(t, r.err)
				require.NotNil(t, r.s)

				next, err := f.m.Load(t.Context(), r.s.ID)
				require.NoError(t, err, "the successor loads after the rotation")
				assert.Equal(t, session.MFASatisfied, next.MFA)

				_, err = f.m.Load(t.Context(), f.pending.ID)
				require.ErrorIs(t, err, session.ErrNotFound, "once deleted the old identifier is not found")
			},
		},
		{
			name: "a failed delete does not fail the rotation",
			store: func(inner *session.MemoryStore) *inFlightStore {
				return &inFlightStore{MemoryStore: inner, failDelete: true}
			},
			run: func(t *testing.T, f *inFlightFixture) {
				rotated, err := f.m.Rotate(t.Context(), f.satisfied)
				require.NoError(t, err, "the successor is stored, so the rotation succeeded")
				require.NotNil(t, rotated)
				assert.Equal(t, session.MFASatisfied, rotated.MFA)

				logged := f.logs.String()
				assert.Contains(t, logged, "level=ERROR")
				assert.Contains(t, logged, "the session rotated from could not be deleted")
				assert.Contains(t, logged, f.pending.FamilyID.String(), "the log names the family")
				assert.NotContains(t, logged, f.pending.ID, "the log never carries the old identifier")
				assert.NotContains(t, logged, rotated.ID, "the log never carries the successor's identifier")

				next, err := f.m.Load(t.Context(), rotated.ID)
				require.NoError(t, err)
				assert.Equal(t, session.MFASatisfied, next.MFA)

				f.clk.Advance(10 * time.Second)
				old, err := f.m.Load(t.Context(), f.pending.ID)
				require.NoError(t, err, "inside the in-flight window the old identifier still loads")
				assert.Equal(t, session.MFAPending, old.MFA)

				f.clk.Advance(session.DefaultRenewalGrace + time.Second - 10*time.Second)
				_, err = f.m.Load(t.Context(), f.pending.ID)
				require.ErrorIs(t, err, session.ErrReused, "after the window the old identifier is reuse")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := &inFlightFixture{clk: clockwork.NewFakeClockAt(createdAt), logs: &bytes.Buffer{}}
			f.inner = session.NewMemoryStore(session.WithMemoryStoreClock(f.clk))
			f.store = tc.store(f.inner)
			f.m = managerFor(t, session.WithStore(f.store), session.WithClock(f.clk),
				session.WithLogger(slog.New(slog.NewTextHandler(f.logs, nil))))

			var err error
			f.pending, err = f.m.Create(t.Context(), testUser)
			require.NoError(t, err)
			f.pending.MFA = session.MFAPending
			require.NoError(t, f.m.Save(t.Context(), f.pending))

			satisfied := *f.pending
			satisfied.MFA = session.MFASatisfied
			satisfied.MFASatisfiedAt = f.clk.Now()
			f.satisfied = &satisfied

			tc.run(t, f)
		})
	}
}

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

func TestValidIdentifier(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		value  func(t *testing.T) string
		assert func(t *testing.T, valid bool)
	}

	valid := func(t *testing.T, ok bool) {
		t.Helper()
		assert.True(t, ok)
	}

	invalid := func(t *testing.T, ok bool) {
		t.Helper()
		assert.False(t, ok)
	}

	fixed := func(v string) func(*testing.T) string {
		return func(*testing.T) string { return v }
	}

	cases := []testCase{
		{
			name: "an identifier the manager issued",
			value: func(t *testing.T) string {
				s, err := managerFor(t).Create(t.Context(), testUser)
				require.NoError(t, err)

				return s.ID
			},
			assert: valid,
		},
		{name: "43 characters of the URL-safe alphabet", value: fixed(strings.Repeat("A-_z", 10) + "Az0"), assert: valid},
		{name: "empty", value: fixed(""), assert: invalid},
		{name: "one character short", value: fixed(strings.Repeat("A", 42)), assert: invalid},
		{name: "one character long", value: fixed(strings.Repeat("A", 44)), assert: invalid},
		{name: "standard base64's plus", value: fixed(strings.Repeat("A", 42) + "+"), assert: invalid},
		{name: "standard base64's slash", value: fixed("/" + strings.Repeat("A", 42)), assert: invalid},
		{name: "padding", value: fixed(strings.Repeat("A", 42) + "="), assert: invalid},
		{name: "a space", value: fixed(strings.Repeat("A", 21) + " " + strings.Repeat("A", 21)), assert: invalid},
		{name: "a dot, as in a signed token", value: fixed(strings.Repeat("A", 21) + "." + strings.Repeat("A", 21)), assert: invalid},
		{name: "a line feed, which the decoder skips", value: fixed(strings.Repeat("A", 21) + "\n" + strings.Repeat("A", 21)), assert: invalid},
		{name: "a multi-byte character", value: fixed(strings.Repeat("A", 41) + "é"), assert: invalid},
		{
			// The last character carries 4 bits of the 32nd byte and 2 zero
			// bits; a strict decoder refuses one whose spare bits are set.
			name:   "a final character with its spare bits set",
			value:  fixed(strings.Repeat("A", 42) + "B"),
			assert: invalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, session.ValidIdentifier(tc.value(t)))
		})
	}
}

func TestManagerTouchInterval(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.Option
		assert func(t *testing.T, got time.Duration)
	}

	cases := []testCase{
		{
			name:   "default is zero, every touch writes",
			assert: func(t *testing.T, got time.Duration) { assert.Zero(t, got) },
		},
		{
			name:   "reports what WithTouchInterval configured",
			opts:   []session.Option{session.WithTouchInterval(time.Minute)},
			assert: func(t *testing.T, got time.Duration) { assert.Equal(t, time.Minute, got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := session.New(append([]session.Option{session.WithStore(session.NewMemoryStore())}, tc.opts...)...)
			require.NoError(t, err)

			tc.assert(t, m.TouchInterval())
		})
	}
}

func TestNewManager_DefaultStoreFollowsClock(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// offset places the manager's clock relative to the system clock.
		offset time.Duration
		// store is the explicit store option, nil for none.
		store func() session.Option
		// plain wraps the clock so that it only tells the time.
		plain bool
		// advance is how far the clock moves after the first session.
		advance time.Duration
		assert  func(t *testing.T, m *session.Sessions, live string, removed int, err error)
	}

	const idle, absolute = 30 * time.Minute, time.Hour

	cases := []testCase{
		{
			name:    "a clock ahead of the system clock sweeps what it expired",
			offset:  365 * 24 * time.Hour,
			advance: 2 * time.Hour,
			assert: func(t *testing.T, m *session.Sessions, live string, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
				_, loadErr := m.Load(t.Context(), live)
				assert.NoError(t, loadErr, "the live session stays")
			},
		},
		{
			name:    "a clock behind the system clock keeps a live session",
			offset:  -365 * 24 * time.Hour,
			advance: 2 * time.Hour,
			assert: func(t *testing.T, m *session.Sessions, live string, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed, "only the session the clock expired goes")
				_, loadErr := m.Load(t.Context(), live)
				assert.NoError(t, loadErr, "the live session stays")
			},
		},
		{
			name:    "a clock that only tells the time is followed too",
			offset:  -365 * 24 * time.Hour,
			plain:   true,
			advance: 0,
			assert: func(t *testing.T, m *session.Sessions, live string, removed int, err error) {
				require.NoError(t, err)
				assert.Zero(t, removed)
				_, loadErr := m.Load(t.Context(), live)
				assert.NoError(t, loadErr, "the live session loads")
			},
		},
		{
			name:    "an explicit store keeps its own clock",
			offset:  365 * 24 * time.Hour,
			store:   func() session.Option { return session.WithStore(session.NewMemoryStore()) },
			advance: 2 * time.Hour,
			assert: func(t *testing.T, _ *session.Sessions, _ string, removed int, err error) {
				require.NoError(t, err)
				assert.Zero(t, removed, "the consumer's store judges expiry on the system clock")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fc := clockwork.NewFakeClockAt(time.Now().Add(tc.offset))
			var clk clock.Clock = fc
			if tc.plain {
				clk = fixedClock{at: fc.Now()}
			}
			opts := []session.Option{
				session.WithClock(clk),
				session.WithIdleTimeout(idle),
				session.WithAbsoluteTimeout(absolute),
			}
			if tc.store != nil {
				opts = append(opts, tc.store())
			}
			m := managerFor(t, opts...)

			ctx := t.Context()
			_, err := m.Create(ctx, testUser)
			require.NoError(t, err)
			fc.Advance(tc.advance)
			liveSession, err := m.Create(ctx, testUser)
			require.NoError(t, err)

			removed, err := m.DeleteExpired(ctx)
			tc.assert(t, m, liveSession.ID, removed, err)
		})
	}
}

// Standalone: it creates two sessions and compares their families.
func TestCreate_StartsAFamilyOfItsOwn(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)

	a, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	b, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	assert.NotEqual(t, a.FamilyID, b.FamilyID)
	assert.False(t, a.FamilyID.IsZero())
	assert.Equal(t, a.CreatedAt, a.FamilyCreatedAt)
}

// Standalone: it rotates twice in sequence and compares every successor's family.
func TestRotate_KeepsTheFamily(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)

	first, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	clk.Advance(5 * time.Minute)
	second, err := m.Rotate(t.Context(), first)
	require.NoError(t, err)
	third, err := m.Rotate(t.Context(), second)
	require.NoError(t, err)

	for _, s := range []*session.Session{second, third} {
		assert.Equal(t, first.FamilyID, s.FamilyID)
		assert.Equal(t, first.FamilyCreatedAt, s.FamilyCreatedAt)
	}
}

func TestRevokeFamily(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)
	ctx := t.Context()

	// The family holds a superseded session, still loadable inside its grace
	// window, and its live successor.
	one, err := m.Create(ctx, testUser)
	require.NoError(t, err)
	oneRenewed, _, err := m.RotateWithGrace(ctx, one, 30*time.Second)
	require.NoError(t, err)
	_, err = m.Load(ctx, one.ID)
	require.NoError(t, err, "the superseded session should load inside its window")
	other, err := m.Create(ctx, testUser)
	require.NoError(t, err)

	n, err := m.RevokeFamily(ctx, one.FamilyID)

	require.NoError(t, err)
	assert.Equal(t, 2, n, "the superseded session and its successor are the family")
	_, err = m.Load(ctx, one.ID)
	require.ErrorIs(t, err, session.ErrNotFound, "the superseded session survived its family's revocation")
	_, err = m.Load(ctx, oneRenewed.ID)
	require.ErrorIs(t, err, session.ErrNotFound)
	_, err = m.Load(ctx, other.ID)
	require.NoError(t, err, "revoking one family took another family of the same user")
}

// Standalone: it revokes through a mock store that fails, unlike TestRevokeFamily's real family.
func TestRevokeFamily_StoreFailure(t *testing.T) {
	t.Parallel()

	store := NewMockStore(gomock.NewController(t))
	family := id.MustParse("01926a4e-0000-7000-8000-0000000000aa")
	store.EXPECT().DeleteFamily(gomock.Any(), family).Return(0, errStoreWrite)
	m := managerFor(t, session.WithStore(store))

	_, err := m.RevokeFamily(t.Context(), family)

	require.ErrorIs(t, err, errStoreWrite)
}

// Standalone: it revokes the nil family through a mock store that expects no call.
func TestRevokeFamily_RefusesTheNilFamily(t *testing.T) {
	t.Parallel()

	// The mock expects no call: the nil family never reaches the store.
	store := NewMockStore(gomock.NewController(t))
	m := managerFor(t, session.WithStore(store))

	n, err := m.RevokeFamily(t.Context(), id.Nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil family")
	assert.Zero(t, n)
}

type failingGenerator struct{ err error }

func (g failingGenerator) NewID() (id.ID, error) { return id.ID{}, g.err }

func TestCreate_RefusesAnUnusableFamilyIdentifier(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		gen  id.Generator
		// assert receives the error and how many sessions reached the store.
		assert func(t *testing.T, err error, stored int)
	}

	errGen := errors.New("generator down")
	cases := []testCase{
		{
			name: "a generator error fails Create",
			gen:  failingGenerator{err: errGen},
			assert: func(t *testing.T, err error, stored int) {
				require.ErrorIs(t, err, errGen)
				assert.Zero(t, stored)
			},
		},
		{
			name: "the nil identifier fails Create",
			gen:  fixedGenerator{value: id.Nil},
			assert: func(t *testing.T, err error, stored int) {
				require.ErrorIs(t, err, session.ErrConfig, "a generator returning the nil identifier is a wiring fault")
				assert.Zero(t, stored, "a session with no family reached the store")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := session.NewMemoryStore()
			m := managerFor(t, session.WithStore(store), session.WithFamilyIDGenerator(tc.gen))

			_, err := m.Create(t.Context(), testUser)

			n, countErr := store.CountActiveByUser(t.Context(), testUser)
			require.NoError(t, countErr)
			tc.assert(t, err, n)
		})
	}
}

// fixedGenerator is a consumer's generator that always hands out one
// identifier.
type fixedGenerator struct{ value id.ID }

func (g fixedGenerator) NewID() (id.ID, error) { return g.value, nil }

func TestWithFamilyIDGenerator(t *testing.T) {
	t.Parallel()

	chosen := id.MustParse("01926a4e-0000-7000-8000-0000000000aa")

	type testCase struct {
		name   string
		opt    session.Option
		assert func(t *testing.T, m *session.Sessions, err error)
	}

	cases := []testCase{
		{
			name: "the consumer's generator mints the family identifier",
			opt:  session.WithFamilyIDGenerator(fixedGenerator{value: chosen}),
			assert: func(t *testing.T, m *session.Sessions, err error) {
				require.NoError(t, err)

				got, err := m.Create(t.Context(), testUser)

				require.NoError(t, err)
				assert.Equal(t, chosen, got.FamilyID)
			},
		},
		{
			name: "a nil generator is a configuration error",
			opt:  session.WithFamilyIDGenerator(nil),
			assert: func(t *testing.T, _ *session.Sessions, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
			},
		},
		{
			name: "a typed-nil generator is a configuration error",
			opt:  session.WithFamilyIDGenerator((*id.V7Generator)(nil)),
			assert: func(t *testing.T, _ *session.Sessions, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := session.New(tc.opt)

			tc.assert(t, m, err)
		})
	}
}

// The default generator reads the manager's clock whichever order the options
// come in, so a family identifier's time prefix is the manager's time.
func TestDefaultFamilyIDsFollowTheClockInAnyOptionOrder(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	store := session.NewMemoryStore(session.WithMemoryStoreClock(clk))

	for name, opts := range map[string][]session.Option{
		"clock first": {session.WithClock(clk), session.WithStore(store)},
		"clock last":  {session.WithStore(store), session.WithClock(clk)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m, err := session.New(opts...)
			require.NoError(t, err)

			got, err := m.Create(t.Context(), testUser)

			require.NoError(t, err)
			wantMillis := createdAt.UnixMilli()
			assert.Equal(t, wantMillis, idMillis(got.FamilyID), "the family identifier carries the manager clock's time")
		})
	}
}

// idMillis reads the 48-bit millisecond prefix of a version 7 identifier.
func idMillis(v id.ID) int64 {
	var ms int64
	for _, b := range v[:6] {
		ms = ms<<8 | int64(b)
	}

	return ms
}

func TestFederatedAssurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// act drives the manager and returns the session as the store now
		// holds it.
		act    func(t *testing.T, m *session.Sessions) *session.Session
		assert func(t *testing.T, got *session.Session, writes storeWrites)
	}

	cases := []testCase{
		{
			name: "recorded at creation in one write",
			act: func(t *testing.T, m *session.Sessions) *session.Session {
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
			act: func(t *testing.T, m *session.Sessions) *session.Session {
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
			act: func(t *testing.T, m *session.Sessions) *session.Session {
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
			act: func(t *testing.T, m *session.Sessions) *session.Session {
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
			act: func(t *testing.T, m *session.Sessions) *session.Session {
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
			act: func(t *testing.T, m *session.Sessions) *session.Session {
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
			act: func(t *testing.T, m *session.Sessions) *session.Session {
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
		act    func(t *testing.T, m *session.Sessions) *session.Session
		assert func(t *testing.T, got *session.Session, writes storeWrites)
	}

	cases := []testCase{
		{
			name: "created satisfied in one write",
			act: func(t *testing.T, m *session.Sessions) *session.Session {
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
			act: func(t *testing.T, m *session.Sessions) *session.Session {
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
			act: func(t *testing.T, m *session.Sessions) *session.Session {
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
			act: func(t *testing.T, m *session.Sessions) *session.Session {
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
			act: func(t *testing.T, m *session.Sessions) *session.Session {
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
			act: func(t *testing.T, m *session.Sessions) *session.Session {
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

// TestStoreReturningNoSessionIsNotFound pins that a store answering a load
// with neither a session nor an error is a missing session on every path that
// consumes a load result, and never a nil dereference.
func TestStoreReturningNoSessionIsNotFound(t *testing.T) {
	t.Parallel()

	const sid = "no-session"

	type testCase struct {
		name   string
		expect func(store *MockStore)
		act    func(ctx context.Context, m *session.Sessions, store session.Store) error
	}

	loadsNothing := func(store *MockStore) {
		store.EXPECT().Load(gomock.Any(), sid).Return(nil, nil).Times(1)
	}

	cases := []testCase{
		{
			name:   "Load",
			expect: loadsNothing,
			act: func(ctx context.Context, m *session.Sessions, _ session.Store) error {
				_, err := m.Load(ctx, sid)
				return err
			},
		},
		{
			name:   "LoadForRenewal",
			expect: loadsNothing,
			act: func(ctx context.Context, m *session.Sessions, _ session.Store) error {
				_, err := m.LoadForRenewal(ctx, sid)
				return err
			},
		},
		{
			name: "the re-read after a failed first-presentation mark",
			expect: func(store *MockStore) {
				store.EXPECT().Load(gomock.Any(), sid).Return(liveUnpresented(sid), nil).Times(1)
				store.EXPECT().MarkPresented(gomock.Any(), sid, createdAt).Return(errStoreQuotes).Times(1)
				store.EXPECT().Load(gomock.Any(), sid).Return(nil, nil).Times(1)
			},
			act: func(ctx context.Context, m *session.Sessions, _ session.Store) error {
				_, err := m.Load(ctx, sid)
				return err
			},
		},
		{
			name:   "Rotate",
			expect: loadsNothing,
			act: func(ctx context.Context, m *session.Sessions, _ session.Store) error {
				_, err := m.Rotate(ctx, liveUnpresented(sid))
				return err
			},
		},
		{
			name:   "RotateWithGrace",
			expect: loadsNothing,
			act: func(ctx context.Context, m *session.Sessions, _ session.Store) error {
				_, _, err := m.RotateWithGrace(ctx, liveUnpresented(sid), 30_000_000_000)
				return err
			},
		},
		{
			name:   "the encrypted store's Load",
			expect: loadsNothing,
			act: func(ctx context.Context, _ *session.Sessions, store session.Store) error {
				sealing, err := session.NewEncryptedStore(store, fakeCipher{key: 0x2a})
				require.NoError(t, err)
				_, err = sealing.Load(ctx, sid)
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockStore(gomock.NewController(t))
			tc.expect(store)
			m := managerFor(t, session.WithStore(store), session.WithClock(clockwork.NewFakeClockAt(createdAt)))

			var err error
			assert.NotPanics(t, func() { err = tc.act(t.Context(), m, store) })
			require.ErrorIs(t, err, session.ErrNotFound)
		})
	}
}

// TestRotate_TakesTheFamilyFromTheStoredRecord pins that a successor stays in
// the family the store holds, whatever family the caller's copy of the
// session carries.
// Standalone: it rotates a caller's copy with no family and reads the stored successor back.
func TestRotate_TakesTheFamilyFromTheStoredRecord(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, store := managerOnClock(t, clk)
	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	clk.Advance(time.Minute)

	stale := *s
	stale.FamilyID = id.Nil
	stale.FamilyCreatedAt = time.Time{}

	rotated, err := m.Rotate(t.Context(), &stale)

	require.NoError(t, err)
	assert.Equal(t, s.FamilyID, rotated.FamilyID)
	assert.Equal(t, s.FamilyCreatedAt, rotated.FamilyCreatedAt)
	stored, err := store.Load(t.Context(), rotated.ID)
	require.NoError(t, err)
	assert.Equal(t, s.FamilyID, stored.FamilyID)
}

// Standalone: it creates two sessions and reads the first one's family back from the store.
func TestCreateStartsAFamily(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, store := managerOnClock(t, clk)

	first, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	second, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	assert.NotEqual(t, id.Nil, first.FamilyID, "a new session starts a family")
	assert.NotEqual(t, first.FamilyID, second.FamilyID, "every sign-in starts a family of its own")
	assert.Equal(t, first.CreatedAt, first.FamilyCreatedAt, "the family starts when its first session is created")
	stored, err := store.Load(t.Context(), first.ID)
	require.NoError(t, err)
	assert.Equal(t, first.FamilyID, stored.FamilyID, "the family is stored by the creating write")
	assert.Equal(t, first.FamilyCreatedAt, stored.FamilyCreatedAt)
}

// returnedErrorsID is a session identifier shaped like the ones the manager
// mints. It is the bearer credential, so no error session returns may quote
// it.
const returnedErrorsID = "q3Vn8xZr0tLbW2mKc7YpE4sHd9FjA1uNo6GiTeRwXyQ"

// sessionSentinels is every sentinel a session store may return bare.
var sessionSentinels = []error{
	session.ErrNotFound,
	session.ErrExpired,
	session.ErrUnreadable,
}

// returnedErrorsSession is a live session on the fixed clock the table's
// managers read, so Touch reaches the store.
func returnedErrorsSession(idToken string) *session.Session {
	return &session.Session{
		ID:                returnedErrorsID,
		UserID:            testUser,
		FamilyID:          storedFamily,
		FamilyCreatedAt:   createdAt,
		CreatedAt:         createdAt,
		LastAccessedAt:    createdAt,
		IdleExpiresAt:     createdAt.Add(time.Hour),
		AbsoluteExpiresAt: createdAt.Add(12 * time.Hour),
		ExternalIDToken:   idToken,
	}
}

// returnedErrorsDoubles are the doubles a row programs before its call.
type returnedErrorsDoubles struct {
	store  *MockStore
	cipher *MockCipher
}

// hidesStoreText asserts err carries none of the dependency's text, still
// matches the dependency's error, and matches exactly the session sentinels
// in want: every one it matched before, and no other.
func hidesStoreText(want ...error) func(t *testing.T, err error) {
	return func(t *testing.T, err error) {
		t.Helper()

		require.Error(t, err)
		assert.NotContains(t, err.Error(), "alice@example.com")
		assert.NotContains(t, err.Error(), "u-123")
		assert.ErrorIs(t, err, errStoreQuotes)

		for _, sentinel := range sessionSentinels {
			wanted := false
			for _, w := range want {
				wanted = wanted || w == sentinel //nolint:errorlint // identity of sentinels
			}
			assert.Equal(t, wanted, errors.Is(err, sentinel), "errors.Is(err, %v)", sentinel)
		}
	}
}

func TestSessionReturnedErrors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		call   func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error
		assert func(t *testing.T, err error)
	}

	manager := func(t *testing.T, d returnedErrorsDoubles) *session.Sessions {
		t.Helper()

		return managerFor(t, session.WithStore(d.store), session.WithClock(clockwork.NewFakeClockAt(createdAt)))
	}
	encrypted := func(t *testing.T, d returnedErrorsDoubles) session.Store {
		t.Helper()

		s, err := session.NewEncryptedStore(d.store, d.cipher)
		require.NoError(t, err)

		return s
	}

	cases := []testCase{
		// Sessions: every store call.
		{
			name: "manager create",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errStoreQuotes)
				_, err := manager(t, d).Create(ctx, testUser)
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager load",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, errStoreQuotes)
				_, err := manager(t, d).Load(ctx, returnedErrorsID)
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager touch",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().RecordActivity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errStoreQuotes)
				return manager(t, d).Touch(ctx, returnedErrorsSession(""))
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager save",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(errStoreQuotes)
				return manager(t, d).Save(ctx, returnedErrorsSession(""))
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager delete",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Delete(gomock.Any(), returnedErrorsID).Return(errStoreQuotes)
				return manager(t, d).Delete(ctx, returnedErrorsID)
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager delete by user",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByUser(gomock.Any(), testUser).Return(errStoreQuotes)
				return manager(t, d).DeleteByUser(ctx, testUser)
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager delete by user except one reports fixed text and the store's count",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByUserExcept(gomock.Any(), testUser, returnedErrorsID).Return(1, errStoreQuotes)
				n, err := manager(t, d).DeleteByUserExcept(ctx, testUser, returnedErrorsID)
				assert.Equal(t, 1, n, "the count the store reported with its error")
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				hidesStoreText()(t, err)
				assert.EqualError(t, err, "session: the user's other sessions could not be deleted")
				assert.NotContains(t, err.Error(), returnedErrorsID)
			},
		},
		{
			name: "manager count active by user passes the store's count along",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().CountActiveByUser(gomock.Any(), testUser).Return(3, errStoreQuotes)
				n, err := manager(t, d).CountActiveByUser(ctx, testUser)
				assert.Equal(t, 3, n, "the count the store reported with its error")
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager delete expired",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteExpired(gomock.Any()).Return(0, errStoreQuotes)
				_, err := manager(t, d).DeleteExpired(ctx)
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager delete by external session",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByExternalSession(gomock.Any(), "https://idp", "sid").Return(0, errStoreQuotes)
				_, err := manager(t, d).DeleteByExternalSession(ctx, "https://idp", "sid")
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager delete by user and external issuer",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByUserAndExternalIssuer(gomock.Any(), testUser, "https://idp").Return(0, errStoreQuotes)
				_, err := manager(t, d).DeleteByUserAndExternalIssuer(ctx, testUser, "https://idp")
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager rotate: load of the old entry",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, errStoreQuotes)
				_, err := manager(t, d).Rotate(ctx, returnedErrorsSession(""))
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager rotate: the supersession of the old entry",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(returnedErrorsSession(""), nil)
				d.store.EXPECT().Supersede(gomock.Any(), gomock.Any()).Return(errStoreQuotes)
				_, err := manager(t, d).Rotate(ctx, returnedErrorsSession(""))
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager rotate: a lost race comes back bare",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(returnedErrorsSession(""), nil)
				d.store.EXPECT().Supersede(gomock.Any(), gomock.Any()).Return(session.ErrRenewalConflict)
				_, err := manager(t, d).Rotate(ctx, returnedErrorsSession(""))
				return err
			},
			assert: isBare(session.ErrRenewalConflict),
		},
		{
			// The successor is stored, so a failed delete is logged by type,
			// never returned: there is no store text to hide.
			name: "manager rotate: delete of the old entry is not returned",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(returnedErrorsSession(""), nil)
				d.store.EXPECT().Supersede(gomock.Any(), gomock.Any()).Return(nil)
				d.store.EXPECT().Delete(gomock.Any(), returnedErrorsID).Return(errStoreQuotes)
				_, err := manager(t, d).Rotate(ctx, returnedErrorsSession(""))
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		{
			name: "manager rotate with grace: load of the old entry",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, errStoreQuotes)
				_, _, err := manager(t, d).RotateWithGrace(ctx, returnedErrorsSession(""), time.Second)
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager rotate with grace: the supersession",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(returnedErrorsSession(""), nil)
				d.store.EXPECT().Supersede(gomock.Any(), gomock.Any()).Return(errStoreQuotes)
				_, _, err := manager(t, d).RotateWithGrace(ctx, returnedErrorsSession(""), time.Second)
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager rotate with grace: a lost race comes back bare",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(returnedErrorsSession(""), nil)
				d.store.EXPECT().Supersede(gomock.Any(), gomock.Any()).Return(session.ErrRenewalConflict)
				_, _, err := manager(t, d).RotateWithGrace(ctx, returnedErrorsSession(""), time.Second)
				return err
			},
			assert: isBare(session.ErrRenewalConflict),
		},
		{
			name: "encrypted supersede: a successor that moved on comes back bare",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Supersede(gomock.Any(), gomock.Any()).Return(session.ErrSuccessorAdvanced)
				return encrypted(t, d).Supersede(ctx, session.Supersession{
					Old: returnedErrorsID, Successor: returnedErrorsSession(""), Now: createdAt,
				})
			},
			assert: isBare(session.ErrSuccessorAdvanced),
		},
		{
			name: "manager load: a store error wrapping a sentinel gets fixed text and still matches it",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).
					Return(nil, fmt.Errorf("%w: %w", session.ErrNotFound, errStoreQuotes))
				_, err := manager(t, d).Load(ctx, returnedErrorsID)
				return err
			},
			assert: hidesStoreText(session.ErrNotFound),
		},

		// Encrypted store: the inner store's and the cipher's failures.
		{
			name: "encrypted create: inner store",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errStoreQuotes)
				return encrypted(t, d).Create(ctx, returnedErrorsSession(""))
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted create: cipher seal hides the session identifier",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.cipher.EXPECT().Seal(gomock.Any(), gomock.Any()).Return(nil, errStoreQuotes)
				return encrypted(t, d).Create(ctx, returnedErrorsSession("id-token"))
			},
			assert: func(t *testing.T, err error) {
				hidesStoreText()(t, err)
				assert.NotContains(t, err.Error(), returnedErrorsID)
			},
		},
		{
			name: "encrypted save: inner store",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(errStoreQuotes)
				return encrypted(t, d).Save(ctx, returnedErrorsSession(""))
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted save: cipher seal hides the session identifier",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.cipher.EXPECT().Seal(gomock.Any(), gomock.Any()).Return(nil, errStoreQuotes)
				return encrypted(t, d).Save(ctx, returnedErrorsSession("id-token"))
			},
			assert: func(t *testing.T, err error) {
				hidesStoreText()(t, err)
				assert.NotContains(t, err.Error(), returnedErrorsID)
			},
		},
		{
			name: "encrypted load: inner store",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, errStoreQuotes)
				_, err := encrypted(t, d).Load(ctx, returnedErrorsID)
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted load: cipher open stays unreadable and hides the session identifier",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				stored := returnedErrorsSession(base64.RawURLEncoding.EncodeToString([]byte("envelope")))
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(stored, nil)
				d.cipher.EXPECT().Open(gomock.Any(), gomock.Any()).Return(nil, errStoreQuotes)
				_, err := encrypted(t, d).Load(ctx, returnedErrorsID)
				return err
			},
			assert: func(t *testing.T, err error) {
				hidesStoreText(session.ErrUnreadable)(t, err)
				assert.NotContains(t, err.Error(), returnedErrorsID)
			},
		},
		{
			name: "encrypted load: an invalid envelope stays unreadable and hides the session identifier",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(returnedErrorsSession("not base64!"), nil)
				_, err := encrypted(t, d).Load(ctx, returnedErrorsID)
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, session.ErrUnreadable)
				assert.NotContains(t, err.Error(), returnedErrorsID)
			},
		},
		{
			name: "encrypted delete",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Delete(gomock.Any(), returnedErrorsID).Return(errStoreQuotes)
				return encrypted(t, d).Delete(ctx, returnedErrorsID)
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted delete by user",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByUser(gomock.Any(), testUser).Return(errStoreQuotes)
				return encrypted(t, d).DeleteByUser(ctx, testUser)
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted delete by user except one",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByUserExcept(gomock.Any(), testUser, returnedErrorsID).Return(0, errStoreQuotes)
				_, err := encrypted(t, d).DeleteByUserExcept(ctx, testUser, returnedErrorsID)
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				hidesStoreText()(t, err)
				assert.EqualError(t, err, "session: the inner store could not delete the user's other sessions")
				assert.NotContains(t, err.Error(), returnedErrorsID)
			},
		},
		{
			name: "encrypted count active by user",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().CountActiveByUser(gomock.Any(), testUser).Return(0, errStoreQuotes)
				_, err := encrypted(t, d).CountActiveByUser(ctx, testUser)
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted delete expired",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteExpired(gomock.Any()).Return(0, errStoreQuotes)
				_, err := encrypted(t, d).DeleteExpired(ctx)
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted delete by external session",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByExternalSession(gomock.Any(), "https://idp", "sid").Return(0, errStoreQuotes)
				_, err := encrypted(t, d).DeleteByExternalSession(ctx, "https://idp", "sid")
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted delete by user and external issuer",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByUserAndExternalIssuer(gomock.Any(), testUser, "https://idp").Return(0, errStoreQuotes)
				_, err := encrypted(t, d).DeleteByUserAndExternalIssuer(ctx, testUser, "https://idp")
				return err
			},
			assert: hidesStoreText(),
		},

		// Memory store: its own refusal.
		{
			name: "memory create: a stored identifier is refused without quoting it",
			call: func(ctx context.Context, t *testing.T, _ returnedErrorsDoubles) error {
				store := session.NewMemoryStore()
				require.NoError(t, store.Create(ctx, returnedErrorsSession("")))
				return store.Create(ctx, returnedErrorsSession(""))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.NotContains(t, err.Error(), returnedErrorsID)
			},
		},
	}

	// A store answering with a session sentinel bare gets that same value
	// back, text included, through every path that can see one. Rotate's row
	// also pins that nothing is written after a refused load: the strict mock
	// fails on any Create or Delete.
	for _, sentinel := range sessionSentinels {
		cases = append(cases,
			testCase{
				name: "bare " + sentinel.Error() + ": manager load",
				call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
					d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, sentinel)
					_, err := manager(t, d).Load(ctx, returnedErrorsID)
					return err
				},
				assert: isBare(sentinel),
			},
			testCase{
				name: "bare " + sentinel.Error() + ": manager save",
				call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
					d.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(sentinel)
					return manager(t, d).Save(ctx, returnedErrorsSession(""))
				},
				assert: isBare(sentinel),
			},
			testCase{
				name: "bare " + sentinel.Error() + ": manager touch",
				call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
					d.store.EXPECT().RecordActivity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(sentinel)
					return manager(t, d).Touch(ctx, returnedErrorsSession(""))
				},
				assert: isBare(sentinel),
			},
			testCase{
				name: "bare " + sentinel.Error() + ": manager rotate refuses and writes nothing",
				call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
					d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, sentinel)
					_, err := manager(t, d).Rotate(ctx, returnedErrorsSession(""))
					return err
				},
				assert: isBare(sentinel),
			},
			testCase{
				name: "bare " + sentinel.Error() + ": encrypted load",
				call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
					d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, sentinel)
					_, err := encrypted(t, d).Load(ctx, returnedErrorsID)
					return err
				},
				assert: isBare(sentinel),
			},
			testCase{
				name: "bare " + sentinel.Error() + ": encrypted save",
				call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
					d.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(sentinel)
					return encrypted(t, d).Save(ctx, returnedErrorsSession(""))
				},
				assert: isBare(sentinel),
			},
			testCase{
				name: "bare " + sentinel.Error() + ": manager over the encrypted store",
				call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
					d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, sentinel)
					m := managerFor(t, session.WithStore(encrypted(t, d)))
					_, err := m.Load(ctx, returnedErrorsID)
					return err
				},
				assert: isBare(sentinel),
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			d := returnedErrorsDoubles{store: NewMockStore(ctrl), cipher: NewMockCipher(ctrl)}

			tc.assert(t, tc.call(t.Context(), t, d))
		})
	}
}

// TestTouch_WritesNothingForASupersededSession pins that grace never extends:
// a superseded session's activity reaches no store.
// Standalone: it touches a superseded session over a mock store that expects no call.
func TestTouch_WritesNothingForASupersededSession(t *testing.T) {
	t.Parallel()

	store := NewMockStore(gomock.NewController(t)) // any call fails the test
	m := managerFor(t, session.WithStore(store), session.WithClock(clockwork.NewFakeClockAt(createdAt)))

	s := liveUnpresented("superseded")
	s.LastAccessedAt = createdAt.Add(-5 * time.Minute)
	s.SupersededAt = createdAt.Add(-10 * time.Second)
	s.AcceptUntil = createdAt.Add(20 * time.Second)

	require.NoError(t, m.Touch(t.Context(), s))
	assert.Equal(t, createdAt.Add(-5*time.Minute), s.LastAccessedAt)
}

// Standalone: already a table over New; inside TestNewManager its cases would sit a level deeper.
func TestNewManager_RenewalOptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.Option
		assert func(t *testing.T, m *session.Sessions, err error)
	}

	cases := []testCase{
		{
			name: "a family maximum below the lifetime maximum is refused",
			opts: []session.Option{
				session.WithMaxAbsoluteLifetime(30 * day),
				session.WithMaxFamilyLifetime(7 * day),
			},
			assert: func(t *testing.T, m *session.Sessions, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, m)
			},
		},
		{
			name: "a family maximum below the default lifetime maximum is refused",
			opts: []session.Option{session.WithMaxFamilyLifetime(time.Hour)},
			assert: func(t *testing.T, m *session.Sessions, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, m)
			},
		},
		{
			name: "a family maximum equal to the lifetime maximum is accepted",
			opts: []session.Option{
				session.WithMaxAbsoluteLifetime(30 * day),
				session.WithMaxFamilyLifetime(30 * day),
			},
			assert: func(t *testing.T, m *session.Sessions, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name: "a nil reuse observer is refused",
			opts: []session.Option{session.WithReuseObserver(nil)},
			assert: func(t *testing.T, m *session.Sessions, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, m)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := session.New(tc.opts...)
			tc.assert(t, m, err)
		})
	}
}

// Standalone: already a table over New; inside TestNewManager its cases would sit a level deeper.
func TestNewManager_TouchIntervalMustBeShorterThanIdleTimeout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		interval time.Duration
		assert   func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:     "negative",
			interval: -time.Second,
			assert:   func(t *testing.T, err error) { require.ErrorIs(t, err, session.ErrConfig) },
		},
		{
			name:     "equal to the idle timeout",
			interval: 30 * time.Minute,
			assert:   func(t *testing.T, err error) { require.ErrorIs(t, err, session.ErrConfig) },
		},
		{
			name:     "longer than the idle timeout",
			interval: 31 * time.Minute,
			assert:   func(t *testing.T, err error) { require.ErrorIs(t, err, session.ErrConfig) },
		},
		{
			name:     "just under the idle timeout",
			interval: 30*time.Minute - time.Nanosecond,
			assert:   func(t *testing.T, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := session.New(session.WithTouchInterval(tc.interval))

			tc.assert(t, err)
		})
	}
}
