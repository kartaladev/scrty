package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

var errSessionStoreDown = errors.New("the session store is unreachable")

func TestExpiryTask(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// task builds the task under test and returns what the assertion needs.
		task   func(t *testing.T) (expiry.Task, func(t *testing.T))
		assert func(t *testing.T, task expiry.Task, removed int, err error, after func(t *testing.T))
	}

	cases := []testCase{
		{
			name: "removes expired sessions and keeps the live one",
			task: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(createdAt)
				m, store := managerOnClock(t, clk,
					session.WithIdleTimeout(30*time.Minute), session.WithAbsoluteTimeout(time.Hour))

				for range 2 {
					_, err := m.Create(t.Context(), testUser)
					require.NoError(t, err)
				}
				clk.Advance(2 * time.Hour)
				live, err := m.Create(t.Context(), testUser)
				require.NoError(t, err)

				return session.ExpiryTask(store), func(t *testing.T) {
					_, err := m.Load(t.Context(), live.ID)
					require.NoError(t, err)
					assert.Equal(t, 1, store.Len())
				}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error, after func(t *testing.T)) {
				require.NoError(t, err)
				assert.Equal(t, 2, removed)
				after(t)
			},
		},
		{
			name: "a store failure propagates",
			task: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				store := NewMockStore(gomock.NewController(t))
				store.EXPECT().DeleteExpired(gomock.Any()).Return(0, errSessionStoreDown)

				return session.ExpiryTask(store), func(*testing.T) {}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error, _ func(t *testing.T)) {
				require.ErrorIs(t, err, errSessionStoreDown)
				assert.Zero(t, removed)
			},
		},
		{
			name: "name is sessions and no interval is set",
			task: func(*testing.T) (expiry.Task, func(t *testing.T)) {
				return session.ExpiryTask(must.Must(session.NewMemoryStore())), func(*testing.T) {}
			},
			assert: func(t *testing.T, task expiry.Task, _ int, err error, _ func(t *testing.T)) {
				require.NoError(t, err)
				assert.Equal(t, "sessions", task.Name)
				assert.Zero(t, task.Interval)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			task, after := tc.task(t)
			require.NotNil(t, task.Run, "the task must carry a Run")

			removed, err := task.Run(t.Context())
			tc.assert(t, task, removed, err, after)
		})
	}
}

// A supersession with no successor has nothing to insert, so both stores
// refuse it and write nothing, the sealing store as the store it wraps.
func TestSupersedeRefusesANilSuccessor(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, store session.Store, inner *session.MemoryStore)
	}

	nilSuccessor := firstRotation("old", nil)

	check := func(t *testing.T, ctx context.Context, store session.Store, inner *session.MemoryStore) {
		t.Helper()

		require.NoError(t, store.Create(ctx, familyOf("old", id.MustParse("01926a4e-0000-7000-8000-000000000001"))))

		err := store.Supersede(ctx, nilSuccessor)

		require.Error(t, err)
		require.NotErrorIs(t, err, session.ErrRenewalConflict)
		require.NotErrorIs(t, err, session.ErrNotFound)
		old, err := store.Load(ctx, "old")
		require.NoError(t, err)
		assert.True(t, old.SupersededAt.IsZero(), "a refused supersession marked the session")
		assert.Empty(t, old.SuccessorDigest)
		assert.Equal(t, 1, inner.Len(), "a refused supersession inserted something")
	}

	cases := []testCase{
		{
			name: "memory store",
			assert: func(t *testing.T, ctx context.Context, _ session.Store, inner *session.MemoryStore) {
				check(t, ctx, inner, inner)
			},
		},
		{
			name: "sealing store",
			assert: func(t *testing.T, ctx context.Context, sealing session.Store, inner *session.MemoryStore) {
				check(t, ctx, sealing, inner)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sealing, inner := sealingStore(t, 0x2a)
			tc.assert(t, t.Context(), sealing, inner)
		})
	}
}
