package session_test

import (
	"bytes"
	"log/slog"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/session"
)

// configError is the assertion every wiring mistake shares: construction
// fails, it fails as a configuration error, and nothing usable comes back.
func configError(t *testing.T, m *session.Manager, err error) {
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

		_, err := session.NewManager(session.WithSessionLogger(logger))
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

		_, err := session.NewManager(
			session.WithStore(session.NewMemoryStore()),
			session.WithSessionLogger(logger))
		require.NoError(t, err)

		assert.Empty(t, buf.String(), "a consumer who supplied their own store was warned about the default")
	})

	t.Run("a nil logger constructs and logs nowhere in particular", func(t *testing.T) {
		t.Parallel()

		// Refusing a nil logger would make logging mandatory; ignoring it
		// leaves the caller on slog.Default(), which is what "do not
		// configure this" reasonably means.
		m, err := session.NewManager(session.WithSessionLogger(nil))
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
		opts   []session.ManagerOption
		assert func(t *testing.T, m *session.Manager, err error)
	}

	cases := []testCase{
		{
			name: "defaults to an in-memory store, 30m idle and 12h absolute",
			assert: func(t *testing.T, m *session.Manager, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
				assert.Equal(t, 30*time.Minute, m.IdleTimeout())
				assert.Equal(t, 12*time.Hour, m.AbsoluteTimeout())
			},
		},
		{
			name: "consumer timeouts replace the defaults",
			opts: []session.ManagerOption{
				session.WithIdleTimeout(5 * time.Minute),
				session.WithAbsoluteTimeout(time.Hour),
			},
			assert: func(t *testing.T, m *session.Manager, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
				assert.Equal(t, 5*time.Minute, m.IdleTimeout())
				assert.Equal(t, time.Hour, m.AbsoluteTimeout())
			},
		},
		{
			name:   "a zero idle timeout is refused, because it expires every session on creation",
			opts:   []session.ManagerOption{session.WithIdleTimeout(0)},
			assert: configError,
		},
		{
			name:   "a negative idle timeout is refused",
			opts:   []session.ManagerOption{session.WithIdleTimeout(-time.Second)},
			assert: configError,
		},
		{
			name:   "a zero absolute timeout is refused",
			opts:   []session.ManagerOption{session.WithAbsoluteTimeout(0)},
			assert: configError,
		},
		{
			name:   "a negative absolute timeout is refused",
			opts:   []session.ManagerOption{session.WithAbsoluteTimeout(-time.Second)},
			assert: configError,
		},
		{
			name:   "a nil store is refused rather than silently kept in memory",
			opts:   []session.ManagerOption{session.WithStore(nil)},
			assert: configError,
		},
		{
			// The asymmetry with the logger below is deliberate: a caller
			// passing a clock meant to inject one, and the wall clock would
			// make a test that never advances look like one that does.
			name:   "a nil clock is refused",
			opts:   []session.ManagerOption{session.WithClock(nil)},
			assert: configError,
		},
		{
			// time-source "Nil time source", typed nil included: a nil
			// pointer inside the interface would otherwise pass construction
			// and panic, or read nonsense, at the first Create.
			name:   "a typed-nil clock is refused like an untyped one",
			opts:   []session.ManagerOption{session.WithClock((*nilClock)(nil))},
			assert: configError,
		},
		{
			name: "a consumer clock with only Now is accepted",
			opts: []session.ManagerOption{session.WithClock(fixedClock{at: createdAt})},
			assert: func(t *testing.T, m *session.Manager, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			},
		},
		{
			name:   "a nil random source is refused",
			opts:   []session.ManagerOption{session.WithRandom(nil)},
			assert: configError,
		},
		{
			// A nil logger has an obvious safe reading — do not log from this
			// component — and refusing it would make logging mandatory.
			name: "a nil logger is ignored rather than refused",
			opts: []session.ManagerOption{session.WithSessionLogger(nil)},
			assert: func(t *testing.T, m *session.Manager, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := session.NewManager(tc.opts...)
			tc.assert(t, m, err)
		})
	}
}
