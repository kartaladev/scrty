package session_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/session"
)

// TestStoreReturningNoSessionIsNotFound pins that a store answering a load
// with neither a session nor an error is a missing session on every path that
// consumes a load result, and never a nil dereference.
func TestStoreReturningNoSessionIsNotFound(t *testing.T) {
	t.Parallel()

	const sid = "no-session"

	type testCase struct {
		name   string
		expect func(store *MockStore)
		act    func(ctx context.Context, m *session.Manager, store session.Store) error
	}

	loadsNothing := func(store *MockStore) {
		store.EXPECT().Load(gomock.Any(), sid).Return(nil, nil).Times(1)
	}

	cases := []testCase{
		{
			name:   "Load",
			expect: loadsNothing,
			act: func(ctx context.Context, m *session.Manager, _ session.Store) error {
				_, err := m.Load(ctx, sid)
				return err
			},
		},
		{
			name:   "LoadForRenewal",
			expect: loadsNothing,
			act: func(ctx context.Context, m *session.Manager, _ session.Store) error {
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
			act: func(ctx context.Context, m *session.Manager, _ session.Store) error {
				_, err := m.Load(ctx, sid)
				return err
			},
		},
		{
			name:   "Rotate",
			expect: loadsNothing,
			act: func(ctx context.Context, m *session.Manager, _ session.Store) error {
				_, err := m.Rotate(ctx, liveUnpresented(sid))
				return err
			},
		},
		{
			name:   "RotateWithGrace",
			expect: loadsNothing,
			act: func(ctx context.Context, m *session.Manager, _ session.Store) error {
				_, _, err := m.RotateWithGrace(ctx, liveUnpresented(sid), 30_000_000_000)
				return err
			},
		},
		{
			name:   "the encrypted store's Load",
			expect: loadsNothing,
			act: func(ctx context.Context, _ *session.Manager, store session.Store) error {
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
			require.ErrorIs(t, err, session.ErrSessionNotFound)
		})
	}
}

// failFirstMarkStore fails the first MarkPresented of one identifier, as a
// store outage would, and delegates everything else.
type failFirstMarkStore struct {
	*session.MemoryStore

	id   string
	once sync.Once
}

func (s *failFirstMarkStore) MarkPresented(ctx context.Context, id string, at time.Time) error {
	if id == s.id {
		failed := false
		s.once.Do(func() { failed = true })
		if failed {
			return errStoreQuotes
		}
	}

	return s.MemoryStore.MarkPresented(ctx, id, at)
}

// TestLoad_FailedFirstUseWrite pins what a failed first-use write does to a
// load: with unused-successor recovery on it fails the load, because serving
// a session whose first use was not recorded would let a used successor be
// judged unused later; with recovery off the session is still served. It also
// pins the other half of that: the successor whose write failed was never
// served, so a late renewal of its predecessor recovers it rather than
// judging it reuse.
func TestLoad_FailedFirstUseWrite(t *testing.T) {
	t.Parallel()

	const sid = "failed-first-use"

	type testCase struct {
		name string
		opts []session.ManagerOption
		// act runs the case's steps and returns what its last step returned.
		act    func(ctx context.Context, t *testing.T, opts []session.ManagerOption) (*session.Session, error)
		assert func(t *testing.T, got *session.Session, err error)
	}

	loadOnMock := func(ctx context.Context, t *testing.T, opts []session.ManagerOption) (*session.Session, error) {
		t.Helper()

		store := NewMockStore(gomock.NewController(t))
		store.EXPECT().Load(gomock.Any(), sid).Return(liveUnpresented(sid), nil).AnyTimes()
		store.EXPECT().MarkPresented(gomock.Any(), sid, createdAt).Return(errStoreQuotes).Times(1)

		all := append([]session.ManagerOption{
			session.WithStore(store), session.WithClock(clockwork.NewFakeClockAt(createdAt)),
		}, opts...)

		return managerFor(t, all...).Load(ctx, sid)
	}

	cases := []testCase{
		{
			name: "with recovery on the load fails",
			opts: []session.ManagerOption{session.WithUnusedSuccessorRecovery()},
			act:  loadOnMock,
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, errStoreQuotes)
				assert.NotContains(t, err.Error(), "alice@example.com")
				assert.Nil(t, got)
			},
		},
		{
			name: "with recovery off the session is served",
			act:  loadOnMock,
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err)
				require.NotNil(t, got)
			},
		},
		{
			name: "with recovery on a later renewal of the predecessor recovers the successor whose write failed",
			act: func(ctx context.Context, t *testing.T, _ []session.ManagerOption) (*session.Session, error) {
				t.Helper()

				clk := clockwork.NewFakeClockAt(createdAt)
				store := &failFirstMarkStore{MemoryStore: session.NewMemoryStore(session.WithMemoryStoreClock(clk))}
				m := recoveryManager(t, store, clk)

				o, err := m.Create(ctx, testUser)
				require.NoError(t, err)
				s1, _, err := m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				store.id = s1.ID
				_, err = m.Load(ctx, s1.ID)
				require.ErrorIs(t, err, errStoreQuotes, "the first use of the successor was not recorded")

				clk.Advance(nextDay)
				got, kind, err := m.RotateWithGrace(ctx, o, 30*time.Second)
				if err == nil {
					assert.Equal(t, session.RenewalRecovery, kind)
				}

				return got, err
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err, "a successor that was never served is recovered, not judged reuse")
				require.NotNil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.act(t.Context(), t, tc.opts)
			tc.assert(t, got, err)
		})
	}
}
