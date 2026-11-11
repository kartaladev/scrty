package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/detach"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// TestSessions_DetachedCallsCarryDeadline pins the bound on each store call
// the manager detaches from the caller's cancellation, and that an end
// observer's context carries no library deadline. The caller's context has no
// deadline, so any deadline a double sees comes from the library.
func TestSessions_DetachedCallsCarryDeadline(t *testing.T) {
	t.Parallel()

	const sid = "detached-deadline"

	// within asserts the context's deadline lies in (floor, bound] from now.
	within := func(t *testing.T, ctx context.Context, floor, bound time.Duration) {
		t.Helper()

		dl, ok := ctx.Deadline()
		require.True(t, ok, "no deadline: a hung store holds the request goroutine without end")
		remaining := time.Until(dl)
		assert.Greater(t, remaining, floor)
		assert.LessOrEqual(t, remaining, bound)
	}

	ended := func() *session.Session {
		s := supersededPastWindow(sid)
		s.IdleExpiresAt = createdAt.Add(-time.Minute)

		return s
	}

	type testCase struct {
		name string
		// recovery turns on unused-successor recovery, which the
		// SuccessorPresented cases need and the reuse cases must not have.
		recovery bool
		opts     func(seen *context.Context) []session.Option
		expect   func(store *MockStore, seen *context.Context)
		call     func(ctx context.Context, m *session.Sessions) error
		assert   func(t *testing.T, err error, seen context.Context)
	}

	cases := []testCase{
		{
			name:     "SuccessorPresented is bounded by the write timeout",
			recovery: true,
			expect: func(store *MockStore, seen *context.Context) {
				store.EXPECT().Load(gomock.Any(), sid).Return(ended(), nil).Times(1)
				store.EXPECT().SuccessorPresented(gomock.Any(), sid).DoAndReturn(func(ctx context.Context, _ string) (bool, error) {
					*seen = ctx
					return false, nil
				}).Times(1)
			},
			call: func(ctx context.Context, m *session.Sessions) error {
				_, err := m.LoadForRenewal(ctx, sid)
				return err
			},
			assert: func(t *testing.T, err error, seen context.Context) {
				require.ErrorIs(t, err, session.ErrExpired)
				require.NotNil(t, seen)
				within(t, seen, 0, detach.WriteTimeout)
			},
		},
		{
			name:     "SuccessorPresented timing out refuses the renewal as a store failure",
			recovery: true,
			expect: func(store *MockStore, _ *context.Context) {
				store.EXPECT().Load(gomock.Any(), sid).Return(ended(), nil).Times(1)
				store.EXPECT().SuccessorPresented(gomock.Any(), sid).Return(false, context.DeadlineExceeded).Times(1)
			},
			call: func(ctx context.Context, m *session.Sessions) error {
				_, err := m.LoadForRenewal(ctx, sid)
				return err
			},
			assert: func(t *testing.T, err error, _ context.Context) {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				assert.NotErrorIs(t, err, session.ErrReused)
				assert.NotErrorIs(t, err, session.ErrExpired)
			},
		},
		{
			name: "DeleteFamily is bounded by the revocation timeout",
			expect: func(store *MockStore, seen *context.Context) {
				store.EXPECT().Load(gomock.Any(), sid).Return(supersededPastWindow(sid), nil).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).DoAndReturn(func(ctx context.Context, _ id.ID) (int, error) {
					*seen = ctx
					return 1, nil
				}).Times(1)
			},
			call: func(ctx context.Context, m *session.Sessions) error {
				_, err := m.Load(ctx, sid)
				return err
			},
			assert: func(t *testing.T, err error, seen context.Context) {
				require.ErrorIs(t, err, session.ErrReused)
				require.NotNil(t, seen)
				within(t, seen, detach.WriteTimeout, detach.RevocationTimeout)
			},
		},
		{
			name: "DeleteFamily timing out joins the store error to ErrReused",
			expect: func(store *MockStore, _ *context.Context) {
				store.EXPECT().Load(gomock.Any(), sid).Return(supersededPastWindow(sid), nil).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).Return(0, context.DeadlineExceeded).Times(1)
			},
			call: func(ctx context.Context, m *session.Sessions) error {
				_, err := m.Load(ctx, sid)
				return err
			},
			assert: func(t *testing.T, err error, _ context.Context) {
				require.ErrorIs(t, err, session.ErrReused)
				assert.ErrorIs(t, err, context.DeadlineExceeded)
			},
		},
		{
			// Class 5: the library gives a consumer's observer no deadline.
			name: "an end observer's context carries no library deadline",
			opts: func(seen *context.Context) []session.Option {
				return []session.Option{session.WithEndObserver(session.EndObserverFunc(
					func(ctx context.Context, _ session.EndReport) { *seen = ctx },
				))}
			},
			expect: func(store *MockStore, _ *context.Context) {
				store.EXPECT().Load(gomock.Any(), sid).Return(supersededPastWindow(sid), nil).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).Return(1, nil).Times(1)
			},
			call: func(ctx context.Context, m *session.Sessions) error {
				_, err := m.Load(ctx, sid)
				return err
			},
			assert: func(t *testing.T, err error, seen context.Context) {
				require.ErrorIs(t, err, session.ErrReused)
				require.NotNil(t, seen, "the observer was not told")
				_, ok := seen.Deadline()
				assert.False(t, ok, "the library bounded a consumer's observer")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var seen context.Context
			store := NewMockStore(gomock.NewController(t))
			tc.expect(store, &seen)
			opts := []session.Option{
				session.WithStore(store),
				session.WithClock(clockwork.NewFakeClockAt(createdAt)),
			}
			if tc.recovery {
				opts = append(opts, session.WithUnusedSuccessorRecovery())
			}
			if tc.opts != nil {
				opts = append(opts, tc.opts(&seen)...)
			}
			m := managerFor(t, opts...)

			err := tc.call(t.Context(), m)
			tc.assert(t, err, seen)
		})
	}
}
