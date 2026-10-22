package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// supersededPastWindow is a session rotated ten minutes before createdAt with
// a thirty-second window, which still names its successor: presenting it at
// createdAt is reuse.
func supersededPastWindow(sid string) *session.Session {
	s := liveUnpresented(sid)
	s.SupersededAt = createdAt.Add(-10 * time.Minute)
	s.AcceptUntil = s.SupersededAt.Add(30 * time.Second)
	s.SuccessorDigest = []byte("successor-digest")

	return s
}

// honouringDeleteFamily is what a context-honouring store does with
// DeleteFamily, as database/sql and pgx do: a cancelled context aborts the
// statement and nothing is deleted. It records the context's state on seen.
func honouringDeleteFamily(seen *error) func(ctx context.Context, _ id.ID) (int, error) {
	return func(ctx context.Context, _ id.ID) (int, error) {
		*seen = ctx.Err()
		if err := ctx.Err(); err != nil {
			return 0, err
		}

		return 1, nil
	}
}

// TestReuse_RevokesTheFamilyWhenThePresentingRequestIsCancelled pins that the
// family revocation on detected reuse does not depend on the presenting
// request staying connected: a client (or a thief) that hangs up once the
// superseded record has been read must not leave the family alive.
func TestReuse_RevokesTheFamilyWhenThePresentingRequestIsCancelled(t *testing.T) {
	t.Parallel()

	const sid = "reused-then-cancelled"

	type testCase struct {
		name string
		// opts are manager options the case adds to the store and the clock.
		opts []session.ManagerOption
		// expect wires the store; cancel is the presenting request hanging up,
		// which each case calls once the store has answered the read.
		expect func(store *MockStore, cancel context.CancelFunc, seen *error)
		call   func(ctx context.Context, m *session.Manager) error
		assert func(t *testing.T, err error, seen error)
	}

	revoked := func(t *testing.T, err error, seen error) {
		t.Helper()
		require.ErrorIs(t, err, session.ErrSessionReused)
		require.NoError(t, seen, "the family was revoked on the presenting request's cancelled context, so a context-honouring store aborted it and the family stays alive")
		assert.NotErrorIs(t, err, context.Canceled, "the revocation failed with the request's cancellation")
	}

	cases := []testCase{
		{
			name: "load of a superseded identifier past its window",
			expect: func(store *MockStore, cancel context.CancelFunc, seen *error) {
				store.EXPECT().Load(gomock.Any(), sid).DoAndReturn(func(context.Context, string) (*session.Session, error) {
					cancel()
					return supersededPastWindow(sid), nil
				}).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).DoAndReturn(honouringDeleteFamily(seen)).Times(1)
			},
			call: func(ctx context.Context, m *session.Manager) error {
				_, err := m.Load(ctx, sid)
				return err
			},
			assert: revoked,
		},
		{
			name: "grace renewal of a superseded identifier past its window",
			expect: func(store *MockStore, cancel context.CancelFunc, seen *error) {
				store.EXPECT().Load(gomock.Any(), sid).DoAndReturn(func(context.Context, string) (*session.Session, error) {
					cancel()
					return supersededPastWindow(sid), nil
				}).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).DoAndReturn(honouringDeleteFamily(seen)).Times(1)
			},
			call: func(ctx context.Context, m *session.Manager) error {
				_, _, err := m.RotateWithGrace(ctx, liveUnpresented(sid), session.DefaultRenewalGrace)
				return err
			},
			assert: revoked,
		},
		{
			name: "strict rotation of a superseded identifier past its window",
			expect: func(store *MockStore, cancel context.CancelFunc, seen *error) {
				store.EXPECT().Load(gomock.Any(), sid).DoAndReturn(func(context.Context, string) (*session.Session, error) {
					cancel()
					return supersededPastWindow(sid), nil
				}).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).DoAndReturn(honouringDeleteFamily(seen)).Times(1)
			},
			call: func(ctx context.Context, m *session.Manager) error {
				_, err := m.Rotate(ctx, liveUnpresented(sid))
				return err
			},
			assert: revoked,
		},
		{
			name: "grace renewal whose supersession finds the successor advanced",
			expect: func(store *MockStore, cancel context.CancelFunc, seen *error) {
				store.EXPECT().Load(gomock.Any(), sid).Return(liveUnpresented(sid), nil).Times(1)
				store.EXPECT().Supersede(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, session.Supersession) error {
					cancel()
					return session.ErrSuccessorAdvanced
				}).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).DoAndReturn(honouringDeleteFamily(seen)).Times(1)
			},
			call: func(ctx context.Context, m *session.Manager) error {
				_, _, err := m.RotateWithGrace(ctx, liveUnpresented(sid), session.DefaultRenewalGrace)
				return err
			},
			assert: revoked,
		},
		{
			name: "renewal of an ended session whose successor was used",
			opts: []session.ManagerOption{session.WithUnusedSuccessorRecovery()},
			expect: func(store *MockStore, cancel context.CancelFunc, seen *error) {
				store.EXPECT().Load(gomock.Any(), sid).DoAndReturn(func(context.Context, string) (*session.Session, error) {
					cancel()
					s := supersededPastWindow(sid)
					s.IdleExpiresAt = createdAt.Add(-time.Minute)

					return s, nil
				}).Times(1)
				store.EXPECT().SuccessorPresented(gomock.Any(), sid).DoAndReturn(func(ctx context.Context, _ string) (bool, error) {
					if err := ctx.Err(); err != nil {
						return false, err
					}

					return true, nil
				}).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).DoAndReturn(honouringDeleteFamily(seen)).Times(1)
			},
			call: func(ctx context.Context, m *session.Manager) error {
				_, err := m.LoadForRenewal(ctx, sid)
				return err
			},
			assert: revoked,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			var seen error
			store := NewMockStore(gomock.NewController(t))
			tc.expect(store, cancel, &seen)
			m := managerFor(t, append([]session.ManagerOption{session.WithStore(store), session.WithClock(clockwork.NewFakeClockAt(createdAt))}, tc.opts...)...)

			err := tc.call(ctx, m)
			tc.assert(t, err, seen)
		})
	}
}
