package mfa_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/session"
)

func TestResetEnrolment(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	ada := &identity.Details{ID: "u-1", Username: "ada@example.com", Name: "Ada"}
	outage := errors.New("session store unavailable")

	type mocks struct {
		enrolments *MockEnrolmentRemover
		sessions   *MockSessionRevoker
		users      *MockUserLoader
		sender     *MockSender
	}

	type testCase struct {
		name string
		// deps picks which of the mocks are handed over; nil means all.
		deps   func(m mocks) mfa.ResetDeps
		opts   []mfa.ResetOption
		expect func(t *testing.T, m mocks)
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "a full reset removes, then ends sessions, then notifies the username",
			expect: func(t *testing.T, m mocks) {
				gomock.InOrder(
					m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(nil),
					m.sessions.EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).Return(nil),
					m.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(ada, nil),
					m.sender.EXPECT().Send(gomock.Any(), gomock.Any()).
						DoAndReturn(func(_ context.Context, msg notify.Message) error {
							assert.Equal(t, "ada@example.com", msg.To)
							assert.Equal(t, "Your sign-in verification was reset", msg.Subject)
							assert.Contains(t, msg.TextBody, at.Format(time.RFC1123),
								"the message names when the reset happened")
							assert.NotContains(t, msg.TextBody, "u-1", "the user reference is internal")

							return nil
						}),
				)
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "a consumer contact resolver chooses the address",
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{
					Enrolments: m.enrolments, Sessions: m.sessions, Users: m.users, Sender: m.sender,
					Contact: func(_ context.Context, d *identity.Details) (string, error) {
						return "security+" + d.Name + "@example.org", nil
					},
				}
			},
			expect: func(t *testing.T, m mocks) {
				m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(nil)
				m.sessions.EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).Return(nil)
				m.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(ada, nil)
				m.sender.EXPECT().Send(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, msg notify.Message) error {
						assert.Equal(t, "security+Ada@example.org", msg.To)

						return nil
					})
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "a failing session deleter is returned after the enrolment is removed",
			expect: func(_ *testing.T, m mocks) {
				gomock.InOrder(
					m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(nil),
					m.sessions.EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).Return(outage),
				)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, outage, "never swallowed")
			},
		},
		{
			name: "a failing removal stops the reset before sessions or notification",
			expect: func(_ *testing.T, m mocks) {
				m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(outage)
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, outage) },
		},
		{
			name: "a failing sender is returned after removal and session deletion",
			expect: func(_ *testing.T, m mocks) {
				gomock.InOrder(
					m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(nil),
					m.sessions.EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).Return(nil),
					m.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(ada, nil),
					m.sender.EXPECT().Send(gomock.Any(), gomock.Any()).Return(errors.New("queue full")),
				)
			},
			assert: func(t *testing.T, err error) { require.Error(t, err) },
		},
		{
			name: "a failing user load is returned after removal and session deletion",
			expect: func(_ *testing.T, m mocks) {
				gomock.InOrder(
					m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(nil),
					m.sessions.EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).Return(nil),
					m.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, outage),
				)
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, outage, "never swallowed") },
		},
		{
			name: "a failing address resolution is returned after removal and session deletion",
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{
					Enrolments: m.enrolments, Sessions: m.sessions, Users: m.users, Sender: m.sender,
					Contact: func(context.Context, *identity.Details) (string, error) { return "", outage },
				}
			},
			expect: func(_ *testing.T, m mocks) {
				gomock.InOrder(
					m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(nil),
					m.sessions.EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).Return(nil),
					m.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(ada, nil),
				)
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, outage, "never swallowed") },
		},
		{
			name: "a consumer message builder sets subject and body, the library the recipient",
			opts: []mfa.ResetOption{mfa.WithResetMessage(func(when time.Time) (string, string) {
				return "Security notice", "Reset on " + when.Format(time.DateOnly)
			})},
			expect: func(t *testing.T, m mocks) {
				m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(nil)
				m.sessions.EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).Return(nil)
				m.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(ada, nil)
				m.sender.EXPECT().Send(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, msg notify.Message) error {
						assert.Equal(t, "ada@example.com", msg.To, "the library sets the recipient")
						assert.Equal(t, "Security notice", msg.Subject)
						assert.Equal(t, "Reset on 2026-09-24", msg.TextBody, "the builder is given the reset time")

						return nil
					})
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:   "a nil message builder is a configuration error and removes nothing",
			opts:   []mfa.ResetOption{mfa.WithResetMessage(nil)},
			expect: func(*testing.T, mocks) {},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, mfa.ErrConfig) },
		},
		{
			name: "sessions kept: no session is deleted",
			opts: []mfa.ResetOption{mfa.WithoutSessionRevocation()},
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{Enrolments: m.enrolments, Users: m.users, Sender: m.sender}
			},
			expect: func(_ *testing.T, m mocks) {
				m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(nil)
				m.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(ada, nil)
				m.sender.EXPECT().Send(gomock.Any(), gomock.Any()).Return(nil)
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "notification off: nothing is sent and no loader or sender is needed",
			opts: []mfa.ResetOption{mfa.WithoutResetNotification()},
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{Enrolments: m.enrolments, Sessions: m.sessions}
			},
			expect: func(_ *testing.T, m mocks) {
				gomock.InOrder(
					m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(nil),
					m.sessions.EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).Return(nil),
				)
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "a missing sender with notification on is a configuration error and removes nothing",
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{Enrolments: m.enrolments, Sessions: m.sessions, Users: m.users}
			},
			expect: func(*testing.T, mocks) {},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, mfa.ErrConfig) },
		},
		{
			name: "a missing loader with notification on is a configuration error and removes nothing",
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{Enrolments: m.enrolments, Sessions: m.sessions, Sender: m.sender}
			},
			expect: func(*testing.T, mocks) {},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, mfa.ErrConfig) },
		},
		{
			name: "a missing session revoker with revocation on is a configuration error and removes nothing",
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{Enrolments: m.enrolments, Users: m.users, Sender: m.sender}
			},
			expect: func(*testing.T, mocks) {},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, mfa.ErrConfig) },
		},
		{
			name:   "a missing enrolment remover is a configuration error",
			deps:   func(m mocks) mfa.ResetDeps { return mfa.ResetDeps{Sessions: m.sessions} },
			opts:   []mfa.ResetOption{mfa.WithoutResetNotification()},
			expect: func(*testing.T, mocks) {},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, mfa.ErrConfig) },
		},
		{
			name: "a cancelled context is passed through to every step",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			expect: func(_ *testing.T, m mocks) {
				m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).
					DoAndReturn(func(ctx context.Context, _ identity.UserID) error { return ctx.Err() })
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, context.Canceled) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			m := mocks{
				enrolments: NewMockEnrolmentRemover(ctrl),
				sessions:   NewMockSessionRevoker(ctrl),
				users:      NewMockUserLoader(ctrl),
				sender:     NewMockSender(ctrl),
			}
			tc.expect(t, m)

			deps := mfa.ResetDeps{Enrolments: m.enrolments, Sessions: m.sessions, Users: m.users, Sender: m.sender}
			if tc.deps != nil {
				deps = tc.deps(m)
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			opts := append([]mfa.ResetOption{mfa.WithResetClock(func() time.Time { return at })}, tc.opts...)
			tc.assert(t, mfa.ResetEnrolment(ctx, "u-1", deps, opts...))
		})
	}
}

// TestResetEnrolmentEndToEnd runs a reset over the real TOTP method and the
// default session manager: the user is no longer enrolled, no session of theirs
// loads, a notification is queued, and their requirement is untouched.
func TestResetEnrolmentEndToEnd(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	store := mfa.NewMemoryEnrolmentStore()
	m, err := mfa.NewTOTP(store, "Example")
	require.NoError(t, err)
	enrolConfirmed(t, store, "u-1", []byte("12345678901234567890"))

	sessions, err := session.NewManager()
	require.NoError(t, err)

	first, err := sessions.Create(ctx, "u-1")
	require.NoError(t, err)
	second, err := sessions.Create(ctx, "u-1")
	require.NoError(t, err)

	sent := make(chan notify.Message, 1)
	requirement := &stubRequirement{required: map[identity.UserID]bool{"u-1": true}}

	ctrl := gomock.NewController(t)
	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
		Return(&identity.Details{ID: "u-1", Username: "ada@example.com"}, nil)
	sender := NewMockSender(ctrl)
	sender.EXPECT().Send(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, msg notify.Message) error { sent <- msg; return nil })

	require.NoError(t, mfa.ResetEnrolment(ctx, "u-1", mfa.ResetDeps{
		Enrolments: m, Sessions: sessions, Users: users, Sender: sender,
	}))

	enrolled, err := m.Enrolled(ctx, "u-1")
	require.NoError(t, err)
	assert.False(t, enrolled)

	for _, s := range []*session.Session{first, second} {
		_, err := sessions.Load(ctx, s.ID)
		require.ErrorIs(t, err, session.ErrSessionNotFound, "no session of the user loads")
	}

	select {
	case msg := <-sent:
		assert.Equal(t, "ada@example.com", msg.To)
	default:
		assert.Fail(t, "no notification was queued")
	}

	required, err := requirement.Required(ctx, "u-1")
	require.NoError(t, err)
	assert.True(t, required, "a reset never touches the requirement")
}
