package mfa_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
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
		// second is another method's remover, for the resets across methods.
		second   *MockEnrolmentRemover
		sessions *MockSessionRevoker
		users    *MockUserLoader
		sender   *MockSender
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
					Enrolments: []mfa.EnrolmentRemover{m.enrolments}, Sessions: m.sessions, Users: m.users, Sender: m.sender,
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
					Enrolments: []mfa.EnrolmentRemover{m.enrolments}, Sessions: m.sessions, Users: m.users, Sender: m.sender,
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
				return mfa.ResetDeps{Enrolments: []mfa.EnrolmentRemover{m.enrolments}, Users: m.users, Sender: m.sender}
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
				return mfa.ResetDeps{Enrolments: []mfa.EnrolmentRemover{m.enrolments}, Sessions: m.sessions}
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
				return mfa.ResetDeps{Enrolments: []mfa.EnrolmentRemover{m.enrolments}, Sessions: m.sessions, Users: m.users}
			},
			expect: func(*testing.T, mocks) {},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, mfa.ErrConfig) },
		},
		{
			name: "a missing loader with notification on is a configuration error and removes nothing",
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{Enrolments: []mfa.EnrolmentRemover{m.enrolments}, Sessions: m.sessions, Sender: m.sender}
			},
			expect: func(*testing.T, mocks) {},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, mfa.ErrConfig) },
		},
		{
			name: "a missing session revoker with revocation on is a configuration error and removes nothing",
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{Enrolments: []mfa.EnrolmentRemover{m.enrolments}, Users: m.users, Sender: m.sender}
			},
			expect: func(*testing.T, mocks) {},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, mfa.ErrConfig) },
		},
		{
			name: "reset across methods removes on every remover in order, then ends sessions and notifies",
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{
					Enrolments: []mfa.EnrolmentRemover{m.enrolments, m.second},
					Sessions:   m.sessions, Users: m.users, Sender: m.sender,
				}
			},
			expect: func(_ *testing.T, m mocks) {
				gomock.InOrder(
					m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(nil),
					m.second.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(nil),
					m.sessions.EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).Return(nil),
					m.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(ada, nil),
					m.sender.EXPECT().Send(gomock.Any(), gomock.Any()).Return(nil),
				)
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			// The mocks are strict: a session deletion or a send here would
			// fail the case as an unexpected call.
			name: "a removal fails: the first stays removed, sessions are kept and nothing is sent",
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{
					Enrolments: []mfa.EnrolmentRemover{m.enrolments, m.second},
					Sessions:   m.sessions, Users: m.users, Sender: m.sender,
				}
			},
			expect: func(_ *testing.T, m mocks) {
				gomock.InOrder(
					m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(nil),
					m.second.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(outage),
				)
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, outage) },
		},
		{
			name: "no removers is a configuration error and writes nothing",
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{Sessions: m.sessions, Users: m.users, Sender: m.sender}
			},
			expect: func(*testing.T, mocks) {},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, mfa.ErrConfig) },
		},
		{
			name: "an empty list of removers is a configuration error and writes nothing",
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{
					Enrolments: []mfa.EnrolmentRemover{}, Sessions: m.sessions, Users: m.users, Sender: m.sender,
				}
			},
			expect: func(*testing.T, mocks) {},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, mfa.ErrConfig) },
		},
		{
			name: "an absent remover is a configuration error",
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{
					Enrolments: []mfa.EnrolmentRemover{nil}, Sessions: m.sessions, Users: m.users, Sender: m.sender,
				}
			},
			expect: func(*testing.T, mocks) {},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, mfa.ErrConfig) },
		},
		{
			name: "an absent remover after a present one is refused before the first removes anything",
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{
					Enrolments: []mfa.EnrolmentRemover{m.enrolments, (*MockEnrolmentRemover)(nil)},
					Sessions:   m.sessions, Users: m.users, Sender: m.sender,
				}
			},
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
				second:     NewMockEnrolmentRemover(ctrl),
				sessions:   NewMockSessionRevoker(ctrl),
				users:      NewMockUserLoader(ctrl),
				sender:     NewMockSender(ctrl),
			}
			tc.expect(t, m)

			deps := mfa.ResetDeps{
				Enrolments: []mfa.EnrolmentRemover{m.enrolments},
				Sessions:   m.sessions, Users: m.users, Sender: m.sender,
			}
			if tc.deps != nil {
				deps = tc.deps(m)
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			opts := append([]mfa.ResetOption{mfa.WithResetClock(clockwork.NewFakeClockAt(at))}, tc.opts...)
			tc.assert(t, mfa.ResetEnrolment(ctx, "u-1", deps, opts...))
		})
	}
}

// TestResetEnrolmentClock covers the clock the notification names. The option
// is ignored when nil, typed nil included, keeping the system clock: a reset
// that refused a nil clock would fail after the enrolment is already gone.
func TestResetEnrolmentClock(t *testing.T) {
	t.Parallel()

	ada := &identity.Details{ID: "u-1", Username: "ada@example.com", Name: "Ada"}
	consumer := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

	// systemTime asserts the instant came from the system clock.
	systemTime := func(t *testing.T, before, got, after time.Time) {
		t.Helper()

		assert.False(t, got.Before(before), "the instant %s is before the reset began (%s)", got, before)
		assert.False(t, got.After(after), "the instant %s is after the reset ended (%s)", got, after)
	}

	type testCase struct {
		name   string
		opts   []mfa.ResetOption
		assert func(t *testing.T, before, got, after time.Time)
	}

	cases := []testCase{
		{name: "no clock option names the system time", assert: systemTime},
		{name: "a nil clock keeps the system clock", opts: []mfa.ResetOption{mfa.WithResetClock(nil)}, assert: systemTime},
		{
			name:   "a typed-nil clock keeps the system clock, rather than being read",
			opts:   []mfa.ResetOption{mfa.WithResetClock((*nilClock)(nil))},
			assert: systemTime,
		},
		{
			name: "a consumer clock names its own time",
			opts: []mfa.ResetOption{mfa.WithResetClock(clockwork.NewFakeClockAt(consumer))},
			assert: func(t *testing.T, _, got, _ time.Time) {
				assert.Equal(t, consumer, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			enrolments := NewMockEnrolmentRemover(ctrl)
			users := NewMockUserLoader(ctrl)
			sender := NewMockSender(ctrl)
			enrolments.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(nil)
			users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(ada, nil)
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).Return(nil)

			var named time.Time
			opts := append([]mfa.ResetOption{
				mfa.WithoutSessionRevocation(),
				mfa.WithResetMessage(func(at time.Time) (string, string) {
					named = at

					return "reset", "reset at " + at.String()
				}),
			}, tc.opts...)

			before := time.Now()
			err := mfa.ResetEnrolment(t.Context(), "u-1",
				mfa.ResetDeps{Enrolments: []mfa.EnrolmentRemover{enrolments}, Users: users, Sender: sender}, opts...)
			after := time.Now()

			require.NoError(t, err)
			tc.assert(t, before, named, after)
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
		Enrolments: []mfa.EnrolmentRemover{m}, Sessions: sessions, Users: users, Sender: sender,
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
