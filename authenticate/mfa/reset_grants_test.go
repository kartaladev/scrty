package mfa_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// nilGrantRevoker is a revoker whose pointer is nil, as a consumer's unset
// variable would be once it reached ResetDeps.
type nilGrantRevoker struct{}

func (*nilGrantRevoker) RevokeUserGrants(context.Context, identity.UserID, string) error { return nil }

// TestResetEnrolment_RevokesGrants pins what a reset does to the user's
// application grants: revoked after the removals by default once a revoker is
// given, kept by the option while the sessions still end, a failure returned
// after the removals, and nothing changed with no provider in use.
func TestResetEnrolment_RevokesGrants(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")

	outage := errors.New("grant store secret text")

	type mocks struct {
		enrolments *MockEnrolmentRemover
		sessions   *MockSessionRevoker
		grants     *MockGrantRevoker
	}

	type testCase struct {
		name   string
		deps   func(m mocks) mfa.ResetDeps
		opts   []mfa.ResetOption
		expect func(m mocks)
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, err error)
	}

	all := func(m mocks) mfa.ResetDeps {
		return mfa.ResetDeps{Enrolments: []mfa.EnrolmentRemover{m.enrolments}, Sessions: m.sessions, Grants: m.grants}
	}

	silent := []mfa.ResetOption{mfa.WithoutResetNotification()}

	succeeds := func(t *testing.T, err error) { t.Helper(); require.NoError(t, err) }

	cases := []testCase{
		{
			name: "removes, ends the sessions, then revokes the grants with the reset's cause",
			opts: silent,
			expect: func(m mocks) {
				gomock.InOrder(
					m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), user).Return(nil),
					m.sessions.EXPECT().DeleteByUser(gomock.Any(), user).Return(nil),
					m.grants.EXPECT().RevokeUserGrants(gomock.Any(), user, "mfa_reset").Return(nil),
				)
			},
			assert: succeeds,
		},
		{
			name: "a failure is returned after the removals, behind fixed text",
			opts: silent,
			expect: func(m mocks) {
				gomock.InOrder(
					m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), user).Return(nil),
					m.sessions.EXPECT().DeleteByUser(gomock.Any(), user).Return(nil),
					m.grants.EXPECT().RevokeUserGrants(gomock.Any(), user, "mfa_reset").Return(outage),
				)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, outage, "the failure still matches")
				assert.NotContains(t, err.Error(), "secret text")
				assert.ErrorContains(t, err, "could not revoke the grants")
			},
		},
		{
			name: "a removal that fails stops the reset, revoking nothing",
			opts: silent,
			expect: func(m mocks) {
				m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), user).Return(outage)
			},
			assert: func(t *testing.T, err error) { t.Helper(); require.ErrorIs(t, err, outage) },
		},
		{
			name: "the keep option keeps the grants while the sessions still end",
			opts: append([]mfa.ResetOption{mfa.WithoutResetGrantRevocation()}, silent...),
			expect: func(m mocks) {
				m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), user).Return(nil)
				m.sessions.EXPECT().DeleteByUser(gomock.Any(), user).Return(nil)
			},
			assert: succeeds,
		},
		{
			name: "keeping the sessions does not keep the grants: the two choices are separate",
			opts: append([]mfa.ResetOption{mfa.WithoutResetSessionRevocation()}, silent...),
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{Enrolments: []mfa.EnrolmentRemover{m.enrolments}, Grants: m.grants}
			},
			expect: func(m mocks) {
				m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), user).Return(nil)
				m.grants.EXPECT().RevokeUserGrants(gomock.Any(), user, "mfa_reset").Return(nil)
			},
			assert: succeeds,
		},
		{
			name: "with no revoker the reset behaves as it always did, and no provider is required",
			opts: silent,
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{Enrolments: []mfa.EnrolmentRemover{m.enrolments}, Sessions: m.sessions}
			},
			expect: func(m mocks) {
				m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), user).Return(nil)
				m.sessions.EXPECT().DeleteByUser(gomock.Any(), user).Return(nil)
			},
			assert: succeeds,
		},
		{
			name: "a raw session store reports no end, and the grants are revoked all the same",
			opts: silent,
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{
					Enrolments: []mfa.EnrolmentRemover{m.enrolments},
					Sessions:   must.Must(session.NewMemoryStore()),
					Grants:     m.grants,
				}
			},
			expect: func(m mocks) {
				m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), user).Return(nil)
				m.grants.EXPECT().RevokeUserGrants(gomock.Any(), user, "mfa_reset").Return(nil)
			},
			assert: succeeds,
		},
		{
			name: "a typed nil revoker is refused before anything is removed",
			opts: silent,
			deps: func(m mocks) mfa.ResetDeps {
				return mfa.ResetDeps{
					Enrolments: []mfa.EnrolmentRemover{m.enrolments},
					Sessions:   m.sessions,
					Grants:     (*nilGrantRevoker)(nil),
				}
			},
			assert: func(t *testing.T, err error) { t.Helper(); require.ErrorIs(t, err, mfa.ErrConfig) },
		},
		{
			name: "a request that ended is passed on with its context, and its failure returned",
			opts: silent,
			ctx: func(ctx context.Context) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				cancel()

				return ctx
			},
			expect: func(m mocks) {
				m.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), user).Return(nil)
				m.sessions.EXPECT().DeleteByUser(gomock.Any(), user).Return(nil)
				m.grants.EXPECT().RevokeUserGrants(gomock.Any(), user, "mfa_reset").DoAndReturn(
					func(ctx context.Context, _ identity.UserID, _ string) error { return ctx.Err() })
			},
			assert: func(t *testing.T, err error) { t.Helper(); require.ErrorIs(t, err, context.Canceled) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			m := mocks{
				enrolments: NewMockEnrolmentRemover(ctrl),
				sessions:   NewMockSessionRevoker(ctrl),
				grants:     NewMockGrantRevoker(ctrl),
			}
			if tc.expect != nil {
				tc.expect(m)
			}

			deps := all(m)
			if tc.deps != nil {
				deps = tc.deps(m)
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			tc.assert(t, mfa.ResetEnrolment(ctx, user, deps, tc.opts...))
		})
	}
}
