package recovery_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/recovery"
)

// wayBackMocks are the dependencies behind one way-back check under test.
type wayBackMocks struct {
	codes *MockCodeStore
	users *MockUserLoader
	kind  *MockAuthenticatorKind
}

func newWayBackMocks(ctrl *gomock.Controller) wayBackMocks {
	return wayBackMocks{
		codes: NewMockCodeStore(ctrl),
		users: NewMockUserLoader(ctrl),
		kind:  namedKind(ctrl, recovery.MFAKind),
	}
}

func TestNewWayBackCheck(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		deps   func(t *testing.T, m wayBackMocks) recovery.WayBackDeps
		opts   []recovery.WayBackOption
		assert func(t *testing.T, c *recovery.WayBackCheck, err error)
	}

	configError := func(t *testing.T, c *recovery.WayBackCheck, err error) {
		t.Helper()
		require.ErrorIs(t, err, recovery.ErrConfig)
		assert.Nil(t, c)
	}

	cases := []testCase{
		{
			name: "users and codes are enough",
			deps: func(t *testing.T, m wayBackMocks) recovery.WayBackDeps {
				return recovery.WayBackDeps{Users: m.users, Codes: newCodes(t)}
			},
			opts: []recovery.WayBackOption{nil},
			assert: func(t *testing.T, c *recovery.WayBackCheck, err error) {
				require.NoError(t, err)
				assert.NotNil(t, c)
			},
		},
		{
			name: "nil users",
			deps: func(t *testing.T, _ wayBackMocks) recovery.WayBackDeps {
				return recovery.WayBackDeps{Codes: newCodes(t)}
			},
			assert: configError,
		},
		{
			name: "typed nil users",
			deps: func(t *testing.T, _ wayBackMocks) recovery.WayBackDeps {
				return recovery.WayBackDeps{Users: (*MockUserLoader)(nil), Codes: newCodes(t)}
			},
			assert: configError,
		},
		{
			name:   "nil codes",
			deps:   func(_ *testing.T, m wayBackMocks) recovery.WayBackDeps { return recovery.WayBackDeps{Users: m.users} },
			assert: configError,
		},
		{
			name: "a nil kind",
			deps: func(t *testing.T, m wayBackMocks) recovery.WayBackDeps {
				return recovery.WayBackDeps{Users: m.users, Codes: newCodes(t), Kinds: []recovery.AuthenticatorKind{nil}}
			},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := recovery.NewWayBackCheck(tc.deps(t, newWayBackMocks(gomock.NewController(t))), tc.opts...)
			tc.assert(t, c, err)
		})
	}
}

func TestWayBackCheck(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")
	var (
		errLookup = errors.New("enrolment lookup failed")
		errLoad   = errors.New("user store down")
		errLinks  = errors.New("link store down")
		errCodes  = errors.New("code store down")
		errAdmits = errors.New("requirement store down: dial tcp 10.0.0.9:5432")
	)

	// admitsOnly admits a login of the given kinds for user, and nothing else.
	admitsOnly := func(kinds ...factor.Kind) func(context.Context, identity.UserID, factor.Kind) (bool, error) {
		return func(_ context.Context, u identity.UserID, k factor.Kind) (bool, error) {
			if u != user {
				return false, errors.New("unexpected user")
			}

			return slices.Contains(kinds, k), nil
		}
	}

	withPassword := &identity.Details{ID: user, Username: "alice", Password: []byte("$2a$hash"), Active: true}
	withoutPassword := &identity.Details{ID: user, Username: "alice", Active: true}

	linked := func(kinds ...factor.Kind) func(context.Context, identity.UserID) ([]factor.Kind, error) {
		return func(_ context.Context, u identity.UserID) ([]factor.Kind, error) {
			if u != user {
				return nil, errors.New("unexpected user")
			}

			return kinds, nil
		}
	}

	type testCase struct {
		name   string
		deps   func(deps *recovery.WayBackDeps, m wayBackMocks)
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ok bool, err error)
	}

	yes := func(t *testing.T, ok bool, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.True(t, ok)
	}
	no := func(t *testing.T, ok bool, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.False(t, ok)
	}
	fails := func(want error) func(t *testing.T, ok bool, err error) {
		return func(t *testing.T, ok bool, err error) {
			t.Helper()
			require.ErrorIs(t, err, want)
			assert.False(t, ok)
		}
	}

	cases := []testCase{
		{
			name: "a password with issued codes enabled",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.IssuedCodes = true
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
				m.users.EXPECT().LoadByUserID(gomock.Any(), user).Return(withPassword, nil)
			},
			assert: yes,
		},
		{
			name: "a password without issued codes",
			deps: func(_ *recovery.WayBackDeps, m wayBackMocks) {
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
			},
			assert: no,
		},
		{
			name: "3 saved codes, and nothing else is looked up",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.IssuedCodes = true
				deps.LinkedLogins = linked(factor.OIDC)
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(3, nil)
			},
			assert: yes,
		},
		{
			name: "an enrolled MFA method with issued codes enabled",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.IssuedCodes = true
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
				m.users.EXPECT().LoadByUserID(gomock.Any(), user).Return(withoutPassword, nil)
				m.kind.EXPECT().Held(gomock.Any(), user).Return([]recovery.AuthenticatorRef{refTOTP}, nil)
			},
			assert: yes,
		},
		{
			name: "an enrolled MFA method without issued codes",
			deps: func(_ *recovery.WayBackDeps, m wayBackMocks) {
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
			},
			assert: no,
		},
		{
			// The default no longer counts an OIDC login, so the case states
			// the consumer's admission of it explicitly.
			name: "a linked OIDC login the consumer's admission admits",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.IssuedCodes = true
				deps.LinkedLogins = linked(factor.OIDC)
				deps.Admits = admitsOnly(factor.OIDC)
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
				m.users.EXPECT().LoadByUserID(gomock.Any(), user).Return(withoutPassword, nil)
				m.kind.EXPECT().Held(gomock.Any(), user).Return(nil, nil)
			},
			assert: yes,
		},
		{
			name: "a linked login of a kind the default does not exempt",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.LinkedLogins = linked(factor.MagicLink)
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
			},
			assert: no,
		},
		{
			name: "a linked OIDC login the consumer's admission refuses",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.LinkedLogins = linked(factor.OIDC)
				deps.Admits = admitsOnly()
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
			},
			assert: no,
		},
		{
			name: "a consumer's admission admits its own kind",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.LinkedLogins = linked(factor.Kind("corp-sso"))
				deps.Admits = admitsOnly(factor.Kind("corp-sso"))
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
			},
			assert: yes,
		},
		{
			// With no admission wired, only factor.Kind.MFAExempt counts, and
			// it no longer exempts an OIDC login: provider assurance is never
			// assumed ahead of a login.
			name: "a linked OIDC login is not a way back under the default",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.IssuedCodes = true
				deps.LinkedLogins = linked(factor.OIDC)
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
				m.users.EXPECT().LoadByUserID(gomock.Any(), user).Return(withoutPassword, nil)
				m.kind.EXPECT().Held(gomock.Any(), user).Return(nil, nil)
			},
			assert: no,
		},
		{
			name: "a linked api-key login is a way back under the default",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.LinkedLogins = linked(factor.APIKey)
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
			},
			assert: yes,
		},
		{
			name: "an admission failure is an error, not a no",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.LinkedLogins = linked(factor.OIDC)
				deps.Admits = func(context.Context, identity.UserID, factor.Kind) (bool, error) {
					return false, errAdmits
				}
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
			},
			assert: func(t *testing.T, ok bool, err error) {
				t.Helper()
				require.ErrorIs(t, err, errAdmits)
				assert.NotContains(t, err.Error(), "10.0.0.9")
				assert.False(t, ok)
			},
		},
		{
			// An admitted later kind does not excuse a failed earlier one:
			// the check fails closed rather than guess past an error.
			name: "an admission failure is an error even when a later kind would be admitted",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.LinkedLogins = linked(factor.OIDC, factor.Kind("corp-sso"))
				deps.Admits = func(_ context.Context, _ identity.UserID, k factor.Kind) (bool, error) {
					if k == factor.OIDC {
						return false, errAdmits
					}

					return true, nil
				}
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
			},
			assert: fails(errAdmits),
		},
		{
			name: "no linked-login lookup: a user with nothing else reports no",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.IssuedCodes = true
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
				m.users.EXPECT().LoadByUserID(gomock.Any(), user).Return(withoutPassword, nil)
				m.kind.EXPECT().Held(gomock.Any(), user).Return(nil, nil)
			},
			assert: no,
		},
		{
			name: "an enrolment lookup failure is an error",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.IssuedCodes = true
				deps.LinkedLogins = linked(factor.OIDC)
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
				m.users.EXPECT().LoadByUserID(gomock.Any(), user).Return(withoutPassword, nil)
				m.kind.EXPECT().Held(gomock.Any(), user).Return(nil, errLookup)
			},
			assert: fails(errLookup),
		},
		{
			name: "a user loader failure is an error",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.IssuedCodes = true
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
				m.users.EXPECT().LoadByUserID(gomock.Any(), user).Return(nil, errLoad)
			},
			assert: fails(errLoad),
		},
		{
			name: "an unknown user is an error, not a no",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.IssuedCodes = true
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
				m.users.EXPECT().LoadByUserID(gomock.Any(), user).Return(nil, identity.ErrUserNotFound)
			},
			assert: fails(identity.ErrUserNotFound),
		},
		{
			name: "a user loader outage does not read as an unknown user",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.IssuedCodes = true
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
				m.users.EXPECT().LoadByUserID(gomock.Any(), user).Return(nil, errLoad)
			},
			assert: func(t *testing.T, ok bool, err error) {
				t.Helper()
				require.ErrorIs(t, err, errLoad)
				assert.NotErrorIs(t, err, identity.ErrUserNotFound)
				assert.False(t, ok)
			},
		},
		{
			name: "a linked-login lookup failure is an error",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.LinkedLogins = func(context.Context, identity.UserID) ([]factor.Kind, error) { return nil, errLinks }
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
			},
			assert: fails(errLinks),
		},
		{
			name: "a saved-code lookup failure is an error",
			deps: func(deps *recovery.WayBackDeps, m wayBackMocks) {
				deps.IssuedCodes = true
				m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, errCodes)
			},
			assert: fails(errCodes),
		},
		{
			name: "a cancelled context reaches the lookups",
			deps: func(_ *recovery.WayBackDeps, m wayBackMocks) {
				m.codes.EXPECT().Remaining(gomock.Any(), user).DoAndReturn(func(ctx context.Context, _ identity.UserID) (int, error) {
					return 0, ctx.Err()
				})
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: fails(context.Canceled),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := newWayBackMocks(gomock.NewController(t))
			deps := recovery.WayBackDeps{
				Users: m.users,
				Codes: newCodes(t, recovery.WithCodeStore(m.codes)),
				Kinds: []recovery.AuthenticatorKind{m.kind},
			}
			tc.deps(&deps, m)

			c, err := recovery.NewWayBackCheck(deps)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			ok, err := c.HasWayBack(ctx, user)
			tc.assert(t, ok, err)
		})
	}
}
