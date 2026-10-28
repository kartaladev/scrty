package recovery_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
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
				Codes: newCodes(t, recovery.WithCodesStore(m.codes)),
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

// TestHasWayBack_LinkedProvider pins that a linked OIDC identity counts as a
// way back exactly when the MFA requirement policy, wired through
// WayBackDeps.Admits, would admit its login without a local second factor.
// The user has nothing else: no saved codes, no password, no authenticator.
// It stands apart from TestWayBackCheck because each case builds a real MFA
// requirement policy over a mocked lookup.
func TestHasWayBack_LinkedProvider(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")
	errLookup := errors.New("requirement store down: dial tcp 10.0.0.7:5432")

	type testCase struct {
		name   string
		mode   policy.FederatedAssuranceMode
		opts   []policy.MFARequirementOption
		lookup func(m *MockMFARequirementLookup)
		assert func(t *testing.T, ok bool, err error)
	}

	cases := []testCase{
		{
			// Exempt mode admits before the requirement is looked up.
			name:   "linked provider under the exempt mode",
			mode:   policy.FederatedAssuranceExempt,
			lookup: func(*MockMFARequirementLookup) {},
			assert: func(t *testing.T, ok bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, ok)
			},
		},
		{
			// An exemption rule that marks the oidc kind exempt is a total
			// exemption, so the login is admitted before any lookup.
			name: "linked provider under an exemption rule that exempts oidc",
			mode: policy.FederatedAssuranceChallenge,
			opts: []policy.MFARequirementOption{
				policy.WithMFAExemption(func(k factor.Kind) bool { return k == factor.OIDC }),
			},
			lookup: func(*MockMFARequirementLookup) {},
			assert: func(t *testing.T, ok bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, ok)
			},
		},
		{
			name: "linked provider, required user, default mode",
			mode: policy.FederatedAssuranceChallenge,
			lookup: func(m *MockMFARequirementLookup) {
				m.EXPECT().Required(gomock.Any(), user).Return(true, nil)
			},
			assert: func(t *testing.T, ok bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, ok)
			},
		},
		{
			name: "linked provider, user not required",
			mode: policy.FederatedAssuranceChallenge,
			lookup: func(m *MockMFARequirementLookup) {
				m.EXPECT().Required(gomock.Any(), user).Return(false, nil)
			},
			assert: func(t *testing.T, ok bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, ok)
			},
		},
		{
			name: "requirement lookup failure",
			mode: policy.FederatedAssuranceChallenge,
			lookup: func(m *MockMFARequirementLookup) {
				m.EXPECT().Required(gomock.Any(), user).Return(false, errLookup)
			},
			assert: func(t *testing.T, ok bool, err error) {
				t.Helper()
				require.ErrorIs(t, err, errLookup)
				assert.NotContains(t, err.Error(), "10.0.0.7")
				assert.False(t, ok)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			lookup := NewMockMFARequirementLookup(ctrl)
			tc.lookup(lookup)

			p, err := policy.NewMFARequirement(lookup, nil,
				append([]policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(tc.mode)}, tc.opts...)...)
			require.NoError(t, err)
			adm, ok := p.(policy.LoginAdmission)
			require.True(t, ok, "the requirement policy must implement LoginAdmission")

			m := newWayBackMocks(ctrl)
			m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)

			c, err := recovery.NewWayBackCheck(recovery.WayBackDeps{
				Users: m.users,
				Codes: newCodes(t, recovery.WithCodesStore(m.codes)),
				Kinds: []recovery.AuthenticatorKind{m.kind},
				LinkedLogins: func(context.Context, identity.UserID) ([]factor.Kind, error) {
					return []factor.Kind{factor.OIDC}, nil
				},
				Admits: adm.AdmitsWithoutLocalSecondFactor,
			})
			require.NoError(t, err)

			got, err := c.HasWayBack(t.Context(), user)
			tc.assert(t, got, err)
		})
	}
}

// TestHasWayBack_IssuedCodePairing pins that the way-back check counts only
// the pairings a recovery accepts, over the library's own MFA kind: an MFA
// method delivered by email does not pair with an issued code, which arrives
// by email too, and a loader that finds no user is a user with nothing.
// It stands apart from TestWayBackCheck because its cases run over the
// library's own MFA kind rather than a mocked one.
func TestHasWayBack_IssuedCodePairing(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")
	withoutPassword := &identity.Details{ID: user, Username: "alice", Active: true}

	type testCase struct {
		name   string
		setup  func(set mfaMethods, users *MockUserLoader)
		assert func(t *testing.T, ok bool, err error)
	}

	cases := []testCase{
		{
			name: "only an emailed MFA method with issued codes is no way back",
			setup: func(set mfaMethods, users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), user).Return(withoutPassword, nil)
				set.methods["totp"].EXPECT().Enrolled(gomock.Any(), user).Return(false, nil)
				set.methods["email-code"].EXPECT().Enrolled(gomock.Any(), user).Return(true, nil)
			},
			assert: func(t *testing.T, ok bool, err error) {
				require.NoError(t, err)
				assert.False(t, ok, "an emailed MFA method was counted as pairing with an emailed issued code")
			},
		},
		{
			name: "TOTP with issued codes is a way back",
			setup: func(set mfaMethods, users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), user).Return(withoutPassword, nil)
				set.methods["totp"].EXPECT().Enrolled(gomock.Any(), user).Return(true, nil)
				set.methods["email-code"].EXPECT().Enrolled(gomock.Any(), user).Return(true, nil).AnyTimes()
			},
			assert: func(t *testing.T, ok bool, err error) {
				require.NoError(t, err)
				assert.True(t, ok)
			},
		},
		{
			name: "a loader with no details does not panic, and the kinds still count",
			setup: func(set mfaMethods, users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), user).Return(nil, nil)
				set.methods["totp"].EXPECT().Enrolled(gomock.Any(), user).Return(true, nil)
				set.methods["email-code"].EXPECT().Enrolled(gomock.Any(), user).Return(false, nil).AnyTimes()
			},
			assert: func(t *testing.T, ok bool, err error) {
				require.NoError(t, err)
				assert.True(t, ok)
			},
		},
		{
			name: "a loader with no details and nothing held is no way back",
			setup: func(set mfaMethods, users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), user).Return(nil, nil)
				set.methods["totp"].EXPECT().Enrolled(gomock.Any(), user).Return(false, nil)
				set.methods["email-code"].EXPECT().Enrolled(gomock.Any(), user).Return(false, nil)
			},
			assert: func(t *testing.T, ok bool, err error) {
				require.NoError(t, err)
				assert.False(t, ok)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			set, methods := removableMethods(ctrl)
			users := NewMockUserLoader(ctrl)
			codes := NewMockCodeStore(ctrl)
			codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
			tc.setup(set, users)

			kind, err := recovery.MFAEnrolments(methods...)
			require.NoError(t, err)

			c, err := recovery.NewWayBackCheck(recovery.WayBackDeps{
				Users:       users,
				Codes:       newCodes(t, recovery.WithCodesStore(codes)),
				Kinds:       []recovery.AuthenticatorKind{kind},
				IssuedCodes: true,
			})
			require.NoError(t, err)

			ok, err := c.HasWayBack(t.Context(), user)
			tc.assert(t, ok, err)
		})
	}
}

// usableKind is a kind that also reports which of its authenticators can
// authenticate now, as a passkey kind holding pending or suspended
// credentials does.
type usableKind struct {
	*MockAuthenticatorKind
	*MockUsableLister
}

var (
	_ recovery.AuthenticatorKind = usableKind{}
	_ recovery.UsableLister      = usableKind{}
)

// TestWayBack_Usable pins that a kind which can tell usable authenticators
// from held ones is counted by what is usable: a user whose only authenticator
// is suspended has no way back through it. A kind that cannot tell is counted
// by what it holds.
// It stands apart from TestWayBackCheck because some cases wrap the kind in a
// UsableLister.
func TestWayBack_Usable(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")

	errUsable := errors.New("usable lookup failed")
	held := []recovery.AuthenticatorRef{{Kind: "passkey", ID: "pk-1"}}
	withoutPassword := &identity.Details{ID: user, Username: "alice", Active: true}

	type testCase struct {
		name string
		// usable wires the kind's Usable; nil means the kind is not a
		// UsableLister at all.
		usable func(u *MockUsableLister)
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ok bool, err error)
	}

	cases := []testCase{
		{
			name: "usable empty",
			usable: func(u *MockUsableLister) {
				u.EXPECT().Usable(gomock.Any(), user).Return(nil, nil)
			},
			assert: func(t *testing.T, ok bool, err error) {
				require.NoError(t, err)
				assert.False(t, ok, "a held authenticator that cannot authenticate is no way back")
			},
		},
		{
			name: "usable one",
			usable: func(u *MockUsableLister) {
				u.EXPECT().Usable(gomock.Any(), user).Return(held, nil)
			},
			assert: func(t *testing.T, ok bool, err error) {
				require.NoError(t, err)
				assert.True(t, ok)
			},
		},
		{
			name: "usable error",
			usable: func(u *MockUsableLister) {
				u.EXPECT().Usable(gomock.Any(), user).Return(nil, errUsable)
			},
			assert: func(t *testing.T, ok bool, err error) {
				require.ErrorIs(t, err, errUsable, "a failed lookup is an error, never no")
				assert.False(t, ok)
			},
		},
		{
			name: "usable canceled context",
			usable: func(u *MockUsableLister) {
				u.EXPECT().Usable(gomock.Any(), user).
					DoAndReturn(func(ctx context.Context, _ identity.UserID) ([]recovery.AuthenticatorRef, error) {
						return nil, ctx.Err()
					})
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, ok bool, err error) {
				require.ErrorIs(t, err, context.Canceled, "the caller's context reaches the lookup")
				assert.False(t, ok)
			},
		},
		{
			name: "no UsableLister",
			assert: func(t *testing.T, ok bool, err error) {
				require.NoError(t, err)
				assert.True(t, ok, "every held authenticator counts")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			m := newWayBackMocks(ctrl)
			m.codes.EXPECT().Remaining(gomock.Any(), user).Return(0, nil)
			m.users.EXPECT().LoadByUserID(gomock.Any(), user).Return(withoutPassword, nil)

			var kind recovery.AuthenticatorKind = m.kind
			if tc.usable != nil {
				u := NewMockUsableLister(ctrl)
				tc.usable(u)
				kind = usableKind{MockAuthenticatorKind: m.kind, MockUsableLister: u}
				// The reset lists Held; the way-back check must not.
				m.kind.EXPECT().Held(gomock.Any(), user).Return(held, nil).AnyTimes()
			} else {
				m.kind.EXPECT().Held(gomock.Any(), user).Return(held, nil)
			}

			c, err := recovery.NewWayBackCheck(recovery.WayBackDeps{
				Users:       m.users,
				Codes:       newCodes(t, recovery.WithCodesStore(m.codes)),
				Kinds:       []recovery.AuthenticatorKind{kind},
				IssuedCodes: true,
			})
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
