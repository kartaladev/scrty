package recovery_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/recovery"
)

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
				Codes:       newCodes(t, recovery.WithCodeStore(m.codes)),
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
