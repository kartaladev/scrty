package admin_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
)

const goodPassword = "correct horse battery staple"

func TestUsers_SetPasswordReuseRefused(t *testing.T) {
	t.Parallel()

	encoder, err := password.NewArgon2idEncoder()
	require.NoError(t, err)
	old, err := encoder.Encode(goodPassword)
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	history := NewMockHistory(ctrl)
	history.EXPECT().RecentPasswords(gomock.Any(), identity.UserID("u-1"), 2).Return(nil, nil).AnyTimes()

	policy, err := password.NewPolicy(password.NoReuse(history, 3))
	require.NoError(t, err)

	// Only the read of the user is expected: SetPassword on the store must not be called.
	store := NewMockUserStore(ctrl)
	store.EXPECT().GetUser(gomock.Any(), identity.UserID("u-1")).
		Return(admin.User{ID: "u-1", Username: "ada", Version: 4}, nil)
	store.EXPECT().CurrentPasswordHash(gomock.Any(), identity.UserID("u-1")).Return(old, nil)

	_, err = newUsers(t, store, admin.WithPasswordPolicy(policy)).
		SetPassword(actorCtx(t), "u-1", 4, []byte(goodPassword))
	assert.ErrorIs(t, err, password.ErrReused)
	assert.NotContains(t, err.Error(), string(old))
}

func TestUsers_SetPasswordReuseOfRetiredHashRefused(t *testing.T) {
	t.Parallel()

	encoder, err := password.NewArgon2idEncoder()
	require.NoError(t, err)
	old, err := encoder.Encode(goodPassword)
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	history := NewMockHistory(ctrl)
	history.EXPECT().RecentPasswords(gomock.Any(), identity.UserID("u-1"), 2).Return([][]byte{old}, nil)
	policy, err := password.NewPolicy(password.NoReuse(history, 3))
	require.NoError(t, err)

	store := NewMockUserStore(ctrl)
	store.EXPECT().GetUser(gomock.Any(), identity.UserID("u-1")).Return(admin.User{ID: "u-1", Version: 4}, nil)
	store.EXPECT().CurrentPasswordHash(gomock.Any(), identity.UserID("u-1")).Return(nil, nil)

	_, err = newUsers(t, store, admin.WithPasswordPolicy(policy)).
		SetPassword(actorCtx(t), "u-1", 4, []byte(goodPassword))
	assert.ErrorIs(t, err, password.ErrReused)
}

func TestUsers_SetPasswordRecordsChange(t *testing.T) {
	t.Parallel()

	encoder, err := password.NewArgon2idEncoder()
	require.NoError(t, err)

	store := NewMockUserStore(gomock.NewController(t))
	store.EXPECT().GetUser(gomock.Any(), identity.UserID("u-1")).Return(admin.User{ID: "u-1", Version: 4}, nil)
	store.EXPECT().CurrentPasswordHash(gomock.Any(), identity.UserID("u-1")).Return(nil, nil)

	var gotHash []byte
	var gotAt time.Time
	store.EXPECT().SetPassword(gomock.Any(), identity.UserID("u-1"), int64(4), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ identity.UserID, _ int64, hash []byte, at time.Time) (admin.User, error) {
			gotHash, gotAt = bytes.Clone(hash), at
			return admin.User{ID: "u-1", Version: 5}, nil
		})

	u, err := newUsers(t, store, admin.WithClock(fixedClock()), admin.WithPasswordEncoder(encoder)).
		SetPassword(actorCtx(t), "u-1", 4, []byte(goodPassword))
	require.NoError(t, err)

	assert.Equal(t, int64(5), u.Version)
	assert.True(t, encoder.Match(goodPassword, gotHash), "the stored hash verifies the password")
	assert.NotContains(t, string(gotHash), goodPassword)
	assert.True(t, gotAt.Equal(testNow), "the change time is the service clock's time, got %s", gotAt)
}

func TestUsers_SetPassword(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		version int64
		plain   []byte
		policy  func(t *testing.T) *password.Policy
		encoder func(t *testing.T) password.Encoder
		setup   func(s *MockUserStore)
		assert  func(t *testing.T, err error)
	}

	getUser := func(s *MockUserStore) {
		s.EXPECT().GetUser(gomock.Any(), identity.UserID("u-1")).Return(admin.User{ID: "u-1", Username: "ada", Version: 1}, nil)
		s.EXPECT().CurrentPasswordHash(gomock.Any(), identity.UserID("u-1")).Return(nil, nil).AnyTimes()
	}
	nothing := func(*MockUserStore) {}
	invalid := func(t *testing.T, err error) { assert.ErrorIs(t, err, admin.ErrInvalidInput) }
	rejected := func(rule password.Rule) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			assert.ErrorIs(t, err, password.ErrPasswordRejected)
			var re password.RejectedError
			require.ErrorAs(t, err, &re)
			assert.Equal(t, rule, re.Rule)
		}
	}

	cases := []testCase{
		{name: "too short is refused by the policy", version: 1, plain: []byte("short"), setup: getUser, assert: rejected(password.RuleTooShort)},
		{name: "empty is refused by the policy", version: 1, plain: nil, setup: getUser, assert: rejected(password.RuleTooShort)},
		{name: "huge input is refused before conversion", version: 1, plain: bytes.Repeat([]byte("a"), admin.MaxPasswordBytes+1), setup: nothing, assert: rejected(password.RuleTooLong)},
		{name: "version zero", version: 0, plain: []byte(goodPassword), setup: nothing, assert: invalid},
		{
			name: "NUL byte is refused with the encoder's error", version: 1, plain: []byte(goodPassword + "\x00x"), setup: getUser,
			encoder: func(t *testing.T) password.Encoder {
				e, err := password.NewBcryptEncoder()
				require.NoError(t, err)
				return e
			},
			assert: func(t *testing.T, err error) { assert.ErrorIs(t, err, password.ErrContainsNUL) },
		},
		{
			name: "unknown user", version: 1, plain: []byte(goodPassword),
			setup: func(s *MockUserStore) {
				s.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(admin.User{}, admin.ErrNotFound)
			},
			assert: func(t *testing.T, err error) { assert.ErrorIs(t, err, admin.ErrNotFound) },
		},
		{
			name: "current hash unreadable", version: 1, plain: []byte(goodPassword),
			setup: func(s *MockUserStore) {
				s.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(admin.User{ID: "u-1", Version: 1}, nil)
				s.EXPECT().CurrentPasswordHash(gomock.Any(), gomock.Any()).Return(nil, errStorage)
			},
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, errStorage)
				for _, r := range reasons {
					assert.NotErrorIs(t, err, r)
				}
			},
		},
		{
			name: "current hash of a vanished user", version: 1, plain: []byte(goodPassword),
			setup: func(s *MockUserStore) {
				s.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(admin.User{ID: "u-1", Version: 1}, nil)
				s.EXPECT().CurrentPasswordHash(gomock.Any(), gomock.Any()).Return(nil, admin.ErrNotFound)
			},
			assert: func(t *testing.T, err error) { assert.ErrorIs(t, err, admin.ErrNotFound) },
		},
		{
			name: "history unreadable fails closed", version: 1, plain: []byte(goodPassword),
			policy: func(t *testing.T) *password.Policy {
				h := NewMockHistory(gomock.NewController(t))
				h.EXPECT().RecentPasswords(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("history down"))
				p, err := password.NewPolicy(password.NoReuse(h, 3))
				require.NoError(t, err)
				return p
			},
			setup:  getUser,
			assert: func(t *testing.T, err error) { assert.ErrorIs(t, err, password.ErrHistoryUnavailable) },
		},
		{
			name: "stale version passes through", version: 1, plain: []byte(goodPassword),
			setup: func(s *MockUserStore) {
				getUser(s)
				s.EXPECT().SetPassword(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(admin.User{}, admin.ErrStaleUpdate)
			},
			assert: func(t *testing.T, err error) { assert.ErrorIs(t, err, admin.ErrStaleUpdate) },
		},
		{
			name: "storage failure leaks neither password nor hash", version: 1, plain: []byte(goodPassword),
			setup: func(s *MockUserStore) {
				getUser(s)
				s.EXPECT().SetPassword(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(admin.User{}, errStorage)
			},
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, errStorage)
				assert.False(t, strings.Contains(err.Error(), goodPassword))
				for _, r := range reasons {
					assert.NotErrorIs(t, err, r)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockUserStore(gomock.NewController(t))
			tc.setup(store)

			var opts []admin.UsersOption
			if tc.policy != nil {
				opts = append(opts, admin.WithPasswordPolicy(tc.policy(t)))
			}

			if tc.encoder != nil {
				opts = append(opts, admin.WithPasswordEncoder(tc.encoder(t)))
			}

			plain := bytes.Clone(tc.plain)
			_, err := newUsers(t, store, opts...).SetPassword(actorCtx(t), "u-1", tc.version, plain)
			tc.assert(t, err)
			assert.Equal(t, tc.plain, plain, "the caller's buffer is not modified")
		})
	}
}

// TestUsers_SetPasswordTooLong pins both ways a password too long for the
// encoder is refused: by the default policy, which is built with the
// configured encoder and so knows its stated limit before any hashing, and by
// the encoder's own ErrTooLong when it states none. Either is a rejection, not
// a failure, and nothing is stored.
func TestUsers_SetPasswordTooLong(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		encoder func(enc *MocklimitedEncoder)
	}

	cases := []testCase{
		{
			name: "the default policy refuses beyond the encoder's stated limit, before encoding",
			encoder: func(enc *MocklimitedEncoder) {
				enc.EXPECT().MaxInputBytes().Return(20).AnyTimes()
			},
		},
		{
			name: "the encoder's ErrTooLong is a rejection",
			encoder: func(enc *MocklimitedEncoder) {
				enc.EXPECT().MaxInputBytes().Return(0).AnyTimes()
				enc.EXPECT().Encode(gomock.Any()).Return(nil, password.ErrTooLong)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			enc := NewMocklimitedEncoder(ctrl)
			tc.encoder(enc)

			store := NewMockUserStore(ctrl)
			store.EXPECT().GetUser(gomock.Any(), identity.UserID("u-1")).Return(admin.User{ID: "u-1", Version: 4}, nil)
			store.EXPECT().CurrentPasswordHash(gomock.Any(), identity.UserID("u-1")).Return(nil, nil)

			_, err := newUsers(t, store, admin.WithPasswordEncoder(enc)).
				SetPassword(actorCtx(t), "u-1", 4, []byte(strings.Repeat("x", 25)))
			require.ErrorIs(t, err, password.ErrPasswordRejected)

			var rejected password.RejectedError
			require.ErrorAs(t, err, &rejected)
			assert.Equal(t, password.RuleTooLong, rejected.Rule)
		})
	}
}

// TestUsers_SetPasswordStaleRead pins that a user whose stored version is not
// the caller's is refused as stale before the policy runs or a hash is made.
func TestUsers_SetPasswordStaleRead(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	enc := NewMocklimitedEncoder(ctrl)
	enc.EXPECT().MaxInputBytes().Return(0).AnyTimes()

	store := NewMockUserStore(ctrl)
	store.EXPECT().GetUser(gomock.Any(), identity.UserID("u-1")).Return(admin.User{ID: "u-1", Version: 5}, nil)

	_, err := newUsers(t, store, admin.WithPasswordEncoder(enc)).
		SetPassword(actorCtx(t), "u-1", 4, []byte(goodPassword))
	require.ErrorIs(t, err, admin.ErrStaleUpdate)
}

// TestUsers_SetPasswordRetiresThroughPolicy pins that the password history
// follows the policy: its reuse rule retires the replaced hash through the
// consumer's history, pruned to the rule's depth, before the store writes the
// new hash once.
func TestUsers_SetPasswordRetiresThroughPolicy(t *testing.T) {
	t.Parallel()

	encoder, err := password.NewArgon2idEncoder()
	require.NoError(t, err)
	old, err := encoder.Encode("an older passphrase nobody reuses")
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	history := NewMockHistory(ctrl)
	store := NewMockUserStore(ctrl)

	store.EXPECT().GetUser(gomock.Any(), identity.UserID("u-1")).Return(admin.User{ID: "u-1", Version: 4}, nil)
	store.EXPECT().CurrentPasswordHash(gomock.Any(), identity.UserID("u-1")).Return(old, nil)
	history.EXPECT().RecentPasswords(gomock.Any(), identity.UserID("u-1"), 2).Return(nil, nil)
	gomock.InOrder(
		history.EXPECT().RetirePassword(gomock.Any(), identity.UserID("u-1"), old, 2).Return(nil),
		store.EXPECT().SetPassword(gomock.Any(), identity.UserID("u-1"), int64(4), gomock.Any(), testNow).
			Return(admin.User{ID: "u-1", Version: 5}, nil).Times(1),
	)

	policy, err := password.NewPolicy(password.NoReuse(history, 3), password.WithEncoder(encoder))
	require.NoError(t, err)

	u, err := newUsers(t, store, admin.WithPasswordPolicy(policy), admin.WithClock(fixedClock())).
		SetPassword(actorCtx(t), "u-1", 4, []byte(goodPassword))
	require.NoError(t, err)
	assert.Equal(t, int64(5), u.Version)
}

// TestUsers_EncoderAndPolicyTogetherRefused pins that a consumer policy and a
// separate encoder are refused at construction: the policy encodes the new
// password, so the encoder would be silently ignored.
func TestUsers_EncoderAndPolicyTogetherRefused(t *testing.T) {
	t.Parallel()

	encoder, err := password.NewBcryptEncoder()
	require.NoError(t, err)
	policy, err := password.NewPolicy()
	require.NoError(t, err)

	_, err = admin.NewUsers(NewMockUserStore(gomock.NewController(t)),
		admin.WithPasswordEncoder(encoder), admin.WithPasswordPolicy(policy))
	require.ErrorIs(t, err, admin.ErrConfig)
}
