package authenticate_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
)

// upgradingEncoder is an encoder that counts what it is asked to encode and
// says whether any stored hash needs upgrading.
type upgradingEncoder struct {
	password.Encoder

	needs      bool
	encodeFail error
	encodes    int
	asked      [][]byte
}

func (u *upgradingEncoder) Encode(in string) ([]byte, error) {
	u.encodes++
	if u.encodeFail != nil && u.encodes > 1 { // the first is the reference hash
		return nil, u.encodeFail
	}

	return u.Encoder.Encode(in)
}

func (u *upgradingEncoder) NeedsUpgrade(encoded []byte) bool {
	u.asked = append(u.asked, encoded)

	return u.needs
}

// plainEncoder hides the Upgrader the encoder behind it may implement.
type plainEncoder struct{ password.Encoder }

func TestPasswordProvider_Upgrade(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		needs     bool
		plain     bool // a consumer encoder that is not an Upgrader
		inactive  bool // the stored account is disabled
		fail      error
		requested bool
		presented string
		assert    func(t *testing.T, u *authenticate.PasswordUpgrade, enc *upgradingEncoder, stored []byte, err error, logs string)
	}

	cases := []testCase{
		{
			name:  "requested and outdated, the result holds the user, the replaced hash and a new one",
			needs: true, requested: true, presented: storedPassword,
			assert: func(t *testing.T, u *authenticate.PasswordUpgrade, enc *upgradingEncoder, stored []byte, err error, _ string) {
				t.Helper()

				require.NoError(t, err)

				user, replaced, upgraded, ok := u.Result()
				require.True(t, ok, "an outdated hash was not upgraded")
				assert.Equal(t, "ada", user.Username)
				assert.Equal(t, stored, replaced)
				assert.NotEqual(t, stored, upgraded)
				assert.True(t, enc.Encoder.Match(storedPassword, upgraded), "the new hash does not verify the password")
			},
		},
		{
			name:  "not requested, nothing is encoded or asked",
			needs: true, requested: false, presented: storedPassword,
			assert: func(t *testing.T, _ *authenticate.PasswordUpgrade, enc *upgradingEncoder, _ []byte, err error, _ string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, 1, enc.encodes, "a password was encoded beyond the reference hash")
				assert.Empty(t, enc.asked)
			},
		},
		{
			name:  "requested but the hash is current, nothing is encoded",
			needs: false, requested: true, presented: storedPassword,
			assert: func(t *testing.T, u *authenticate.PasswordUpgrade, enc *upgradingEncoder, _ []byte, err error, _ string) {
				t.Helper()

				require.NoError(t, err)
				_, _, _, ok := u.Result()
				assert.False(t, ok)
				assert.Equal(t, 1, enc.encodes)
			},
		},
		{
			name:  "a wrong password asks nothing and encodes nothing",
			needs: true, requested: true, presented: "not-the-password",
			assert: func(t *testing.T, u *authenticate.PasswordUpgrade, enc *upgradingEncoder, _ []byte, err error, _ string) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				_, _, _, ok := u.Result()
				assert.False(t, ok)
				assert.Empty(t, enc.asked)
				assert.Equal(t, 1, enc.encodes)
			},
		},
		{
			name:  "an inactive account is refused and its hash is not upgraded",
			needs: true, requested: true, presented: storedPassword, inactive: true,
			assert: func(t *testing.T, u *authenticate.PasswordUpgrade, enc *upgradingEncoder, _ []byte, err error, _ string) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				_, _, _, ok := u.Result()
				assert.False(t, ok, "a disabled account's hash was prepared for upgrading")
				assert.Empty(t, enc.asked)
				assert.Equal(t, 1, enc.encodes, "a disabled account's password was encoded again")
			},
		},
		{
			name:  "an encoder that is not an Upgrader never upgrades",
			plain: true, requested: true, presented: storedPassword,
			assert: func(t *testing.T, u *authenticate.PasswordUpgrade, _ *upgradingEncoder, _ []byte, err error, _ string) {
				t.Helper()

				require.NoError(t, err)
				_, _, _, ok := u.Result()
				assert.False(t, ok)
			},
		},
		{
			name:  "an encoder that fails to encode leaves the login successful and logs without the hash",
			needs: true, requested: true, presented: storedPassword, fail: errors.New("entropy exhausted"),
			assert: func(t *testing.T, u *authenticate.PasswordUpgrade, _ *upgradingEncoder, stored []byte, err error, logs string) {
				t.Helper()

				require.NoError(t, err)
				_, _, _, ok := u.Result()
				assert.False(t, ok)
				assert.NotEmpty(t, logs, "the failure was swallowed without a record")
				assert.NotContains(t, logs, string(stored))
				assert.NotContains(t, logs, storedPassword)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inner := cheapEncoder(t)
			enc := &upgradingEncoder{Encoder: inner, needs: tc.needs, encodeFail: tc.fail}

			var used password.Encoder = enc
			if tc.plain {
				used = plainEncoder{inner}
			}

			stored := storedUser(t, inner, !tc.inactive)
			ctrl := gomock.NewController(t)
			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUsername(gomock.Any(), "ada").Return(stored, nil)

			buf := &bytes.Buffer{}
			auth, err := authenticate.NewUsernamePasswordAuthenticator(users,
				authenticate.WithPasswordEncoder(used), authenticate.WithPasswordLogger(debugLogger(buf)))
			require.NoError(t, err)

			ctx := t.Context()
			u := &authenticate.PasswordUpgrade{}
			if tc.requested {
				ctx, u = authenticate.RequestPasswordUpgrade(ctx)
			}

			_, err = auth.Authenticate(ctx, identity.NewUsernamePassword("ada", []byte(tc.presented)))
			tc.assert(t, u, enc, stored.Password, err, buf.String())
		})
	}
}
