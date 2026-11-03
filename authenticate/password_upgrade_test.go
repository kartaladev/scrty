package authenticate_test

import (
	"bytes"
	"errors"
	"sync"
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
		assert    func(t *testing.T, u *authenticate.PasswordUpgrade, enc *upgradingEncoder, stored []byte, err error, logs func() string)
	}

	cases := []testCase{
		{
			name:  "requested and outdated, the result holds the user, the replaced hash and a new one",
			needs: true, requested: true, presented: storedPassword,
			assert: func(t *testing.T, u *authenticate.PasswordUpgrade, enc *upgradingEncoder, stored []byte, err error, _ func() string) {
				t.Helper()

				require.NoError(t, err)

				user, replaced, upgraded, ok := u.Result()
				require.True(t, ok, "an outdated hash was not upgraded")
				assert.Equal(t, "ada", user.Username)
				assert.Equal(t, stored, replaced)
				assert.NotEqual(t, stored, upgraded)
				assert.True(t, enc.Match(storedPassword, upgraded), "the new hash does not verify the password")
			},
		},
		{
			name:  "not requested, nothing is encoded or asked",
			needs: true, requested: false, presented: storedPassword,
			assert: func(t *testing.T, _ *authenticate.PasswordUpgrade, enc *upgradingEncoder, _ []byte, err error, _ func() string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, 1, enc.encodes, "a password was encoded beyond the reference hash")
				assert.Empty(t, enc.asked)
			},
		},
		{
			name:  "requested but the hash is current, nothing is encoded",
			needs: false, requested: true, presented: storedPassword,
			assert: func(t *testing.T, u *authenticate.PasswordUpgrade, enc *upgradingEncoder, _ []byte, err error, _ func() string) {
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
			assert: func(t *testing.T, u *authenticate.PasswordUpgrade, enc *upgradingEncoder, _ []byte, err error, _ func() string) {
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
			assert: func(t *testing.T, u *authenticate.PasswordUpgrade, enc *upgradingEncoder, _ []byte, err error, _ func() string) {
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
			assert: func(t *testing.T, u *authenticate.PasswordUpgrade, _ *upgradingEncoder, _ []byte, err error, _ func() string) {
				t.Helper()

				require.NoError(t, err)
				_, _, _, ok := u.Result()
				assert.False(t, ok)
			},
		},
		{
			name:  "an encoder that fails to encode leaves the login successful and logs without the hash",
			needs: true, requested: true, presented: storedPassword, fail: errors.New("entropy exhausted"),
			assert: func(t *testing.T, u *authenticate.PasswordUpgrade, _ *upgradingEncoder, stored []byte, err error, logs func() string) {
				t.Helper()

				require.NoError(t, err)
				_, _, _, ok := u.Result()
				assert.False(t, ok)
				assert.NotEmpty(t, logs(), "the failure was swallowed without a record")
				assert.NotContains(t, logs(), string(stored))
				assert.NotContains(t, logs(), storedPassword)
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
			tc.assert(t, u, enc, stored.Password, err, buf.String)
		})
	}
}

// TestPasswordUpgrade_ResultEncodesOnce pins that the provider leaves the
// encoding to the handle: nothing is encoded when the password verifies, the
// first Result encodes once, and every later Result, in turn or at once,
// answers the same hash without encoding again.
func TestPasswordUpgrade_ResultEncodesOnce(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// results asks the handle for its answer and returns every answer.
		results func(u *authenticate.PasswordUpgrade) [][]byte
		assert  func(t *testing.T, enc *upgradingEncoder, upgraded [][]byte)
	}

	once := func(t *testing.T, enc *upgradingEncoder, upgraded [][]byte) {
		t.Helper()

		assert.Equal(t, 2, enc.encodes, "the reference hash and one upgrade, no more")
		require.NotEmpty(t, upgraded)

		for _, h := range upgraded {
			assert.Equal(t, upgraded[0], h, "a later Result answered another hash")
		}

		assert.True(t, enc.Match(storedPassword, upgraded[0]), "the new hash does not verify the password")
	}

	cases := []testCase{
		{
			name: "two calls in turn",
			results: func(u *authenticate.PasswordUpgrade) [][]byte {
				var out [][]byte

				for range 2 {
					_, _, upgraded, ok := u.Result()
					if ok {
						out = append(out, upgraded)
					}
				}

				return out
			},
			assert: once,
		},
		{
			name: "calls from several goroutines at once",
			results: func(u *authenticate.PasswordUpgrade) [][]byte {
				const callers = 8

				out := make([][]byte, callers)

				var wg sync.WaitGroup
				for i := range callers {
					wg.Go(func() {
						if _, _, upgraded, ok := u.Result(); ok {
							out[i] = upgraded
						}
					})
				}

				wg.Wait()

				return out
			},
			assert: once,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inner := cheapEncoder(t)
			enc := &upgradingEncoder{Encoder: inner, needs: true}
			stored := storedUser(t, inner, true)

			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUsername(gomock.Any(), "ada").Return(stored, nil)

			auth, err := authenticate.NewUsernamePasswordAuthenticator(users, authenticate.WithPasswordEncoder(enc))
			require.NoError(t, err)

			ctx, u := authenticate.RequestPasswordUpgrade(t.Context())

			_, err = auth.Authenticate(ctx, identity.NewUsernamePassword("ada", []byte(storedPassword)))
			require.NoError(t, err)
			assert.Equal(t, 1, enc.encodes, "the password was encoded before anyone asked for the upgrade")

			tc.assert(t, enc, tc.results(u))
		})
	}
}

// TestPasswordUpgrade_Discard pins that Discard drops the presented password
// without encoding it: a Result after it answers nothing and encodes nothing,
// a Discard after Result keeps Result's answer, and Discard is idempotent and
// safe on a nil handle.
func TestPasswordUpgrade_Discard(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// run uses the handle and returns what the last Result answered.
		run    func(u *authenticate.PasswordUpgrade) (upgraded []byte, ok bool)
		assert func(t *testing.T, enc *upgradingEncoder, upgraded []byte, ok bool)
	}

	cases := []testCase{
		{
			name: "discarded before Result: no answer and no encoding",
			run: func(u *authenticate.PasswordUpgrade) ([]byte, bool) {
				u.Discard()

				_, _, upgraded, ok := u.Result()

				return upgraded, ok
			},
			assert: func(t *testing.T, enc *upgradingEncoder, upgraded []byte, ok bool) {
				t.Helper()

				assert.False(t, ok)
				assert.Empty(t, upgraded)
				assert.Equal(t, 1, enc.encodes, "a discarded password was encoded")
			},
		},
		{
			name: "discarded twice: still no answer and no encoding",
			run: func(u *authenticate.PasswordUpgrade) ([]byte, bool) {
				u.Discard()
				u.Discard()

				_, _, upgraded, ok := u.Result()

				return upgraded, ok
			},
			assert: func(t *testing.T, enc *upgradingEncoder, upgraded []byte, ok bool) {
				t.Helper()

				assert.False(t, ok)
				assert.Equal(t, 1, enc.encodes)
			},
		},
		{
			name: "discarded after Result: Result's answer is kept",
			run: func(u *authenticate.PasswordUpgrade) ([]byte, bool) {
				_, _, first, firstOK := u.Result()
				u.Discard()

				_, _, again, ok := u.Result()
				if !firstOK || !ok {
					return nil, false
				}

				if !bytes.Equal(first, again) {
					return nil, false
				}

				return again, true
			},
			assert: func(t *testing.T, enc *upgradingEncoder, upgraded []byte, ok bool) {
				t.Helper()

				assert.True(t, ok, "Discard changed an answer already given")
				assert.NotEmpty(t, upgraded)
				assert.Equal(t, 2, enc.encodes, "the reference hash and one upgrade, no more")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inner := cheapEncoder(t)
			enc := &upgradingEncoder{Encoder: inner, needs: true}
			stored := storedUser(t, inner, true)

			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUsername(gomock.Any(), "ada").Return(stored, nil)

			auth, err := authenticate.NewUsernamePasswordAuthenticator(users, authenticate.WithPasswordEncoder(enc))
			require.NoError(t, err)

			ctx, u := authenticate.RequestPasswordUpgrade(t.Context())

			_, err = auth.Authenticate(ctx, identity.NewUsernamePassword("ada", []byte(storedPassword)))
			require.NoError(t, err)

			upgraded, ok := tc.run(u)
			tc.assert(t, enc, upgraded, ok)
		})
	}

	t.Run("a nil handle is safe", func(t *testing.T) {
		t.Parallel()

		var u *authenticate.PasswordUpgrade

		assert.NotPanics(t, u.Discard)
	})
}
