package authenticate_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/password"
)

// presentedPassword is what every refusal case below presents. No stored user
// has it, so the only thing that could ever distinguish these refusals is how
// the provider reached them.
const presentedPassword = "hunter2"

// storedPassword is the password the known users in these cases actually have.
const storedPassword = "correct-horse-battery-staple"

func TestPasswordAuthenticatorDoesNotRevealWhyItFailed(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		creds  func(t *testing.T) identity.Credentials
		users  func(t *testing.T, ctrl *gomock.Controller, inner password.Encoder) identity.UserLoader
		assert func(t *testing.T, err error, enc *recordingEncoder)
	}

	// bare is the whole of what a caller may learn: the sentinel itself, with
	// nothing wrapped and nothing added. Two refusals that both satisfy this
	// are indistinguishable from outside.
	bare := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
		assert.Equal(t, authenticate.ErrAuthenticationFailed, err,
			"the refusal carried detail a caller could tell refusals apart by")
	}

	cases := []testCase{
		{
			name: "an unknown user still costs a password comparison",
			users: func(t *testing.T, ctrl *gomock.Controller, _ password.Encoder) identity.UserLoader {
				t.Helper()

				users := NewMockUserLoader(ctrl)
				users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
					Return(nil, identity.ErrUserNotFound)

				return users
			},
			assert: func(t *testing.T, err error, enc *recordingEncoder) {
				t.Helper()

				bare(t, err)

				matches, matchedTo := enc.calls()
				require.Equal(t, 1, matches,
					"the unknown-user path skipped the comparison, so it is faster than a wrong password")
				assert.Equal(t, enc.reference(t), matchedTo[0],
					"the comparison ran against something other than the construction-time reference hash")
			},
		},
		{
			name: "a wrong password returns the same bare sentinel",
			users: func(t *testing.T, ctrl *gomock.Controller, inner password.Encoder) identity.UserLoader {
				t.Helper()

				users := NewMockUserLoader(ctrl)
				users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
					Return(storedUser(t, inner, true), nil)

				return users
			},
			assert: func(t *testing.T, err error, enc *recordingEncoder) {
				t.Helper()

				bare(t, err)

				matches, _ := enc.calls()
				assert.Equal(t, 1, matches)
			},
		},
		{
			name: "a loader failure returns the same bare sentinel, and still pays for a comparison",
			users: func(t *testing.T, ctrl *gomock.Controller, _ password.Encoder) identity.UserLoader {
				t.Helper()

				users := NewMockUserLoader(ctrl)
				users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
					Return(nil, errBackendDown)

				return users
			},
			assert: func(t *testing.T, err error, enc *recordingEncoder) {
				t.Helper()

				bare(t, err)
				assert.NotErrorIs(t, err, errBackendDown,
					"the outage reached the caller, who can now tell a broken store from a wrong password")

				matches, matchedTo := enc.calls()
				require.Equal(t, 1, matches)
				assert.Equal(t, enc.reference(t), matchedTo[0])
			},
		},
		{
			name: "a loader returning neither a user nor an error is a refusal, not a nil dereference",
			users: func(t *testing.T, ctrl *gomock.Controller, _ password.Encoder) identity.UserLoader {
				t.Helper()

				users := NewMockUserLoader(ctrl)
				users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).Return(nil, nil)

				return users
			},
			assert: func(t *testing.T, err error, enc *recordingEncoder) {
				t.Helper()

				bare(t, err)

				matches, _ := enc.calls()
				assert.Equal(t, 1, matches)
			},
		},
		{
			name: "an inactive account with a wrong password is indistinguishable from an active one",
			users: func(t *testing.T, ctrl *gomock.Controller, inner password.Encoder) identity.UserLoader {
				t.Helper()

				users := NewMockUserLoader(ctrl)
				users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
					Return(storedUser(t, inner, false), nil)

				return users
			},
			assert: func(t *testing.T, err error, enc *recordingEncoder) {
				t.Helper()

				bare(t, err)

				matches, _ := enc.calls()
				assert.Equal(t, 1, matches)
			},
		},
		{
			name:  "an inactive account with the right password is still refused, after the comparison",
			creds: rightPassword,
			users: func(t *testing.T, ctrl *gomock.Controller, inner password.Encoder) identity.UserLoader {
				t.Helper()

				users := NewMockUserLoader(ctrl)
				users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
					Return(storedUser(t, inner, false), nil)

				return users
			},
			assert: func(t *testing.T, err error, enc *recordingEncoder) {
				t.Helper()

				bare(t, err)

				matches, _ := enc.calls()
				assert.Equal(t, 1, matches,
					"Active was read before the password, so a disabled account is observable without it")
			},
		},
		{
			name: "credentials of another kind are skipped without reaching the user loader",
			creds: func(t *testing.T) identity.Credentials {
				t.Helper()

				return authenticate.NewBearerToken("a.b.c")
			},
			users: func(t *testing.T, ctrl *gomock.Controller, _ password.Encoder) identity.UserLoader {
				t.Helper()

				// No EXPECT: a provider that loads before it knows the
				// credential kind hands the store traffic it cannot use.
				return NewMockUserLoader(ctrl)
			},
			assert: func(t *testing.T, err error, enc *recordingEncoder) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrUnsupportedCredentials)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed,
					"a skip was reported as a judged refusal, which stops the manager")

				matches, _ := enc.calls()
				assert.Zero(t, matches)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			inner := cheapEncoder(t)
			enc := newRecordingEncoder(t, ctrl, inner)

			auth, err := authenticate.NewUsernamePasswordAuthenticator(
				tc.users(t, ctrl, inner), authenticate.WithPasswordEncoder(enc))
			require.NoError(t, err)

			creds := identity.Credentials(identity.NewUsernamePassword("ada", []byte(presentedPassword)))
			if tc.creds != nil {
				creds = tc.creds(t)
			}

			_, err = auth.Authenticate(t.Context(), creds)
			tc.assert(t, err, enc)
		})
	}
}

// cheapEncoder returns a real encoder at the weakest parameters the library
// accepts. The algorithm and its output format are what these tests care about;
// the cost is what makes a table of them run in reasonable time.
func cheapEncoder(t *testing.T) password.Encoder {
	t.Helper()

	enc, err := password.NewArgon2idEncoder(
		password.WithArgon2idMemory(19*1024),
		password.WithArgon2idIterations(2),
	)
	require.NoError(t, err)

	return enc
}

// storedUser returns the record a user loader reports for a known user.
func storedUser(t *testing.T, enc password.Encoder, active bool) *identity.Details {
	t.Helper()

	hash, err := enc.Encode(storedPassword)
	require.NoError(t, err)

	return &identity.Details{
		ID:                identity.UserID("u1"),
		Name:              "Ada Lovelace",
		Username:          "ada",
		Password:          hash,
		Active:            active,
		PasswordChangedAt: passwordChangedAt,
	}
}

// passwordChangedAt is when the known users below last changed their password.
// It is far enough in the past to be distinguishable from any time a test
// observes.
var passwordChangedAt = time.Date(2019, time.March, 14, 9, 26, 53, 0, time.UTC)

// rightPassword presents the password the known users actually have, so what
// refuses the caller is something other than the secret.
func rightPassword(t *testing.T) identity.Credentials {
	t.Helper()

	return identity.NewUsernamePassword("ada", []byte(storedPassword))
}
