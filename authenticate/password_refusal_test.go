package authenticate_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
)

// TestPasswordRefusalRecords covers task 2.1: refusal records carry no
// submitted username by default, WithUsernameInRefusalLogs restores it, and
// the sampling key stays per reason rather than per username.
func TestPasswordRefusalRecords(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		loadErr   error
		user      *identity.Details
		matches   bool
		opts      []authenticate.PasswordOption
		usernames []string
		assert    func(t *testing.T, buf *bytes.Buffer)
	}

	cases := []testCase{
		{
			name:      "an unknown username is refused, and by default the record carries no username",
			loadErr:   identity.ErrUserNotFound,
			usernames: []string{"alice@example.com"},
			assert: func(t *testing.T, buf *bytes.Buffer) {
				t.Helper()

				assert.NotContains(t, buf.String(), "alice@example.com")

				records := refusalRecords(t, buf)
				require.Len(t, records, 1)
				assert.Equal(t, "unknown-user", records[0]["reason"])
				assert.NotContains(t, records[0], "username")
			},
		},
		{
			name:      "a known user's wrong password is refused, and the record carries no username",
			user:      &identity.Details{Username: "ada", Active: true},
			matches:   false,
			usernames: []string{"ada"},
			assert: func(t *testing.T, buf *bytes.Buffer) {
				t.Helper()

				records := refusalRecords(t, buf)
				require.Len(t, records, 1)
				assert.Equal(t, "wrong-password", records[0]["reason"])
				assert.NotContains(t, records[0], "username")
			},
		},
		{
			name:      "with the option, the record carries the submitted username",
			loadErr:   identity.ErrUserNotFound,
			usernames: []string{"alice@example.com"},
			opts:      []authenticate.PasswordOption{authenticate.WithUsernameInRefusalLogs()},
			assert: func(t *testing.T, buf *bytes.Buffer) {
				t.Helper()

				records := refusalRecords(t, buf)
				require.Len(t, records, 1)
				assert.Equal(t, "alice@example.com", records[0]["username"])
			},
		},
		{
			name:      "with the option and the default interval, two usernames refused for the same reason still produce one record",
			loadErr:   identity.ErrUserNotFound,
			usernames: []string{"alice", "bob"},
			opts:      []authenticate.PasswordOption{authenticate.WithUsernameInRefusalLogs()},
			assert: func(t *testing.T, buf *bytes.Buffer) {
				t.Helper()

				records := refusalRecords(t, buf)
				require.Len(t, records, 1,
					"the username became part of the sampling key")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
				Return(tc.user, tc.loadErr).Times(len(tc.usernames))

			enc := NewMockEncoder(ctrl)
			enc.EXPECT().Encode(gomock.Any()).Return([]byte("$fake$reference"), nil)
			enc.EXPECT().Match(gomock.Any(), gomock.Any()).Return(tc.matches).AnyTimes()

			buf := &bytes.Buffer{}
			opts := append([]authenticate.PasswordOption{
				authenticate.WithPasswordEncoder(enc),
				authenticate.WithPasswordAuthenticatorLogger(debugLogger(buf)),
			}, tc.opts...)

			auth, err := authenticate.NewUsernamePasswordAuthenticator(users, opts...)
			require.NoError(t, err)

			for _, username := range tc.usernames {
				_, _ = auth.Authenticate(t.Context(),
					identity.NewUsernamePassword(username, []byte(presentedPassword)))
			}

			tc.assert(t, buf)
		})
	}
}

// TestPasswordLoaderFailureRecord covers task 2.2: a user loader failure is
// recorded through internal/diag, so neither the values its error text quotes
// nor the text itself reach the log.
func TestPasswordLoaderFailureRecord(t *testing.T) {
	t.Parallel()

	loaderErr := errors.New("store: Key (username)=(alice@example.com) for user u-123")

	ctrl := gomock.NewController(t)

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).Return(nil, loaderErr)

	enc := NewMockEncoder(ctrl)
	enc.EXPECT().Encode(gomock.Any()).Return([]byte("$fake$reference"), nil)
	enc.EXPECT().Match(gomock.Any(), gomock.Any()).Return(false).AnyTimes()

	buf := &bytes.Buffer{}
	auth, err := authenticate.NewUsernamePasswordAuthenticator(users,
		authenticate.WithPasswordEncoder(enc),
		authenticate.WithPasswordAuthenticatorLogger(debugLogger(buf)))
	require.NoError(t, err)

	_, _ = auth.Authenticate(t.Context(),
		identity.NewUsernamePassword("alice@example.com", []byte(presentedPassword)))

	assert.NotContains(t, buf.String(), "alice@example.com")
	assert.NotContains(t, buf.String(), "u-123")

	records := refusalRecords(t, buf)
	require.Len(t, records, 1)
	assert.Equal(t, "user-loader", records[0]["reason"])
	assert.NotEmpty(t, records[0]["error_type"])
	assert.NotContains(t, records[0], "error")
}
