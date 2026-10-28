package authenticate_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

func TestNewUsernamePasswordAuthenticator(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		users  func(t *testing.T, ctrl *gomock.Controller) identity.UserLoader
		opts   func(t *testing.T, ctrl *gomock.Controller) []authenticate.PasswordOption
		assert func(t *testing.T, a authenticate.Authenticator, err error)
	}

	configError := func(t *testing.T, a authenticate.Authenticator, err error) {
		t.Helper()

		require.ErrorIs(t, err, authenticate.ErrConfig)
		assert.Nil(t, a, "a refused configuration still produced a provider")
	}

	liveLoader := func(t *testing.T, ctrl *gomock.Controller) identity.UserLoader {
		t.Helper()

		return NewMockUserLoader(ctrl)
	}

	cases := []testCase{
		{
			name:  "a user loader alone constructs, with no further configuration",
			users: liveLoader,
			assert: func(t *testing.T, a authenticate.Authenticator, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, a)
			},
		},
		{
			name: "a nil user loader is refused, naming the port",
			users: func(t *testing.T, _ *gomock.Controller) identity.UserLoader {
				t.Helper()

				return nil
			},
			assert: func(t *testing.T, a authenticate.Authenticator, err error) {
				t.Helper()

				configError(t, a, err)
				assert.ErrorIs(t, err, identity.ErrMissingPort,
					"the consumer is told something is missing but not which port")
				assert.Contains(t, err.Error(), "user loader")
			},
		},
		{
			name: "a non-nil interface holding a nil pointer is refused too",
			users: func(t *testing.T, _ *gomock.Controller) identity.UserLoader {
				t.Helper()

				// What an unchecked constructor error hands over.
				var unchecked *MockUserLoader

				return unchecked
			},
			assert: configError,
		},
		{
			name:  "an encoder that cannot produce the reference hash is refused",
			users: liveLoader,
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.PasswordOption {
				t.Helper()

				enc := NewMockEncoder(ctrl)
				enc.EXPECT().Encode(gomock.Any()).Return(nil, errEncoderBroken)

				return []authenticate.PasswordOption{authenticate.WithPasswordEncoder(enc)}
			},
			assert: func(t *testing.T, a authenticate.Authenticator, err error) {
				t.Helper()

				configError(t, a, err)
				assert.ErrorIs(t, err, errEncoderBroken,
					"the cause was collapsed, so the consumer cannot see why the encoder refused")
			},
		},
		{
			name:  "a nil encoder is refused rather than quietly restoring the default",
			users: liveLoader,
			opts: func(t *testing.T, _ *gomock.Controller) []authenticate.PasswordOption {
				t.Helper()

				return []authenticate.PasswordOption{authenticate.WithPasswordEncoder(nil)}
			},
			assert: configError,
		},
		{
			name:  "a nil identifier generator is refused rather than quietly restoring the default",
			users: liveLoader,
			opts: func(t *testing.T, _ *gomock.Controller) []authenticate.PasswordOption {
				t.Helper()

				return []authenticate.PasswordOption{authenticate.WithPasswordIDGenerator(nil)}
			},
			assert: configError,
		},
		{
			name:  "a nil option is skipped, so a conditionally built slice need not be filtered",
			users: liveLoader,
			opts: func(t *testing.T, _ *gomock.Controller) []authenticate.PasswordOption {
				t.Helper()

				return []authenticate.PasswordOption{nil}
			},
			assert: func(t *testing.T, a authenticate.Authenticator, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, a)
			},
		},
		{
			name:  "the reference hash is encoded at construction, by the configured encoder",
			users: liveLoader,
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.PasswordOption {
				t.Helper()

				enc := NewMockEncoder(ctrl)
				// Exactly once, before any traffic: a provider that encoded it
				// per request would pay for it on every refusal.
				enc.EXPECT().Encode(gomock.Any()).Return([]byte("$fake$reference"), nil).Times(1)

				return []authenticate.PasswordOption{authenticate.WithPasswordEncoder(enc)}
			},
			assert: func(t *testing.T, a authenticate.Authenticator, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, a)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			var opts []authenticate.PasswordOption
			if tc.opts != nil {
				opts = tc.opts(t, ctrl)
			}

			a, err := authenticate.NewUsernamePasswordAuthenticator(tc.users(t, ctrl), opts...)
			tc.assert(t, a, err)
		})
	}
}

// errEncoderBroken stands for an encoder that cannot hash at all — misconfigured
// parameters, or a salt source that will not read.
var errEncoderBroken = errors.New("the encoder cannot hash")

// recordingEncoder is a generated Encoder mock in front of a real encoder. The
// hashing stays real, so a test asserts against the format the configured
// algorithm actually produces, while the calls the provider made stay visible.
type recordingEncoder struct {
	*MockEncoder

	mu        sync.Mutex
	encoded   [][]byte
	matchedTo [][]byte
	matches   int
}

func newRecordingEncoder(t *testing.T, ctrl *gomock.Controller, inner password.Encoder) *recordingEncoder {
	t.Helper()

	r := &recordingEncoder{MockEncoder: NewMockEncoder(ctrl)}

	r.EXPECT().Encode(gomock.Any()).DoAndReturn(func(in string) ([]byte, error) {
		encoded, err := inner.Encode(in)

		r.mu.Lock()
		defer r.mu.Unlock()
		r.encoded = append(r.encoded, encoded)

		return encoded, err
	}).AnyTimes()

	r.EXPECT().Match(gomock.Any(), gomock.Any()).DoAndReturn(func(in string, encoded []byte) bool {
		r.mu.Lock()
		r.matches++
		r.matchedTo = append(r.matchedTo, encoded)
		r.mu.Unlock()

		return inner.Match(in, encoded)
	}).AnyTimes()

	return r
}

// calls reports how many verifications ran and what they were checked against.
func (r *recordingEncoder) calls() (matches int, matchedTo [][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.matches, append([][]byte(nil), r.matchedTo...)
}

// reference returns the hash the provider had this encoder produce at
// construction.
func (r *recordingEncoder) reference(t *testing.T) []byte {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()
	require.Len(t, r.encoded, 1, "the reference hash was not encoded exactly once at construction")

	return r.encoded[0]
}

// TestPasswordRefusalRecords covers task 2.1: refusal records carry no
// submitted username by default, WithPasswordUsernameInRefusalLogs restores it, and
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
			user:      &identity.Details{Username: "ada", Password: stubHash, Active: true},
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
			opts:      []authenticate.PasswordOption{authenticate.WithPasswordUsernameInRefusalLogs()},
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
			opts:      []authenticate.PasswordOption{authenticate.WithPasswordUsernameInRefusalLogs()},
			assert: func(t *testing.T, buf *bytes.Buffer) {
				t.Helper()

				records := refusalRecords(t, buf)
				require.Len(t, records, 1,
					"the username became part of the sampling key")
			},
		},
		{
			// A user loader failure is recorded through internal/diag, so
			// neither the values its error text quotes nor the text itself
			// reach the log.
			name:      "loader failure record",
			loadErr:   errors.New("store: Key (username)=(alice@example.com) for user u-123"),
			usernames: []string{"alice@example.com"},
			assert: func(t *testing.T, buf *bytes.Buffer) {
				t.Helper()

				assert.NotContains(t, buf.String(), "alice@example.com")
				assert.NotContains(t, buf.String(), "u-123")

				records := refusalRecords(t, buf)
				require.Len(t, records, 1)
				assert.Equal(t, "user-loader", records[0]["reason"])
				assert.NotEmpty(t, records[0]["error_type"])
				assert.NotContains(t, records[0], "error")
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
				authenticate.WithPasswordLogger(debugLogger(buf)),
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

// presentedPassword is what every refusal case below presents. No stored user
// has it, so the only thing that could ever distinguish these refusals is how
// the provider reached them.
const presentedPassword = "hunter2"

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

func TestRefusalLogsAreBoundedAndCarryNoPassword(t *testing.T) {
	t.Parallel()

	t.Run("one record per reason per window, with the rest counted", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			auth, buf := refusingAuthenticator(t, identity.ErrUserNotFound,
				authenticate.WithPasswordLogInterval(time.Minute))

			for range 50 {
				_, _ = auth.Authenticate(t.Context(),
					identity.NewUsernamePassword("ada", []byte(presentedPassword)))
			}
			synctest.Wait()

			assert.Equal(t, 1, strings.Count(buf.String(), `"msg":"authentication refused"`),
				"the sampler let more than one record through inside its window")
			assert.NotContains(t, buf.String(), presentedPassword,
				"a refusal log carried the presented password")

			flusher, ok := auth.(authenticate.RefusalLogFlusher)
			require.True(t, ok, "the provider offers no way to report what it suppressed")
			require.NoError(t, flusher.FlushRefusalLogs())

			assert.Contains(t, buf.String(), `"suppressed":49`,
				"the suppressed count was dropped rather than reported")
		})
	})

	t.Run("the default window is one minute, with no configuration at all", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			auth, buf := refusingAuthenticator(t, identity.ErrUserNotFound)

			_, _ = auth.Authenticate(t.Context(),
				identity.NewUsernamePassword("ada", []byte(presentedPassword)))
			time.Sleep(59 * time.Second)
			_, _ = auth.Authenticate(t.Context(),
				identity.NewUsernamePassword("ada", []byte(presentedPassword)))
			synctest.Wait()

			require.Equal(t, 1, strings.Count(buf.String(), `"msg":"authentication refused"`),
				"the default window is shorter than a minute")

			time.Sleep(2 * time.Second)
			_, _ = auth.Authenticate(t.Context(),
				identity.NewUsernamePassword("ada", []byte(presentedPassword)))
			synctest.Wait()

			assert.Equal(t, 2, strings.Count(buf.String(), `"msg":"authentication refused"`),
				"the default window is longer than a minute")
		})
	})

	t.Run("a new window admits another record", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			auth, buf := refusingAuthenticator(t, identity.ErrUserNotFound,
				authenticate.WithPasswordLogInterval(time.Minute))

			_, _ = auth.Authenticate(t.Context(),
				identity.NewUsernamePassword("ada", []byte(presentedPassword)))
			time.Sleep(90 * time.Second)
			_, _ = auth.Authenticate(t.Context(),
				identity.NewUsernamePassword("ada", []byte(presentedPassword)))
			synctest.Wait()

			assert.Equal(t, 2, strings.Count(buf.String(), `"msg":"authentication refused"`),
				"suppression outlived its own window, so a sustained attack goes unreported")
		})
	})

	t.Run("a consumer disables sampling with an interval of zero", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			auth, buf := refusingAuthenticator(t, identity.ErrUserNotFound,
				authenticate.WithPasswordLogInterval(0))

			for range 50 {
				_, _ = auth.Authenticate(t.Context(),
					identity.NewUsernamePassword("ada", []byte(presentedPassword)))
			}
			synctest.Wait()

			assert.Equal(t, 50, strings.Count(buf.String(), `"msg":"authentication refused"`),
				"the override did not disable sampling, so an audit trail is still missing records")
		})
	})
}

func TestRefusalLogRecords(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		loadErr    error
		user       *identity.Details
		matches    bool
		assert     func(t *testing.T, record map[string]any)
		wantRecord bool
	}

	cases := []testCase{
		{
			name:       "an unknown username is a routine event, recorded at debug",
			loadErr:    identity.ErrUserNotFound,
			wantRecord: true,
			assert: func(t *testing.T, record map[string]any) {
				t.Helper()

				assert.Equal(t, "DEBUG", record["level"])
				assert.Equal(t, "unknown-user", record["reason"])
				assert.NotContains(t, record, "username",
					"the username reached the log without the consumer opting in")
			},
		},
		{
			name:       "a user store that is down is an operator's problem, recorded at error, naming the failure but not its text",
			loadErr:    errBackendDown,
			wantRecord: true,
			assert: func(t *testing.T, record map[string]any) {
				t.Helper()

				assert.Equal(t, "ERROR", record["level"])
				assert.Equal(t, "user-loader", record["reason"])
				assert.NotEmpty(t, record["error_type"],
					"the record does not name the failure an operator has to fix")
				assert.NotContains(t, record, "error",
					"the dependency's error text reached the log")
			},
		},
		{
			name:       "a wrong password is a routine event, recorded at debug",
			user:       &identity.Details{Username: "ada", Password: stubHash, Active: true},
			matches:    false,
			wantRecord: true,
			assert: func(t *testing.T, record map[string]any) {
				t.Helper()

				assert.Equal(t, "DEBUG", record["level"])
				assert.Equal(t, "wrong-password", record["reason"])
			},
		},
		{
			name:       "the right password for a disabled account is worth an operator's attention",
			user:       &identity.Details{Username: "ada", Password: stubHash, Active: false},
			matches:    true,
			wantRecord: true,
			assert: func(t *testing.T, record map[string]any) {
				t.Helper()

				assert.Equal(t, "WARN", record["level"])
				assert.Equal(t, "account-inactive", record["reason"])
			},
		},
		{
			name:    "a success is not a refusal, and writes no refusal record",
			user:    &identity.Details{Username: "ada", Password: stubHash, Active: true},
			matches: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).Return(tc.user, tc.loadErr)

			enc := NewMockEncoder(ctrl)
			enc.EXPECT().Encode(gomock.Any()).Return([]byte("$fake$reference"), nil)
			enc.EXPECT().Match(gomock.Any(), gomock.Any()).Return(tc.matches).AnyTimes()

			buf := &bytes.Buffer{}
			auth, err := authenticate.NewUsernamePasswordAuthenticator(users,
				authenticate.WithPasswordEncoder(enc),
				authenticate.WithPasswordLogger(debugLogger(buf)))
			require.NoError(t, err)

			_, _ = auth.Authenticate(t.Context(),
				identity.NewUsernamePassword("ada", []byte(presentedPassword)))

			assert.NotContains(t, buf.String(), presentedPassword,
				"a refusal log carried the presented password")

			records := refusalRecords(t, buf)
			if !tc.wantRecord {
				assert.Empty(t, records)

				return
			}

			require.Len(t, records, 1)
			tc.assert(t, records[0])
		})
	}
}

func TestPasswordAuthenticatorLoggerDefaults(t *testing.T) {
	t.Parallel()

	t.Run("a nil logger is ignored rather than refused", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		enc := NewMockEncoder(ctrl)
		enc.EXPECT().Encode(gomock.Any()).Return([]byte("$fake$reference"), nil)

		auth, err := authenticate.NewUsernamePasswordAuthenticator(NewMockUserLoader(ctrl),
			authenticate.WithPasswordEncoder(enc),
			authenticate.WithPasswordLogger(nil))
		require.NoError(t, err, "a nil logger made logging mandatory")
		assert.NotNil(t, auth)
	})

	t.Run("flushing a provider that suppressed nothing reports nothing", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		enc := NewMockEncoder(ctrl)
		enc.EXPECT().Encode(gomock.Any()).Return([]byte("$fake$reference"), nil)

		buf := &bytes.Buffer{}
		auth, err := authenticate.NewUsernamePasswordAuthenticator(NewMockUserLoader(ctrl),
			authenticate.WithPasswordEncoder(enc),
			authenticate.WithPasswordLogger(debugLogger(buf)))
		require.NoError(t, err)

		flusher, ok := auth.(authenticate.RefusalLogFlusher)
		require.True(t, ok)
		require.NoError(t, flusher.FlushRefusalLogs())
		assert.Empty(t, buf.String())
	})
}

// refusingAuthenticator returns a provider whose user loader always fails with
// loadErr, logging to the buffer it returns. Nothing is hashed: these cases
// count records, and a real encoder would only make them slow.
func refusingAuthenticator(t *testing.T, loadErr error, opts ...authenticate.PasswordOption) (authenticate.Authenticator, *bytes.Buffer) {
	t.Helper()

	ctrl := gomock.NewController(t)

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).Return(nil, loadErr).AnyTimes()

	enc := NewMockEncoder(ctrl)
	enc.EXPECT().Encode(gomock.Any()).Return([]byte("$fake$reference"), nil)
	enc.EXPECT().Match(gomock.Any(), gomock.Any()).Return(false).AnyTimes()

	buf := &bytes.Buffer{}
	auth, err := authenticate.NewUsernamePasswordAuthenticator(users,
		append([]authenticate.PasswordOption{
			authenticate.WithPasswordEncoder(enc),
			authenticate.WithPasswordLogger(debugLogger(buf)),
		}, opts...)...)
	require.NoError(t, err)

	return auth, buf
}

// debugLogger writes JSON records of every level to w, so a test can see the
// debug-level refusals a production handler would drop.
func debugLogger(w *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// refusalRecords decodes the refusal records written to buf.
func refusalRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()

	var records []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}

		record := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		if record["msg"] == "authentication refused" {
			records = append(records, record)
		}
	}

	return records
}

// stubHash is the stored hash of a known user in the tables that verify through
// a mock encoder. It only has to be non-empty: a mock encoder does not implement
// password.Recognizer, so the provider trusts it with any non-empty hash, while
// an empty one would send the user down the no-usable-hash refusal instead.
var stubHash = []byte("$fake$stored")

func TestPasswordAuthenticatorSuccess(t *testing.T) {
	t.Parallel()

	t.Run("presented secrets are wiped", func(t *testing.T) {
		t.Parallel()

		secret := []byte(storedPassword)
		creds := identity.NewUsernamePassword("ada", secret)

		auth, _ := authenticatorFor(t, cheapEncoder(t))

		got, err := auth.Authenticate(t.Context(), creds)
		require.NoError(t, err)

		assert.NotContains(t, string(secret), storedPassword,
			"the presented password survived in the caller's own buffer")
		assert.Equal(t, make([]byte, len(secret)), secret,
			"the buffer was released rather than overwritten, so the secret is still resident")
		assert.Same(t, creds, got.Credentials,
			"the result carries credentials other than the ones presented")
	})

	t.Run("the result describes the authentication", func(t *testing.T) {
		t.Parallel()

		auth, _ := authenticatorFor(t, cheapEncoder(t))

		before := time.Now()
		got, err := auth.Authenticate(t.Context(),
			identity.NewUsernamePassword("ada", []byte(storedPassword)))
		require.NoError(t, err)
		require.NotNil(t, got)

		require.NotNil(t, got.Principal)
		assert.Equal(t, identity.UserID("u1"), got.Principal.ID)
		assert.Equal(t, "ada", got.Principal.Username)
		assert.Equal(t, passwordChangedAt, got.PasswordChangedAt)
		assert.False(t, got.Time.Before(before), "the result is dated before the request that produced it")
		assert.Equal(t, identity.CredentialsUsernamePassword, got.Credentials.Type())
	})

	t.Run("the default encoder verifies hashes the default encoder produced", func(t *testing.T) {
		t.Parallel()

		// The point of the default is that a consumer who configures nothing
		// can still verify what scrty's own encoder wrote. A default that were
		// a no-op, or another algorithm, would refuse this.
		enc, err := password.NewArgon2idEncoder()
		require.NoError(t, err)

		ctrl := gomock.NewController(t)
		users := NewMockUserLoader(ctrl)
		users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).Return(storedUser(t, enc, true), nil)

		auth, err := authenticate.NewUsernamePasswordAuthenticator(users)
		require.NoError(t, err)

		got, err := auth.Authenticate(t.Context(),
			identity.NewUsernamePassword("ada", []byte(storedPassword)))
		require.NoError(t, err)
		assert.NotNil(t, got)
	})
}

// authenticatorFor returns a provider over one active user whose password is
// storedPassword, hashed by enc, and the loader behind it.
func authenticatorFor(t *testing.T, enc password.Encoder, opts ...authenticate.PasswordOption) (authenticate.Authenticator, *MockUserLoader) {
	t.Helper()

	ctrl := gomock.NewController(t)
	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
		Return(storedUser(t, enc, true), nil).AnyTimes()

	auth, err := authenticate.NewUsernamePasswordAuthenticator(users,
		append([]authenticate.PasswordOption{authenticate.WithPasswordEncoder(enc)}, opts...)...)
	require.NoError(t, err)

	return auth, users
}

// The three tests below share one table runner: each is a table over the same
// Authenticate call, split by the guarantee it pins so each can be run by name.

// recognizingRecorder is a recordingEncoder that also forwards recognition to
// the real encoder behind it, as a built-in encoder would offer it.
type recognizingRecorder struct {
	*recordingEncoder

	inner password.Recognizer
}

func (r recognizingRecorder) Recognizes(encoded []byte) bool { return r.inner.Recognizes(encoded) }

type unusableHashCase struct {
	name string
	// stored returns the hash the known user "ada" has; inner is the real
	// encoder behind the recorder.
	stored func(t *testing.T, inner password.Encoder) []byte
	// recognizing wires an encoder that implements password.Recognizer; false
	// wires one that, like a consumer's own encoder, does not.
	recognizing bool
	presented   string
	// reason and level, when set, are the refusal record the case must leave:
	// its reason, and its slog level name.
	reason, level string
	assert        func(t *testing.T, err error, enc *recordingEncoder)
}

func runUnusableHashCases(t *testing.T, cases []unusableHashCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			inner := cheapEncoder(t)
			rec := newRecordingEncoder(t, ctrl, inner)

			var enc password.Encoder = rec
			if tc.recognizing {
				r, ok := inner.(password.Recognizer)
				require.True(t, ok)
				enc = recognizingRecorder{recordingEncoder: rec, inner: r}
			}

			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUsername(gomock.Any(), "ada").Return(&identity.Details{
				Username: "ada",
				Password: tc.stored(t, inner),
				Active:   true,
			}, nil)

			buf := &bytes.Buffer{}
			auth, err := authenticate.NewUsernamePasswordAuthenticator(users, authenticate.WithPasswordEncoder(enc), authenticate.WithPasswordLogger(debugLogger(buf)))
			require.NoError(t, err)

			presented := tc.presented
			if presented == "" {
				presented = presentedPassword
			}

			_, err = auth.Authenticate(t.Context(), identity.NewUsernamePassword("ada", []byte(presented)))
			tc.assert(t, err, rec)

			if tc.reason != "" {
				records := refusalRecords(t, buf)
				require.Len(t, records, 1)
				assert.Equal(t, tc.reason, records[0]["reason"])
				assert.Equal(t, tc.level, records[0]["level"])
			}
		})
	}
}

// refusedAfterOneReferenceVerification asserts the refusal cost exactly what an
// unknown username costs: one verification, against the reference hash.
func refusedAfterOneReferenceVerification(t *testing.T, err error, enc *recordingEncoder) {
	t.Helper()

	assert.Equal(t, authenticate.ErrAuthenticationFailed, err)

	matches, matchedTo := enc.calls()
	require.Equal(t, 1, matches,
		"an unusable hash must cost one verification, as an unknown user does, and never two")
	assert.Equal(t, enc.reference(t), matchedTo[0],
		"the one verification was not against the reference hash, so it derived nothing")
}

func noHash(t *testing.T, _ password.Encoder) []byte {
	t.Helper()

	return nil
}

func bcryptHash(t *testing.T, _ password.Encoder) []byte {
	t.Helper()

	enc, err := password.NewBcryptEncoder()
	require.NoError(t, err)

	h, err := enc.Encode(presentedPassword)
	require.NoError(t, err)

	return h
}

func TestPasswordProvider_PasswordlessUserCostsSameAsUnknownUser(t *testing.T) {
	t.Parallel()

	runUnusableHashCases(t, []unusableHashCase{
		{
			name:   "a nil hash, through an encoder without recognition",
			stored: noHash,
			reason: "no-password-hash", level: "DEBUG",
			assert: refusedAfterOneReferenceVerification,
		},
		{
			name: "an empty hash, through an encoder without recognition",
			stored: func(t *testing.T, _ password.Encoder) []byte {
				t.Helper()

				return []byte{}
			},
			assert: refusedAfterOneReferenceVerification,
		},
		{
			name:        "a nil hash, through an encoder with recognition",
			stored:      noHash,
			recognizing: true,
			reason:      "no-password-hash", level: "DEBUG",
			assert: refusedAfterOneReferenceVerification,
		},
	})
}

func TestPasswordProvider_UnrecognisedHashCostsOneVerification(t *testing.T) {
	t.Parallel()

	runUnusableHashCases(t, []unusableHashCase{
		{
			name:        "a hash in another algorithm's format, through an encoder that recognises its own",
			stored:      bcryptHash,
			recognizing: true,
			reason:      "unrecognised-hash", level: "WARN",
			assert: refusedAfterOneReferenceVerification,
		},
		{
			name: "a usable hash and a wrong password cost one verification, against the stored hash",
			stored: func(t *testing.T, inner password.Encoder) []byte {
				t.Helper()

				h, err := inner.Encode(storedPassword)
				require.NoError(t, err)

				return h
			},
			recognizing: true,
			assert: func(t *testing.T, err error, enc *recordingEncoder) {
				t.Helper()

				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)

				matches, matchedTo := enc.calls()
				require.Equal(t, 1, matches, "a wrong password must not cost two derivations")
				assert.NotEqual(t, enc.reference(t), matchedTo[0])
			},
		},
		{
			name:   "by default, an encoder without recognition is trusted with any non-empty hash",
			stored: bcryptHash,
			assert: func(t *testing.T, err error, enc *recordingEncoder) {
				t.Helper()

				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)

				matches, matchedTo := enc.calls()
				require.Equal(t, 1, matches)
				assert.NotEqual(t, enc.reference(t), matchedTo[0],
					"an encoder that cannot report recognition was second-guessed")
			},
		},
	})
}

func TestPasswordProvider_ReferencePasswordNeverAdmits(t *testing.T) {
	t.Parallel()

	runUnusableHashCases(t, []unusableHashCase{
		{
			name:      "a user without a hash presents the reference password",
			stored:    noHash,
			presented: authenticate.ReferencePassword,
			assert:    refusedAfterOneReferenceVerification,
		},
		{
			name:        "a user with an unrecognised hash presents the reference password",
			stored:      bcryptHash,
			recognizing: true,
			presented:   authenticate.ReferencePassword,
			assert:      refusedAfterOneReferenceVerification,
		},
	})
}

func TestAuthenticationIdentifier(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(t *testing.T, ctrl *gomock.Controller) []authenticate.PasswordOption
		assert func(t *testing.T, first, second *authenticate.Authentication, err error)
	}

	cases := []testCase{
		{
			name: "the default generator yields a fresh, sortable identifier per authentication",
			assert: func(t *testing.T, first, second *authenticate.Authentication, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, first.ID.IsZero(), "the result carries no identifier at all")
				assert.NotEqual(t, first.ID, second.ID, "two authentications share one identifier")
				assert.Negative(t, bytes.Compare(first.ID[:], second.ID[:]),
					"identifiers do not increase, so they cannot order the events they name")
			},
		},
		{
			name: "a consumer generator replaces the default",
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.PasswordOption {
				t.Helper()

				ids := NewMockGenerator(ctrl)
				ids.EXPECT().NewID().Return(consumerID, nil).AnyTimes()

				return []authenticate.PasswordOption{authenticate.WithPasswordIDGenerator(ids)}
			},
			assert: func(t *testing.T, first, second *authenticate.Authentication, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, consumerID, first.ID)
				assert.Equal(t, consumerID, second.ID)
			},
		},
		{
			name: "a generator failure is an error, never a result with no identifier",
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.PasswordOption {
				t.Helper()

				ids := NewMockGenerator(ctrl)
				ids.EXPECT().NewID().Return(id.Nil, errNoIdentifier).AnyTimes()

				return []authenticate.PasswordOption{authenticate.WithPasswordIDGenerator(ids)}
			},
			assert: func(t *testing.T, first, _ *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, errNoIdentifier)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed,
					"a failure to name the event was reported as a decision about the caller")
				assert.Nil(t, first)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			var opts []authenticate.PasswordOption
			if tc.opts != nil {
				opts = tc.opts(t, ctrl)
			}
			auth, _ := authenticatorFor(t, cheapEncoder(t), opts...)

			first, err := auth.Authenticate(t.Context(),
				identity.NewUsernamePassword("ada", []byte(storedPassword)))
			if err != nil {
				tc.assert(t, first, nil, err)

				return
			}

			second, err := auth.Authenticate(t.Context(),
				identity.NewUsernamePassword("ada", []byte(storedPassword)))
			tc.assert(t, first, second, err)
		})
	}
}

// consumerID is the identifier a consumer's own generator hands back, so a test
// can tell it apart from anything the library would have minted.
var consumerID = id.MustParse("0192f3a4-5b6c-7d8e-9f01-234567890abc")

func TestPasswordAuthenticator_VerifyDecoy(t *testing.T) {
	t.Parallel()

	reference := []byte("reference-hash")

	type testCase struct {
		name   string
		creds  identity.Credentials
		expect func(enc *MockEncoder)
		assert func(t *testing.T, handled bool)
	}

	cases := []testCase{
		{
			name:  "username and password is verified against the reference hash once",
			creds: identity.NewUsernamePassword("ada", []byte("guess")),
			expect: func(enc *MockEncoder) {
				enc.EXPECT().Match("guess", reference).Return(false).Times(1)
			},
			assert: func(t *testing.T, handled bool) {
				assert.True(t, handled)
			},
		},
		{
			name:  "other credentials are declined without hashing",
			creds: authenticate.NewBearerToken("x"),
			assert: func(t *testing.T, handled bool) {
				assert.False(t, handled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			enc := NewMockEncoder(ctrl)
			enc.EXPECT().Encode(gomock.Any()).Return(reference, nil).Times(1)
			if tc.expect != nil {
				tc.expect(enc)
			}
			// No expectations: any call to the loader fails the test.
			users := NewMockUserLoader(ctrl)

			a, err := authenticate.NewUsernamePasswordAuthenticator(users, authenticate.WithPasswordEncoder(enc))
			require.NoError(t, err)

			v, ok := a.(authenticate.DecoyVerifier)
			require.True(t, ok, "the password provider must implement DecoyVerifier")

			tc.assert(t, v.VerifyDecoy(t.Context(), tc.creds))
		})
	}
}

// Standalone: each case drives a different method over a provider with no user expectations.
func TestPasswordProvider_TypedNilCredentialsRefusedWithoutPanic(t *testing.T) {
	t.Parallel()

	var typedNil *identity.UsernamePassword

	type testCase struct {
		name string
		run  func(t *testing.T, p authenticate.Authenticator)
	}

	cases := []testCase{
		{
			name: "Authenticate reports unsupported credentials",
			run: func(t *testing.T, p authenticate.Authenticator) {
				t.Helper()

				got, err := p.Authenticate(t.Context(), typedNil)

				require.ErrorIs(t, err, authenticate.ErrUnsupportedCredentials)
				assert.Nil(t, got)
			},
		},
		{
			name: "VerifyDecoy declines them without hashing",
			run: func(t *testing.T, p authenticate.Authenticator) {
				t.Helper()

				v, ok := p.(authenticate.DecoyVerifier)
				require.True(t, ok, "the password provider must implement DecoyVerifier")

				assert.False(t, v.VerifyDecoy(t.Context(), typedNil))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			enc := NewMockEncoder(ctrl)
			// Only the construction-time reference: any Match call is a failure.
			enc.EXPECT().Encode(gomock.Any()).Return([]byte("reference-hash"), nil).Times(1)
			// No expectations: loading a user for no one is a failure.
			users := NewMockUserLoader(ctrl)

			p, err := authenticate.NewUsernamePasswordAuthenticator(users, authenticate.WithPasswordEncoder(enc))
			require.NoError(t, err)

			tc.run(t, p)
		})
	}
}
