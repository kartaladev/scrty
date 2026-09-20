package authenticate_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
)

func TestRefusalLogsAreBoundedAndCarryNoPassword(t *testing.T) {
	t.Parallel()

	t.Run("one record per reason per window, with the rest counted", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			auth, buf := refusingAuthenticator(t, identity.ErrUserNotFound,
				authenticate.WithPasswordAuthenticatorLogInterval(time.Minute))

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
				authenticate.WithPasswordAuthenticatorLogInterval(time.Minute))

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
				authenticate.WithPasswordAuthenticatorLogInterval(0))

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
				assert.Equal(t, "ada", record["username"])
			},
		},
		{
			name:       "a user store that is down is an operator's problem, recorded at error with the cause",
			loadErr:    errBackendDown,
			wantRecord: true,
			assert: func(t *testing.T, record map[string]any) {
				t.Helper()

				assert.Equal(t, "ERROR", record["level"])
				assert.Equal(t, "user-load-failed", record["reason"])
				assert.Contains(t, record["error"], errBackendDown.Error(),
					"the record does not name the failure an operator has to fix")
			},
		},
		{
			name:       "a wrong password is a routine event, recorded at debug",
			user:       &identity.Details{Username: "ada", Active: true},
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
			user:       &identity.Details{Username: "ada", Active: false},
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
			user:    &identity.Details{Username: "ada", Active: true},
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
				authenticate.WithPasswordAuthenticatorLogger(debugLogger(buf)))
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
			authenticate.WithPasswordAuthenticatorLogger(nil))
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
			authenticate.WithPasswordAuthenticatorLogger(debugLogger(buf)))
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
			authenticate.WithPasswordAuthenticatorLogger(debugLogger(buf)),
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
