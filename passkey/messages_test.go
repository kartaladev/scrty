package passkey_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// logBuffer collects JSON log records written by concurrent goroutines.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

// String returns everything written so far.
func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// records returns the written records, one line each.
func (b *logBuffer) records() []string {
	s := strings.TrimSpace(b.String())
	if s == "" {
		return nil
	}

	return strings.Split(s, "\n")
}

// logger returns a debug-level JSON logger writing to b.
func (b *logBuffer) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// assertNoSecrets fails when any of secrets, raw or in base64 (padded,
// unpadded, standard and URL alphabets) or hex, appears in out.
func assertNoSecrets(t *testing.T, out string, secrets ...[]byte) {
	t.Helper()

	for _, s := range secrets {
		forms := []string{
			string(s),
			base64.StdEncoding.EncodeToString(s),
			base64.RawStdEncoding.EncodeToString(s),
			base64.URLEncoding.EncodeToString(s),
			base64.RawURLEncoding.EncodeToString(s),
			hex.EncodeToString(s),
		}
		for _, f := range forms {
			assert.NotContains(t, out, f)
		}
	}
}

// customMessages renders every message with a fixed, recognisable text.
type customMessages struct{}

func (customMessages) Registered(n passkey.Notice) (string, string) {
	return "custom registered", "custom body for " + n.Name
}

func (customMessages) Removed(n passkey.Notice) (string, string) {
	return "custom removed", "custom body for " + n.Name + ", sessions ended: " + strconv.FormatBool(n.SessionsEnded)
}

func (customMessages) Suspended(n passkey.Notice) (string, string) {
	return "custom suspended", "custom body for " + n.Name + ", sessions ended: " + strconv.FormatBool(n.SessionsEnded)
}

func (customMessages) EmailCode(code string, _ time.Time) (string, string) {
	return "custom code", "code " + code
}

func TestNotices(t *testing.T) {
	t.Parallel()

	type env struct {
		f    *fixture
		m    *passkey.Manager
		logs *logBuffer
		recv *passkey.RecoveryDeps
	}

	type testCase struct {
		name   string
		opts   []passkey.Option
		codes  bool // wire saved codes with a way-back check
		assert func(t *testing.T, e *env)
	}

	// register runs a begin and a finish for s with credential credID and
	// name.
	register := func(
		t *testing.T, e *env, s *session.Session, credID, name string, rc passkey.RegistrationContext,
	) (*passkey.RegistrationResult, string) {
		t.Helper()

		challenge := e.f.begin(t, e.m, s)
		res, err := e.m.FinishRegistration(t.Context(), s, regBody(challenge, credID, name), rc)
		require.NoError(t, err)

		return res, challenge
	}

	ended := func(
		t *testing.T, e *env, notify func(*testing.T, *passkey.Manager, *passkey.Credential, bool), v bool,
	) string {
		t.Helper()

		notify(t, e.m, &passkey.Credential{ID: id.ID{15: 1}, User: "u-1", Name: "Old key"}, v)

		msgs := e.f.messages()
		require.Len(t, msgs, 1)

		return msgs[0].TextBody
	}
	removed := func(t *testing.T, m *passkey.Manager, c *passkey.Credential, v bool) {
		m.NotifyRemoved(t.Context(), c, v)
	}
	suspended := func(t *testing.T, m *passkey.Manager, c *passkey.Credential, v bool) {
		m.NotifySuspended(t.Context(), c, v)
	}

	cases := []testCase{
		{
			name: "a removal notice says the other sessions were signed out when they were",
			assert: func(t *testing.T, e *env) {
				assert.Contains(t, ended(t, e, removed, true), "Your other sessions were signed out.")
			},
		},
		{
			name: "a removal notice says nothing of sessions when none were ended",
			assert: func(t *testing.T, e *env) {
				assert.NotContains(t, ended(t, e, removed, false), "signed out")
			},
		},
		{
			name: "a suspension notice says all sessions were signed out when they were",
			assert: func(t *testing.T, e *env) {
				assert.Contains(t, ended(t, e, suspended, true), "All your sessions were signed out.")
			},
		},
		{
			name: "a suspension notice says nothing of sessions when none were ended",
			assert: func(t *testing.T, e *env) {
				assert.NotContains(t, ended(t, e, suspended, false), "signed out")
			},
		},
		{
			name: "custom messages receive SessionsEnded and replace the default text",
			opts: []passkey.Option{passkey.WithMessages(customMessages{})},
			assert: func(t *testing.T, e *env) {
				assert.Equal(t, "custom body for Old key, sessions ended: true", ended(t, e, removed, true))
			},
		},
		{
			name: "custom suspension messages receive SessionsEnded as false when nothing ended",
			opts: []passkey.Option{passkey.WithMessages(customMessages{})},
			assert: func(t *testing.T, e *env) {
				assert.Equal(t, "custom body for Old key, sessions ended: false", ended(t, e, suspended, false))
			},
		},
		{
			name: "a binding notice names the passkey, the time and the repudiation contact",
			assert: func(t *testing.T, e *env) {
				e.f.clock.Advance(time.Minute)
				_, challenge := register(t, e, fullSession("sess-a", "u-1"), "cred-a", "Phone", passkey.RegistrationContext{})

				msgs := e.f.messages()
				require.Len(t, msgs, 1)
				assert.Equal(t, "ana@example.com", msgs[0].To)
				assert.NotEmpty(t, msgs[0].Subject)
				assert.Contains(t, msgs[0].TextBody, "Phone")
				assert.Contains(t, msgs[0].TextBody, "1 October 2026 09:01 UTC")
				assert.Contains(t, msgs[0].TextBody, "help@example.com")
				assertNoSecrets(t, msgs[0].Subject+msgs[0].TextBody, []byte(challenge), []byte("cred-a"))
				assert.NotContains(t, msgs[0].TextBody, "cose-")
			},
		},
		{
			name:  "a passkey awaiting saved codes notifies at confirmation, not at finish",
			codes: true,
			assert: func(t *testing.T, e *env) {
				s := fullSession("sess-a", "u-1")
				res, _ := register(t, e, s, "cred-a", "Key", passkey.RegistrationContext{})
				require.False(t, res.Activated)
				assert.Empty(t, e.f.messages())

				c, err := e.m.ConfirmSavedCode(t.Context(), s, res.RecoveryCodes[0], passkey.RegistrationContext{})
				require.NoError(t, err)
				require.NotNil(t, c)

				msgs := e.f.messages()
				require.Len(t, msgs, 1)
				assert.Equal(t, "ana@example.com", msgs[0].To)
				assert.Contains(t, msgs[0].TextBody, "Key")
			},
		},
		{
			name:  "the confirmation's contact resolver addresses the notice",
			codes: true,
			assert: func(t *testing.T, e *env) {
				s := fullSession("sess-a", "u-1")
				res, _ := register(t, e, s, "cred-a", "Key", passkey.RegistrationContext{})

				rc := passkey.RegistrationContext{ContactResolver: func(_ context.Context, d *identity.Details) (string, error) {
					return "alt-" + d.Username, nil
				}}
				_, err := e.m.ConfirmSavedCode(t.Context(), s, res.RecoveryCodes[0], rc)
				require.NoError(t, err)

				msgs := e.f.messages()
				require.Len(t, msgs, 1)
				assert.Equal(t, "alt-ana@example.com", msgs[0].To)
			},
		},
		{
			name: "an emailed-code confirmation notifies through the path's resolver",
			assert: func(t *testing.T, e *env) {
				s := enrolmentSession("sess-a", "u-1")
				rc := passkey.RegistrationContext{
					EmailConfirmation: true,
					ContactResolver: func(_ context.Context, d *identity.Details) (string, error) {
						return "path-" + d.Username, nil
					},
				}
				res, _ := register(t, e, s, "cred-a", "Laptop", rc)
				require.False(t, res.Activated)

				code := emailedCode(t, e.f)
				c, err := e.m.ConfirmEmailCode(t.Context(), s, code, rc)
				require.NoError(t, err)
				require.NotNil(t, c)

				msgs := e.f.messages()
				require.Len(t, msgs, 2)
				assert.Equal(t, "path-ana@example.com", msgs[1].To)
				assert.Contains(t, msgs[1].TextBody, "Laptop")
				assert.NotContains(t, msgs[1].TextBody, code)
			},
		},
		{
			name: "the manager's contact resolver replaces the username",
			opts: []passkey.Option{passkey.WithContactResolver(func(_ context.Context, d *identity.Details) (string, error) {
				return "contact-" + d.Username, nil
			})},
			assert: func(t *testing.T, e *env) {
				register(t, e, fullSession("sess-a", "u-1"), "cred-a", "Phone", passkey.RegistrationContext{})

				msgs := e.f.messages()
				require.Len(t, msgs, 1)
				assert.Equal(t, "contact-ana@example.com", msgs[0].To)
			},
		},
		{
			name: "a first device-bound passkey reports no synced passkey",
			assert: func(t *testing.T, e *env) {
				e.f.adjustVerify("cred-a", func(nc *passkey.NewCredential) error {
					nc.BackupEligible, nc.BackupState = false, false
					return nil
				})

				res, _ := register(t, e, fullSession("sess-a", "u-1"), "cred-a", "", passkey.RegistrationContext{})
				assert.False(t, res.BackupEligible)
				assert.True(t, res.NoSyncedPasskey)
			},
		},
		{
			name: "a synced passkey reports a synced passkey",
			assert: func(t *testing.T, e *env) {
				res, _ := register(t, e, fullSession("sess-a", "u-1"), "cred-a", "", passkey.RegistrationContext{})
				assert.True(t, res.BackupEligible)
				assert.False(t, res.NoSyncedPasskey)
			},
		},
		{
			name: "a device-bound passkey beside an active synced one reports a synced passkey",
			assert: func(t *testing.T, e *env) {
				register(t, e, fullSession("sess-a", "u-1"), "cred-a", "", passkey.RegistrationContext{})
				e.f.adjustVerify("cred-b", func(nc *passkey.NewCredential) error {
					nc.BackupEligible, nc.BackupState = false, false
					return nil
				})

				res, _ := register(t, e, fullSession("sess-a", "u-1"), "cred-b", "", passkey.RegistrationContext{})
				assert.False(t, res.BackupEligible)
				assert.False(t, res.NoSyncedPasskey)
			},
		},
		{
			name: "a refused notice is logged without its body or address and the passkey stays active",
			assert: func(t *testing.T, e *env) {
				e.f.mu.Lock()
				e.f.sendErr = errors.New("queue full for ana@example.com")
				e.f.mu.Unlock()

				res, challenge := register(t, e, fullSession("sess-a", "u-1"), "cred-a", "Phone", passkey.RegistrationContext{})
				assert.True(t, res.Activated)
				assert.Equal(t, passkey.StateActive, onlyCredential(t, e.f, "u-1").State)

				recs := e.logs.records()
				require.NotEmpty(t, recs)

				out := e.logs.String()
				assert.Contains(t, out, `"level":"ERROR"`)
				assert.Contains(t, out, res.Credential.ID.String())
				assert.NotContains(t, out, "ana@example.com")
				assert.NotContains(t, out, "Phone")
				assert.NotContains(t, out, "help@example.com")
				assertNoSecrets(t, out, []byte(challenge), []byte("cred-a"), []byte("cose-cred-a"))
			},
		},
		{
			name: "consumer messages replace the texts while the library sets the recipient",
			opts: []passkey.Option{passkey.WithMessages(customMessages{})},
			assert: func(t *testing.T, e *env) {
				register(t, e, fullSession("sess-a", "u-1"), "cred-a", "Phone", passkey.RegistrationContext{})

				msgs := e.f.messages()
				require.Len(t, msgs, 1)
				assert.Equal(t, "ana@example.com", msgs[0].To)
				assert.Equal(t, "custom registered", msgs[0].Subject)
				assert.Equal(t, "custom body for Phone", msgs[0].TextBody)
			},
		},
		{
			name: "consumer messages render the emailed code",
			opts: []passkey.Option{passkey.WithMessages(customMessages{})},
			assert: func(t *testing.T, e *env) {
				register(t, e, enrolmentSession("sess-a", "u-1"), "cred-a", "",
					passkey.RegistrationContext{EmailConfirmation: true})

				msgs := e.f.messages()
				require.Len(t, msgs, 1)
				assert.Equal(t, "ana@example.com", msgs[0].To)
				assert.Equal(t, "custom code", msgs[0].Subject)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			e := &env{f: f, logs: &logBuffer{}}

			if tc.codes {
				e.recv = recoveryDeps(t, f, recovery.WayBackDeps{})
				f.deps.Recovery = e.recv
			}

			e.m = f.manager(t, append([]passkey.Option{passkey.WithLogger(e.logs.logger())}, tc.opts...)...)
			tc.assert(t, e)
		})
	}
}
