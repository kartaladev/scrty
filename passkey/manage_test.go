package passkey_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// manageEnv is a manager whose user u-1 holds the login fixture's active
// security key and a suspended passkey, and u-2 one active passkey.
type manageEnv struct {
	*loginEnv
	suspendedCred, theirs *passkey.Credential
}

// seedSessions stores the fixture's sessions (see fixture.seedSessions).
func (e *manageEnv) seedSessions(t *testing.T) {
	t.Helper()

	e.sids = e.f.seedSessions(t)
}

// loads reports whether the session stored for device still loads.
func (e *manageEnv) loads(t *testing.T, device string) bool {
	t.Helper()

	return e.f.loads(t, e.sids[device])
}

// mockRevoker wires a gomock session revoker in place of the session manager.
func (e *manageEnv) mockRevoker() *MockSessionRevoker { return e.f.mockRevoker() }

// lastNotice returns the body of the only notice queued.
func (e *manageEnv) lastNotice(t *testing.T) string {
	t.Helper()

	msgs := e.f.messages()
	require.Len(t, msgs, 1)

	return msgs[0].TextBody
}

func newManageEnv(t *testing.T) *manageEnv {
	t.Helper()

	e := &manageEnv{loginEnv: newLoginEnv(t, func(c *passkey.Credential) {
		c.Transports = []string{"usb"}
		c.BackupEligible = false
	})}
	e.suspendedCred = addCredential(t, e.loginEnv, "u-1", "key-suspended", passkey.StateSuspended)
	e.theirs = addCredential(t, e.loginEnv, "u-2", "key-of-u-2", passkey.StateActive)

	return e
}

// exists reports whether user still holds credential cid.
func (e *manageEnv) exists(t *testing.T, user identity.UserID, cid id.ID) bool {
	t.Helper()

	_, err := e.f.creds.Find(t.Context(), user, cid)

	return err == nil
}

// assertNoKeyBytes fails when any field of any summary, at any depth, holds
// one of keys' bytes.
func assertNoKeyBytes(t *testing.T, summaries []passkey.Summary, keys ...[]byte) {
	t.Helper()

	var walk func(v reflect.Value)
	walk = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.Struct:
			for i := range v.NumField() {
				walk(v.Field(i))
			}
		case reflect.Slice:
			if v.Type().Elem().Kind() == reflect.Uint8 {
				for _, k := range keys {
					assert.False(t, bytes.Contains(v.Bytes(), k), "a summary holds public-key bytes")
				}

				return
			}

			for i := range v.Len() {
				walk(v.Index(i))
			}
		case reflect.String:
			for _, k := range keys {
				assert.NotContains(t, v.String(), string(k), "a summary holds public-key bytes")
			}
		default:
		}
	}

	walk(reflect.ValueOf(summaries))
}

func TestManageList(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		user   identity.UserID
		broken bool
		assert func(t *testing.T, e *manageEnv, out []passkey.Summary, err error)
	}

	cases := []testCase{
		{
			name: "lists the user's active and suspended passkeys with their states, and no public key",
			user: "u-1",
			assert: func(t *testing.T, e *manageEnv, out []passkey.Summary, err error) {
				t.Helper()
				require.NoError(t, err)
				require.Len(t, out, 2)

				byID := map[id.ID]passkey.Summary{}
				for _, s := range out {
					byID[s.ID] = s
				}

				active := byID[e.cred.ID]
				assert.Equal(t, passkey.Summary{
					ID:         e.cred.ID,
					Name:       "Security key",
					State:      passkey.StateActive,
					CreatedAt:  regStart,
					Transports: []string{"usb"},
					AAGUID:     bytes.Repeat([]byte{0xAA}, 16),
				}, active)
				assert.Equal(t, passkey.StateSuspended, byID[e.suspendedCred.ID].State)
				assert.Equal(t, "key-suspended", byID[e.suspendedCred.ID].Name)

				_, hasKeyField := reflect.TypeFor[passkey.Summary]().FieldByName("PublicKey")
				assert.False(t, hasKeyField, "Summary has no public-key field")
				assertNoKeyBytes(t, out, e.cred.PublicKey, e.suspendedCred.PublicKey)
			},
		},
		{
			name: "a user with no passkey lists none",
			user: "u-3",
			assert: func(t *testing.T, _ *manageEnv, out []passkey.Summary, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Empty(t, out)
			},
		},
		{
			name:   "a store failure is an error, never an empty list",
			user:   "u-1",
			broken: true,
			assert: func(t *testing.T, _ *manageEnv, out []passkey.Summary, err error) {
				t.Helper()
				require.ErrorIs(t, err, errStore)
				assert.Nil(t, out)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newManageEnv(t)
			if tc.broken {
				e.f.deps.Credentials = brokenCredentials{e.f.creds}
			}

			out, err := e.manager(t).List(t.Context(), tc.user)
			tc.assert(t, e, out, err)
		})
	}
}

func TestManageRename(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		user   identity.UserID
		target func(e *manageEnv) id.ID
		rename string
		broken bool
		assert func(t *testing.T, e *manageEnv, err error)
	}

	mine := func(e *manageEnv) id.ID { return e.cred.ID }
	listedAs := func(want string) func(t *testing.T, e *manageEnv, err error) {
		return func(t *testing.T, e *manageEnv, err error) {
			t.Helper()
			require.NoError(t, err)

			out, err := e.m.List(t.Context(), "u-1")
			require.NoError(t, err)

			for _, s := range out {
				if s.ID == e.cred.ID {
					assert.Equal(t, want, s.Name)

					return
				}
			}

			t.Fatal("the renamed passkey is not listed")
		}
	}

	cases := []testCase{
		{name: "renames the passkey", user: "u-1", target: mine, rename: "Old phone", assert: listedAs("Old phone")},
		{name: "trims surrounding white space", user: "u-1", target: mine, rename: "  Old phone \t", assert: listedAs("Old phone")},
		{
			name: "a 200-character name is replaced by the default date name, never truncated",
			user: "u-1", target: mine, rename: strings.Repeat("x", 200), assert: listedAs("Passkey 2026-10-01"),
		},
		{
			name: "a name with a control character is replaced by the default date name",
			user: "u-1", target: mine, rename: "Old\nphone", assert: listedAs("Passkey 2026-10-01"),
		},
		{name: "an empty name is replaced by the default date name", user: "u-1", target: mine, rename: "", assert: listedAs("Passkey 2026-10-01")},
		{
			name:   "a suspended passkey can be renamed",
			user:   "u-1",
			target: func(e *manageEnv) id.ID { return e.suspendedCred.ID },
			rename: "Lost key",
			assert: func(t *testing.T, e *manageEnv, err error) {
				t.Helper()
				require.NoError(t, err)

				c, err := e.f.creds.Find(t.Context(), "u-1", e.suspendedCred.ID)
				require.NoError(t, err)
				assert.Equal(t, "Lost key", c.Name)
			},
		},
		{
			name:   "another user's passkey is not found and is not renamed",
			user:   "u-1",
			target: func(e *manageEnv) id.ID { return e.theirs.ID },
			rename: "Mine now",
			assert: func(t *testing.T, e *manageEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrNotFound)

				c, err := e.f.creds.Find(t.Context(), "u-2", e.theirs.ID)
				require.NoError(t, err)
				assert.Equal(t, "key-of-u-2", c.Name)
			},
		},
		{
			name: "an unknown identifier is not found",
			user: "u-1",
			target: func(*manageEnv) id.ID {
				cid, _ := id.NewV7Generator().NewID()

				return cid
			},
			rename: "Old phone",
			assert: func(t *testing.T, _ *manageEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrNotFound)
			},
		},
		{
			name:   "a store failure is returned",
			user:   "u-1",
			target: mine,
			rename: "Old phone",
			broken: true,
			assert: func(t *testing.T, _ *manageEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, errStore)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newManageEnv(t)
			if tc.broken {
				e.f.deps.Credentials = brokenFind{e.f.creds}
			}

			m := e.manager(t)
			err := m.Rename(t.Context(), tc.user, tc.target(e), tc.rename)
			tc.assert(t, e, err)
		})
	}
}

// brokenFind is a memory store whose single-credential reads and deletes
// fail.
type brokenFind struct {
	*passkey.MemoryCredentialStore
}

func (brokenFind) Find(context.Context, identity.UserID, id.ID) (*passkey.Credential, error) {
	return nil, errStore
}

func (brokenFind) Delete(context.Context, identity.UserID, id.ID) (bool, error) {
	return false, errStore
}

func TestManageRemove(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		session     func(e *manageEnv) *session.Session
		target      func(e *manageEnv) id.ID
		totp        bool // the user is enrolled on a TOTP second factor, listed in Deps
		rcTOTP      bool // the user is enrolled on a TOTP second factor, listed in the context only
		advance     time.Duration
		broken      bool
		prepare     func(t *testing.T, e *manageEnv) // runs before the manager is built
		managerOpts []passkey.Option
		opts        []passkey.RemoveOption
		ctx         func(ctx context.Context) context.Context
		assert      func(t *testing.T, e *manageEnv, err error)
	}

	fresh := func(*manageEnv) *session.Session { return fullSession("sess-1", "u-1") }
	mine := func(e *manageEnv) id.ID { return e.cred.ID }
	removedWithNotice := func(name string, target func(e *manageEnv) id.ID) func(t *testing.T, e *manageEnv, err error) {
		return func(t *testing.T, e *manageEnv, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.False(t, e.exists(t, "u-1", target(e)))

			msgs := e.f.messages()
			require.Len(t, msgs, 1)
			assert.Equal(t, "ana@example.com", msgs[0].To)
			assert.Contains(t, msgs[0].TextBody, name)
			assert.Contains(t, msgs[0].TextBody, "help@example.com")
		}
	}
	refusedKept := func(want error) func(t *testing.T, e *manageEnv, err error) {
		return func(t *testing.T, e *manageEnv, err error) {
			t.Helper()
			require.ErrorIs(t, err, want)
			assert.True(t, e.exists(t, "u-1", e.cred.ID))
			assert.Empty(t, e.f.messages())
		}
	}

	// refusedKeepingSessions asserts the removal refused with want, the
	// passkey kept, no notice, and every seeded session still loading.
	refusedKeepingSessions := func(want error) func(t *testing.T, e *manageEnv, err error) {
		return func(t *testing.T, e *manageEnv, err error) {
			t.Helper()
			require.ErrorIs(t, err, want)
			assert.True(t, e.exists(t, "u-1", e.cred.ID))
			assert.Empty(t, e.f.messages())

			for _, device := range []string{"laptop", "phone", "tablet", "theirs"} {
				assert.True(t, e.loads(t, device), "the %s session must still load", device)
			}
		}
	}
	// cancelRemoval cancels the context the second-pass case hands to Remove.
	var cancelRemoval context.CancelFunc

	fromLaptop := func(e *manageEnv) *session.Session { return fullSession(e.sids["laptop"], "u-1") }
	seeded := func(t *testing.T, e *manageEnv) { e.seedSessions(t) }
	// removedEnding asserts the passkey removed, only the laptop session of
	// u-1 still loading, u-2's untouched, and a notice saying so.
	removedEnding := func(t *testing.T, e *manageEnv, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.False(t, e.exists(t, "u-1", e.cred.ID))
		assert.True(t, e.loads(t, "laptop"), "the removing session must still load")
		assert.False(t, e.loads(t, "phone"))
		assert.False(t, e.loads(t, "tablet"))
		assert.True(t, e.loads(t, "theirs"), "another user's session must survive")
		assert.Contains(t, e.lastNotice(t), "Your other sessions were signed out.")
	}
	// removedKeeping asserts the passkey removed, every session still loading,
	// and a notice saying nothing of sessions.
	removedKeeping := func(t *testing.T, e *manageEnv, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.False(t, e.exists(t, "u-1", e.cred.ID))

		for _, device := range []string{"laptop", "phone", "tablet", "theirs"} {
			assert.True(t, e.loads(t, device), "the %s session must still load", device)
		}

		assert.NotContains(t, e.lastNotice(t), "signed out")
	}

	cases := []testCase{
		{
			name:    "a removal ends the user's other sessions, keeps the removing one, and the notice says so",
			prepare: seeded, session: fromLaptop, target: mine,
			assert: removedEnding,
		},
		{
			name:    "with removal revocation off, every session still loads and the notice says nothing of them",
			prepare: seeded, session: fromLaptop, target: mine,
			managerOpts: []passkey.Option{passkey.WithoutSessionRevocationOnRemoval()},
			assert:      removedKeeping,
		},
		{
			name:    "KeepOtherSessions keeps every session against the default",
			prepare: seeded, session: fromLaptop, target: mine,
			opts:   []passkey.RemoveOption{passkey.KeepOtherSessions()},
			assert: removedKeeping,
		},
		{
			name:    "EndOtherSessions ends the other sessions against a keep default",
			prepare: seeded, session: fromLaptop, target: mine,
			managerOpts: []passkey.Option{passkey.WithoutSessionRevocationOnRemoval()},
			opts:        []passkey.RemoveOption{passkey.EndOtherSessions()},
			assert:      removedEnding,
		},
		{
			name:    "the last option wins: end then keep keeps",
			prepare: seeded, session: fromLaptop, target: mine,
			opts:   []passkey.RemoveOption{passkey.EndOtherSessions(), passkey.KeepOtherSessions()},
			assert: removedKeeping,
		},
		{
			name:    "the last option wins: keep then end ends",
			prepare: seeded, session: fromLaptop, target: mine,
			managerOpts: []passkey.Option{passkey.WithoutSessionRevocationOnRemoval()},
			opts:        []passkey.RemoveOption{passkey.KeepOtherSessions(), nil, passkey.EndOtherSessions()},
			assert:      removedEnding,
		},
		{
			name:    "the other sessions end before the passkey goes, and again after",
			session: fresh, target: mine,
			prepare: func(t *testing.T, e *manageEnv) {
				r := e.mockRevoker()
				first := r.EXPECT().DeleteByUserExcept(gomock.Any(), identity.UserID("u-1"), "sess-1").
					DoAndReturn(func(ctx context.Context, _ identity.UserID, _ string) (int, error) {
						_, err := e.f.creds.Find(ctx, "u-1", e.cred.ID)
						assert.NoError(t, err, "the passkey must still exist at the first pass")

						return 2, nil
					})
				r.EXPECT().DeleteByUserExcept(gomock.Any(), identity.UserID("u-1"), "sess-1").
					DoAndReturn(func(ctx context.Context, _ identity.UserID, _ string) (int, error) {
						_, err := e.f.creds.Find(ctx, "u-1", e.cred.ID)
						assert.ErrorIs(t, err, passkey.ErrNotFound, "the passkey must be gone at the second pass")

						return 0, nil
					}).After(first.Call)
			},
			assert: func(t *testing.T, e *manageEnv, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, e.exists(t, "u-1", e.cred.ID))
				assert.Contains(t, e.lastNotice(t), "Your other sessions were signed out.")
			},
		},
		{
			name:    "a failed first pass refuses with fixed text, keeps the passkey and queues no notice",
			session: fresh, target: mine,
			prepare: func(_ *testing.T, e *manageEnv) {
				e.mockRevoker().EXPECT().DeleteByUserExcept(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(0, errors.New("db down: secret-host"))
			},
			assert: func(t *testing.T, e *manageEnv, err error) {
				t.Helper()
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "secret-host")
				assert.True(t, e.exists(t, "u-1", e.cred.ID))
				assert.Empty(t, e.f.messages())
			},
		},
		{
			name:    "a failed second pass is logged without the dependency's text and the removal stands",
			session: fresh, target: mine,
			prepare: func(_ *testing.T, e *manageEnv) {
				r := e.mockRevoker()
				first := r.EXPECT().DeleteByUserExcept(gomock.Any(), identity.UserID("u-1"), "sess-1").Return(1, nil)
				r.EXPECT().DeleteByUserExcept(gomock.Any(), identity.UserID("u-1"), "sess-1").
					Return(0, errors.New("db down: secret-host")).After(first.Call)
			},
			assert: func(t *testing.T, e *manageEnv, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, e.exists(t, "u-1", e.cred.ID))
				assert.Contains(t, e.lastNotice(t), "Your other sessions were signed out.")
				assert.Equal(t, 1, countRecords(e.logs, "passkey: the user's sessions could not all be ended"))
				assert.Contains(t, e.logs.String(), `"level":"ERROR"`)
				assert.Contains(t, e.logs.String(), `"key":"remove|sessions-not-ended"`)
				assert.NotContains(t, e.logs.String(), "secret-host")
			},
		},
		{
			name:    "KeepOtherSessions calls no revoker",
			session: fresh, target: mine,
			prepare: func(_ *testing.T, e *manageEnv) { e.mockRevoker() }, // gomock fails on any call
			opts:    []passkey.RemoveOption{passkey.KeepOtherSessions()},
			assert: func(t *testing.T, e *manageEnv, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, e.exists(t, "u-1", e.cred.ID))
				assert.NotContains(t, e.lastNotice(t), "signed out")
			},
		},
		{
			name:    "EndOtherSessions on a manager wired without a revoker is a configuration error that changes nothing",
			session: fresh, target: mine,
			prepare: func(_ *testing.T, e *manageEnv) { e.f.deps.Sessions = nil },
			managerOpts: []passkey.Option{
				passkey.WithoutSessionRevocationOnRemoval(), passkey.WithoutSessionRevocationOnClone(),
			},
			opts: []passkey.RemoveOption{passkey.EndOtherSessions()},
			assert: func(t *testing.T, e *manageEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrConfig)
				assert.True(t, e.exists(t, "u-1", e.cred.ID))
				assert.Empty(t, e.f.messages())
			},
		},
		{
			name:    "the second pass runs on a context the cancelled request cannot cancel",
			session: fresh, target: mine,
			prepare: func(t *testing.T, e *manageEnv) {
				r := e.mockRevoker()
				first := r.EXPECT().DeleteByUserExcept(gomock.Any(), identity.UserID("u-1"), "sess-1").
					DoAndReturn(func(context.Context, identity.UserID, string) (int, error) {
						cancelRemoval()

						return 1, nil
					})
				r.EXPECT().DeleteByUserExcept(gomock.Any(), identity.UserID("u-1"), "sess-1").
					DoAndReturn(func(ctx context.Context, _ identity.UserID, _ string) (int, error) {
						assert.NoError(t, ctx.Err(), "the second pass must not run on the cancelled context")

						return 0, nil
					}).After(first.Call)
			},
			ctx: func(ctx context.Context) context.Context {
				// The first revocation pass calls cancelRemoval.
				c, cancel := context.WithCancel(ctx) //nolint:gosec // cancelled by the case's first pass
				cancelRemoval = cancel

				return c
			},
			assert: func(t *testing.T, e *manageEnv, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, e.exists(t, "u-1", e.cred.ID))
			},
		},
		{
			name:    "another user's passkey is refused and ends no session",
			prepare: seeded, session: fromLaptop,
			target: func(e *manageEnv) id.ID { return e.theirs.ID },
			assert: refusedKeepingSessions(passkey.ErrNotFound),
		},
		{
			name:    "an unknown identifier ends no session",
			prepare: seeded, session: fromLaptop,
			target: func(*manageEnv) id.ID {
				cid, _ := id.NewV7Generator().NewID()

				return cid
			},
			assert: refusedKeepingSessions(passkey.ErrNotFound),
		},
		{
			name:    "a stale session is refused and ends no session",
			prepare: seeded, session: fromLaptop, target: mine, advance: 20 * time.Minute,
			assert: refusedKeepingSessions(passkey.ErrReauthenticationRequired),
		},
		{
			name:    "a session with a pending challenge is refused and ends no session",
			prepare: seeded, target: mine,
			session: func(e *manageEnv) *session.Session {
				s := fullSession(e.sids["laptop"], "u-1")
				s.MFA = session.MFAPending

				return s
			},
			assert: refusedKeepingSessions(passkey.ErrReauthenticationRequired),
		},
		{
			name:    "a fresh full session removes its passkey and the user is notified",
			session: fresh, target: mine,
			assert: removedWithNotice("Security key", mine),
		},
		{
			name:    "a suspended passkey is removable",
			session: fresh, target: func(e *manageEnv) id.ID { return e.suspendedCred.ID },
			assert: removedWithNotice("key-suspended", func(e *manageEnv) id.ID { return e.suspendedCred.ID }),
		},
		{
			name:    "another user's passkey is not found, still exists, and no one is notified",
			session: fresh,
			target:  func(e *manageEnv) id.ID { return e.theirs.ID },
			assert: func(t *testing.T, e *manageEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrNotFound)
				assert.True(t, e.exists(t, "u-2", e.theirs.ID))
				assert.Empty(t, e.f.messages())
			},
		},
		{
			name:    "an unknown identifier is not found",
			session: fresh,
			target: func(*manageEnv) id.ID {
				cid, _ := id.NewV7Generator().NewID()

				return cid
			},
			assert: refusedKept(passkey.ErrNotFound),
		},
		{
			name:    "a session whose latest authentication is 20 minutes old must reauthenticate",
			session: fresh, target: mine, advance: 20 * time.Minute,
			assert: refusedKept(passkey.ErrReauthenticationRequired),
		},
		{
			name:    "a session at exactly the freshness window is admitted",
			session: fresh, target: mine, advance: 15 * time.Minute,
			assert: removedWithNotice("Security key", mine),
		},
		{
			name: "a second factor met 5 minutes ago keeps an older session fresh",
			session: func(*manageEnv) *session.Session {
				s := fullSession("sess-1", "u-1")
				s.MFA, s.MFASatisfiedAt = session.MFASatisfied, regStart.Add(15*time.Minute)

				return s
			},
			target: mine, totp: true, advance: 20 * time.Minute,
			assert: removedWithNotice("Security key", mine),
		},
		{
			name:    "a user with a usable second factor not yet met must reauthenticate",
			session: fresh, target: mine, totp: true,
			assert: refusedKept(passkey.ErrReauthenticationRequired),
		},
		{
			name:    "the context's second factors decide when Deps lists none",
			session: fresh, target: mine, rcTOTP: true,
			assert: refusedKept(passkey.ErrReauthenticationRequired),
		},
		{
			name: "a recovery-pending session is refused",
			session: func(*manageEnv) *session.Session {
				s := fullSession("sess-1", "u-1")
				s.MFA = session.MFARecoveryPending

				return s
			},
			target: mine,
			assert: refusedKept(passkey.ErrReauthenticationRequired),
		},
		{
			name: "an enrolment-only session is refused",
			session: func(*manageEnv) *session.Session {
				s := fullSession("sess-1", "u-1")
				s.MFA = session.MFAEnrolmentPending

				return s
			},
			target: mine,
			assert: refusedKept(passkey.ErrReauthenticationRequired),
		},
		{
			name: "a session with a pending challenge is refused",
			session: func(*manageEnv) *session.Session {
				s := fullSession("sess-1", "u-1")
				s.MFA = session.MFAPending

				return s
			},
			target: mine,
			assert: refusedKept(passkey.ErrReauthenticationRequired),
		},
		{
			name: "a session owing a password change is refused",
			session: func(*manageEnv) *session.Session {
				s := fullSession("sess-1", "u-1")
				s.PasswordChangePending = true

				return s
			},
			target: mine,
			assert: refusedKept(passkey.ErrReauthenticationRequired),
		},
		{
			name:    "no session is refused",
			session: func(*manageEnv) *session.Session { return nil },
			target:  mine,
			assert:  refusedKept(passkey.ErrReauthenticationRequired),
		},
		{
			name:    "a store failure is returned and no one is notified",
			session: fresh, target: mine, broken: true,
			assert: func(t *testing.T, e *manageEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, errStore)
				assert.Empty(t, e.f.messages())
			},
		},
		{
			name:    "a cancelled context removes nothing",
			session: fresh, target: mine,
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithCancel(ctx)
				cancel()

				return c
			},
			assert: refusedKept(context.Canceled),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newManageEnv(t)
			if tc.totp {
				e.f.withTOTP(true, nil)
			}

			if tc.broken {
				e.f.deps.Credentials = brokenFind{e.f.creds}
			}

			if tc.prepare != nil {
				tc.prepare(t, e)
			}

			m := e.manager(t, tc.managerOpts...)
			e.f.clock.Advance(tc.advance)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			var rc passkey.RegistrationContext
			if tc.rcTOTP {
				rc.MFAMethods = []policy.MFAMethodLookup{e.f.totp(true, nil)}
			}

			err := m.Remove(ctx, tc.session(e), tc.target(e), rc, tc.opts...)
			tc.assert(t, e, err)
		})
	}
}
