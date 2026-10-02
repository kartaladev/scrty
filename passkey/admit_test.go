package passkey_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// brokenList is a memory store whose listing fails, and nothing else.
type brokenList struct {
	*passkey.MemoryCredentialStore
}

func (brokenList) List(context.Context, identity.UserID) ([]*passkey.Credential, error) {
	return nil, errStore
}

// countingHandles counts the user handles a manager assigns.
type countingHandles struct {
	passkey.HandleStore
	assigned atomic.Int32
}

func (c *countingHandles) Assign(ctx context.Context, u identity.UserID, offered []byte) ([]byte, error) {
	c.assigned.Add(1)

	return c.HandleStore.Assign(ctx, u, offered)
}

// admitOp is one of the two operations admission guards: a registration
// begin, or the removal of u-1's suspended passkey.
type admitOp struct {
	name string
	run  func(t *testing.T, e *manageEnv, s *session.Session, rc passkey.RegistrationContext) error
}

var admitOps = []admitOp{
	{
		name: "begin",
		run: func(t *testing.T, e *manageEnv, s *session.Session, rc passkey.RegistrationContext) error {
			_, err := e.m.BeginRegistration(t.Context(), s, rc)

			return err
		},
	},
	{
		name: "remove",
		run: func(t *testing.T, e *manageEnv, s *session.Session, rc passkey.RegistrationContext) error {
			return e.m.Remove(t.Context(), s, e.suspendedCred.ID, rc)
		},
	},
}

func TestAdmissionCountsOwnPasskeys(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []passkey.Option
		seed    func(t *testing.T, e *manageEnv)
		broken  bool
		handles *countingHandles
		session func() *session.Session
		rc      func(t *testing.T, e *manageEnv) passkey.RegistrationContext
		assert  func(t *testing.T, e *manageEnv, op string, err error)
	}

	password := func() *session.Session { return fullSession("sess-1", "u-1") }
	passkeyLogin := func() *session.Session {
		s := fullSession("sess-1", "u-1")
		s.FirstFactor = factor.Passkey

		return s
	}
	ownMethod := func(_ *testing.T, e *manageEnv) passkey.RegistrationContext {
		return passkey.RegistrationContext{MFAMethods: []policy.MFAMethodLookup{e.m.MFAMethod()}}
	}
	passwordless := func(*testing.T, *manageEnv) passkey.RegistrationContext {
		return passkey.RegistrationContext{PasswordlessLogin: true}
	}

	admitted := func(t *testing.T, e *manageEnv, op string, err error) {
		t.Helper()
		require.NoError(t, err)

		if op == "begin" {
			assert.Len(t, e.f.creations(), 1)
		} else {
			assert.False(t, e.exists(t, "u-1", e.suspendedCred.ID))
		}
	}
	refused := func(t *testing.T, e *manageEnv, _ string, err error) {
		t.Helper()
		require.ErrorIs(t, err, passkey.ErrReauthenticationRequired)
		assert.Empty(t, e.f.creations())
		assert.True(t, e.exists(t, "u-1", e.suspendedCred.ID))
		assert.True(t, e.exists(t, "u-1", e.cred.ID))
		assert.Empty(t, e.f.messages())
	}

	lookupHandles := &countingHandles{HandleStore: passkey.NewMemoryHandleStore()}

	recoveryPending := func() *session.Session {
		s := fullSession("sess-1", "u-1")
		s.MFA, s.FirstFactor = session.MFARecoveryPending, ""

		return s
	}
	enrolmentPending := func() *session.Session {
		s := fullSession("sess-1", "u-1")
		s.MFA, s.EnrolmentOriginDeadline = session.MFAEnrolmentPending, s.CreatedAt.Add(time.Hour)

		return s
	}
	nilEntry := func(*testing.T, *manageEnv) passkey.RegistrationContext {
		return passkey.RegistrationContext{MFAMethods: []policy.MFAMethodLookup{nil}}
	}
	typedNilEntry := func(*testing.T, *manageEnv) passkey.RegistrationContext {
		return passkey.RegistrationContext{MFAMethods: []policy.MFAMethodLookup{(*passkey.MFAMethod)(nil)}}
	}
	// A bad context is a configuration error on begin. Remove refuses a
	// confined session before it reads the context, so it never gets there.
	confinedConfig := func(t *testing.T, e *manageEnv, op string, err error) {
		t.Helper()

		if op == "begin" {
			require.ErrorIs(t, err, passkey.ErrConfig)
			assert.Empty(t, e.f.creations())

			return
		}

		require.ErrorIs(t, err, passkey.ErrReauthenticationRequired)
		assert.True(t, e.exists(t, "u-1", e.suspendedCred.ID))
	}

	cases := []testCase{
		{
			name:    "a passkey login without user verification is refused when the passkey method is configured",
			opts:    []passkey.Option{passkey.WithUserVerification(passkey.UVPreferred)},
			session: passkeyLogin,
			rc:      ownMethod,
			assert:  refused,
		},
		{
			name:    "a password session of a passkey holder is refused when passwordless login meets the second factor",
			session: password,
			rc:      passwordless,
			assert:  refused,
		},
		{
			name:    "the passkey method counts the user's passkeys even when passwordless login proves nothing",
			opts:    []passkey.Option{passkey.WithoutSecondFactorAtLogin()},
			session: passkeyLogin,
			rc: func(t *testing.T, e *manageEnv) passkey.RegistrationContext {
				rc := ownMethod(t, e)
				rc.PasswordlessLogin = true

				return rc
			},
			assert: refused,
		},
		{
			name:    "passwordless login that proves no second factor is no route",
			opts:    []passkey.Option{passkey.WithoutSecondFactorAtLogin()},
			session: password,
			rc:      passwordless,
			assert:  admitted,
		},
		{
			name:    "with no passkey route the user's passkeys do not count",
			session: password,
			assert:  admitted,
		},
		{
			name:    "another manager's passkey method is no route to this manager's passkeys",
			session: password,
			rc: func(t *testing.T, _ *manageEnv) passkey.RegistrationContext {
				other := newFixture(t).manager(t).MFAMethod()

				return passkey.RegistrationContext{MFAMethods: []policy.MFAMethodLookup{other}}
			},
			assert: admitted,
		},
		{
			name: "a pending or suspended passkey alone does not count",
			seed: func(t *testing.T, e *manageEnv) {
				_, err := e.f.creds.Delete(t.Context(), "u-1", e.cred.ID)
				require.NoError(t, err)
				addCredential(t, e.loginEnv, "u-1", "key-pending", passkey.StatePending)
			},
			session: password,
			rc:      passwordless,
			assert: func(t *testing.T, e *manageEnv, op string, err error) {
				t.Helper()
				require.NoError(t, err)

				if op == "remove" {
					assert.False(t, e.exists(t, "u-1", e.suspendedCred.ID))
				}
			},
		},
		{
			name: "a user-verified passkey login is admitted",
			session: func() *session.Session {
				s := passkeyLogin()
				s.MFA, s.MFASatisfiedAt = session.MFASatisfied, s.CreatedAt

				return s
			},
			rc:     ownMethod,
			assert: admitted,
		},
		{
			name: "a password session that stepped up is admitted",
			session: func() *session.Session {
				s := password()
				s.MFA, s.MFASatisfiedAt = session.MFASatisfied, s.CreatedAt.Add(time.Minute)

				return s
			},
			rc:     passwordless,
			assert: admitted,
		},
		{
			name:    "a failed passkey lookup refuses with fixed text",
			broken:  true,
			handles: lookupHandles,
			session: password,
			rc:      passwordless,
			assert: func(t *testing.T, e *manageEnv, op string, err error) {
				t.Helper()
				require.ErrorIs(t, err, errStore)
				assert.NotContains(t, err.Error(), errStore.Error())
				assert.Contains(t, err.Error(), "passkey: could not list the user's passkeys")
				assert.Empty(t, e.f.creations())
				assert.True(t, e.exists(t, "u-1", e.suspendedCred.ID))

				if op == "begin" {
					// Refused at admission, before any handle is assigned; the
					// listing for the exclude list comes after the assignment.
					assert.Zero(t, lookupHandles.assigned.Load())
				}
			},
		},
		{
			name:    "a nil method entry on a recovery-pending session is refused",
			session: recoveryPending,
			rc:      nilEntry,
			assert:  confinedConfig,
		},
		{
			name:    "a typed nil method entry on a recovery-pending session is refused",
			session: recoveryPending,
			rc:      typedNilEntry,
			assert:  confinedConfig,
		},
		{
			name:    "a nil method entry on an enrolment-only session is refused",
			session: enrolmentPending,
			rc:      nilEntry,
			assert:  confinedConfig,
		},
		{
			name:    "a typed nil method entry on an enrolment-only session is refused",
			session: enrolmentPending,
			rc:      typedNilEntry,
			assert:  confinedConfig,
		},
		{
			name:    "a nil method entry in the context is refused",
			session: password,
			rc: func(*testing.T, *manageEnv) passkey.RegistrationContext {
				return passkey.RegistrationContext{MFAMethods: []policy.MFAMethodLookup{nil}}
			},
			assert: func(t *testing.T, e *manageEnv, _ string, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrConfig)
				assert.Empty(t, e.f.creations())
				assert.True(t, e.exists(t, "u-1", e.suspendedCred.ID))
			},
		},
		{
			name:    "a typed nil method entry in the context is refused",
			session: password,
			rc: func(*testing.T, *manageEnv) passkey.RegistrationContext {
				return passkey.RegistrationContext{MFAMethods: []policy.MFAMethodLookup{(*passkey.MFAMethod)(nil)}}
			},
			assert: func(t *testing.T, e *manageEnv, _ string, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrConfig)
				assert.Empty(t, e.f.creations())
			},
		},
	}

	for _, tc := range cases {
		for _, op := range admitOps {
			t.Run(tc.name+"/"+op.name, func(t *testing.T) {
				t.Parallel()

				e := newManageEnv(t)
				if tc.seed != nil {
					tc.seed(t, e)
				}

				if tc.handles != nil {
					e.f.deps.Handles = tc.handles
				}

				if tc.broken {
					e.f.deps.Credentials = brokenList{e.f.creds}
				}

				e.manager(t, tc.opts...)

				var rc passkey.RegistrationContext
				if tc.rc != nil {
					rc = tc.rc(t, e)
				}

				var err error

				require.NotPanics(t, func() { err = op.run(t, e, tc.session(), rc) })
				tc.assert(t, e, op.name, err)
			})
		}
	}
}
