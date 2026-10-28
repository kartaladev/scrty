package passkey_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// limitedCredentials is a memory credential store whose bounded insert always
// answers that the user is at the limit, as it does for the finish that loses
// a race the early count let through.
type limitedCredentials struct {
	*passkey.MemoryCredentialStore
}

func (limitedCredentials) InsertWithin(context.Context, *passkey.Credential, int) (bool, error) {
	return false, nil
}

// cancelAwareCredentials is a memory credential store whose Delete fails once
// the caller's context is done, as a durable store's does.
type cancelAwareCredentials struct {
	*passkey.MemoryCredentialStore
}

func (s cancelAwareCredentials) Delete(ctx context.Context, user identity.UserID, cid id.ID) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	return s.MemoryCredentialStore.Delete(ctx, user, cid)
}

// undeletableCredentials is a memory credential store whose Delete always
// fails, as a store that goes down between an insert and its removal does.
type undeletableCredentials struct {
	*passkey.MemoryCredentialStore

	err error
}

func (s undeletableCredentials) Delete(context.Context, identity.UserID, id.ID) (bool, error) {
	return false, s.err
}

// msgUnsettledRecord is the record a finish logs when the passkey it stored
// and then failed to settle could not be removed.
const msgUnsettledRecord = "passkey: a passkey whose registration failed after it was stored could not be removed"

// replaceCodes is a memory code store that counts the sets it is asked to
// store, and fails each with err when err is set, first calling cancel when it
// is set.
type replaceCodes struct {
	*recovery.MemoryCodeStore

	replaced atomic.Int32
	err      error
	cancel   context.CancelFunc
}

func (s *replaceCodes) ReplaceSet(ctx context.Context, user identity.UserID, hashes [][]byte, at time.Time) error {
	s.replaced.Add(1)

	if s.cancel != nil {
		s.cancel()
	}

	if s.err != nil {
		return s.err
	}

	return s.MemoryCodeStore.ReplaceSet(ctx, user, hashes, at)
}

// TestFinishRegistration_RefusedOrFailedFinishLeavesNothing pins the work a
// finish does after its bounded insert: a finish the insert refuses neither
// generates saved codes nor sends an emailed code, and a finish whose saved
// codes cannot be generated after the insert removes the passkey it stored,
// even when the request was cancelled meanwhile.
func TestFinishRegistration_RefusedOrFailedFinishLeavesNothing(t *testing.T) {
	t.Parallel()

	type env struct {
		f     *fixture
		codes *replaceCodes
		logs  *logBuffer
	}

	type testCase struct {
		name    string
		session func() *session.Session // nil: a full session of u-1
		rc      passkey.RegistrationContext
		creds   func(inner *passkey.MemoryCredentialStore) passkey.CredentialStore
		codes   func(cancel context.CancelFunc) *replaceCodes // nil: no saved codes wired
		assert  func(t *testing.T, e *env, res *passkey.RegistrationResult, err error)
	}

	codeStoreErr := errors.New("code store down")
	deleteErr := errors.New("credential store down")

	storedNothing := func(t *testing.T, e *env) {
		t.Helper()

		n, err := e.f.creds.Count(t.Context(), "u-1")
		require.NoError(t, err)
		assert.Zero(t, n, "passkeys u-1 holds")
	}

	cases := []testCase{
		{
			name:    "a refused finish sends no emailed code",
			session: func() *session.Session { return enrolmentSession("sess-a", "u-1") },
			rc:      passkey.RegistrationContext{EmailConfirmation: true},
			creds: func(inner *passkey.MemoryCredentialStore) passkey.CredentialStore {
				return limitedCredentials{inner}
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				require.ErrorIs(t, err, passkey.ErrLimitReached)
				assert.Nil(t, res)
				assert.Empty(t, e.f.messages(), "messages sent")
				storedNothing(t, e)
			},
		},
		{
			name: "a refused finish generates no saved codes",
			creds: func(inner *passkey.MemoryCredentialStore) passkey.CredentialStore {
				return limitedCredentials{inner}
			},
			codes: func(context.CancelFunc) *replaceCodes {
				return &replaceCodes{MemoryCodeStore: recovery.NewMemoryCodeStore()}
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				require.ErrorIs(t, err, passkey.ErrLimitReached)
				assert.Nil(t, res)
				assert.Zero(t, e.codes.replaced.Load(), "saved-code sets stored")
				storedNothing(t, e)
			},
		},
		{
			name: "saved codes that cannot be generated remove the stored passkey",
			creds: func(inner *passkey.MemoryCredentialStore) passkey.CredentialStore {
				return cancelAwareCredentials{inner}
			},
			codes: func(context.CancelFunc) *replaceCodes {
				return &replaceCodes{MemoryCodeStore: recovery.NewMemoryCodeStore(), err: codeStoreErr}
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				require.ErrorIs(t, err, codeStoreErr)
				assert.Nil(t, res)
				storedNothing(t, e)
			},
		},
		{
			name: "the stored passkey is removed even when the request was cancelled",
			creds: func(inner *passkey.MemoryCredentialStore) passkey.CredentialStore {
				return cancelAwareCredentials{inner}
			},
			codes: func(cancel context.CancelFunc) *replaceCodes {
				return &replaceCodes{MemoryCodeStore: recovery.NewMemoryCodeStore(), err: codeStoreErr, cancel: cancel}
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				require.ErrorIs(t, err, codeStoreErr)
				assert.Nil(t, res)
				storedNothing(t, e)
			},
		},
		{
			name: "a removal that also fails is logged and the settling failure returned",
			creds: func(inner *passkey.MemoryCredentialStore) passkey.CredentialStore {
				return undeletableCredentials{MemoryCredentialStore: inner, err: deleteErr}
			},
			codes: func(context.CancelFunc) *replaceCodes {
				return &replaceCodes{MemoryCodeStore: recovery.NewMemoryCodeStore(), err: codeStoreErr}
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				require.ErrorIs(t, err, codeStoreErr)
				assert.NotErrorIs(t, err, deleteErr)
				assert.Nil(t, res)
				assert.Equal(t, 1, countRecords(e.logs, msgUnsettledRecord), "unsettled-not-removed records")

				n, err := e.f.creds.Count(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, 1, n, "the pending passkey the failed removal left behind")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			f := newFixture(t)
			e := &env{f: f, logs: &logBuffer{}}

			if tc.codes != nil {
				e.codes = tc.codes(cancel)
				f.deps.Recovery = recoveryDeps(t, f, recovery.WayBackDeps{}, recovery.WithCodeStore(e.codes))
			}

			f.deps.Credentials = tc.creds(f.creds)
			m := f.manager(t, passkey.WithLogger(e.logs.logger()))

			s := fullSession("sess-a", "u-1")
			if tc.session != nil {
				s = tc.session()
			}

			f.clock.Advance(time.Minute)
			challenge := f.begin(t, m, s)

			res, err := m.FinishRegistration(ctx, s, regBody(challenge, "cred-a", ""), tc.rc)
			tc.assert(t, e, res, err)
		})
	}
}

// TestFinishRegistration_AbandonedRegistrationReplacedAtLimitOne holds a user
// at a passkey limit of one with a passkey left pending by a registration they
// abandoned. Registering again replaces it: the old passkey is gone, so it no
// longer counts against the limit, and the new one confirms with its own codes.
func TestFinishRegistration_AbandonedRegistrationReplacedAtLimitOne(t *testing.T) {
	t.Parallel()

	type env struct {
		f *fixture
		m *passkey.Passkeys
		s *session.Session
	}

	type testCase struct {
		name    string
		session *session.Session
		rc      passkey.RegistrationContext
		codes   bool // wire saved codes for a user with no way back
		confirm func(t *testing.T, e *env, res *passkey.RegistrationResult) (*passkey.Credential, error)
	}

	cases := []testCase{
		{
			name:    "a passkey awaiting saved codes",
			session: fullSession("sess-a", "u-1"),
			codes:   true,
			confirm: func(t *testing.T, e *env, res *passkey.RegistrationResult) (*passkey.Credential, error) {
				require.Len(t, res.RecoveryCodes, 10)

				return e.m.ConfirmSavedCode(t.Context(), e.s, res.RecoveryCodes[0], passkey.RegistrationContext{})
			},
		},
		{
			name:    "a passkey awaiting an emailed code",
			session: enrolmentSession("sess-a", "u-1"),
			rc:      passkey.RegistrationContext{EmailConfirmation: true},
			confirm: func(t *testing.T, e *env, _ *passkey.RegistrationResult) (*passkey.Credential, error) {
				msgs := e.f.messages()
				require.Len(t, msgs, 2, "one code for each registration")

				return e.m.ConfirmEmailCode(t.Context(), e.s, sixDigits.FindString(msgs[1].TextBody),
					passkey.RegistrationContext{EmailConfirmation: true})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			if tc.codes {
				f.deps.Recovery = recoveryDeps(t, f, recovery.WayBackDeps{})
			}

			e := &env{f: f, m: f.manager(t, passkey.WithPasskeyLimit(1)), s: tc.session}

			first, err := e.m.FinishRegistration(t.Context(), e.s,
				regBody(f.begin(t, e.m, e.s), "cred-first", ""), tc.rc)
			require.NoError(t, err, "the abandoned registration")
			require.Equal(t, passkey.StatePending, first.Credential.State)

			f.clock.Advance(time.Minute)

			second, err := e.m.FinishRegistration(t.Context(), e.s,
				regBody(f.begin(t, e.m, e.s), "cred-second", ""), tc.rc)
			require.NoError(t, err, "registering again at the limit")

			held, err := f.creds.List(t.Context(), "u-1")
			require.NoError(t, err)
			require.Len(t, held, 1, "passkeys u-1 holds")
			assert.Equal(t, second.Credential.ID, held[0].ID, "the passkey u-1 holds")

			c, err := tc.confirm(t, e, second)
			require.NoError(t, err, "the new registration's own codes")
			assert.Equal(t, second.Credential.ID, c.ID)
			assert.Equal(t, passkey.StateActive, c.State)
		})
	}
}
