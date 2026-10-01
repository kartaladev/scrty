package passkey_test

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// sixDigits finds the emailed code in a message body.
var sixDigits = regexp.MustCompile(`\b\d{6}\b`)

// enrolmentSession is an enrolment-only session of user created at regStart.
func enrolmentSession(sid string, user identity.UserID) *session.Session {
	s := fullSession(sid, user)
	s.MFA, s.EnrolmentOriginDeadline = session.MFAEnrolmentPending, regStart.Add(time.Hour)

	return s
}

// recoverySession is a recovery-pending session of user created at regStart.
func recoverySession(sid string, user identity.UserID) *session.Session {
	s := fullSession(sid, user)
	s.MFA, s.FirstFactor = session.MFARecoveryPending, ""
	s.EnrolmentOriginDeadline, s.RecoveredAt = regStart.Add(15*time.Minute), regStart

	return s
}

// emailedCode returns the code in the only message sent so far.
func emailedCode(t *testing.T, f *fixture) string {
	t.Helper()

	msgs := f.messages()
	require.Len(t, msgs, 1)

	code := sixDigits.FindString(msgs[0].TextBody)
	require.NotEmpty(t, code)

	return code
}

// wrongCode returns a six-digit code that is not code.
func wrongCode(code string) string {
	if code == "000000" {
		return "111111"
	}

	return "000000"
}

// permissive is a limiter that never refuses, so a test sees the store's own
// cap on emailed-code attempts.
func permissive(t *testing.T) ratelimit.Limiter {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(1000, time.Minute)
	require.NoError(t, err)

	return l
}

// onlyCredential returns user's only credential.
func onlyCredential(t *testing.T, f *fixture, user identity.UserID) *passkey.Credential {
	t.Helper()

	held, err := f.creds.List(t.Context(), user)
	require.NoError(t, err)
	require.Len(t, held, 1)

	return held[0]
}

func TestPending(t *testing.T) {
	t.Parallel()

	type env struct {
		f    *fixture
		m    *passkey.Manager
		s    *session.Session
		rc   passkey.RegistrationContext
		recv *passkey.RecoveryDeps
	}

	type testCase struct {
		name    string
		opts    []passkey.Option
		codes   bool                                  // wire saved codes with a way-back check
		wayBack func(f *fixture) recovery.WayBackDeps // nil: the fixture's loader, no issued codes
		setup   func(t *testing.T, e *env)            // before the begin
		session func() *session.Session               // nil: a full session of u-1
		rc      func(t *testing.T) passkey.RegistrationContext
		assert  func(t *testing.T, e *env, res *passkey.RegistrationResult, err error)
	}

	email := func(*testing.T) passkey.RegistrationContext {
		return passkey.RegistrationContext{EmailConfirmation: true}
	}
	emailPermissive := func(t *testing.T) passkey.RegistrationContext {
		return passkey.RegistrationContext{EmailConfirmation: true, ConfirmLimiter: permissive(t)}
	}
	enrolling := func() *session.Session { return enrolmentSession("sess-a", "u-1") }

	awaitingCodes := func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.False(t, res.Activated)
		assert.Len(t, res.RecoveryCodes, 10)

		c := onlyCredential(t, e.f, "u-1")
		assert.Equal(t, passkey.StatePending, c.State)
		assert.Equal(t, passkey.AwaitingSavedCodes, c.Pending)
	}
	awaitingEmail := func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.False(t, res.Activated)
		assert.Empty(t, res.RecoveryCodes)

		c := onlyCredential(t, e.f, "u-1")
		assert.Equal(t, passkey.StatePending, c.State)
		assert.Equal(t, passkey.AwaitingEmailCode, c.Pending)
	}
	stillPending := func(t *testing.T, e *env) {
		t.Helper()
		assert.Equal(t, passkey.StatePending, onlyCredential(t, e.f, "u-1").State)
	}
	activeAtOnce := func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.True(t, res.Activated)
		assert.Empty(t, res.RecoveryCodes)
		assert.Empty(t, e.f.messages())
		assert.Equal(t, passkey.StateActive, onlyCredential(t, e.f, "u-1").State)
	}

	loaderErr := errors.New("user store down")

	cases := []testCase{
		{
			name:   "a first passkey with no way back waits for saved codes",
			codes:  true,
			assert: awaitingCodes,
		},
		{
			name:  "one of the saved codes activates it and stays unspent",
			codes: true,
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				awaitingCodes(t, e, res, err)

				c, err := e.m.ConfirmSavedCode(t.Context(), e.s, res.RecoveryCodes[3])
				require.NoError(t, err)
				require.NotNil(t, c)
				assert.Equal(t, passkey.StateActive, c.State)
				assert.Zero(t, c.Pending)
				assert.Equal(t, passkey.StateActive, onlyCredential(t, e.f, "u-1").State)

				left, err := e.recv.Codes.Remaining(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, 10, left.N)
			},
		},
		{
			name:  "a wrong saved code leaves it pending",
			codes: true,
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				awaitingCodes(t, e, res, err)

				c, err := e.m.ConfirmSavedCode(t.Context(), e.s, "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GG")
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Nil(t, c)
				stillPending(t, e)
			},
		},
		{
			name:  "the saved-code throttle is returned unchanged",
			codes: true,
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				awaitingCodes(t, e, res, err)

				for range 5 {
					_, err := e.m.ConfirmSavedCode(t.Context(), e.s, "wrong")
					require.ErrorIs(t, err, mfa.ErrInvalidCode)
				}

				_, err = e.m.ConfirmSavedCode(t.Context(), e.s, res.RecoveryCodes[0])
				require.ErrorIs(t, err, recovery.ErrCodeThrottled)
				stillPending(t, e)
			},
		},
		{
			name:  "no passkey awaiting saved codes",
			codes: true,
			setup: func(t *testing.T, e *env) {
				_, err := e.recv.Codes.Generate(t.Context(), "u-1")
				require.NoError(t, err)
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				activeAtOnce(t, e, res, err)

				c, err := e.m.ConfirmSavedCode(t.Context(), e.s, "anything")
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Nil(t, c)
			},
		},
		{
			name:  "an abandoned registration is replaced",
			codes: true,
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				awaitingCodes(t, e, res, err)
				old := onlyCredential(t, e.f, "u-1")

				challenge := e.f.begin(t, e.m, e.s)
				res2, err := e.m.FinishRegistration(t.Context(), e.s, regBody(challenge, "cred-b", ""), e.rc)
				require.NoError(t, err)
				assert.Len(t, res2.RecoveryCodes, 10)
				assert.NotEqual(t, res.RecoveryCodes, res2.RecoveryCodes)

				c := onlyCredential(t, e.f, "u-1")
				assert.NotEqual(t, old.ID, c.ID)
				assert.Equal(t, []byte("cred-b"), c.CredentialID)
				assert.Equal(t, passkey.AwaitingSavedCodes, c.Pending)
			},
		},
		{
			name:  "a user holding saved codes is active at once",
			codes: true,
			setup: func(t *testing.T, e *env) {
				_, err := e.recv.Codes.Generate(t.Context(), "u-1")
				require.NoError(t, err)
			},
			assert: activeAtOnce,
		},
		{
			name:  "the optional mode is active at once and reports recovery not set up",
			opts:  []passkey.Option{passkey.WithOptionalRecoveryCodes()},
			codes: true,
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				activeAtOnce(t, e, res, err)
				assert.True(t, res.RecoveryNotSetUp)
			},
		},
		{
			name:  "a failed way-back check stores nothing",
			codes: true,
			wayBack: func(f *fixture) recovery.WayBackDeps {
				broken := NewMockUserLoader(f.ctrl)
				broken.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).Return(nil, loaderErr).AnyTimes()

				return recovery.WayBackDeps{Users: broken, IssuedCodes: true}
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, loaderErr)
				assert.Nil(t, res)

				n, err := e.f.creds.Count(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Zero(t, n)
			},
		},
		{
			name:    "an enrolment-only session's passkey waits for an emailed code",
			session: enrolling,
			rc:      email,
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				awaitingEmail(t, e, res, err)

				msgs := e.f.messages()
				require.Len(t, msgs, 1)
				assert.Equal(t, "ana@example.com", msgs[0].To)

				c := onlyCredential(t, e.f, "u-1")
				require.NotNil(t, c.EmailCode)
				assert.Equal(t, emailedCode(t, e.f), c.EmailCode.Code)
				assert.Equal(t, regStart.Add(time.Minute+10*time.Minute), c.EmailCode.ExpiresAt)
			},
		},
		{
			name:    "the emailed code within ten minutes activates it",
			session: enrolling,
			rc:      email,
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				awaitingEmail(t, e, res, err)

				e.f.clock.Advance(9 * time.Minute)

				c, err := e.m.ConfirmEmailCode(t.Context(), e.s, emailedCode(t, e.f), e.rc)
				require.NoError(t, err)
				require.NotNil(t, c)
				assert.Equal(t, passkey.StateActive, c.State)

				got := onlyCredential(t, e.f, "u-1")
				assert.Equal(t, passkey.StateActive, got.State)
				assert.Nil(t, got.EmailCode)
			},
		},
		{
			name:    "the emailed code at eleven minutes is refused",
			session: enrolling,
			rc:      email,
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				awaitingEmail(t, e, res, err)

				e.f.clock.Advance(11 * time.Minute)

				c, err := e.m.ConfirmEmailCode(t.Context(), e.s, emailedCode(t, e.f), e.rc)
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Nil(t, c)
				stillPending(t, e)
			},
		},
		{
			name:    "the right code after five wrong ones is refused",
			session: enrolling,
			rc:      emailPermissive,
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				awaitingEmail(t, e, res, err)
				code := emailedCode(t, e.f)

				for range 5 {
					_, err := e.m.ConfirmEmailCode(t.Context(), e.s, wrongCode(code), e.rc)
					require.ErrorIs(t, err, mfa.ErrInvalidCode)
				}

				c, err := e.m.ConfirmEmailCode(t.Context(), e.s, code, e.rc)
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Nil(t, c)
				stillPending(t, e)
			},
		},
		{
			name:    "the default limiter throttles after five failures",
			session: enrolling,
			rc:      email,
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				awaitingEmail(t, e, res, err)
				code := emailedCode(t, e.f)

				for range 5 {
					_, err := e.m.ConfirmEmailCode(t.Context(), e.s, wrongCode(code), e.rc)
					require.ErrorIs(t, err, mfa.ErrInvalidCode)
				}

				_, err = e.m.ConfirmEmailCode(t.Context(), e.s, code, e.rc)
				require.ErrorIs(t, err, mfa.ErrEnrolmentThrottled)
				stillPending(t, e)
			},
		},
		{
			name:    "the consumer limiter counts failures under the shared key",
			session: enrolling,
			rc: func(t *testing.T) passkey.RegistrationContext {
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), "mfa-enrol-confirm:u-1").Return(false, nil)
				l.EXPECT().RecordFailure(gomock.Any(), "mfa-enrol-confirm:u-1").Return(nil)

				return passkey.RegistrationContext{EmailConfirmation: true, ConfirmLimiter: l}
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				awaitingEmail(t, e, res, err)

				_, err = e.m.ConfirmEmailCode(t.Context(), e.s, wrongCode(emailedCode(t, e.f)), e.rc)
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
			},
		},
		{
			name:    "another user cannot confirm the emailed code",
			session: enrolling,
			rc:      emailPermissive,
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				awaitingEmail(t, e, res, err)

				c, err := e.m.ConfirmEmailCode(t.Context(), enrolmentSession("sess-b", "u-2"), emailedCode(t, e.f), e.rc)
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Nil(t, c)
				stillPending(t, e)
			},
		},
		{
			name:    "a sender that cannot queue fails the finish and stores nothing",
			session: enrolling,
			rc:      email,
			setup: func(_ *testing.T, e *env) {
				e.f.mu.Lock()
				e.f.sendErr = notify.ErrQueueFull
				e.f.mu.Unlock()
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, notify.ErrQueueFull)
				assert.Nil(t, res)

				n, err := e.f.creds.Count(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Zero(t, n)
			},
		},
		{
			name:    "the consumer's contact resolver addresses the code",
			session: enrolling,
			rc: func(*testing.T) passkey.RegistrationContext {
				return passkey.RegistrationContext{
					EmailConfirmation: true,
					ContactResolver: func(_ context.Context, d *identity.Details) (string, error) {
						return "alt-" + d.Username, nil
					},
				}
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				awaitingEmail(t, e, res, err)
				assert.Equal(t, "alt-ana@example.com", e.f.messages()[0].To)
			},
		},
		{
			name:    "email confirmation off on the path activates at once",
			session: enrolling,
			assert:  activeAtOnce,
		},
		{
			name:   "a full session is not asked for an emailed code",
			rc:     email,
			assert: activeAtOnce,
		},
		{
			name:    "both reasons, emailed code first",
			codes:   true,
			session: enrolling,
			rc:      email,
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.NoError(t, err)
				require.Len(t, res.RecoveryCodes, 10)
				assert.Equal(t, passkey.AwaitingSavedCodes|passkey.AwaitingEmailCode, onlyCredential(t, e.f, "u-1").Pending)

				c, err := e.m.ConfirmEmailCode(t.Context(), e.s, emailedCode(t, e.f), e.rc)
				require.NoError(t, err)
				assert.Nil(t, c)
				stillPending(t, e)

				c, err = e.m.ConfirmSavedCode(t.Context(), e.s, res.RecoveryCodes[0])
				require.NoError(t, err)
				require.NotNil(t, c)
				assert.Equal(t, passkey.StateActive, onlyCredential(t, e.f, "u-1").State)
			},
		},
		{
			name:    "both reasons, saved code first",
			codes:   true,
			session: enrolling,
			rc:      email,
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.NoError(t, err)
				require.Len(t, res.RecoveryCodes, 10)

				c, err := e.m.ConfirmSavedCode(t.Context(), e.s, res.RecoveryCodes[0])
				require.NoError(t, err)
				assert.Nil(t, c)
				stillPending(t, e)

				c, err = e.m.ConfirmEmailCode(t.Context(), e.s, emailedCode(t, e.f), e.rc)
				require.NoError(t, err)
				require.NotNil(t, c)
				assert.Equal(t, passkey.StateActive, onlyCredential(t, e.f, "u-1").State)
			},
		},
		{
			name:    "a recovery-pending passkey left pending is replaced by a later full session",
			codes:   true,
			session: func() *session.Session { return recoverySession("sess-r", "u-1") },
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				awaitingCodes(t, e, res, err)
				left := onlyCredential(t, e.f, "u-1")

				// The recovery-pending session expires unconfirmed; the passkey
				// stays pending and unusable.
				e.f.clock.Advance(2 * time.Hour)
				assert.Equal(t, passkey.StatePending, onlyCredential(t, e.f, "u-1").State)

				later := fullSession("sess-b", "u-1")
				later.CreatedAt = e.f.clock.Now()

				challenge := e.f.begin(t, e.m, later)
				res2, err := e.m.FinishRegistration(t.Context(), later, regBody(challenge, "cred-b", ""),
					passkey.RegistrationContext{})
				require.NoError(t, err)
				assert.False(t, res2.Activated)
				assert.Len(t, res2.RecoveryCodes, 10)

				_, err = e.f.creds.Find(t.Context(), "u-1", left.ID)
				require.ErrorIs(t, err, passkey.ErrNotFound)

				c := onlyCredential(t, e.f, "u-1")
				assert.Equal(t, []byte("cred-b"), c.CredentialID)
				assert.Equal(t, passkey.AwaitingSavedCodes, c.Pending)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			e := &env{f: f}

			if tc.codes {
				wb := recovery.WayBackDeps{}
				if tc.wayBack != nil {
					wb = tc.wayBack(f)
				}

				e.recv = recoveryDeps(t, f, wb)
				f.deps.Recovery = e.recv
			}

			e.m = f.manager(t, tc.opts...)

			if tc.setup != nil {
				tc.setup(t, e)
			}

			e.s = fullSession("sess-a", "u-1")
			if tc.session != nil {
				e.s = tc.session()
			}

			if tc.rc != nil {
				e.rc = tc.rc(t)
			}

			f.clock.Advance(time.Minute)
			challenge := f.begin(t, e.m, e.s)

			res, err := e.m.FinishRegistration(t.Context(), e.s, regBody(challenge, "cred-a", ""), e.rc)
			tc.assert(t, e, res, err)
		})
	}
}

// TestPendingConcurrentEmailGuessesAreBounded posts twenty wrong emailed codes
// at once, then the right one: no more than five are ever compared, and the
// passkey stays pending.
func TestPendingConcurrentEmailGuessesAreBounded(t *testing.T) {
	t.Parallel()

	var compared atomic.Int32

	f := newFixture(t)
	m := f.manager(t, passkey.WithEmailCodeCompare(func(stored, presented string) bool {
		compared.Add(1)

		return stored == presented
	}))

	s := enrolmentSession("sess-a", "u-1")
	rc := passkey.RegistrationContext{EmailConfirmation: true, ConfirmLimiter: permissive(t)}

	challenge := f.begin(t, m, s)
	_, err := m.FinishRegistration(t.Context(), s, regBody(challenge, "cred-a", ""), rc)
	require.NoError(t, err)

	code := emailedCode(t, f)

	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
	)

	for range 20 {
		wg.Go(func() {
			<-start

			_, err := m.ConfirmEmailCode(t.Context(), s, wrongCode(code), rc)
			assert.ErrorIs(t, err, mfa.ErrInvalidCode)
		})
	}

	close(start)
	wg.Wait()

	c, err := m.ConfirmEmailCode(t.Context(), s, code, rc)
	require.ErrorIs(t, err, mfa.ErrInvalidCode)
	assert.Nil(t, c)
	assert.LessOrEqual(t, compared.Load(), int32(5))
	assert.Equal(t, passkey.StatePending, onlyCredential(t, f, "u-1").State)
}
