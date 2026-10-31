package passkey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

func TestBeginRegistration(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		setup   func(t *testing.T, f *fixture)
		opts    []passkey.Option
		session func() *session.Session
		rc      func(f *fixture) passkey.RegistrationContext
		at      time.Duration // after regStart, when the begin runs
		before  func(t *testing.T, f *fixture, m *passkey.Passkeys, s *session.Session)
		ctx     func(ctx context.Context) context.Context
		assert  func(t *testing.T, f *fixture, raw json.RawMessage, err error)
	}

	full := func() *session.Session { return fullSession("sess-a", "u-1") }

	issued := func(t *testing.T, f *fixture, raw json.RawMessage, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.JSONEq(t, `{"publicKey":{}}`, string(raw))
		require.Len(t, f.creations(), 1)
	}
	reauth := func(t *testing.T, f *fixture, raw json.RawMessage, err error) {
		t.Helper()
		require.ErrorIs(t, err, passkey.ErrReauthenticationRequired)
		assert.Nil(t, raw)
		assert.Empty(t, f.creations())
	}

	lookupErr := errors.New("enrolment store down")

	cases := []testCase{
		{
			name: "fresh full session gets the default creation options",
			setup: func(t *testing.T, f *fixture) {
				for n, cred := range []string{"cred-a", "cred-b"} {
					c := &passkey.Credential{
						ID: id.ID{15: byte(n + 1)}, User: "u-1", CredentialID: []byte(cred),
						Transports: []string{"internal"}, CreatedAt: regStart.Add(time.Duration(n) * time.Minute),
						State: passkey.StateActive,
					}
					require.NoError(t, f.creds.Insert(t.Context(), c))
				}
			},
			session: full,
			at:      10 * time.Minute,
			assert: func(t *testing.T, f *fixture, raw json.RawMessage, err error) {
				issued(t, f, raw, err)

				in := f.creations()[0]
				assert.Equal(t, passkey.UserVerificationRequired, in.UV)
				assert.Equal(t, passkey.ResidentKeyRequired, in.ResidentKey)
				assert.Len(t, in.UserHandle, passkey.HandleSize)
				assert.Equal(t, 5*time.Minute, in.Timeout)
				assert.Equal(t, "ana@example.com", in.UserName)
				assert.Equal(t, "ana@example.com", in.DisplayName)
				assert.NotEmpty(t, in.Challenge)
				assert.Equal(t, []passkey.Descriptor{
					{ID: []byte("cred-a"), Transports: []string{"internal"}},
					{ID: []byte("cred-b"), Transports: []string{"internal"}},
				}, in.Exclude)
			},
		},
		{
			name:    "the handle carries neither the user reference nor the username",
			session: full,
			at:      time.Minute,
			assert: func(t *testing.T, f *fixture, raw json.RawMessage, err error) {
				issued(t, f, raw, err)

				h := f.creations()[0].UserHandle
				assert.False(t, bytes.Contains(h, []byte("u-1")))
				assert.False(t, bytes.Contains(h, []byte("ana@example.com")))
			},
		},
		{name: "stale full session", session: full, at: 16 * time.Minute, assert: reauth},
		{
			name:  "freshness counts from the second factor",
			setup: func(_ *testing.T, f *fixture) { f.withTOTP(true, nil) },
			session: func() *session.Session {
				s := full()
				s.MFA, s.MFASatisfiedAt = session.MFASatisfied, regStart.Add(20*time.Minute)
				s.AuthenticatedAt = s.MFASatisfiedAt

				return s
			},
			at:     30 * time.Minute,
			assert: issued,
		},
		{
			name:    "a usable second factor not yet satisfied",
			setup:   func(_ *testing.T, f *fixture) { f.withTOTP(true, nil) },
			session: full,
			at:      5 * time.Minute,
			assert:  reauth,
		},
		{
			name:    "the context's second factors decide when Deps lists none",
			session: full,
			rc: func(f *fixture) passkey.RegistrationContext {
				return passkey.RegistrationContext{MFAMethods: []policy.MFAMethodLookup{f.totp(true, nil)}}
			},
			at:     5 * time.Minute,
			assert: reauth,
		},
		{
			name:    "the context's second factors replace Deps'",
			setup:   func(_ *testing.T, f *fixture) { f.withTOTP(true, nil) },
			session: full,
			rc: func(f *fixture) passkey.RegistrationContext {
				return passkey.RegistrationContext{MFAMethods: []policy.MFAMethodLookup{f.totp(false, nil)}}
			},
			at:     5 * time.Minute,
			assert: issued,
		},
		{
			name: "a recovery-pending session owing a password change",
			session: func() *session.Session {
				s := full()
				s.MFA, s.FirstFactor = session.MFARecoveryPending, ""
				s.EnrolmentOriginDeadline, s.RecoveredAt = regStart.Add(time.Hour), regStart
				s.PasswordChangePending = true

				return s
			},
			at:     time.Minute,
			assert: reauth,
		},
		{
			name:    "an MFA lookup failure refuses",
			setup:   func(_ *testing.T, f *fixture) { f.withTOTP(false, lookupErr) },
			session: full,
			at:      5 * time.Minute,
			assert: func(t *testing.T, f *fixture, raw json.RawMessage, err error) {
				t.Helper()
				require.ErrorIs(t, err, lookupErr)
				assert.NotContains(t, err.Error(), "enrolment store down")
				assert.Nil(t, raw)
				assert.Empty(t, f.creations())
			},
		},
		{
			name: "a session with a pending MFA challenge",
			session: func() *session.Session {
				s := full()
				s.MFA = session.MFAPending

				return s
			},
			at:     time.Minute,
			assert: reauth,
		},
		{
			name: "a session owing a password change",
			session: func() *session.Session {
				s := full()
				s.PasswordChangePending = true

				return s
			},
			at:     time.Minute,
			assert: reauth,
		},
		{
			name:  "a recovery-pending session skips assurance and freshness",
			setup: func(_ *testing.T, f *fixture) { f.withTOTP(true, nil) },
			session: func() *session.Session {
				s := full()
				s.MFA, s.FirstFactor = session.MFARecoveryPending, ""
				s.EnrolmentOriginDeadline, s.RecoveredAt = regStart.Add(time.Hour), regStart

				return s
			},
			at:     40 * time.Minute,
			assert: issued,
		},
		{
			name:  "an enrolment-only session skips assurance and freshness",
			setup: func(_ *testing.T, f *fixture) { f.withTOTP(true, nil) },
			session: func() *session.Session {
				s := full()
				s.MFA, s.EnrolmentOriginDeadline = session.MFAEnrolmentPending, regStart.Add(time.Hour)

				return s
			},
			at:     14 * time.Minute,
			assert: issued,
		},
		{
			name: "a confined session with no second factor is not a full session",
			session: func() *session.Session {
				s := full()
				s.EnrolmentOriginDeadline = regStart.Add(time.Hour)

				return s
			},
			assert: reauth,
		},
		{
			name: "a confined session with its second factor met is not a full session",
			session: func() *session.Session {
				s := full()
				s.MFA, s.MFASatisfiedAt = session.MFASatisfied, regStart
				s.EnrolmentOriginDeadline = regStart.Add(time.Hour)

				return s
			},
			assert: reauth,
		},
		{
			name:    "consumer freshness window",
			opts:    []passkey.Option{passkey.WithManagementFreshness(time.Hour)},
			session: full,
			at:      50 * time.Minute,
			assert:  issued,
		},
		{
			name:    "the eleventh begin within the hour is throttled",
			session: full,
			at:      time.Minute,
			before: func(t *testing.T, _ *fixture, m *passkey.Passkeys, s *session.Session) {
				for range 10 {
					_, err := m.BeginRegistration(t.Context(), s, passkey.RegistrationContext{})
					require.NoError(t, err)
				}
			},
			assert: func(t *testing.T, f *fixture, raw json.RawMessage, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrRegistrationThrottled)
				require.ErrorIs(t, err, ratelimit.ErrThrottled)
				assert.Nil(t, raw)
				assert.Len(t, f.creations(), 10)
			},
		},
		{
			name:    "consumer issuance limit",
			opts:    []passkey.Option{passkey.WithRegistrationChallengeLimit(1)},
			session: full,
			at:      time.Minute,
			before: func(t *testing.T, _ *fixture, m *passkey.Passkeys, s *session.Session) {
				_, err := m.BeginRegistration(t.Context(), s, passkey.RegistrationContext{})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, _ *fixture, _ json.RawMessage, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrRegistrationThrottled)
			},
		},
		{
			name:    "the handle is reused a day later",
			session: full,
			before: func(t *testing.T, f *fixture, m *passkey.Passkeys, s *session.Session) {
				_, err := m.BeginRegistration(t.Context(), s, passkey.RegistrationContext{})
				require.NoError(t, err)

				f.clock.Advance(24 * time.Hour)
				s.CreatedAt = f.clock.Now()
				s.AuthenticatedAt = s.CreatedAt
			},
			assert: func(t *testing.T, f *fixture, _ json.RawMessage, err error) {
				t.Helper()
				require.NoError(t, err)

				in := f.creations()
				require.Len(t, in, 2)
				assert.Len(t, in[0].UserHandle, passkey.HandleSize)
				assert.Equal(t, in[0].UserHandle, in[1].UserHandle)
			},
		},
		{
			name:    "concurrent first registrations share one handle",
			session: full,
			at:      time.Minute,
			before: func(t *testing.T, _ *fixture, m *passkey.Passkeys, s *session.Session) {
				const callers = 8

				start := make(chan struct{})
				errs := make(chan error, callers)

				var wg sync.WaitGroup
				for range callers {
					wg.Go(func() {
						<-start

						_, err := m.BeginRegistration(t.Context(), s, passkey.RegistrationContext{})
						errs <- err
					})
				}

				close(start)
				wg.Wait()
				close(errs)

				for err := range errs {
					require.NoError(t, err)
				}
			},
			assert: func(t *testing.T, f *fixture, _ json.RawMessage, err error) {
				t.Helper()
				require.NoError(t, err)

				in := f.creations()
				require.Len(t, in, 9)

				for _, c := range in[1:] {
					assert.Equal(t, in[0].UserHandle, c.UserHandle)
				}
			},
		},
		{
			name: "consumer name resolver",
			opts: []passkey.Option{passkey.WithNameResolver(
				func(_ context.Context, d *identity.Details) (string, string, error) {
					return "display-" + d.Username, "Ana", nil
				})},
			session: full,
			at:      time.Minute,
			assert: func(t *testing.T, f *fixture, raw json.RawMessage, err error) {
				issued(t, f, raw, err)
				assert.Equal(t, "display-ana@example.com", f.creations()[0].UserName)
				assert.Equal(t, "Ana", f.creations()[0].DisplayName)
			},
		},
		{
			name:    "consumer user verification and resident key",
			opts:    []passkey.Option{passkey.WithUserVerification(passkey.UserVerificationPreferred), passkey.WithResidentKey(passkey.ResidentKeyPreferred), passkey.WithChallengeTTL(2 * time.Minute)},
			session: full,
			at:      time.Minute,
			assert: func(t *testing.T, f *fixture, raw json.RawMessage, err error) {
				issued(t, f, raw, err)
				assert.Equal(t, passkey.UserVerificationPreferred, f.creations()[0].UV)
				assert.Equal(t, passkey.ResidentKeyPreferred, f.creations()[0].ResidentKey)
				assert.Equal(t, 2*time.Minute, f.creations()[0].Timeout)
			},
		},
		{
			name:    "a user the loader cannot find",
			session: func() *session.Session { return fullSession("sess-a", "u-9") },
			at:      time.Minute,
			assert: func(t *testing.T, f *fixture, raw json.RawMessage, err error) {
				t.Helper()
				require.ErrorIs(t, err, identity.ErrUserNotFound)
				assert.Nil(t, raw)
				assert.Empty(t, f.creations())
			},
		},
		{
			name:    "a cancelled context issues nothing",
			session: full,
			at:      time.Minute,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, f *fixture, raw json.RawMessage, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, raw)
				assert.Empty(t, f.creations())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			if tc.setup != nil {
				tc.setup(t, f)
			}

			m := f.manager(t, tc.opts...)
			s := tc.session()

			if tc.before != nil {
				tc.before(t, f, m, s)
			}

			f.clock.Advance(tc.at)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			var rc passkey.RegistrationContext
			if tc.rc != nil {
				rc = tc.rc(f)
			}

			raw, err := m.BeginRegistration(ctx, s, rc)
			tc.assert(t, f, raw, err)
		})
	}
}

// TestBeginRegistration_LoaderReturningNoUserIsRefused pins that a loader
// answering neither details nor an error is a refusal naming the user as
// unknown, not a nil dereference in the name resolver.
//
// Standalone from TestBeginRegistration: it wraps the call in require.NotPanics.
func TestBeginRegistration_LoaderReturningNoUserIsRefused(t *testing.T) {
	t.Parallel()

	f := newFixture(t)

	empty := NewMockUserLoader(f.ctrl)
	empty.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	f.deps.Users = empty

	m := f.manager(t)

	var (
		raw json.RawMessage
		err error
	)

	require.NotPanics(t, func() {
		raw, err = m.BeginRegistration(t.Context(), fullSession("sess-a", "u-1"), passkey.RegistrationContext{})
	})
	require.ErrorIs(t, err, identity.ErrUserNotFound)
	assert.Nil(t, raw)
	assert.Empty(t, f.creations())
}

func TestDefaultNameResolver_NoUserIsNotFound(t *testing.T) {
	t.Parallel()

	var err error

	require.NotPanics(t, func() { _, _, err = passkey.UsernameAsNames(t.Context(), nil) })
	require.ErrorIs(t, err, identity.ErrUserNotFound)
}

// defaultName is the name a passkey created on regStart's date defaults to.
const defaultName = "Passkey 2026-10-01"

func TestFinishRegistration(t *testing.T) {
	t.Parallel()

	type env struct {
		f         *fixture
		m         *passkey.Passkeys
		s         *session.Session
		challenge string
	}

	type testCase struct {
		name   string
		opts   []passkey.Option
		setup  func(t *testing.T, f *fixture)
		before func(t *testing.T, e *env) // after the begin, before the finish
		body   func(e *env) []byte        // nil: a valid response for "cred-a"
		at     time.Duration              // after the begin, when the finish runs
		finish func(e *env) *session.Session
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, e *env, res *passkey.RegistrationResult, err error)
	}

	nothingStored := func(t *testing.T, e *env) {
		t.Helper()

		held, err := e.f.creds.List(t.Context(), "u-1")
		require.NoError(t, err)
		assert.Empty(t, held)
	}
	failed := func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
		assert.Nil(t, res)
		nothingStored(t, e)
	}
	named := func(want string) func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
		return func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
			t.Helper()
			require.NoError(t, err)
			require.NotNil(t, res)

			stored, err := e.f.creds.Find(t.Context(), "u-1", res.Credential.ID)
			require.NoError(t, err)
			assert.Equal(t, want, stored.Name)
		}
	}

	consumerErr := errors.New("administrators need a hardware key")
	verifyErr := errors.New("signature does not verify")

	cases := []testCase{
		{
			name: "stores the verified credential active",
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.True(t, res.Activated)
				assert.True(t, res.BackupEligible)
				assert.Empty(t, res.RecoveryCodes)
				assert.False(t, res.RecoveryNotSetUp)

				held, err := e.f.creds.List(t.Context(), "u-1")
				require.NoError(t, err)
				require.Len(t, held, 1)

				c := held[0]
				assert.Equal(t, res.Credential.ID, c.ID)
				assert.NotEqual(t, id.Nil, c.ID)
				assert.Equal(t, identity.UserID("u-1"), c.User)
				assert.Equal(t, []byte("cred-a"), c.CredentialID)
				assert.Equal(t, []byte("cose-cred-a"), c.PublicKey)
				assert.Equal(t, uint32(0), c.SignCount)
				assert.True(t, c.BackupEligible)
				assert.True(t, c.BackupState)
				assert.Equal(t, []string{"internal", "hybrid"}, c.Transports)
				assert.Len(t, c.AAGUID, 16)
				assert.Equal(t, regStart.Add(time.Minute), c.CreatedAt)
				assert.Equal(t, passkey.StateActive, c.State)
				assert.Zero(t, c.Pending)
				assert.Nil(t, c.EmailCode)
				assert.Equal(t, defaultName, c.Name)

				exp := e.f.verifications()
				require.Len(t, exp, 1)
				assert.Equal(t, e.challenge, exp[0].Challenge)
				assert.Equal(t, passkey.UserVerificationRequired, exp[0].UV)
			},
		},
		{
			name: "an unreadable response spends nothing",
			body: func(*env) []byte { return []byte("not json") },
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrMalformedResponse)
				assert.Nil(t, res)
				nothingStored(t, e)

				_, err = e.m.FinishRegistration(t.Context(), e.s, regBody(e.challenge, "cred-a", ""),
					passkey.RegistrationContext{})
				require.NoError(t, err)
			},
		},
		{
			name: "a spent challenge is refused without verifying",
			before: func(t *testing.T, e *env) {
				_, err := e.m.FinishRegistration(t.Context(), e.s, regBody(e.challenge, "cred-z", ""),
					passkey.RegistrationContext{})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, res)
				assert.Len(t, e.f.verifications(), 1)

				_, err = e.f.creds.FindByCredentialID(t.Context(), []byte("cred-a"))
				require.ErrorIs(t, err, passkey.ErrNotFound)
			},
		},
		{
			name: "a challenge refused once stays spent",
			setup: func(_ *testing.T, f *fixture) {
				f.adjustVerify("cred-z", func(*passkey.CredentialInput) error { return verifyErr })
			},
			before: func(t *testing.T, e *env) {
				_, err := e.m.FinishRegistration(t.Context(), e.s, regBody(e.challenge, "cred-z", ""),
					passkey.RegistrationContext{})
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
			},
			assert: failed,
		},
		{
			name:   "a challenge from another session",
			finish: func(*env) *session.Session { return fullSession("sess-b", "u-1") },
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				failed(t, e, res, err)
				assert.Empty(t, e.f.verifications())
			},
		},
		{
			name:   "a challenge issued to another user of the same session ID is refused and spent",
			finish: func(*env) *session.Session { return fullSession("sess-a", "u-2") },
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				failed(t, e, res, err)
				assert.Empty(t, e.f.verifications())

				_, err = e.m.FinishRegistration(t.Context(), e.s, regBody(e.challenge, "cred-a", ""),
					passkey.RegistrationContext{})
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed, "the challenge should have been spent")
				nothingStored(t, e)
			},
		},
		{
			name:   "a challenge the library never issued",
			body:   func(*env) []byte { return regBody("invented.challenge", "cred-a", "") },
			assert: failed,
		},
		{
			name:   "an absent challenge",
			body:   func(*env) []byte { return []byte(`{"id":"cred-a"}`) },
			assert: failed,
		},
		{name: "an expired challenge", at: 6 * time.Minute, assert: failed},
		{
			name: "a response that fails verification",
			setup: func(_ *testing.T, f *fixture) {
				f.adjustVerify("cred-a", func(*passkey.CredentialInput) error { return verifyErr })
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				failed(t, e, res, err)
				assert.NotContains(t, err.Error(), verifyErr.Error())
			},
		},
		{
			// WebAuthn Level 3 §6.1: a credential cannot be backed up without
			// being eligible for backup. The core refuses it whatever the
			// verifier accepted, before the consumer's check is asked.
			name: "a backed-up state without backup eligibility is refused",
			opts: []passkey.Option{passkey.WithRegistrationCheck(
				func(context.Context, passkey.RegistrationFacts) error { return consumerErr })},
			setup: func(_ *testing.T, f *fixture) {
				f.adjustVerify("cred-a", func(nc *passkey.CredentialInput) error {
					nc.BackupEligible, nc.BackupState = false, true

					return nil
				})
			},
			assert: failed,
		},
		{
			name: "a refused attestation is its own refusal",
			setup: func(_ *testing.T, f *fixture) {
				f.adjustVerify("cred-a", func(*passkey.CredentialInput) error { return passkey.ErrAttestationRefused })
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrAttestationRefused)
				assert.Nil(t, res)
				nothingStored(t, e)
			},
		},
		{
			name: "no user verification when it is required",
			setup: func(_ *testing.T, f *fixture) {
				f.adjustVerify("cred-a", func(nc *passkey.CredentialInput) error { nc.UserVerified = false; return nil })
			},
			assert: failed,
		},
		{
			name: "no user verification when it is preferred",
			opts: []passkey.Option{passkey.WithUserVerification(passkey.UserVerificationPreferred)},
			setup: func(_ *testing.T, f *fixture) {
				f.adjustVerify("cred-a", func(nc *passkey.CredentialInput) error { nc.UserVerified = false; return nil })
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, res.Activated)
				assert.Equal(t, passkey.UserVerificationPreferred, e.f.verifications()[0].UV)
			},
		},
		{
			name: "the consumer check refuses with its own error",
			opts: []passkey.Option{passkey.WithRegistrationCheck(
				func(_ context.Context, f passkey.RegistrationFacts) error {
					if f.User == "u-1" && f.BackupEligible && f.BackupState && len(f.AAGUID) == 16 &&
						f.AttestationFormat == "packed" && f.AttestationTrusted {
						return consumerErr
					}

					return nil
				})},
			setup: func(_ *testing.T, f *fixture) {
				f.adjustVerify("cred-a", func(nc *passkey.CredentialInput) error {
					nc.AttestationFormat, nc.AttestationTrusted = "packed", true

					return nil
				})
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.Equal(t, consumerErr, err)
				assert.Nil(t, res)
				nothingStored(t, e)
			},
		},
		{
			name: "the passkey limit",
			setup: func(t *testing.T, f *fixture) {
				for n := range 25 {
					c := &passkey.Credential{
						ID: id.ID{14: 1, 15: byte(n)}, User: "u-1", CredentialID: []byte{'x', byte(n)},
						CreatedAt: regStart, State: passkey.StateActive,
					}
					require.NoError(t, f.creds.Insert(t.Context(), c))
				}
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrPerUserLimitReached)
				assert.Nil(t, res)

				n, err := e.f.creds.Count(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, 25, n)
			},
		},
		{
			name: "consumer passkey limit counts pending credentials",
			opts: []passkey.Option{passkey.WithPerUserLimit(1)},
			setup: func(t *testing.T, f *fixture) {
				require.NoError(t, f.creds.Insert(t.Context(), &passkey.Credential{
					ID: id.ID{15: 9}, User: "u-1", CredentialID: []byte("old"), CreatedAt: regStart,
					State: passkey.StatePending, Pending: passkey.PendingEmailCode,
				}))
			},
			assert: func(t *testing.T, _ *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrPerUserLimitReached)
				assert.Nil(t, res)
			},
		},
		{
			name: "a credential ID another user holds",
			setup: func(t *testing.T, f *fixture) {
				require.NoError(t, f.creds.Insert(t.Context(), &passkey.Credential{
					ID: id.ID{15: 7}, User: "u-2", CredentialID: []byte("cred-a"), PublicKey: []byte("u-2-key"),
					Name: "Bo's key", CreatedAt: regStart, State: passkey.StateActive,
				}))
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				failed(t, e, res, err)

				c, err := e.f.creds.FindByCredentialID(t.Context(), []byte("cred-a"))
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-2"), c.User)
				assert.Equal(t, []byte("u-2-key"), c.PublicKey)
				assert.Equal(t, "Bo's key", c.Name)
			},
		},
		{
			name:   "the response's name is kept",
			body:   func(e *env) []byte { return regBody(e.challenge, "cred-a", " Work laptop ") },
			assert: named("Work laptop"),
		},
		{
			name:   "a 200-character name gives the date name",
			body:   func(e *env) []byte { return regBody(e.challenge, "cred-a", strings.Repeat("é", 200)) },
			assert: named(defaultName),
		},
		{
			name:   "a name with a line break gives the date name",
			body:   func(e *env) []byte { return regBody(e.challenge, "cred-a", "a\nb") },
			assert: named(defaultName),
		},
		{
			name: "a cancelled context stores nothing",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, res)
				nothingStored(t, e)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			if tc.setup != nil {
				tc.setup(t, f)
			}

			m := f.manager(t, tc.opts...)
			f.clock.Advance(time.Minute)

			e := &env{f: f, m: m, s: fullSession("sess-a", "u-1")}
			e.challenge = f.begin(t, m, e.s)

			if tc.before != nil {
				tc.before(t, e)
			}

			f.clock.Advance(tc.at)

			body := regBody(e.challenge, "cred-a", "")
			if tc.body != nil {
				body = tc.body(e)
			}

			s := e.s
			if tc.finish != nil {
				s = tc.finish(e)
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			res, err := m.FinishRegistration(ctx, s, body, passkey.RegistrationContext{})
			tc.assert(t, e, res, err)
		})
	}
}

// TestFinishRegistrationRacingFinishesVerifyOnce runs eight finishes
// presenting one challenge at once: the challenge is spent before verifying,
// so at most one reaches the verifier and at most one stores.
//
// Standalone from TestFinishRegistration: it races eight finishes presenting one challenge.
func TestFinishRegistrationRacingFinishesVerifyOnce(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	m := f.manager(t)
	s := fullSession("sess-a", "u-1")
	challenge := f.begin(t, m, s)

	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		mu    sync.Mutex
		ok    int
	)

	for n := range 8 {
		wg.Go(func() {
			<-start

			_, err := m.FinishRegistration(t.Context(), s, regBody(challenge, "cred-"+string(rune('a'+n)), ""), //nolint:gosec // G115: a small test index
				passkey.RegistrationContext{})
			if err == nil {
				mu.Lock()
				ok++
				mu.Unlock()

				return
			}

			assert.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
		})
	}

	close(start)
	wg.Wait()

	assert.LessOrEqual(t, len(f.verifications()), 1)
	assert.Equal(t, 1, ok)

	n, err := f.creds.Count(t.Context(), "u-1")
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

// The tests that race registration steps for one user against a per-user
// limit share no setup beyond the fixture: each stages its racers with its own
// store double, holding a count until every racer has read it or a read until
// another racer has stored. The barrier below and the doubles after it serve
// those tests.

// barrier releases its callers once racers of them have arrived, or after a
// few seconds. Until it is armed, it lets every caller through.
type barrier struct {
	racers  int32
	armed   atomic.Bool
	arrived atomic.Int32
	all     chan struct{}
}

func newBarrier(racers int32) *barrier { return &barrier{racers: racers, all: make(chan struct{})} }

// wait holds the caller until every racer has arrived, once the barrier is
// armed.
func (b *barrier) wait(ctx context.Context) {
	if !b.armed.Load() {
		return
	}

	if b.arrived.Add(1) == b.racers {
		close(b.all)
	}

	select {
	case <-b.all:
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}
}

// countBarrierCredentials is a memory credential store whose Count answers
// only once every racing finish has counted, so a finish that counts and then
// inserts lets every racer read the same count before any of them stores.
type countBarrierCredentials struct {
	*passkey.MemoryCredentialStore

	b *barrier
}

func (s *countBarrierCredentials) Count(ctx context.Context, user identity.UserID) (int, error) {
	n, err := s.MemoryCredentialStore.Count(ctx, user)
	s.b.wait(ctx)

	return n, err
}

// countBarrierChallenges is a memory challenge store whose issuance count
// answers only once every racing begin has counted.
type countBarrierChallenges struct {
	*onetime.MemoryStore

	b *barrier
}

func (s *countBarrierChallenges) CountRecentBySubject(
	ctx context.Context, purpose, subject string, since time.Time,
) (int, error) {
	n, err := s.MemoryStore.CountRecentBySubject(ctx, purpose, subject, since)
	s.b.wait(ctx)

	return n, err
}

// race runs n calls of f released together and returns their errors.
func race(n int, f func(i int) error) []error {
	errs := make([]error, n)
	start := make(chan struct{})

	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			errs[i] = f(i)
		})
	}
	close(start)
	wg.Wait()

	return errs
}

// TestFinishRegistration_ConcurrentFinishesStayWithinPasskeyLimit races four
// finishes for u-1, each answering a challenge of its own, against a passkey
// limit of one. The limit is decided by the write, so exactly one stores a
// passkey and the other three are refused with ErrPerUserLimitReached.
//
// Standalone from TestFinishRegistration: it races four finishes through a barrier store.
func TestFinishRegistration_ConcurrentFinishesStayWithinPasskeyLimit(t *testing.T) {
	t.Parallel()

	const racers = 4

	f := newFixture(t)
	creds := &countBarrierCredentials{MemoryCredentialStore: f.creds, b: newBarrier(racers)}
	f.deps.Credentials = creds
	m := f.manager(t, passkey.WithPerUserLimit(1))
	s := fullSession("sess-a", "u-1")

	challenges := make([]string, racers)
	for i := range challenges {
		challenges[i] = f.begin(t, m, s)
	}

	creds.b.armed.Store(true)

	errs := race(racers, func(i int) error {
		_, err := m.FinishRegistration(t.Context(), s,
			regBody(challenges[i], "cred-"+strconv.Itoa(i), ""), passkey.RegistrationContext{})

		return err
	})

	var stored, refused int
	for _, err := range errs {
		if err == nil {
			stored++

			continue
		}

		require.ErrorIs(t, err, passkey.ErrPerUserLimitReached)
		refused++
	}

	assert.Equal(t, 1, stored, "finishes that stored a passkey")
	assert.Equal(t, racers-1, refused, "finishes refused with the passkey-limit refusal")

	n, err := f.creds.Count(t.Context(), "u-1")
	require.NoError(t, err)
	assert.Equal(t, 1, n, "passkeys u-1 holds")
}

// TestBeginRegistration_ConcurrentBeginsStayWithinChallengeLimit races twenty
// begins for u-1 against the default registration-challenge limit of ten. The
// count and the issue are one decision, so exactly ten challenges are issued
// and the other ten begins are refused with ErrRegistrationThrottled.
//
// Standalone from TestBeginRegistration: it races twenty begins through a barrier store.
func TestBeginRegistration_ConcurrentBeginsStayWithinChallengeLimit(t *testing.T) {
	t.Parallel()

	const (
		racers = 20
		limit  = 10 // the default registration-challenge limit
	)

	f := newFixture(t)
	challenges := &countBarrierChallenges{
		MemoryStore: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(f.clock)),
		b:           newBarrier(racers),
	}
	challenges.b.armed.Store(true)
	f.deps.Challenges = challenges
	m := f.manager(t)
	s := fullSession("sess-a", "u-1")

	errs := race(racers, func(int) error {
		_, err := m.BeginRegistration(t.Context(), s, passkey.RegistrationContext{})

		return err
	})

	var issued, throttled int
	for _, err := range errs {
		if err == nil {
			issued++

			continue
		}

		require.ErrorIs(t, err, passkey.ErrRegistrationThrottled)
		throttled++
	}

	assert.Equal(t, limit, issued, "begins issued a challenge")
	assert.Equal(t, racers-limit, throttled, "begins refused as throttled")
	assert.Equal(t, limit, len(f.creations()), "the refused begins render no options")
}

// staggeredCredentials is a memory credential store that stages two racing
// finishes for one user so the one the limit refuses inserts only after the
// one that stores has:
//
//   - Count answers once both have counted, so both pass the early count;
//   - the first to insert waits until the second has reached its insert too,
//     and the second inserts only once the first has.
//
// Every wait gives up after a few seconds, so a finish that never arrives
// fails the test rather than hanging it.
type staggeredCredentials struct {
	*passkey.MemoryCredentialStore

	counted        *barrier
	writes         atomic.Int32
	secondAtInsert chan struct{}
	firstInserted  chan struct{}
}

func newStaggeredCredentials(inner *passkey.MemoryCredentialStore) *staggeredCredentials {
	return &staggeredCredentials{
		MemoryCredentialStore: inner,
		counted:               newBarrier(2),
		secondAtInsert:        make(chan struct{}),
		firstInserted:         make(chan struct{}),
	}
}

// await waits for ch, the caller's context, or a few seconds.
func await(ctx context.Context, ch <-chan struct{}) {
	select {
	case <-ch:
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}
}

func (s *staggeredCredentials) Count(ctx context.Context, user identity.UserID) (int, error) {
	n, err := s.MemoryCredentialStore.Count(ctx, user)
	s.counted.wait(ctx)

	return n, err
}

func (s *staggeredCredentials) InsertWithin(ctx context.Context, c *passkey.Credential, limit int) (bool, error) {
	if s.writes.Add(1) == 1 {
		await(ctx, s.secondAtInsert)

		defer close(s.firstInserted)

		return s.MemoryCredentialStore.InsertWithin(ctx, c, limit)
	}

	close(s.secondAtInsert)
	await(ctx, s.firstInserted)

	return s.MemoryCredentialStore.InsertWithin(ctx, c, limit)
}

// TestFinishRegistration_RefusedFinishLeavesStoredFinishsCodesWorking races
// two finishes for u-1, who has no way back in, against a passkey limit of
// one. The finish the limit refuses reaches its insert only after the other
// has reached its own. A refused finish stores nothing, so the saved codes the
// stored finish returned are the ones that confirm its passkey.
//
// Standalone from TestFinishRegistration: it races two finishes through a staggered store.
func TestFinishRegistration_RefusedFinishLeavesStoredFinishsCodesWorking(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.deps.Recovery = recoveryDeps(t, f, recovery.WayBackDeps{})
	creds := newStaggeredCredentials(f.creds)
	f.deps.Credentials = creds
	m := f.manager(t, passkey.WithPerUserLimit(1))
	s := fullSession("sess-a", "u-1")

	challenges := []string{f.begin(t, m, s), f.begin(t, m, s)}
	f.clock.Advance(time.Minute)
	creds.counted.armed.Store(true)

	results := make([]*passkey.RegistrationResult, len(challenges))
	errs := race(len(challenges), func(i int) error {
		var err error
		results[i], err = m.FinishRegistration(t.Context(), s,
			regBody(challenges[i], "cred-"+strconv.Itoa(i), ""), passkey.RegistrationContext{})

		return err
	})

	var stored *passkey.RegistrationResult
	for i, err := range errs {
		if err != nil {
			require.ErrorIs(t, err, passkey.ErrPerUserLimitReached)

			continue
		}

		require.Nil(t, stored, "a second finish stored a passkey")
		stored = results[i]
	}

	require.NotNil(t, stored, "no finish stored a passkey")
	require.Len(t, stored.RecoveryCodes, 10)

	c, err := m.ConfirmSavedCode(t.Context(), s, stored.RecoveryCodes[0], passkey.RegistrationContext{})
	require.NoError(t, err, "the stored finish's own saved codes do not confirm its passkey")
	require.NotNil(t, c)
	assert.Equal(t, stored.Credential.ID, c.ID)
	assert.Equal(t, passkey.StateActive, c.State)
}

// racerKey keys the index of a racing finish in its context.
type racerKey struct{}

// racer returns the index of the racing finish ctx belongs to, or -1.
func racer(ctx context.Context) int {
	if i, ok := ctx.Value(racerKey{}).(int); ok {
		return i
	}

	return -1
}

// lateListCredentials is a memory credential store that stages two racing
// finishes for one user so the second reads the user's passkeys only once the
// first has stored its own: every List of the second finish waits until the
// first has inserted, and nothing else is held.
//
// A finish lists the user's passkeys while it plans what its registration
// replaces, before it counts them, so the second finish decides what it
// replaces, and then counts, while the first finish's passkey is already
// stored. The first finish is never held, so the staging needs no timeout to
// complete; the wait gives up after a few seconds only so that a finish that
// never lists fails the test rather than hanging it.
type lateListCredentials struct {
	*passkey.MemoryCredentialStore

	firstInserted chan struct{}
}

func (s *lateListCredentials) List(ctx context.Context, user identity.UserID) ([]*passkey.Credential, error) {
	if racer(ctx) == 1 {
		await(ctx, s.firstInserted)
	}

	return s.MemoryCredentialStore.List(ctx, user)
}

func (s *lateListCredentials) InsertWithin(ctx context.Context, c *passkey.Credential, limit int) (bool, error) {
	ok, err := s.MemoryCredentialStore.InsertWithin(ctx, c, limit)
	if racer(ctx) == 0 {
		close(s.firstInserted)
	}

	return ok, err
}

// TestFinishRegistration_ConcurrentFinishKeepsStoredFinishsPasskey races two
// finishes for u-1 against a passkey limit of one, the second deciding what
// its registration replaces only once the first has stored its pending
// passkey. That passkey was created at or after the instant the second
// finish's challenge was issued, so it belongs to a concurrent ceremony, not an abandoned one, and is
// kept. The second finish then counts a full limit and is refused with
// ErrPerUserLimitReached before it inserts; the first finish stores, and the codes it
// returned or sent confirm its own passkey. Were the kept passkey deleted
// instead, the second finish would find room and store.
//
// Standalone from TestFinishRegistration: its cases race two finishes through a late-listing store.
func TestFinishRegistration_ConcurrentFinishKeepsStoredFinishsPasskey(t *testing.T) {
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
		codes   bool          // wire saved codes for a user with no way back
		advance time.Duration // between the begins and the finishes
		confirm func(t *testing.T, e *env, res *passkey.RegistrationResult) (*passkey.Credential, error)
	}

	cases := []testCase{
		{
			name:    "a passkey awaiting saved codes",
			session: fullSession("sess-a", "u-1"),
			codes:   true,
			advance: time.Minute,
			confirm: func(t *testing.T, e *env, res *passkey.RegistrationResult) (*passkey.Credential, error) {
				require.Len(t, res.RecoveryCodes, 10)

				return e.m.ConfirmSavedCode(t.Context(), e.s, res.RecoveryCodes[0], passkey.RegistrationContext{})
			},
		},
		{
			name:    "a passkey awaiting an emailed code, created at the instant the challenge was issued",
			session: enrolmentSession("sess-a", "u-1"),
			rc:      passkey.RegistrationContext{EmailConfirmation: true},
			confirm: func(t *testing.T, e *env, _ *passkey.RegistrationResult) (*passkey.Credential, error) {
				return e.m.ConfirmEmailCode(t.Context(), e.s, emailedCode(t, e.f),
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

			creds := &lateListCredentials{MemoryCredentialStore: f.creds, firstInserted: make(chan struct{})}
			f.deps.Credentials = creds
			e := &env{f: f, m: f.manager(t, passkey.WithPerUserLimit(1)), s: tc.session}

			challenges := []string{f.begin(t, e.m, e.s), f.begin(t, e.m, e.s)}
			f.clock.Advance(tc.advance)

			results := make([]*passkey.RegistrationResult, len(challenges))
			errs := race(len(challenges), func(i int) error {
				ctx := context.WithValue(t.Context(), racerKey{}, i)

				var err error
				results[i], err = e.m.FinishRegistration(ctx, e.s,
					regBody(challenges[i], "cred-"+strconv.Itoa(i), ""), tc.rc)

				return err
			})

			require.NoError(t, errs[0], "the first finish")
			require.ErrorIs(t, errs[1], passkey.ErrPerUserLimitReached, "the second finish")

			stored := results[0]
			require.NotNil(t, stored)

			held, err := f.creds.List(t.Context(), "u-1")
			require.NoError(t, err)
			require.Len(t, held, 1, "passkeys u-1 holds")
			assert.Equal(t, stored.Credential.ID, held[0].ID, "the passkey u-1 holds")

			c, err := tc.confirm(t, e, stored)
			require.NoError(t, err, "the stored finish's own codes do not confirm its passkey")
			require.NotNil(t, c)
			assert.Equal(t, stored.Credential.ID, c.ID)
			assert.Equal(t, passkey.StateActive, c.State)
		})
	}
}

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
//
// Standalone from TestFinishRegistration: its cases replace the stores and may cancel the request mid-finish.
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
				require.ErrorIs(t, err, passkey.ErrPerUserLimitReached)
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
				require.ErrorIs(t, err, passkey.ErrPerUserLimitReached)
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
				f.deps.Recovery = recoveryDeps(t, f, recovery.WayBackDeps{}, recovery.WithCodesStore(e.codes))
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
//
// Standalone from TestFinishRegistration: its cases run two registrations, then a confirmation.
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

			e := &env{f: f, m: f.manager(t, passkey.WithPerUserLimit(1)), s: tc.session}

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
