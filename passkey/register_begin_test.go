package passkey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
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
		before  func(t *testing.T, f *fixture, m *passkey.Manager, s *session.Session)
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
				assert.Equal(t, passkey.UVRequired, in.UV)
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
			before: func(t *testing.T, _ *fixture, m *passkey.Manager, s *session.Session) {
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
			before: func(t *testing.T, _ *fixture, m *passkey.Manager, s *session.Session) {
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
			before: func(t *testing.T, f *fixture, m *passkey.Manager, s *session.Session) {
				_, err := m.BeginRegistration(t.Context(), s, passkey.RegistrationContext{})
				require.NoError(t, err)

				f.clock.Advance(24 * time.Hour)
				s.CreatedAt = f.clock.Now()
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
			before: func(t *testing.T, _ *fixture, m *passkey.Manager, s *session.Session) {
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
			opts:    []passkey.Option{passkey.WithUserVerification(passkey.UVPreferred), passkey.WithResidentKey(passkey.ResidentKeyPreferred), passkey.WithChallengeTTL(2 * time.Minute)},
			session: full,
			at:      time.Minute,
			assert: func(t *testing.T, f *fixture, raw json.RawMessage, err error) {
				issued(t, f, raw, err)
				assert.Equal(t, passkey.UVPreferred, f.creations()[0].UV)
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
