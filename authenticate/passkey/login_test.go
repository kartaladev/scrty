package passkey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
)

func TestLoginBegin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []passkey.Option
		binding string
		ctx     func(ctx context.Context) context.Context
		assert  func(t *testing.T, e *loginEnv, raw json.RawMessage, err error)
	}

	cases := []testCase{
		{
			name:    "renders discoverable request options and issues a bound challenge",
			binding: "ceremony-cookie-value",
			assert: func(t *testing.T, e *loginEnv, raw json.RawMessage, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.JSONEq(t, `{"publicKey":{}}`, string(raw))

				require.Len(t, e.requested, 1)
				in := e.requested[0]
				assert.NotEmpty(t, in.Challenge)
				assert.Empty(t, in.Allow)
				assert.Equal(t, passkey.UserVerificationRequired, in.UV)
				assert.Equal(t, 5*time.Minute, in.Timeout)

				res, err := e.m.Authenticate(t.Context(), assertion(in.Challenge, nil), "ceremony-cookie-value")
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-1"), res.User)
			},
		},
		{
			name:    "user verification and the timeout follow the configuration",
			opts:    []passkey.Option{passkey.WithUserVerification(passkey.UserVerificationPreferred), passkey.WithChallengeTTL(2 * time.Minute)},
			binding: "ceremony-cookie-value",
			assert: func(t *testing.T, e *loginEnv, _ json.RawMessage, err error) {
				t.Helper()
				require.NoError(t, err)
				require.Len(t, e.requested, 1)
				assert.Equal(t, passkey.UserVerificationPreferred, e.requested[0].UV)
				assert.Equal(t, 2*time.Minute, e.requested[0].Timeout)
			},
		},
		{
			name:    "an empty binding issues nothing",
			binding: "",
			assert: func(t *testing.T, e *loginEnv, raw json.RawMessage, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Nil(t, raw)
				assert.Empty(t, e.requested)
				assert.Zero(t, e.challenges.Len())
			},
		},
		{
			name:    "a cancelled context issues nothing",
			binding: "ceremony-cookie-value",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, e *loginEnv, raw json.RawMessage, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, raw)
				assert.Zero(t, e.challenges.Len())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newLoginEnv(t, nil)
			e.manager(t, tc.opts...)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			raw, err := e.m.BeginLogin(ctx, tc.binding)
			tc.assert(t, e, raw, err)
		})
	}
}

func TestLoginBeginPurge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		reapErr error
		assert  func(t *testing.T, e *loginEnv)
	}

	cases := []testCase{
		{
			name: "expired challenges are purged at most once per lifetime",
			assert: func(t *testing.T, e *loginEnv) {
				t.Helper()

				for range 200 {
					e.begin(t)
				}

				reaps, _ := e.challenges.purges()
				assert.Equal(t, 1, reaps, "only the first begin purges within the lifetime")

				e.f.clock.Advance(5*time.Minute + time.Second)
				e.begin(t)

				reaps, removed := e.challenges.purges()
				assert.Equal(t, 2, reaps)
				assert.Equal(t, 200, removed)
				assert.Equal(t, 1, e.challenges.Len())

				e.f.clock.Advance(time.Minute)
				e.begin(t)

				reaps, _ = e.challenges.purges()
				assert.Equal(t, 2, reaps, "a begin within the lifetime of the last purge does not purge")
			},
		},
		{
			name:    "a failed purge does not refuse the begin",
			reapErr: errors.New("challenge store down"),
			assert: func(t *testing.T, e *loginEnv) {
				t.Helper()

				challenge := e.begin(t)
				reaps, _ := e.challenges.purges()
				assert.Equal(t, 1, reaps)

				_, err := e.m.Authenticate(t.Context(), assertion(challenge, nil), e.binding)
				require.NoError(t, err)
				assert.NotContains(t, e.logs.String(), "challenge store down")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newLoginEnv(t, nil)
			e.challenges.err = tc.reapErr
			e.manager(t)
			tc.assert(t, e)
		})
	}
}

func TestLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []passkey.Option
		seed    func(c *passkey.Credential)
		before  func(t *testing.T, e *loginEnv, challenge string)        // after the begin
		body    func(t *testing.T, e *loginEnv, challenge string) []byte // nil: a valid assertion
		binding *string                                                  // nil: the begin's binding
		ctx     func(ctx context.Context) context.Context
		assert  func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error)
	}

	unchanged := func(t *testing.T, e *loginEnv) {
		t.Helper()

		c := e.stored(t)
		assert.Equal(t, uint32(42), c.SignCount)
		assert.True(t, c.LastUsedAt.IsZero())
	}
	refused := func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
		assert.Equal(t, authenticate.ErrAuthenticationFailed.Error(), err.Error(), "one uniform refusal")
		assert.Nil(t, res)
		unchanged(t, e)
	}
	withBody := func(adjust func(b *assertionBody)) func(*testing.T, *loginEnv, string) []byte {
		return func(_ *testing.T, _ *loginEnv, challenge string) []byte { return assertion(challenge, adjust) }
	}
	str := func(s string) *string { return &s }

	consumerErr := errors.New("device-bound passkeys are not accepted for this user")

	cases := []testCase{
		{
			name: "a user-verified assertion logs in and proves the second factor",
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.Equal(t, identity.UserID("u-1"), res.User)
				assert.Equal(t, e.cred.ID, res.Credential)
				assert.True(t, res.Proof.Holds())
				assert.Equal(t, factor.Passkey, res.Proof.Kind())
				assert.Equal(t, regStart, res.Proof.At())

				c := e.stored(t)
				assert.Equal(t, uint32(43), c.SignCount)
				assert.Equal(t, regStart, c.LastUsedAt)
			},
		},
		{
			name: "the backup state is recorded",
			seed: func(c *passkey.Credential) { c.BackupEligible, c.SignCount = true, 0 },
			body: withBody(func(b *assertionBody) { b.BE, b.BS, b.Count = true, true, 0 }),
			assert: func(t *testing.T, e *loginEnv, _ *passkey.LoginResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, e.stored(t).BackupState)
			},
		},
		{
			name: "without the second factor at login the proof does not hold",
			opts: []passkey.Option{passkey.WithoutSecondFactorAtLogin()},
			assert: func(t *testing.T, _ *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.False(t, res.Proof.Holds())
			},
		},
		{
			// WebAuthn Level 3 §6.1: a credential cannot be backed up without
			// being eligible for backup. The stored credential is not
			// backup-eligible either, so only this rule refuses it.
			name:   "an assertion backed up without backup eligibility is refused",
			opts:   []passkey.Option{passkey.WithLoginCheck(func(context.Context, passkey.LoginFacts) error { return consumerErr })},
			body:   withBody(func(b *assertionBody) { b.BE, b.BS = false, true }),
			assert: refused,
		},
		{
			name:   "an assertion without user verification is refused under required",
			body:   withBody(func(b *assertionBody) { b.UV = false }),
			assert: refused,
		},
		{
			name: "an assertion without user verification logs in single-factor under preferred",
			opts: []passkey.Option{passkey.WithUserVerification(passkey.UserVerificationPreferred)},
			body: withBody(func(b *assertionBody) { b.UV = false }),
			assert: func(t *testing.T, _ *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.False(t, res.Proof.Holds())
			},
		},
		{
			name:   "an unknown credential is refused",
			body:   withBody(func(b *assertionBody) { b.ID = "nobody's key" }),
			assert: refused,
		},
		{
			name:   "another user's handle is refused",
			body:   withBody(func(b *assertionBody) { b.Handle = handleU2 }),
			assert: refused,
		},
		{
			name:   "an unknown handle is refused",
			body:   withBody(func(b *assertionBody) { b.Handle = bytes.Repeat([]byte{0x09}, passkey.HandleSize) }),
			assert: refused,
		},
		{
			name:   "a missing handle is refused",
			body:   withBody(func(b *assertionBody) { b.Handle = nil }),
			assert: refused,
		},
		{
			name:   "a bad signature is refused",
			body:   withBody(func(b *assertionBody) { b.Sig = "forged" }),
			assert: refused,
		},
		{
			name: "a pending credential with a valid assertion is refused as pending",
			seed: func(c *passkey.Credential) { c.State, c.Pending = passkey.StatePending, passkey.PendingSavedCodes },
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrPending)
				assert.Nil(t, res)
				assert.Equal(t, 1, e.verifyCount(), "the assertion is verified before the state is revealed")
				assert.Zero(t, e.creds.records.Load())
				unchanged(t, e)
			},
		},
		{
			name: "a suspended credential with a valid assertion is refused as suspended",
			seed: func(c *passkey.Credential) { c.State = passkey.StateSuspended },
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrSuspended)
				assert.Nil(t, res)
				assert.Equal(t, 1, e.verifyCount(), "the assertion is verified before the state is revealed")
				assert.Zero(t, e.creds.records.Load())
				unchanged(t, e)
			},
		},
		{
			name:   "a pending credential's ID with a signature its key did not make is refused like an unknown one",
			seed:   func(c *passkey.Credential) { c.State, c.Pending = passkey.StatePending, passkey.PendingSavedCodes },
			body:   withBody(func(b *assertionBody) { b.Sig = "forged" }),
			assert: refused,
		},
		{
			name:   "a suspended credential's ID with a signature its key did not make is refused like an unknown one",
			seed:   func(c *passkey.Credential) { c.State = passkey.StateSuspended },
			body:   withBody(func(b *assertionBody) { b.Sig = "forged" }),
			assert: refused,
		},
		{
			name:   "a suspended credential's ID with another user's handle is refused like an unknown one",
			seed:   func(c *passkey.Credential) { c.State = passkey.StateSuspended },
			body:   withBody(func(b *assertionBody) { b.Handle = handleU2 }),
			assert: refused,
		},
		{
			name: "a suspended credential is refused as suspended before the login check runs",
			seed: func(c *passkey.Credential) { c.State = passkey.StateSuspended },
			opts: []passkey.Option{passkey.WithLoginCheck(func(context.Context, passkey.LoginFacts) error {
				return consumerErr
			})},
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrSuspended)
				assert.NotErrorIs(t, err, consumerErr)
				assert.Nil(t, res)
				unchanged(t, e)
			},
		},
		{
			name:    "a missing binding is refused",
			binding: str(""),
			assert:  refused,
		},
		{
			name:    "another browser's binding is refused",
			binding: str("another-browser"),
			assert:  refused,
		},
		{
			name:   "an expired challenge is refused",
			before: func(_ *testing.T, e *loginEnv, _ string) { e.f.clock.Advance(5*time.Minute + time.Second) },
			assert: refused,
		},
		{
			name:   "a challenge the library never issued is refused",
			body:   func(*testing.T, *loginEnv, string) []byte { return assertion("forged.challenge", nil) },
			assert: refused,
		},
		{
			name: "a challenge is spent by a refused attempt",
			before: func(t *testing.T, e *loginEnv, challenge string) {
				t.Helper()

				_, err := e.m.Authenticate(t.Context(), assertion(challenge, func(b *assertionBody) { b.Sig = "forged" }), e.binding)
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
			},
			assert: refused,
		},
		{
			name: "an unreadable response is malformed and spends nothing",
			body: func(*testing.T, *loginEnv, string) []byte { return []byte("not json") },
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrMalformedResponse)
				assert.Nil(t, res)

				e.mu.Lock()
				challenge := e.requested[0].Challenge
				e.mu.Unlock()

				_, err = e.m.Authenticate(t.Context(), assertion(challenge, nil), e.binding)
				require.NoError(t, err)
			},
		},
		{
			name: "the consumer's login check refuses unchanged and writes nothing",
			opts: []passkey.Option{passkey.WithLoginCheck(func(_ context.Context, f passkey.LoginFacts) error {
				if f.User == "u-1" && !f.BackupEligible && f.UserVerified && len(f.AAGUID) == 16 && !f.Credential.IsZero() {
					return consumerErr
				}

				return nil
			})},
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, consumerErr)
				assert.Nil(t, res)
				assert.Zero(t, e.creds.records.Load())
				unchanged(t, e)
			},
		},
		{
			name: "a registration challenge is refused before any credential lookup",
			body: func(t *testing.T, e *loginEnv, _ string) []byte {
				t.Helper()

				// The registration manager's challenge for u-1's session,
				// presented with that session's ID as the binding.
				s := fullSession("sess-a", "u-1")
				e.binding = s.ID

				return assertion(e.f.begin(t, e.m, s), nil)
			},
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				refused(t, e, res, err)
				assert.Zero(t, e.creds.finds.Load(), "no credential lookup")
				assert.Zero(t, e.creds.records.Load(), "no counter write")
				assert.Zero(t, e.verifyCount())
			},
		},
		{
			name:   "a verifier cancelled mid-flight is a context error, not a bad signature",
			before: func(_ *testing.T, e *loginEnv, _ string) { e.failVerifier(context.Canceled) },
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, res)
				unchanged(t, e)
			},
		},
		{
			name: "a verifier past its deadline is a context error, not a bad signature",
			before: func(_ *testing.T, e *loginEnv, _ string) {
				e.failVerifier(fmt.Errorf("verify: %w", context.DeadlineExceeded))
			},
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.DeadlineExceeded)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, res)
				unchanged(t, e)
			},
		},
		{
			name: "a cancelled context is refused before anything is spent",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, res)
				unchanged(t, e)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newLoginEnv(t, tc.seed)
			e.manager(t, tc.opts...)

			challenge := e.begin(t)
			if tc.before != nil {
				tc.before(t, e, challenge)
			}

			body := assertion(challenge, nil)
			if tc.body != nil {
				body = tc.body(t, e, challenge)
			}

			binding := e.binding
			if tc.binding != nil {
				binding = *tc.binding
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			res, err := e.m.Authenticate(ctx, body, binding)
			tc.assert(t, e, res, err)
		})
	}
}
