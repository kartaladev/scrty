package passkey_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// defaultName is the name a passkey created on regStart's date defaults to.
const defaultName = "Passkey 2026-10-01"

func TestFinishRegistration(t *testing.T) {
	t.Parallel()

	type env struct {
		f         *fixture
		m         *passkey.Manager
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
				assert.Equal(t, passkey.UVRequired, exp[0].UV)
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
				f.adjustVerify("cred-z", func(*passkey.NewCredential) error { return verifyErr })
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
				f.adjustVerify("cred-a", func(*passkey.NewCredential) error { return verifyErr })
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				failed(t, e, res, err)
				assert.NotContains(t, err.Error(), verifyErr.Error())
			},
		},
		{
			name: "a refused attestation is its own refusal",
			setup: func(_ *testing.T, f *fixture) {
				f.adjustVerify("cred-a", func(*passkey.NewCredential) error { return passkey.ErrAttestationRefused })
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
				f.adjustVerify("cred-a", func(nc *passkey.NewCredential) error { nc.UserVerified = false; return nil })
			},
			assert: failed,
		},
		{
			name: "no user verification when it is preferred",
			opts: []passkey.Option{passkey.WithUserVerification(passkey.UVPreferred)},
			setup: func(_ *testing.T, f *fixture) {
				f.adjustVerify("cred-a", func(nc *passkey.NewCredential) error { nc.UserVerified = false; return nil })
			},
			assert: func(t *testing.T, e *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, res.Activated)
				assert.Equal(t, passkey.UVPreferred, e.f.verifications()[0].UV)
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
				f.adjustVerify("cred-a", func(nc *passkey.NewCredential) error {
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
				require.ErrorIs(t, err, passkey.ErrLimitReached)
				assert.Nil(t, res)

				n, err := e.f.creds.Count(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, 25, n)
			},
		},
		{
			name: "consumer passkey limit counts pending credentials",
			opts: []passkey.Option{passkey.WithPasskeyLimit(1)},
			setup: func(t *testing.T, f *fixture) {
				require.NoError(t, f.creds.Insert(t.Context(), &passkey.Credential{
					ID: id.ID{15: 9}, User: "u-1", CredentialID: []byte("old"), CreatedAt: regStart,
					State: passkey.StatePending, Pending: passkey.AwaitingEmailCode,
				}))
			},
			assert: func(t *testing.T, _ *env, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrLimitReached)
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
