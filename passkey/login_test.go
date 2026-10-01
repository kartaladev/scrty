package passkey_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
)

// assertionBody is the login fixture's assertion response body.
type assertionBody struct {
	Challenge string `json:"challenge"` // as clientDataJSON carries it
	ID        string `json:"id"`
	Handle    []byte `json:"handle"`
	Sig       string `json:"sig"` // "ok" verifies; anything else does not
	Count     uint32 `json:"count"`
	UV        bool   `json:"uv"`
	BE        bool   `json:"be"`
	BS        bool   `json:"bs"`
}

// parsedAssertion is a parsed assertionBody.
type parsedAssertion struct{ b assertionBody }

func (p parsedAssertion) Challenge() string    { return p.b.Challenge }
func (p parsedAssertion) CredentialID() []byte { return []byte(p.b.ID) }
func (p parsedAssertion) UserHandle() []byte   { return p.b.Handle }

// spyCredentials counts the lookups and counter writes made on a memory store.
type spyCredentials struct {
	*passkey.MemoryCredentialStore
	finds   atomic.Int32
	records atomic.Int32
	// useHook, when set, runs in place of RecordUse's write.
	useHook func(ctx context.Context, cid id.ID) (bool, error)
}

func (s *spyCredentials) RecordUse(ctx context.Context, cid id.ID, bs bool, at time.Time) (bool, error) {
	if s.useHook != nil {
		return s.useHook(ctx, cid)
	}

	return s.MemoryCredentialStore.RecordUse(ctx, cid, bs, at)
}

func (s *spyCredentials) FindByCredentialID(ctx context.Context, credID []byte) (*passkey.Credential, error) {
	s.finds.Add(1)
	return s.MemoryCredentialStore.FindByCredentialID(ctx, credID)
}

func (s *spyCredentials) RecordAssertion(
	ctx context.Context, cid id.ID, n uint32, bs bool, at time.Time,
) (bool, error) {
	s.records.Add(1)
	return s.MemoryCredentialStore.RecordAssertion(ctx, cid, n, bs, at)
}

// spyChallenges counts the purges made on a memory challenge store, and fails
// them with err when set.
type spyChallenges struct {
	*onetime.MemoryStore
	err     error
	mu      sync.Mutex
	reaps   int
	removed int
}

func (s *spyChallenges) DeleteExpiredBefore(ctx context.Context, purpose string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.reaps++
	if s.err != nil {
		return 0, s.err
	}

	n, err := s.MemoryStore.DeleteExpiredBefore(ctx, purpose, since)
	s.removed += n

	return n, err
}

// purges returns how many purges ran and how many records they removed.
func (s *spyChallenges) purges() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.reaps, s.removed
}

// The login fixture's handles, one per user.
var (
	handleU1 = bytes.Repeat([]byte{0x01}, passkey.HandleSize)
	handleU2 = bytes.Repeat([]byte{0x02}, passkey.HandleSize)
)

// loginEnv is a manager over the fixture with one seeded credential, "key-1"
// of u-1: a device-bound security key with a stored counter of 42.
type loginEnv struct {
	f          *fixture
	m          *passkey.Manager
	creds      *spyCredentials
	challenges *spyChallenges
	cred       *passkey.Credential
	logs       *logBuffer
	binding    string

	mu        sync.Mutex
	requested []passkey.RequestInput
	verifies  int
}

// newLoginEnv wires the fixture for login. seed may adjust the credential
// before it is stored.
func newLoginEnv(t *testing.T, seed func(c *passkey.Credential)) *loginEnv {
	t.Helper()

	f := newFixture(t)
	e := &loginEnv{
		f:          f,
		creds:      &spyCredentials{MemoryCredentialStore: f.creds},
		challenges: &spyChallenges{MemoryStore: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(f.clock))},
		logs:       &logBuffer{},
		binding:    "ceremony-cookie-value",
	}

	handles := passkey.NewMemoryHandleStore()
	_, err := handles.Assign(t.Context(), "u-1", handleU1)
	require.NoError(t, err)
	_, err = handles.Assign(t.Context(), "u-2", handleU2)
	require.NoError(t, err)

	f.deps.Credentials = e.creds
	f.deps.Handles = handles
	f.deps.Challenges = e.challenges

	f.verifier.EXPECT().RequestOptions(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, in passkey.RequestInput) (json.RawMessage, error) {
			e.mu.Lock()
			defer e.mu.Unlock()

			e.requested = append(e.requested, in)

			return json.RawMessage(`{"publicKey":{}}`), nil
		}).AnyTimes()
	f.verifier.EXPECT().ParseAssertion(gomock.Any()).DoAndReturn(
		func(body []byte) (passkey.ParsedAssertion, error) {
			var b assertionBody
			if err := json.Unmarshal(body, &b); err != nil || b.ID == "" {
				return nil, errors.New("unparseable")
			}

			return parsedAssertion{b}, nil
		}).AnyTimes()
	f.verifier.EXPECT().VerifyAssertion(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(
			_ context.Context, p passkey.ParsedAssertion, c *passkey.Credential, exp passkey.AssertionExpectation,
		) (*passkey.AssertionResult, error) {
			e.mu.Lock()
			e.verifies++
			e.mu.Unlock()

			b := p.(parsedAssertion).b
			signed, _ := passkey.DecodeChallenge(b.Challenge)

			if b.Sig != "ok" || signed != exp.Challenge || !bytes.Equal(c.CredentialID, []byte(b.ID)) {
				return nil, errors.New("signature does not verify")
			}

			return &passkey.AssertionResult{SignCount: b.Count, UserVerified: b.UV, BackupEligible: b.BE, BackupState: b.BS}, nil
		}).AnyTimes()

	cid, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	e.cred = &passkey.Credential{
		ID:           cid,
		User:         "u-1",
		CredentialID: []byte("key-1"),
		PublicKey:    []byte("cose-public-key-of-key-1"),
		SignCount:    42,
		AAGUID:       bytes.Repeat([]byte{0xAA}, 16),
		Name:         "Security key",
		CreatedAt:    regStart,
		State:        passkey.StateActive,
	}
	if seed != nil {
		seed(e.cred)
	}

	require.NoError(t, f.creds.Insert(t.Context(), e.cred))

	return e
}

// manager builds the manager, logging to e.logs.
func (e *loginEnv) manager(t *testing.T, opts ...passkey.Option) *passkey.Manager {
	t.Helper()

	e.m = e.f.manager(t, append([]passkey.Option{passkey.WithLogger(e.logs.logger())}, opts...)...)

	return e.m
}

// begin runs a passwordless begin bound to e.binding, and returns the token
// string it issued.
func (e *loginEnv) begin(t *testing.T) string {
	t.Helper()

	_, err := e.m.BeginLogin(t.Context(), e.binding)
	require.NoError(t, err)

	e.mu.Lock()
	defer e.mu.Unlock()

	require.NotEmpty(t, e.requested)

	return e.requested[len(e.requested)-1].Challenge
}

// verifyCount returns how many assertions the verifier was asked to verify.
func (e *loginEnv) verifyCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.verifies
}

// stored returns the seeded credential as stored now.
func (e *loginEnv) stored(t *testing.T) *passkey.Credential {
	t.Helper()

	c, err := e.f.creds.Find(t.Context(), "u-1", e.cred.ID)
	require.NoError(t, err)

	return c
}

// assertion returns a valid, user-verified assertion body from "key-1"
// answering challenge with counter 43, adjusted by adjust.
func assertion(challenge string, adjust func(b *assertionBody)) []byte {
	b := assertionBody{
		Challenge: base64.RawURLEncoding.EncodeToString([]byte(challenge)),
		ID:        "key-1",
		Handle:    handleU1,
		Sig:       "ok",
		Count:     43,
		UV:        true,
	}
	if adjust != nil {
		adjust(&b)
	}

	out, _ := json.Marshal(b)

	return out
}

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
				assert.Equal(t, passkey.UVRequired, in.UV)
				assert.Equal(t, 5*time.Minute, in.Timeout)

				res, err := e.m.Authenticate(t.Context(), assertion(in.Challenge, nil), "ceremony-cookie-value")
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-1"), res.User)
			},
		},
		{
			name:    "user verification and the timeout follow the configuration",
			opts:    []passkey.Option{passkey.WithUserVerification(passkey.UVPreferred), passkey.WithChallengeTTL(2 * time.Minute)},
			binding: "ceremony-cookie-value",
			assert: func(t *testing.T, e *loginEnv, _ json.RawMessage, err error) {
				t.Helper()
				require.NoError(t, err)
				require.Len(t, e.requested, 1)
				assert.Equal(t, passkey.UVPreferred, e.requested[0].UV)
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
			name:   "an assertion without user verification is refused under required",
			body:   withBody(func(b *assertionBody) { b.UV = false }),
			assert: refused,
		},
		{
			name: "an assertion without user verification logs in single-factor under preferred",
			opts: []passkey.Option{passkey.WithUserVerification(passkey.UVPreferred)},
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
			name: "a pending credential is refused as pending",
			seed: func(c *passkey.Credential) { c.State, c.Pending = passkey.StatePending, passkey.AwaitingSavedCodes },
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrPending)
				assert.Nil(t, res)
				assert.Zero(t, e.verifyCount())
				unchanged(t, e)
			},
		},
		{
			name: "a suspended credential is refused as suspended",
			seed: func(c *passkey.Credential) { c.State = passkey.StateSuspended },
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrSuspended)
				assert.Nil(t, res)
				assert.Zero(t, e.verifyCount())
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
