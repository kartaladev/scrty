package passkey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
)

var (
	_ mfa.ChallengeMethod  = (*passkey.MFAMethod)(nil)
	_ mfa.EnrolmentRemover = (*passkey.MFAMethod)(nil)
)

// slotChallenge stands for the token string the MFA slot issues and hands to
// BeginChallenge; the slot itself checks and spends it before Verify.
const slotChallenge = "mfa-slot-challenge-token"

// errStore is the failure brokenCredentials reports.
var errStore = errors.New("credential store unavailable")

// brokenHandles is a handle store whose lookups fail.
type brokenHandles struct{ passkey.HandleStore }

func (brokenHandles) UserFor(context.Context, []byte) (identity.UserID, bool, error) {
	return "", false, errStore
}

// brokenCredentials is a memory store whose reads and bulk deletes fail.
type brokenCredentials struct {
	*passkey.MemoryCredentialStore
}

func (brokenCredentials) List(context.Context, identity.UserID) ([]*passkey.Credential, error) {
	return nil, errStore
}

func (brokenCredentials) FindByCredentialID(context.Context, []byte) (*passkey.Credential, error) {
	return nil, errStore
}

func (brokenCredentials) DeleteUser(context.Context, identity.UserID) (int, error) {
	return 0, errStore
}

func (brokenCredentials) Delete(context.Context, identity.UserID, id.ID) (bool, error) {
	return false, errStore
}

// addCredential stores another credential of user in state st, named by its
// WebAuthn credential ID, and returns it.
func addCredential(t *testing.T, e *loginEnv, user identity.UserID, credID string, st passkey.State) *passkey.Credential {
	t.Helper()

	cid, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	c := &passkey.Credential{
		ID:           cid,
		User:         user,
		CredentialID: []byte(credID),
		PublicKey:    []byte("cose-" + credID),
		Transports:   []string{"usb", "nfc"},
		Name:         credID,
		CreatedAt:    regStart,
		State:        st,
	}
	if st == passkey.StatePending {
		c.Pending = passkey.AwaitingSavedCodes
	}

	require.NoError(t, e.f.creds.Insert(t.Context(), c))

	return c
}

func TestMFAMethodDeclaration(t *testing.T) {
	t.Parallel()

	e := newLoginEnv(t, nil)
	method := e.manager(t).MFAMethod()

	assert.Equal(t, "passkey", method.Name())
	assert.Equal(t, passkey.MethodName, method.Name())
	assert.Equal(t, factor.PublicKey, method.Channel())
	assert.Equal(t, mfa.JSONBody(16<<10), method.Response())
	assert.True(t, method.SupportsEnrolmentPath())

	lookups, err := mfa.LookupsFor(method)
	require.NoError(t, err)
	require.Len(t, lookups, 1)
}

func TestMFAMethodEnrolled(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		seed   func(c *passkey.Credential)
		extra  func(t *testing.T, e *loginEnv)
		broken bool
		user   identity.UserID
		assert func(t *testing.T, enrolled bool, err error)
	}

	notEnrolled := func(t *testing.T, enrolled bool, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.False(t, enrolled)
	}

	cases := []testCase{
		{
			name: "one active passkey is enrolled",
			user: "u-1",
			assert: func(t *testing.T, enrolled bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, enrolled)
			},
		},
		{
			name: "only a pending passkey is not enrolled",
			user: "u-1",
			seed: func(c *passkey.Credential) {
				c.State, c.Pending = passkey.StatePending, passkey.AwaitingSavedCodes
			},
			assert: notEnrolled,
		},
		{
			name:   "only a suspended passkey is not enrolled",
			user:   "u-1",
			seed:   func(c *passkey.Credential) { c.State = passkey.StateSuspended },
			assert: notEnrolled,
		},
		{
			name:   "another user's active passkey does not enrol u-2",
			user:   "u-2",
			assert: notEnrolled,
		},
		{
			name: "a suspended and an active passkey are enrolled",
			user: "u-1",
			seed: func(c *passkey.Credential) { c.State = passkey.StateSuspended },
			extra: func(t *testing.T, e *loginEnv) {
				t.Helper()
				addCredential(t, e, "u-1", "key-2", passkey.StateActive)
			},
			assert: func(t *testing.T, enrolled bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, enrolled)
			},
		},
		{
			name:   "a store failure is an error, never not enrolled",
			user:   "u-1",
			broken: true,
			assert: func(t *testing.T, _ bool, err error) {
				t.Helper()
				require.ErrorIs(t, err, errStore)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newLoginEnv(t, tc.seed)
			if tc.extra != nil {
				tc.extra(t, e)
			}

			if tc.broken {
				e.f.deps.Credentials = brokenCredentials{e.f.creds}
			}

			enrolled, err := e.manager(t).MFAMethod().Enrolled(t.Context(), tc.user)
			tc.assert(t, enrolled, err)
		})
	}
}

func TestMFAMethodUsableMethods(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		seed   func(c *passkey.Credential)
		first  factor.Kind
		assert func(t *testing.T, usable []policy.MFAMethodLookup, err error)
	}

	cases := []testCase{
		{
			name:  "an active passkey is offered after a password",
			first: factor.Password,
			assert: func(t *testing.T, usable []policy.MFAMethodLookup, err error) {
				t.Helper()
				require.NoError(t, err)
				require.Len(t, usable, 1)
				assert.Equal(t, "passkey", usable[0].Name())
			},
		},
		{
			name: "only pending passkeys are not offered after a password",
			seed: func(c *passkey.Credential) {
				c.State, c.Pending = passkey.StatePending, passkey.AwaitingSavedCodes
			},
			first: factor.Password,
			assert: func(t *testing.T, usable []policy.MFAMethodLookup, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Empty(t, usable)
			},
		},
		{
			name:  "the passkey method is never offered after a passkey login",
			first: factor.Passkey,
			assert: func(t *testing.T, usable []policy.MFAMethodLookup, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Empty(t, usable)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newLoginEnv(t, tc.seed)
			lookups, err := mfa.LookupsFor(e.manager(t).MFAMethod())
			require.NoError(t, err)

			usable, err := policy.UsableMFAMethods(t.Context(), lookups, "u-1", tc.first)
			tc.assert(t, usable, err)
		})
	}
}

func TestMFAMethodBeginChallenge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []passkey.Option
		user   identity.UserID
		broken bool
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, e *loginEnv, raw json.RawMessage, err error)
	}

	cases := []testCase{
		{
			name: "lists only the user's active passkeys with their transports",
			user: "u-1",
			assert: func(t *testing.T, e *loginEnv, raw json.RawMessage, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.JSONEq(t, `{"publicKey":{}}`, string(raw))

				require.Len(t, e.requested, 1)
				in := e.requested[0]
				assert.Equal(t, slotChallenge, in.Challenge)
				assert.Equal(t, passkey.UVRequired, in.UV)
				assert.Equal(t, 5*time.Minute, in.Timeout)
				assert.ElementsMatch(t, []passkey.Descriptor{
					{ID: []byte("key-1")},
					{ID: []byte("key-2"), Transports: []string{"usb", "nfc"}},
				}, in.Allow)
			},
		},
		{
			name: "user verification and the timeout follow the configuration",
			user: "u-1",
			opts: []passkey.Option{passkey.WithUserVerification(passkey.UVPreferred), passkey.WithChallengeTTL(time.Minute)},
			assert: func(t *testing.T, e *loginEnv, _ json.RawMessage, err error) {
				t.Helper()
				require.NoError(t, err)
				require.Len(t, e.requested, 1)
				assert.Equal(t, passkey.UVPreferred, e.requested[0].UV)
				assert.Equal(t, time.Minute, e.requested[0].Timeout)
			},
		},
		{
			name: "a user with no active passkey is refused, rendering nothing",
			user: "u-3",
			assert: func(t *testing.T, e *loginEnv, raw json.RawMessage, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrNotFound)
				assert.Nil(t, raw)
				assert.Empty(t, e.requested)
			},
		},
		{
			name:   "a store failure is returned",
			user:   "u-1",
			broken: true,
			assert: func(t *testing.T, e *loginEnv, _ json.RawMessage, err error) {
				t.Helper()
				require.ErrorIs(t, err, errStore)
				assert.Empty(t, e.requested)
			},
		},
		{
			name: "a cancelled context renders nothing",
			user: "u-1",
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithCancel(ctx)
				cancel()

				return c
			},
			assert: func(t *testing.T, e *loginEnv, _ json.RawMessage, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.Empty(t, e.requested)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newLoginEnv(t, nil)
			addCredential(t, e, "u-1", "key-2", passkey.StateActive)
			addCredential(t, e, "u-1", "key-pending", passkey.StatePending)
			addCredential(t, e, "u-1", "key-suspended", passkey.StateSuspended)
			addCredential(t, e, "u-2", "key-of-u-2", passkey.StateActive)
			addCredential(t, e, "u-3", "key-of-u-3", passkey.StateSuspended)

			if tc.broken {
				e.f.deps.Credentials = brokenCredentials{e.f.creds}
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			raw, err := e.manager(t, tc.opts...).MFAMethod().BeginChallenge(ctx, tc.user, slotChallenge)
			tc.assert(t, e, raw, err)
		})
	}
}

func TestMFAMethodPresentedChallenge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		body   []byte
		assert func(t *testing.T, challenge string, err error)
	}

	cases := []testCase{
		{
			name: "returns the token string the assertion answers",
			body: assertion(slotChallenge, nil),
			assert: func(t *testing.T, challenge string, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, slotChallenge, challenge)
			},
		},
		{
			name: "an unreadable response is an error",
			body: []byte(`not json`),
			assert: func(t *testing.T, challenge string, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Empty(t, challenge)
			},
		},
		{
			name: "a challenge that is not unpadded base64url is an error",
			body: assertion(slotChallenge, func(b *assertionBody) { b.Challenge = "not base64url!" }),
			assert: func(t *testing.T, challenge string, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Empty(t, challenge)
			},
		},
		{
			name: "an empty challenge is an error",
			body: assertion(slotChallenge, func(b *assertionBody) { b.Challenge = "" }),
			assert: func(t *testing.T, challenge string, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Empty(t, challenge)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newLoginEnv(t, nil)
			challenge, err := e.manager(t).MFAMethod().PresentedChallenge(tc.body)
			tc.assert(t, challenge, err)
		})
	}
}

func TestMFAMethodVerify(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name          string
		seed          func(c *passkey.Credential)
		opts          []passkey.Option
		user          identity.UserID
		body          []byte
		broken        bool
		verifyErr     error
		brokenHandles bool
		ctx           func(ctx context.Context) context.Context
		assert        func(t *testing.T, e *loginEnv, err error)
	}

	// refusedUnchanged asserts an invalid code with the credential as seeded.
	refusedUnchanged := func(t *testing.T, e *loginEnv, err error) {
		t.Helper()
		require.ErrorIs(t, err, mfa.ErrInvalidCode)
		assert.NotErrorIs(t, err, mfa.ErrAuthenticatorRefused)
		assert.Equal(t, uint32(42), e.stored(t).SignCount)
		assert.True(t, e.stored(t).LastUsedAt.IsZero())
	}
	errLoginCheck := errors.New("consumer refuses this authenticator")

	cases := []testCase{
		{
			name: "a valid assertion from the user's active passkey verifies and records its use",
			user: "u-1",
			body: assertion(slotChallenge, nil),
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, uint32(43), e.stored(t).SignCount)
				assert.Equal(t, regStart, e.stored(t).LastUsedAt)
			},
		},
		{
			name: "another user's credential is an invalid code, and nothing is verified",
			user: "u-2",
			body: assertion(slotChallenge, nil),
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				refusedUnchanged(t, e, err)
				assert.Zero(t, e.verifyCount())
				assert.Zero(t, e.creds.records.Load())
			},
		},
		{
			name: "an unknown credential is an invalid code",
			user: "u-1",
			body: assertion(slotChallenge, func(b *assertionBody) { b.ID = "key-unknown" }),
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				refusedUnchanged(t, e, err)
				assert.Zero(t, e.verifyCount())
			},
		},
		{
			name: "a pending credential is an invalid code, and nothing is verified",
			user: "u-1",
			seed: func(c *passkey.Credential) {
				c.State, c.Pending = passkey.StatePending, passkey.AwaitingSavedCodes
			},
			body: assertion(slotChallenge, nil),
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				refusedUnchanged(t, e, err)
				assert.Zero(t, e.verifyCount())
			},
		},
		{
			name: "a suspended credential is refused as suspended, an authenticator refusal",
			user: "u-1",
			seed: func(c *passkey.Credential) { c.State = passkey.StateSuspended },
			body: assertion(slotChallenge, nil),
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrSuspended)
				require.ErrorIs(t, err, mfa.ErrAuthenticatorRefused)
				assert.Zero(t, e.verifyCount())
				assert.Equal(t, uint32(42), e.stored(t).SignCount)
			},
		},
		{
			name: "user presence only is accepted under preferred user verification",
			user: "u-1",
			opts: []passkey.Option{passkey.WithUserVerification(passkey.UVPreferred)},
			body: assertion(slotChallenge, func(b *assertionBody) { b.UV = false }),
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, uint32(43), e.stored(t).SignCount)
			},
		},
		{
			name:   "user presence only is an invalid code under required user verification",
			user:   "u-1",
			body:   assertion(slotChallenge, func(b *assertionBody) { b.UV = false }),
			assert: refusedUnchanged,
		},
		{
			name:   "a signature that does not verify is an invalid code",
			user:   "u-1",
			body:   assertion(slotChallenge, func(b *assertionBody) { b.Sig = "forged" }),
			assert: refusedUnchanged,
		},
		{
			name:   "a backup-eligibility flag that differs from the stored one is an invalid code",
			user:   "u-1",
			body:   assertion(slotChallenge, func(b *assertionBody) { b.BE = true }),
			assert: refusedUnchanged,
		},
		{
			name:   "an unreadable response is an invalid code",
			user:   "u-1",
			body:   []byte(`not json`),
			assert: refusedUnchanged,
		},
		{
			name:   "a challenge that does not decode is an invalid code",
			user:   "u-1",
			body:   assertion(slotChallenge, func(b *assertionBody) { b.Challenge = "not base64url!" }),
			assert: refusedUnchanged,
		},
		{
			name: "a counter that does not move forward is a suspected clone and suspends the passkey",
			user: "u-1",
			body: assertion(slotChallenge, func(b *assertionBody) { b.Count = 42 }),
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				require.ErrorIs(t, err, mfa.ErrAuthenticatorRefused)
				assert.NotErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Equal(t, passkey.StateSuspended, e.stored(t).State)
			},
		},
		{
			name: "the consumer's login check error is returned unchanged and nothing is written",
			user: "u-1",
			opts: []passkey.Option{passkey.WithLoginCheck(func(context.Context, passkey.LoginFacts) error {
				return errLoginCheck
			})},
			body: assertion(slotChallenge, nil),
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, errLoginCheck)
				assert.Equal(t, uint32(42), e.stored(t).SignCount)
			},
		},
		{
			name:   "a store failure is returned, not an invalid code",
			user:   "u-1",
			body:   assertion(slotChallenge, nil),
			broken: true,
			assert: func(t *testing.T, _ *loginEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, errStore)
				assert.NotErrorIs(t, err, mfa.ErrInvalidCode)
			},
		},
		{
			name:      "a verifier cancelled mid-flight is a context error, not an invalid code",
			user:      "u-1",
			body:      assertion(slotChallenge, nil),
			verifyErr: context.Canceled,
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, mfa.ErrInvalidCode)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, uint32(42), e.stored(t).SignCount)
			},
		},
		{
			name: "a user handle that maps to the user is accepted",
			user: "u-1",
			body: assertion(slotChallenge, func(b *assertionBody) { b.Handle = handleU1 }),
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, uint32(43), e.stored(t).SignCount)
			},
		},
		{
			name: "an absent user handle is accepted",
			user: "u-1",
			body: assertion(slotChallenge, func(b *assertionBody) { b.Handle = nil }),
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, uint32(43), e.stored(t).SignCount)
			},
		},
		{
			name: "another user's handle is an invalid code and nothing is written",
			user: "u-1",
			body: assertion(slotChallenge, func(b *assertionBody) { b.Handle = handleU2 }),
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				refusedUnchanged(t, e, err)
				assert.Zero(t, e.creds.records.Load())
			},
		},
		{
			name: "an unknown user handle is an invalid code and nothing is written",
			user: "u-1",
			body: assertion(slotChallenge, func(b *assertionBody) { b.Handle = bytes.Repeat([]byte{0x09}, passkey.HandleSize) }),
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				refusedUnchanged(t, e, err)
				assert.Zero(t, e.creds.records.Load())
			},
		},
		{
			name:          "a user handle lookup failure is returned, not an invalid code",
			user:          "u-1",
			body:          assertion(slotChallenge, nil),
			brokenHandles: true,
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, errStore)
				assert.NotErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Equal(t, uint32(42), e.stored(t).SignCount)
			},
		},
		{
			name: "a cancelled context verifies nothing",
			user: "u-1",
			body: assertion(slotChallenge, nil),
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithCancel(ctx)
				cancel()

				return c
			},
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.Zero(t, e.verifyCount())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newLoginEnv(t, tc.seed)
			if tc.broken {
				e.f.deps.Credentials = brokenCredentials{e.f.creds}
			}

			if tc.brokenHandles {
				e.f.deps.Handles = brokenHandles{e.f.deps.Handles}
			}

			e.failVerifier(tc.verifyErr)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			err := e.manager(t, tc.opts...).MFAMethod().Verify(ctx, tc.user, tc.body)
			tc.assert(t, e, err)
		})
	}
}

func TestMFAMethodRemoveEnrolment(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		user      identity.UserID
		broken    bool
		verifyErr error
		assert    func(t *testing.T, e *loginEnv, err error)
	}

	cases := []testCase{
		{
			name: "removes every passkey of the user, in every state, and no one else's",
			user: "u-1",
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()
				require.NoError(t, err)

				mine, err := e.f.creds.List(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Empty(t, mine)

				theirs, err := e.f.creds.List(t.Context(), "u-2")
				require.NoError(t, err)
				assert.Len(t, theirs, 1)
			},
		},
		{
			name: "a user with no passkey is not an error",
			user: "u-3",
			assert: func(t *testing.T, _ *loginEnv, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		{
			name:   "a store failure is returned",
			user:   "u-1",
			broken: true,
			assert: func(t *testing.T, _ *loginEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, errStore)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newLoginEnv(t, nil)
			addCredential(t, e, "u-1", "key-pending", passkey.StatePending)
			addCredential(t, e, "u-1", "key-suspended", passkey.StateSuspended)
			addCredential(t, e, "u-2", "key-of-u-2", passkey.StateActive)

			if tc.broken {
				e.f.deps.Credentials = brokenCredentials{e.f.creds}
			}

			err := e.manager(t).MFAMethod().RemoveEnrolment(t.Context(), tc.user)
			tc.assert(t, e, err)
		})
	}
}
