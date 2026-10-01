package passkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// passkeyRef names credential c as the passkey kind does.
func passkeyRef(c *passkey.Credential) recovery.AuthenticatorRef {
	return recovery.AuthenticatorRef{Kind: "passkey", ID: c.ID.String()}
}

// kindEnv is a manager whose user u-1 holds an active, a pending and a
// suspended passkey, and u-2 one active passkey.
type kindEnv struct {
	*loginEnv
	active, pendingCred, suspendedCred, theirs *passkey.Credential
}

func newKindEnv(t *testing.T) *kindEnv {
	t.Helper()

	e := &kindEnv{loginEnv: newLoginEnv(t, nil)}
	e.active = e.cred
	e.pendingCred = addCredential(t, e.loginEnv, "u-1", "key-pending", passkey.StatePending)
	e.suspendedCred = addCredential(t, e.loginEnv, "u-1", "key-suspended", passkey.StateSuspended)
	e.theirs = addCredential(t, e.loginEnv, "u-2", "key-of-u-2", passkey.StateActive)

	return e
}

// remaining lists the library IDs of user's credentials.
func (e *kindEnv) remaining(t *testing.T, user identity.UserID) []id.ID {
	t.Helper()

	all, err := e.f.creds.List(t.Context(), user)
	require.NoError(t, err)

	out := make([]id.ID, len(all))
	for i, c := range all {
		out[i] = c.ID
	}

	return out
}

// kindSource builds the passkey kind over e's credential store, the way a
// Manager reports it or the way a consumer builds it before any Manager.
type kindSource struct {
	name string
	kind func(t *testing.T, e *kindEnv) recovery.AuthenticatorKind
}

// kindSources lists both ways to get the kind; each must behave identically.
func kindSources() []kindSource {
	return []kindSource{
		{"Manager.RecoveryKind", func(t *testing.T, e *kindEnv) recovery.AuthenticatorKind {
			t.Helper()

			return e.manager(t).RecoveryKind()
		}},
		{"NewRecoveryKind", func(_ *testing.T, e *kindEnv) recovery.AuthenticatorKind {
			return passkey.NewRecoveryKind(e.f.deps.Credentials)
		}},
	}
}

func TestRecoveryKindListing(t *testing.T) {
	t.Parallel()

	type lister func(k recovery.AuthenticatorKind) func(context.Context, identity.UserID) ([]recovery.AuthenticatorRef, error)

	held := func(k recovery.AuthenticatorKind) func(context.Context, identity.UserID) ([]recovery.AuthenticatorRef, error) {
		return k.Held
	}
	usable := func(k recovery.AuthenticatorKind) func(context.Context, identity.UserID) ([]recovery.AuthenticatorRef, error) {
		ul, ok := k.(recovery.UsableLister)
		require.True(t, ok, "the passkey kind implements recovery.UsableLister")

		return ul.Usable
	}

	type testCase struct {
		name   string
		list   lister
		user   identity.UserID
		broken bool
		assert func(t *testing.T, e *kindEnv, refs []recovery.AuthenticatorRef, err error)
	}

	cases := []testCase{
		{
			name: "held lists every passkey of the user, in every state",
			list: held,
			user: "u-1",
			assert: func(t *testing.T, e *kindEnv, refs []recovery.AuthenticatorRef, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.ElementsMatch(t, []recovery.AuthenticatorRef{
					passkeyRef(e.active), passkeyRef(e.pendingCred), passkeyRef(e.suspendedCred),
				}, refs)
			},
		},
		{
			name: "usable lists only the user's active passkeys",
			list: usable,
			user: "u-1",
			assert: func(t *testing.T, e *kindEnv, refs []recovery.AuthenticatorRef, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, []recovery.AuthenticatorRef{passkeyRef(e.active)}, refs)
			},
		},
		{
			name: "held for a user with no passkey is empty",
			list: held,
			user: "u-3",
			assert: func(t *testing.T, _ *kindEnv, refs []recovery.AuthenticatorRef, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Empty(t, refs)
			},
		},
		{
			name:   "a failed held listing is an error, never an empty list",
			list:   held,
			user:   "u-1",
			broken: true,
			assert: func(t *testing.T, _ *kindEnv, refs []recovery.AuthenticatorRef, err error) {
				t.Helper()
				require.ErrorIs(t, err, errStore)
				assert.Nil(t, refs)
			},
		},
		{
			name:   "a failed usable listing is an error, never an empty list",
			list:   usable,
			user:   "u-1",
			broken: true,
			assert: func(t *testing.T, _ *kindEnv, refs []recovery.AuthenticatorRef, err error) {
				t.Helper()
				require.ErrorIs(t, err, errStore)
				assert.Nil(t, refs)
			},
		},
	}

	for _, src := range kindSources() {
		for _, tc := range cases {
			t.Run(src.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				e := newKindEnv(t)
				if tc.broken {
					e.f.deps.Credentials = brokenCredentials{e.f.creds}
				}

				kind := src.kind(t, e)
				assert.Equal(t, "passkey", kind.Kind())

				refs, err := tc.list(kind)(t.Context(), tc.user)
				tc.assert(t, e, refs, err)
			})
		}
	}
}

func TestRecoveryKindRemove(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		user   identity.UserID
		refs   func(e *kindEnv) []recovery.AuthenticatorRef
		broken bool
		assert func(t *testing.T, e *kindEnv, err error)
	}

	cases := []testCase{
		{
			name: "removes the named passkeys, in any state, and keeps the rest",
			user: "u-1",
			refs: func(e *kindEnv) []recovery.AuthenticatorRef {
				return []recovery.AuthenticatorRef{passkeyRef(e.active), passkeyRef(e.suspendedCred)}
			},
			assert: func(t *testing.T, e *kindEnv, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, []id.ID{e.pendingCred.ID}, e.remaining(t, "u-1"))
			},
		},
		{
			name: "another user's passkey, an unknown and a malformed identifier are ignored",
			user: "u-1",
			refs: func(e *kindEnv) []recovery.AuthenticatorRef {
				unknown, _ := id.NewV7Generator().NewID()

				return []recovery.AuthenticatorRef{
					passkeyRef(e.theirs),
					{Kind: "passkey", ID: unknown.String()},
					{Kind: "passkey", ID: "not-an-id"},
					passkeyRef(e.pendingCred),
				}
			},
			assert: func(t *testing.T, e *kindEnv, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{e.active.ID, e.suspendedCred.ID}, e.remaining(t, "u-1"))
				assert.Equal(t, []id.ID{e.theirs.ID}, e.remaining(t, "u-2"))
			},
		},
		{
			name: "a reference of another kind is ignored",
			user: "u-1",
			refs: func(e *kindEnv) []recovery.AuthenticatorRef {
				return []recovery.AuthenticatorRef{{Kind: "mfa", ID: e.active.ID.String()}}
			},
			assert: func(t *testing.T, e *kindEnv, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Len(t, e.remaining(t, "u-1"), 3)
			},
		},
		{
			name: "a store failure is returned",
			user: "u-1",
			refs: func(e *kindEnv) []recovery.AuthenticatorRef {
				return []recovery.AuthenticatorRef{passkeyRef(e.active)}
			},
			broken: true,
			assert: func(t *testing.T, _ *kindEnv, err error) {
				t.Helper()
				require.ErrorIs(t, err, errStore)
			},
		},
	}

	for _, src := range kindSources() {
		for _, tc := range cases {
			t.Run(src.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				e := newKindEnv(t)
				if tc.broken {
					e.f.deps.Credentials = brokenCredentials{e.f.creds}
				}

				err := src.kind(t, e).Remove(t.Context(), tc.user, tc.refs(e))
				tc.assert(t, e, err)
			})
		}
	}
}

// recoveryWorld is a real recovery over in-memory stores for u-1, who holds
// two active passkeys — a synced one and a security key — and a confirmed
// TOTP enrolment.
type recoveryWorld struct {
	*loginEnv
	synced, securityKey *passkey.Credential
	totpStore           *mfa.MemoryEnrolmentStore
	totp                *mfa.TOTP
	codes               *recovery.Codes
	saved               []string
	issued              string
	tokens              *onetime.MemoryStore
	sessions            *session.Manager
}

func newRecoveryWorld(t *testing.T) *recoveryWorld {
	t.Helper()

	w := &recoveryWorld{loginEnv: newLoginEnv(t, nil), totpStore: mfa.NewMemoryEnrolmentStore()}
	w.securityKey = w.cred
	w.synced = addCredential(t, w.loginEnv, "u-1", "key-synced", passkey.StateActive)
	addCredential(t, w.loginEnv, "u-2", "key-of-u-2", passkey.StateActive)

	ctx := t.Context()

	totp, err := mfa.NewTOTP(w.totpStore, "Example", mfa.WithClock(w.f.clock))
	require.NoError(t, err)
	w.totp = totp

	require.NoError(t, w.totpStore.PutPending(ctx, mfa.Enrolment{
		User: "u-1", Secret: []byte("0123456789abcdef0123"), CreatedAt: regStart,
	}))
	confirmed, err := w.totpStore.Confirm(ctx, "u-1", 1, regStart)
	require.NoError(t, err)
	require.True(t, confirmed)

	w.codes, err = recovery.NewCodes(recovery.WithCodesClock(w.f.clock))
	require.NoError(t, err)
	w.saved, err = w.codes.Generate(ctx, "u-1")
	require.NoError(t, err)

	w.tokens = onetime.NewMemoryStore(onetime.WithMemoryStoreClock(w.f.clock))
	mint, err := onetime.NewManager(recovery.IssuedCodePurpose, onetime.WithStore(w.tokens), onetime.WithClock(w.f.clock))
	require.NoError(t, err)
	w.issued, _, err = mint.Issue(ctx, "u-1")
	require.NoError(t, err)

	w.sessions, err = session.NewManager(session.WithClock(w.f.clock),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(w.f.clock))))
	require.NoError(t, err)

	w.f.users.EXPECT().LoadByUsername(gomock.Any(), "ana@example.com").Return(
		&identity.Details{ID: "u-1", Username: "ana@example.com", Active: true}, nil).AnyTimes()

	return w
}

// recoverer builds a recoverer over saved and issued codes, resetting the
// MFA enrolments and the passkey kind of m, with extra options.
func (w *recoveryWorld) recoverer(t *testing.T, m *passkey.Manager, extra ...recovery.Option) *recovery.Recoverer {
	t.Helper()

	mfaKind, err := recovery.MFAEnrolments(w.totp)
	require.NoError(t, err)

	r, err := recovery.NewRecoverer(recovery.Deps{
		Users:    w.f.users,
		Sessions: w.sessions,
		Sender:   nonBlocking{w.f.sender},
		Codes:    w.codes,
	}, append([]recovery.Option{
		recovery.WithProofs(recovery.ProofSaved, recovery.ProofIssued),
		recovery.WithRepudiationContact("help@example.com"),
		recovery.WithAuthenticatorKinds(mfaKind, m.RecoveryKind()),
		recovery.WithIssuedCodeStore(w.tokens),
		recovery.WithClock(w.f.clock),
	}, extra...)...)
	require.NoError(t, err)

	return r
}

func TestRecoveryKindInRecovery(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []recovery.Option
		lost   func(w *recoveryWorld) []string
		assert func(t *testing.T, w *recoveryWorld, res *recovery.Result, err error)
	}

	cases := []testCase{
		{
			name: "the default reset removes every passkey and the TOTP enrolment",
			assert: func(t *testing.T, w *recoveryWorld, res *recovery.Result, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, res.Session)

				mine, err := w.f.creds.List(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Empty(t, mine)

				theirs, err := w.f.creds.List(t.Context(), "u-2")
				require.NoError(t, err)
				assert.Len(t, theirs, 1)

				enrolled, err := w.totp.Enrolled(t.Context(), "u-1")
				require.NoError(t, err)
				assert.False(t, enrolled)
			},
		},
		{
			name: "the reported-loss mode removes only the passkey reported lost",
			opts: []recovery.Option{recovery.WithResetReported()},
			lost: func(w *recoveryWorld) []string { return []string{passkeyRef(w.securityKey).String()} },
			assert: func(t *testing.T, w *recoveryWorld, res *recovery.Result, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, res.Session)

				mine, err := w.f.creds.List(t.Context(), "u-1")
				require.NoError(t, err)
				require.Len(t, mine, 1)
				assert.Equal(t, w.synced.ID, mine[0].ID)

				enrolled, err := w.totp.Enrolled(t.Context(), "u-1")
				require.NoError(t, err)
				assert.True(t, enrolled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newRecoveryWorld(t)
			r := w.recoverer(t, w.manager(t), tc.opts...)

			req := recovery.Request{Username: "ana@example.com", Saved: w.saved[0], Issued: w.issued}
			if tc.lost != nil {
				req.Lost = tc.lost(w)
			}

			res, err := r.Recover(t.Context(), req)
			tc.assert(t, w, res, err)
		})
	}
}

func TestRecoveryKindWayBack(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		seed   func(c *passkey.Credential)
		broken bool
		assert func(t *testing.T, has bool, err error)
	}

	cases := []testCase{
		{
			name: "one active passkey pairs with an issued code",
			assert: func(t *testing.T, has bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, has)
			},
		},
		{
			name: "only a suspended passkey is no way back",
			seed: func(c *passkey.Credential) { c.State = passkey.StateSuspended },
			assert: func(t *testing.T, has bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, has)
			},
		},
		{
			name: "only a pending passkey is no way back",
			seed: func(c *passkey.Credential) {
				c.State, c.Pending = passkey.StatePending, passkey.AwaitingSavedCodes
			},
			assert: func(t *testing.T, has bool, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, has)
			},
		},
		{
			name:   "a failed listing is an error, never no",
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
			if tc.broken {
				e.f.deps.Credentials = brokenCredentials{e.f.creds}
			}

			codes, err := recovery.NewCodes(recovery.WithCodesClock(e.f.clock))
			require.NoError(t, err)

			check, err := recovery.NewWayBackCheck(recovery.WayBackDeps{
				Users:       e.f.users,
				Codes:       codes,
				Kinds:       []recovery.AuthenticatorKind{e.manager(t).RecoveryKind()},
				IssuedCodes: true,
			})
			require.NoError(t, err)

			has, err := check.HasWayBack(t.Context(), "u-1")
			tc.assert(t, has, err)
		})
	}
}

func TestNewRecoveryKindWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		seed   func(t *testing.T, f *fixture) // before the registration
		assert func(t *testing.T, f *fixture, res *passkey.RegistrationResult, err error)
	}

	cases := []testCase{
		{
			name: "a first passkey for a user with no way back waits pending on saved codes",
			assert: func(t *testing.T, f *fixture, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.False(t, res.Activated)
				assert.Len(t, res.RecoveryCodes, 10)

				c := onlyCredential(t, f, "u-1")
				assert.Equal(t, passkey.StatePending, c.State)
				assert.Equal(t, passkey.AwaitingSavedCodes, c.Pending)
			},
		},
		{
			name: "a passkey already held in the shared store is a way back, so a second activates at once",
			seed: func(t *testing.T, f *fixture) {
				t.Helper()

				cid, err := id.NewV7Generator().NewID()
				require.NoError(t, err)
				require.NoError(t, f.creds.Insert(t.Context(), &passkey.Credential{
					ID: cid, User: "u-1", CredentialID: []byte("held"), PublicKey: []byte("cose-held"),
					Name: "held", CreatedAt: regStart, State: passkey.StateActive,
				}))
			},
			assert: func(t *testing.T, f *fixture, res *passkey.RegistrationResult, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.True(t, res.Activated)

				n, err := f.creds.Count(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, 2, n)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)

			codes, err := recovery.NewCodes(recovery.WithCodesClock(f.clock))
			require.NoError(t, err)

			// The check comes first, over the store the manager will share.
			check, err := recovery.NewWayBackCheck(recovery.WayBackDeps{
				Users:       f.users,
				Codes:       codes,
				Kinds:       []recovery.AuthenticatorKind{passkey.NewRecoveryKind(f.creds)},
				IssuedCodes: true,
			})
			require.NoError(t, err)

			f.deps.Credentials = f.creds
			f.deps.Recovery = &passkey.RecoveryDeps{Codes: codes, WayBack: check}

			if tc.seed != nil {
				tc.seed(t, f)
			}

			m := f.manager(t)
			s := fullSession("sess-a", "u-1")

			f.clock.Advance(time.Minute)

			res, err := m.FinishRegistration(t.Context(), s, regBody(f.begin(t, m, s), "cred-a", ""),
				passkey.RegistrationContext{})
			tc.assert(t, f, res, err)
		})
	}
}

func TestNewRecoveryKindNilStore(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, k recovery.AuthenticatorKind)
	}

	cases := []testCase{
		{
			name: "a nil store is a configuration error on every call, never an empty list",
			assert: func(t *testing.T, k recovery.AuthenticatorKind) {
				t.Helper()

				refs, err := k.Held(t.Context(), "u-1")
				require.ErrorIs(t, err, passkey.ErrConfig)
				assert.Nil(t, refs)

				ul, ok := k.(recovery.UsableLister)
				require.True(t, ok)

				refs, err = ul.Usable(t.Context(), "u-1")
				require.ErrorIs(t, err, passkey.ErrConfig)
				assert.Nil(t, refs)

				ref := recovery.AuthenticatorRef{Kind: "passkey", ID: "x"}
				require.ErrorIs(t, k.Remove(t.Context(), "u-1", []recovery.AuthenticatorRef{ref}), passkey.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, passkey.NewRecoveryKind(nil))
		})
	}
}
