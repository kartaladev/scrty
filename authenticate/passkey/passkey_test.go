package passkey_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// synchronousSender is a sender that does not report notify.NonBlocking.
type synchronousSender struct{}

func (synchronousSender) Send(context.Context, notify.Message) error { return nil }

// typedNilLoader is a nil pointer whose type implements identity.UserLoader.
type typedNilLoader struct{}

func (*typedNilLoader) LoadByUsername(context.Context, string) (*identity.Details, error) {
	return nil, errors.New("unreachable")
}

func (*typedNilLoader) LoadByUserID(context.Context, identity.UserID) (*identity.Details, error) {
	return nil, errors.New("unreachable")
}

func TestNew(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		deps   func(t *testing.T, f *fixture)
		opts   []passkey.Option
		noRepu bool
		assert func(t *testing.T, m *passkey.Passkeys, err error)
	}

	refused := func(t *testing.T, m *passkey.Passkeys, err error) {
		t.Helper()
		require.ErrorIs(t, err, passkey.ErrConfig)
		assert.Nil(t, m)
	}
	accepted := func(t *testing.T, m *passkey.Passkeys, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.NotNil(t, m)
	}

	cases := []testCase{
		{name: "valid deps succeed", assert: accepted},
		{name: "nil verifier", deps: func(_ *testing.T, f *fixture) { f.deps.Verifier = nil }, assert: refused},
		{name: "nil users", deps: func(_ *testing.T, f *fixture) { f.deps.Users = nil }, assert: refused},
		{
			name:   "typed-nil users",
			deps:   func(_ *testing.T, f *fixture) { f.deps.Users = (*typedNilLoader)(nil) },
			assert: refused,
		},
		{name: "nil sender", deps: func(_ *testing.T, f *fixture) { f.deps.Sender = nil }, assert: refused},
		{name: "missing repudiation contact", noRepu: true, assert: refused},
		{
			name: "invalid relying party",
			deps: func(_ *testing.T, f *fixture) {
				v := NewMockVerifier(f.ctrl)
				v.EXPECT().RelyingParty().Return(passkey.RelyingParty{ID: "https://example.com"}).AnyTimes()
				f.deps.Verifier = v
			},
			assert: refused,
		},
		{
			name:   "synchronous sender",
			deps:   func(_ *testing.T, f *fixture) { f.deps.Sender = synchronousSender{} },
			assert: refused,
		},
		{
			name:   "synchronous sender with synchronous delivery accepted",
			deps:   func(_ *testing.T, f *fixture) { f.deps.Sender = synchronousSender{} },
			opts:   []passkey.Option{passkey.WithSynchronousDelivery()},
			assert: accepted,
		},
		{name: "zero challenge TTL", opts: []passkey.Option{passkey.WithChallengeTTL(0)}, assert: refused},
		{name: "negative freshness", opts: []passkey.Option{passkey.WithManagementFreshness(-time.Minute)}, assert: refused},
		{name: "zero issuance limit", opts: []passkey.Option{passkey.WithRegistrationChallengeLimit(0)}, assert: refused},
		{name: "zero passkey limit", opts: []passkey.Option{passkey.WithLimit(0)}, assert: refused},
		{name: "unknown user verification", opts: []passkey.Option{passkey.WithUserVerification(0)}, assert: refused},
		{name: "unknown resident key", opts: []passkey.Option{passkey.WithResidentKey(9)}, assert: refused},
		{name: "nil name resolver", opts: []passkey.Option{passkey.WithNameResolver(nil)}, assert: refused},
		{name: "nil registration check", opts: []passkey.Option{passkey.WithRegistrationCheck(nil)}, assert: refused},
		{name: "nil clock", opts: []passkey.Option{passkey.WithClock(nil)}, assert: refused},
		{name: "nil random", opts: []passkey.Option{passkey.WithRandom(nil)}, assert: refused},
		{name: "nil id generator", opts: []passkey.Option{passkey.WithIDGenerator(nil)}, assert: refused},
		{name: "nil login check", opts: []passkey.Option{passkey.WithLoginCheck(nil)}, assert: refused},
		{name: "unknown clone response", opts: []passkey.Option{passkey.WithCloneResponse(9)}, assert: refused},
		{name: "nil clone policy", opts: []passkey.Option{passkey.WithClonePolicy(nil)}, assert: refused},
		{name: "nil messages", opts: []passkey.Option{passkey.WithMessages(nil)}, assert: refused},
		{name: "nil contact resolver", opts: []passkey.Option{passkey.WithContactResolver(nil)}, assert: refused},
		{name: "zero log interval writes every record", opts: []passkey.Option{passkey.WithLogInterval(0)}, assert: accepted},
		{
			name:   "no session revoker while revocation is on",
			deps:   func(_ *testing.T, f *fixture) { f.deps.Sessions = nil },
			assert: refused,
		},
		{
			name:   "typed-nil session revoker",
			deps:   func(_ *testing.T, f *fixture) { f.deps.Sessions = (*session.Sessions)(nil) },
			assert: refused,
		},
		{
			name:   "no session revoker with only removal revocation off",
			deps:   func(_ *testing.T, f *fixture) { f.deps.Sessions = nil },
			opts:   []passkey.Option{passkey.WithoutSessionRevocationOnRemoval()},
			assert: refused,
		},
		{
			name:   "no session revoker with only clone revocation off",
			deps:   func(_ *testing.T, f *fixture) { f.deps.Sessions = nil },
			opts:   []passkey.Option{passkey.WithoutSessionRevocationOnClone()},
			assert: refused,
		},
		{
			name: "no session revoker with both revocations off",
			deps: func(_ *testing.T, f *fixture) { f.deps.Sessions = nil },
			opts: []passkey.Option{
				passkey.WithoutSessionRevocationOnRemoval(), passkey.WithoutSessionRevocationOnClone(),
			},
			assert: accepted,
		},
		{
			name:   "nil MFA method entry",
			deps:   func(_ *testing.T, f *fixture) { f.deps.MFAMethods = []policy.MFAMethodLookup{nil} },
			assert: refused,
		},
		{
			name:   "recovery without codes",
			deps:   func(_ *testing.T, f *fixture) { f.deps.Recovery = &passkey.RecoveryDeps{} },
			assert: refused,
		},
		{
			name: "recovery wired",
			deps: func(t *testing.T, f *fixture) {
				f.deps.Recovery = recoveryDeps(t, f, recovery.WayBackDeps{})
			},
			assert: accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			if tc.deps != nil {
				tc.deps(t, f)
			}

			opts := []passkey.Option{passkey.WithClock(f.clock)}
			if !tc.noRepu {
				opts = append(opts, passkey.WithRepudiationContact("help@example.com"))
			}

			m, err := passkey.New(f.deps, append(opts, tc.opts...)...)
			tc.assert(t, m, err)
		})
	}
}

// TestManagerRequiresRecoveryCodes pins what a passwordless login's wiring
// check reads: a manager needs saved codes wired unless they are, or the
// optional mode is chosen.
func TestManagerRequiresRecoveryCodes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		deps   func(t *testing.T, f *fixture)
		opts   []passkey.Option
		assert func(t *testing.T, requires bool)
	}

	cases := []testCase{
		{
			name:   "neither recovery nor the optional mode",
			assert: func(t *testing.T, requires bool) { assert.True(t, requires) },
		},
		{
			name:   "the optional mode",
			opts:   []passkey.Option{passkey.WithOptionalRecoveryCodes()},
			assert: func(t *testing.T, requires bool) { assert.False(t, requires) },
		},
		{
			name: "recovery wired",
			deps: func(t *testing.T, f *fixture) {
				f.deps.Recovery = recoveryDeps(t, f, recovery.WayBackDeps{})
			},
			assert: func(t *testing.T, requires bool) { assert.False(t, requires) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			if tc.deps != nil {
				tc.deps(t, f)
			}

			tc.assert(t, f.manager(t, tc.opts...).RequiresRecoveryCodes())
		})
	}
}

// TestManagerChallengeTTL pins the lifetime a ceremony cookie is given: the
// default, or the consumer's.
func TestManagerChallengeTTL(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []passkey.Option
		assert func(t *testing.T, ttl time.Duration)
	}

	cases := []testCase{
		{
			name:   "default",
			assert: func(t *testing.T, ttl time.Duration) { assert.Equal(t, 5*time.Minute, ttl) },
		},
		{
			name:   "consumer lifetime",
			opts:   []passkey.Option{passkey.WithChallengeTTL(90 * time.Second)},
			assert: func(t *testing.T, ttl time.Duration) { assert.Equal(t, 90*time.Second, ttl) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newFixture(t).manager(t, tc.opts...).ChallengeTTL())
		})
	}
}

// The purposes and subject the manager's challenges are stored under, as its
// godoc names them.
const (
	expiryLoginPurpose        = "passkey-login"
	expiryLoginSubject        = "passkey-login"
	expiryRegistrationPurpose = "passkey-registration"
)

// storedChallenges counts the challenges of purpose and subject still held by
// store, spent or not.
func storedChallenges(t *testing.T, store onetime.Store, purpose, subject string) int {
	t.Helper()

	n, err := store.CountRecentBySubject(t.Context(), purpose, subject, time.Time{})
	require.NoError(t, err)

	return n
}

// expiryTask returns the task of tasks with the given name.
func expiryTask(t *testing.T, tasks []expiry.Task, name string) expiry.Task {
	t.Helper()

	for _, task := range tasks {
		if task.Name == name {
			return task
		}
	}
	require.Failf(t, "no such task", "%q not among the manager's tasks", name)

	return expiry.Task{}
}

// noReapStore hides MemoryStore's Reaper, as a durable store with no purge
// would.
type noReapStore struct{ onetime.Store }

// TestManager_ExpiryTasks uses a run closure rather than assert: each case seeds
// and calls the tasks differently, so no single call shape is shared.
func TestManager_ExpiryTasks(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// run wires a manager over env, seeds challenges, runs its tasks and
		// asserts what is left.
		run func(t *testing.T, env *loginEnv)
	}

	cases := []testCase{
		{
			name: "names in order and no interval",
			run: func(t *testing.T, env *loginEnv) {
				tasks := env.manager(t).ExpiryTasks()

				require.Len(t, tasks, 2)
				assert.Equal(t, "passkey-registration-challenges", tasks[0].Name)
				assert.Equal(t, "passkey-login-challenges", tasks[1].Name)
				for _, task := range tasks {
					assert.Zero(t, task.Interval, task.Name)
					assert.NotNil(t, task.Run, task.Name)
				}
			},
		},
		{
			name: "strangers' expired login challenges go and one inside its window stays",
			run: func(t *testing.T, env *loginEnv) {
				m := env.manager(t)
				// Two passwordless begins, as anyone may make with no session.
				env.begin(t)
				env.begin(t)
				// A third, two minutes on: the inline purge is not yet due.
				env.f.clock.Advance(2 * time.Minute)
				env.begin(t)
				// Six minutes after the first two: they are expired and past
				// their issuance window; the third is expired by neither.
				env.f.clock.Advance(4 * time.Minute)
				require.Equal(t, 3, storedChallenges(t, env.challenges, expiryLoginPurpose, expiryLoginSubject))

				removed, err := expiryTask(t, m.ExpiryTasks(), "passkey-login-challenges").Run(t.Context())

				require.NoError(t, err)
				assert.Equal(t, 2, removed)
				assert.Equal(t, 1, storedChallenges(t, env.challenges, expiryLoginPurpose, expiryLoginSubject))
			},
		},
		{
			name: "each task sweeps only its own ceremony",
			run: func(t *testing.T, env *loginEnv) {
				m := env.manager(t)
				env.begin(t)
				// A registration challenge in the same store, issued by a
				// manager of the registration purpose.
				reg, err := onetime.New(expiryRegistrationPurpose,
					onetime.WithStore(env.challenges), onetime.WithClock(env.f.clock))
				require.NoError(t, err)
				_, _, err = reg.Issue(t.Context(), "u-1")
				require.NoError(t, err)
				// Past both lifetimes and the hour-long registration window.
				env.f.clock.Advance(2 * time.Hour)
				tasks := m.ExpiryTasks()

				removed, err := expiryTask(t, tasks, "passkey-login-challenges").Run(t.Context())
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
				assert.Equal(t, 1, storedChallenges(t, env.challenges, expiryRegistrationPurpose, "u-1"),
					"the login task must not sweep registration challenges")

				removed, err = expiryTask(t, tasks, "passkey-registration-challenges").Run(t.Context())
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
				assert.Zero(t, storedChallenges(t, env.challenges, expiryRegistrationPurpose, "u-1"))
			},
		},
		{
			name: "a challenge store that cannot purge says so",
			run: func(t *testing.T, env *loginEnv) {
				env.f.deps.Challenges = noReapStore{env.challenges}

				for _, task := range env.manager(t).ExpiryTasks() {
					removed, err := task.Run(t.Context())

					require.ErrorIs(t, err, expiry.ErrPurgeUnsupported, task.Name)
					require.ErrorIs(t, err, onetime.ErrReapUnsupported, task.Name)
					assert.Zero(t, removed, task.Name)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.run(t, newLoginEnv(t, nil))
		})
	}
}

func TestManager_LogInterval(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []passkey.Option
		assert func(t *testing.T, d time.Duration)
	}

	cases := []testCase{
		{
			name: "defaults to one minute",
			assert: func(t *testing.T, d time.Duration) {
				assert.Equal(t, time.Minute, d)
			},
		},
		{
			name: "reports the interval WithLogInterval set",
			opts: []passkey.Option{passkey.WithLogInterval(5 * time.Second)},
			assert: func(t *testing.T, d time.Duration) {
				assert.Equal(t, 5*time.Second, d)
			},
		},
		{
			name: "reports an interval that writes every record",
			opts: []passkey.Option{passkey.WithLogInterval(-1)},
			assert: func(t *testing.T, d time.Duration) {
				assert.Equal(t, time.Duration(-1), d)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := newFixture(t).manager(t, tc.opts...)
			tc.assert(t, m.LogInterval())
		})
	}
}

func TestPasskeyLogs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []passkey.Option
		assert func(t *testing.T, e *loginEnv)
	}

	// refuseUnknown runs n begins, each answered from a credential nobody
	// holds.
	refuseUnknown := func(t *testing.T, e *loginEnv, n int) {
		t.Helper()

		for range n {
			_, err := e.m.Authenticate(t.Context(),
				assertion(e.begin(t), func(b *assertionBody) { b.ID = "nobody's key" }), e.binding)
			require.Error(t, err)
		}
	}

	cases := []testCase{
		{
			name: "refusals within one window are written once and the rest reported",
			assert: func(t *testing.T, e *loginEnv) {
				t.Helper()

				refuseUnknown(t, e, 200)
				assert.Equal(t, 1, countRecords(e.logs, "passkey: assertion refused"))

				require.NoError(t, e.m.FlushRefusalLogs())

				var reported []string
				for _, r := range e.logs.records() {
					if strings.Contains(r, `"msg":"passkey: records suppressed"`) {
						reported = append(reported, r)
					}
				}

				require.Len(t, reported, 1)
				assert.Contains(t, reported[0], `"key":"refused|unknown-credential"`)
				assert.Contains(t, reported[0], `"suppressed":199`)
			},
		},
		{
			name: "a log interval of zero writes every record",
			opts: []passkey.Option{passkey.WithLogInterval(0)},
			assert: func(t *testing.T, e *loginEnv) {
				t.Helper()

				refuseUnknown(t, e, 20)
				assert.Equal(t, 20, countRecords(e.logs, "passkey: assertion refused"))
			},
		},
		{
			name: "a log interval replaces the window",
			opts: []passkey.Option{passkey.WithLogInterval(10 * time.Second)},
			assert: func(t *testing.T, e *loginEnv) {
				t.Helper()

				refuseUnknown(t, e, 5)
				e.f.clock.Advance(11 * time.Second)
				refuseUnknown(t, e, 5)
				assert.Equal(t, 2, countRecords(e.logs, "passkey: assertion refused"))
			},
		},
		{
			name: "no record carries a challenge, a key, a handle, a credential ID or an address",
			opts: []passkey.Option{passkey.WithLogInterval(0)},
			assert: func(t *testing.T, e *loginEnv) {
				t.Helper()

				var challenges [][]byte

				// A bad signature.
				c := e.begin(t)
				challenges = append(challenges, []byte(c))
				_, err := e.m.Authenticate(t.Context(), assertion(c, func(b *assertionBody) { b.Sig = "forged" }), e.binding)
				require.Error(t, err)

				// Another user's handle.
				c = e.begin(t)
				challenges = append(challenges, []byte(c))
				_, err = e.m.Authenticate(t.Context(), assertion(c, func(b *assertionBody) { b.Handle = handleU2 }), e.binding)
				require.Error(t, err)

				// A suspected clone, whose notice the queue refuses.
				e.f.mu.Lock()
				e.f.sendErr = errors.New("queue full for ana@example.com")
				e.f.mu.Unlock()

				c = e.begin(t)
				challenges = append(challenges, []byte(c))
				_, err = e.m.Authenticate(t.Context(), assertion(c, func(b *assertionBody) { b.Count = 41 }), e.binding)
				require.ErrorIs(t, err, passkey.ErrCloneSuspected)

				// A wrong binding.
				c = e.begin(t)
				challenges = append(challenges, []byte(c))
				_, err = e.m.Authenticate(t.Context(), assertion(c, nil), "another-browser")
				require.Error(t, err)

				out := e.logs.String()
				require.NotEmpty(t, out)
				assert.Contains(t, out, e.cred.ID.String(), "credentials are named by their library identifier")
				assert.NotContains(t, out, "ana@example.com")
				assert.NotContains(t, out, "queue full")
				assert.NotContains(t, out, e.binding)
				assertNoSecrets(t, out, append(challenges,
					e.cred.PublicKey, e.cred.CredentialID, handleU1, handleU2)...)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newLoginEnv(t, nil)
			e.manager(t, tc.opts...)
			tc.assert(t, e)
		})
	}
}

// TestNew_ConfirmLimiterFactory pins where the emailed-code confirm limiter
// comes from: the factory when one is given, then the in-memory default. The
// explicit limiter of this flow is per call (RegistrationContext.ConfirmLimiter)
// and is pinned where ConfirmEmailCode is.
//
// Standalone from TestNew: its cases build their options from per-case gomock limiters.
func TestNew_ConfirmLimiterFactory(t *testing.T) {
	t.Parallel()

	errFactory := errors.New("factory: backend refused the namespace")

	const user = "u-1"

	type testCase struct {
		name   string
		opts   func(t *testing.T) []passkey.Option
		assert func(t *testing.T, m *passkey.Passkeys, err error)
	}

	// confirm presents a code for user with no per-call limiter, so the
	// Passkeys own limiter answers.
	confirm := func(t *testing.T, m *passkey.Passkeys) error {
		t.Helper()

		_, err := m.ConfirmEmailCode(t.Context(), &session.Session{UserID: user}, "000000",
			passkey.RegistrationContext{})

		return err
	}

	cases := []testCase{
		{
			name: "default builds in-memory",
			opts: func(*testing.T) []passkey.Option { return nil },
			assert: func(t *testing.T, m *passkey.Passkeys, err error) {
				require.NoError(t, err)
				assert.NotErrorIs(t, confirm(t, m), mfa.ErrEnrolmentThrottled,
					"a fresh in-memory limiter has nothing counted yet")
			},
		},
		{
			name: "factory asked with namespace, limit, window",
			opts: func(t *testing.T) []passkey.Option {
				ctrl := gomock.NewController(t)
				built := NewMockLimiter(ctrl)
				built.EXPECT().Exceeded(gomock.Any(), passkey.EmailConfirmThrottleKey(user)).Return(true, nil)

				f := NewMockLimiterFactory(ctrl)
				f.EXPECT().NewLimiter("passkey-email-confirm", 5, 15*time.Minute).Return(built, nil).Times(1)

				return []passkey.Option{passkey.WithConfirmLimiterFactory(f)}
			},
			assert: func(t *testing.T, m *passkey.Passkeys, err error) {
				require.NoError(t, err)
				assert.ErrorIs(t, confirm(t, m), mfa.ErrEnrolmentThrottled,
					"the confirmation is counted through the limiter the factory built")
			},
		},
		{
			name: "nil factory refused",
			opts: func(*testing.T) []passkey.Option {
				return []passkey.Option{passkey.WithConfirmLimiterFactory(nil)}
			},
			assert: func(t *testing.T, m *passkey.Passkeys, err error) {
				require.ErrorIs(t, err, passkey.ErrConfig)
				assert.Nil(t, m)
			},
		},
		{
			name: "typed-nil factory refused",
			opts: func(*testing.T) []passkey.Option {
				return []passkey.Option{passkey.WithConfirmLimiterFactory((*MockLimiterFactory)(nil))}
			},
			assert: func(t *testing.T, m *passkey.Passkeys, err error) {
				require.ErrorIs(t, err, passkey.ErrConfig)
				assert.Nil(t, m)
			},
		},
		{
			name: "factory error fails construction",
			opts: func(t *testing.T) []passkey.Option {
				f := NewMockLimiterFactory(gomock.NewController(t))
				f.EXPECT().NewLimiter("passkey-email-confirm", 5, 15*time.Minute).Return(nil, errFactory)

				return []passkey.Option{passkey.WithConfirmLimiterFactory(f)}
			},
			assert: func(t *testing.T, m *passkey.Passkeys, err error) {
				require.ErrorIs(t, err, passkey.ErrConfig)
				require.ErrorIs(t, err, errFactory)
				assert.Contains(t, err.Error(), `"passkey-email-confirm"`, "the error names the namespace")
				assert.Nil(t, m)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			base := []passkey.Option{passkey.WithClock(f.clock), passkey.WithRepudiationContact("help@example.com")}

			m, err := passkey.New(f.deps, append(base, tc.opts(t)...)...)
			tc.assert(t, m, err)
		})
	}
}

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
			opts:    []passkey.Option{passkey.WithUserVerification(passkey.UserVerificationPreferred)},
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
				s.AuthenticatedAt = s.MFASatisfiedAt

				return s
			},
			rc:     passwordless,
			assert: admitted,
		},
		{
			name: "a renewed session is judged by its authentication time, not its renewal time",
			session: func() *session.Session {
				s := password()
				s.MFA, s.MFASatisfiedAt = session.MFASatisfied, s.CreatedAt.Add(-6*time.Hour)
				s.AuthenticatedAt = s.CreatedAt.Add(-6 * time.Hour)

				return s
			},
			rc:     passwordless,
			assert: refused,
		},
		{
			name: "a session whose authentication time is fresh is admitted",
			session: func() *session.Session {
				s := password()
				s.MFA, s.MFASatisfiedAt = session.MFASatisfied, s.CreatedAt
				s.AuthenticatedAt = s.CreatedAt

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
