package httpsec_test

//go:generate mockgen -destination=userprovisioner_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/identity UserProvisioner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

// The password the user "ada" really has in these cases, and the cost of the
// hash she is stored with and the one the chain's encoder now asks for.
const (
	rehashPassword  = "correct-horse-battery-staple"
	rehashOldMemory = 19 * 1024
	rehashNewMemory = 46 * 1024
)

var errRehashStore = errors.New("rehash store down, dsn=postgres://secret")

// countingEncoder is the chain's current encoder, counting every Encode. It is
// an Argon2id encoder underneath, so it recognises and upgrades hashes as the
// built-in does.
type countingEncoder struct {
	*password.Argon2idEncoder

	mu      sync.Mutex
	encodes int
}

func (c *countingEncoder) Encode(in string) ([]byte, error) {
	c.mu.Lock()
	c.encodes++
	c.mu.Unlock()

	return c.Argon2idEncoder.Encode(in)
}

func (c *countingEncoder) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.encodes
}

// rehashCall is what a rehash write was handed.
type rehashCall struct {
	user              *identity.Details
	replaced, renewed []byte
}

// rehashRecorder is a rehash write that records its calls and answers err.
type rehashRecorder struct {
	mu    sync.Mutex
	calls []rehashCall
	err   error
}

func (r *rehashRecorder) write(_ context.Context, user *identity.Details, replaced, upgraded []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls = append(r.calls, rehashCall{user: user, replaced: replaced, renewed: upgraded})

	return r.err
}

func (r *rehashRecorder) recorded() []rehashCall {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]rehashCall(nil), r.calls...)
}

// rehashRig is a real password provider over a user store that holds ada under
// an old, cheaper hash, with the chain's encoder at a higher cost.
type rehashRig struct {
	h        *authHarness
	enc      *countingEncoder
	provider *authenticate.UsernamePasswordAuthenticator
	stored   []byte
	logs     *bytes.Buffer
}

func newRehashRig(t *testing.T, storedMemory uint32) *rehashRig {
	t.Helper()

	old, err := password.NewArgon2idEncoder(password.WithArgon2idMemory(storedMemory), password.WithArgon2idIterations(2))
	require.NoError(t, err)

	current, err := password.NewArgon2idEncoder(password.WithArgon2idMemory(rehashNewMemory), password.WithArgon2idIterations(2))
	require.NoError(t, err)

	stored, err := old.Encode(rehashPassword)
	require.NoError(t, err)

	h := newAuthHarness(t)
	h.users.EXPECT().LoadByUsername(gomock.Any(), "ada").AnyTimes().
		DoAndReturn(func(context.Context, string) (*identity.Details, error) {
			return &identity.Details{
				ID: "u-1", Username: "ada", Name: "Ada Lovelace", Password: bytes.Clone(stored), Active: true,
			}, nil
		})

	enc := &countingEncoder{Argon2idEncoder: current}
	logs := &bytes.Buffer{}

	provider, err := authenticate.NewUsernamePasswordAuthenticator(h.users,
		authenticate.WithPasswordEncoder(enc),
		authenticate.WithPasswordLogger(slog.New(slog.NewTextHandler(logs, nil))))
	require.NoError(t, err)

	return &rehashRig{h: h, enc: enc, provider: provider, stored: stored, logs: logs}
}

// deps is the authentication every surface is wired to.
func (r *rehashRig) loginDeps() httpsec.FormLoginDeps {
	d := r.h.formLoginDeps()
	d.Authenticator = r.provider

	return d
}

func (r *rehashRig) basicDeps() httpsec.BasicAuthDeps {
	return httpsec.BasicAuthDeps{Authenticator: r.provider, Attempts: r.h.attempts}
}

// chainLogs is every record the chain wrote, as text.
func (r *rehashRig) chainLogs() string {
	var b strings.Builder

	for _, rec := range r.h.logs.records() {
		b.WriteString(rec.Message)
		rec.Attrs(func(a slog.Attr) bool {
			fmt.Fprintf(&b, " %s=%s", a.Key, a.Value)

			return true
		})
		b.WriteString("\n")
	}

	return b.String() + r.logs.String()
}

func TestLogin_Rehash(t *testing.T) {
	t.Parallel()

	type surface struct {
		name string
		// outcome is what the surface does with a login that verified and one
		// that did not, so a case can name either.
		run func(t *testing.T, r *rehashRig, rehash httpsec.RehashFunc, pw string, extra ...httpsec.Option) served
		// expectSuccess wires what a verified request reaches on this surface.
		expectSuccess func(r *rehashRig)
		// success asserts a request that verified was not refused.
		success func(t *testing.T, out served)
	}

	surfaces := []surface{
		{
			name: "form login",
			run: func(t *testing.T, r *rehashRig, rehash httpsec.RehashFunc, pw string, extra ...httpsec.Option) served {
				t.Helper()

				var opts []httpsec.LoginOption
				if rehash != nil {
					opts = append(opts, httpsec.WithLoginRehash(rehash))
				}

				chain, err := httpsec.New(append([]httpsec.Option{
					httpsec.WithLogger(r.h.logger()),
					httpsec.EnableFormLogin(r.loginDeps(), opts...),
				}, extra...)...)
				require.NoError(t, err)

				return serve(t, chain, formRequest(t.Context(), "/login", "username=ada&password="+pw))
			},
			expectSuccess: func(r *rehashRig) {
				r.h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				r.h.expectSessionOpened("issued-token")
			},
			success: func(t *testing.T, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
		{
			name: "Basic",
			run: func(t *testing.T, r *rehashRig, rehash httpsec.RehashFunc, pw string, extra ...httpsec.Option) served {
				t.Helper()

				var opts []httpsec.BasicAuthOption
				if rehash != nil {
					opts = append(opts, httpsec.WithBasicAuthRehash(rehash))
				}

				chain, err := httpsec.New(append([]httpsec.Option{
					httpsec.WithLogger(r.h.logger()),
					httpsec.EnableBasicAuth(r.basicDeps(), opts...),
				}, extra...)...)
				require.NoError(t, err)

				return serve(t, chain, basicRequest(t.Context(), "ada", pw))
			},
			expectSuccess: func(r *rehashRig) {
				r.h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
			},
			success: func(t *testing.T, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
			},
		},
	}

	type testCase struct {
		name         string
		storedMemory uint32
		password     string
		failing      bool
		assert       func(t *testing.T, s surface, r *rehashRig, rec *rehashRecorder, out served)
	}

	cases := []testCase{
		{
			name:         "Raised cost: the write receives the old hash it replaces and a new one at the current cost",
			storedMemory: rehashOldMemory,
			password:     rehashPassword,
			assert: func(t *testing.T, s surface, r *rehashRig, rec *rehashRecorder, out served) {
				t.Helper()

				s.success(t, out)

				calls := rec.recorded()
				require.Len(t, calls, 1, "the outdated hash was not handed to the write exactly once")
				assert.Equal(t, r.stored, calls[0].replaced)
				assert.Equal(t, "ada", calls[0].user.Username)
				assert.Equal(t, identity.UserID("u-1"), calls[0].user.ID)
				assert.True(t, strings.HasPrefix(string(calls[0].renewed),
					fmt.Sprintf("argon2id$%d$2$", rehashNewMemory)), "the new hash is not at the current cost")
				assert.True(t, r.enc.Match(rehashPassword, calls[0].renewed), "the new hash does not verify the password")
			},
		},
		{
			name:         "A hash already at the current cost is left alone",
			storedMemory: rehashNewMemory,
			password:     rehashPassword,
			assert: func(t *testing.T, s surface, r *rehashRig, rec *rehashRecorder, out served) {
				t.Helper()

				s.success(t, out)
				assert.Empty(t, rec.recorded())
				assert.Equal(t, 1, r.enc.count(), "a current hash must cost no extra derivation")
			},
		},
		{
			name:         "Wrong password: the write is not called and nothing is encoded",
			storedMemory: rehashOldMemory,
			password:     "not-the-password",
			assert: func(t *testing.T, _ surface, r *rehashRig, rec *rehashRecorder, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				assert.Empty(t, rec.recorded())
				assert.Equal(t, 1, r.enc.count(), "only the reference hash was encoded")
			},
		},
		{
			name:         "Write fails: the request still succeeds and the record carries no hash",
			storedMemory: rehashOldMemory,
			password:     rehashPassword,
			failing:      true,
			assert: func(t *testing.T, s surface, r *rehashRig, rec *rehashRecorder, out served) {
				t.Helper()

				s.success(t, out)
				require.Len(t, rec.recorded(), 1)

				logs := r.chainLogs()
				assert.Contains(t, logs, "could not be stored")
				assert.Contains(t, logs, "rehash-write")
				assert.NotContains(t, logs, string(r.stored), "the replaced hash reached a log")
				assert.NotContains(t, logs, string(rec.recorded()[0].renewed), "the new hash reached a log")
				assert.NotContains(t, logs, rehashPassword)
				assert.NotContains(t, logs, "secret", "the write's error text reached a log")
			},
		},
	}

	for _, sf := range surfaces {
		for _, tc := range cases {
			t.Run(sf.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				r := newRehashRig(t, tc.storedMemory)
				rec := &rehashRecorder{}
				if tc.failing {
					rec.err = errRehashStore
				}

				if tc.password == rehashPassword {
					sf.expectSuccess(r)
				} else {
					r.h.attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).Return(nil)
				}

				out := sf.run(t, r, rec.write, tc.password)
				tc.assert(t, sf, r, rec, out)
			})
		}

		t.Run(sf.name+"/No write configured: nothing is encoded", func(t *testing.T) {
			t.Parallel()

			r := newRehashRig(t, rehashOldMemory)
			sf.expectSuccess(r)

			out := sf.run(t, r, nil, rehashPassword)

			sf.success(t, out)
			assert.Equal(t, 1, r.enc.count(), "a password was encoded although no write was configured")
		})
	}

	t.Run("form login/Challenged for a second factor: the write is still called", func(t *testing.T) {
		t.Parallel()

		r := newRehashRig(t, rehashOldMemory)
		rec := &rehashRecorder{}
		r.h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
		r.h.expectSessionOpened("issued-token")

		chain, err := httpsec.New(
			httpsec.WithLogger(r.h.logger()),
			httpsec.EnableFormLogin(r.loginDeps(), httpsec.WithLoginRehash(rec.write)),
			httpsec.WithPolicyEngine(challengingIn(t, policy.PostAuthentication, policy.ChallengeMFA)),
			httpsec.EnableGateForTest(policy.ChallengeMFA),
		)
		require.NoError(t, err)

		out := serve(t, chain, formRequest(t.Context(), "/login", "username=ada&password="+rehashPassword))

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch, "the login was challenged")
		require.Len(t, rec.recorded(), 1, "a challenged login still upgrades the hash")
		assert.Equal(t, r.stored, rec.recorded()[0].replaced)
	})

	t.Run("form login/A login refused after the password verified does not upgrade", func(t *testing.T) {
		t.Parallel()

		r := newRehashRig(t, rehashOldMemory)
		rec := &rehashRecorder{}
		r.h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)

		chain, err := httpsec.New(
			httpsec.WithLogger(r.h.logger()),
			httpsec.EnableFormLogin(r.loginDeps(), httpsec.WithLoginRehash(rec.write)),
			httpsec.WithPolicyEngine(denyingIn(t, policy.PostAuthentication, policy.ErrTooManySessions)),
		)
		require.NoError(t, err)

		out := serve(t, chain, formRequest(t.Context(), "/login", "username=ada&password="+rehashPassword))

		require.ErrorIs(t, out.err, policy.ErrTooManySessions)
		assert.Empty(t, rec.recorded())
	})
}

// TestLogin_RehashBasicRefusedAfterVerify pins that a Basic request whose
// password verified but which the stateless phase then refused upgrades
// nothing: Basic has no later request in which a challenge is answered, so a
// challenge refuses it as a denial does.
func TestLogin_RehashBasicRefusedAfterVerify(t *testing.T) {
	t.Parallel()

	errBasicDenied := errors.New("rehash_test: basic denied by policy")

	type testCase struct {
		name   string
		engine func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, out served)
	}

	cases := []testCase{
		{
			name: "denied after the password verified",
			engine: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithPolicyEngine(denyingIn(t, policy.StatelessAuthentication, errBasicDenied)),
				}
			},
			assert: func(t *testing.T, out served) { require.ErrorIs(t, out.err, errBasicDenied) },
		},
		{
			name: "challenged after the password verified",
			engine: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableGateForTest(policy.ChallengeMFA),
					httpsec.WithPolicyEngine(challengingIn(t, policy.StatelessAuthentication, policy.ChallengeMFA)),
				}
			},
			assert: func(t *testing.T, out served) {
				var ce *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ce)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRehashRig(t, rehashOldMemory)
			rec := &rehashRecorder{}
			r.h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)

			chain, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithLogger(r.h.logger()),
				httpsec.EnableBasicAuth(r.basicDeps(), httpsec.WithBasicAuthRehash(rec.write)),
			}, tc.engine(t)...)...)
			require.NoError(t, err)

			out := serve(t, chain, basicRequest(t.Context(), "ada", rehashPassword))

			tc.assert(t, out)
			assert.False(t, out.handlerRan)
			assert.Empty(t, rec.recorded(), "a Basic request refused after its password verified upgraded the hash")
		})
	}
}

func TestLogin_RehashOptionsRefuseNil(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// build constructs a chain whose only fault is the nil write.
		build  func(t *testing.T) error
		assert func(t *testing.T, err error)
	}

	refused := func(option string) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.ErrorContains(t, err, option, "the refusal names the option given no write")
		}
	}

	cases := []testCase{
		{
			name: "form login",
			build: func(t *testing.T) error {
				h := newAuthHarness(t)
				_, err := httpsec.New(httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginRehash(nil)))
				return err
			},
			assert: refused("WithLoginRehash"),
		},
		{
			name: "Basic",
			build: func(t *testing.T) error {
				h := newAuthHarness(t)
				_, err := httpsec.New(httpsec.EnableBasicAuth(h.basicAuthDeps(), httpsec.WithBasicAuthRehash(nil)))
				return err
			},
			assert: refused("WithBasicAuthRehash"),
		},
		{
			name: "re-proof",
			build: func(t *testing.T) error {
				h := newReauthHarness(t)
				h.reauthOpts = []httpsec.ReauthenticationOption{httpsec.WithReauthenticationRehash(nil)}
				_, err := h.build(nil)
				return err
			},
			assert: refused("WithReauthenticationRehash"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.build(t))
		})
	}
}

// conditionalStore stands in for an identity store that decides a password
// condition in the write itself: its Update compares the expected hash with the
// one it holds, under its own lock, as the shipped stores' UPDATE ... WHERE
// does.
type conditionalStore struct {
	mu     sync.Mutex
	stored []byte
}

func (s *conditionalStore) set(hash []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stored = bytes.Clone(hash)
}

func (s *conditionalStore) current() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	return bytes.Clone(s.stored)
}

func (s *conditionalStore) update(_ context.Context, _ string, opts ...identity.UserOption) (*identity.Details, error) {
	change := identity.ApplyUserOptions(opts...)

	s.mu.Lock()
	defer s.mu.Unlock()

	if expected, ok := change.ExpectedPassword(); ok && !bytes.Equal(expected, s.stored) {
		return nil, identity.ErrNotUpdated
	}

	if change.IsSet(identity.FieldPassword) {
		s.stored = bytes.Clone(change.Password)
	}

	return &identity.Details{ID: "u-1", Username: "ada", Password: bytes.Clone(s.stored)}, nil
}

func TestLogin_RehashConditionalWriteKeepsAConcurrentChange(t *testing.T) {
	t.Parallel()

	changed := []byte("argon2id$47104$2$a$b-changed-meanwhile")

	type testCase struct {
		name string
		// changeBeforeWrite commits a password change after the login verified
		// the old password and before the write runs.
		changeBeforeWrite bool
		assert            func(t *testing.T, r *rehashRig, stored []byte)
	}

	cases := []testCase{
		{
			name:              "a password change landed after the login verified: the new hash stays",
			changeBeforeWrite: true,
			assert: func(t *testing.T, _ *rehashRig, stored []byte) {
				assert.Equal(t, changed, stored,
					"the ready-made write overwrote a password changed meanwhile, putting the old one back")
			},
		},
		{
			name: "nothing changed: the upgraded hash is stored",
			assert: func(t *testing.T, r *rehashRig, stored []byte) {
				assert.NotEqual(t, r.stored, stored, "the outdated hash was not replaced")
				assert.True(t, r.enc.Match(rehashPassword, stored), "the stored hash must verify the same password")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRehashRig(t, rehashOldMemory)
			r.h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
			r.h.expectSessionOpened("issued-token")

			store := &conditionalStore{stored: bytes.Clone(r.stored)}

			// One call to the store and no reload: the provisioner is the whole
			// store the write is given, and it is written once.
			prov := NewMockUserProvisioner(gomock.NewController(t))
			prov.EXPECT().Update(gomock.Any(), "ada", gomock.Any()).DoAndReturn(store.update).Times(1)

			conditional := password.ConditionalProvisionerRehash(prov)
			write := func(ctx context.Context, user *identity.Details, replaced, upgraded []byte) error {
				if tc.changeBeforeWrite {
					store.set(changed)
				}

				err := conditional(ctx, user, replaced, upgraded)
				assert.NoError(t, err, "a concurrent change is not a write failure")

				return err
			}

			chain, err := httpsec.New(
				httpsec.WithLogger(r.h.logger()),
				httpsec.EnableFormLogin(r.loginDeps(), httpsec.WithLoginRehash(write)),
			)
			require.NoError(t, err)

			out := serve(t, chain, formRequest(t.Context(), "/login", "username=ada&password="+rehashPassword))
			require.NoError(t, out.err)
			assert.Equal(t, http.StatusOK, out.rec.Code, "the login still succeeds")
			tc.assert(t, r, store.current())
		})
	}
}
