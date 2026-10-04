package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// The source and the password every password-login guard test logs in with.
const (
	loginGuardSource = "203.0.113.7"

	//nolint:gosec // G101: a fixture password, not a credential
	loginGuardRightPassword = "right horse battery"
)

// passwordLoginNamespace is the flow and factory namespace the login guard is
// built under.
const passwordLoginNamespace = "password-login"

// loginGuardHarness is a chain with form login and Basic both enabled over one
// authenticator, counting what reached the authenticator and the
// pre-authentication phase, so a row can say a refused request reached
// neither.
type loginGuardHarness struct {
	authn    *MockAuthenticator
	attempts *policy.MemoryAttemptStore
	sessions *session.Manager
	tokens   *MockGenerator
	logs     *capturingHandler

	authnCalls   atomic.Int64
	preAuthCalls atomic.Int64

	// lockout, when set, is registered beside the counting policy.
	lockout policy.Policy

	mu       sync.Mutex
	reported map[string]int
}

func newLoginGuardHarness(t *testing.T) *loginGuardHarness {
	t.Helper()

	ctrl := gomock.NewController(t)
	h := &loginGuardHarness{
		authn:    NewMockAuthenticator(ctrl),
		attempts: policy.NewMemoryAttemptStore(),
		tokens:   NewMockGenerator(ctrl),
		logs:     &capturingHandler{},
		reported: map[string]int{},
	}

	store := NewMockStore(ctrl)
	store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	sessions, err := session.NewManager(session.WithStore(store))
	require.NoError(t, err)

	h.sessions = sessions

	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("tok", nil).AnyTimes()

	// The right password authenticates as the submitted user; any other is
	// refused, as a password provider refuses it.
	h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, c identity.Credentials) (*authenticate.Authentication, error) {
			h.authnCalls.Add(1)

			creds, ok := c.(*identity.UsernamePassword)
			if !ok || string(creds.Password) != loginGuardRightPassword {
				return nil, authenticate.ErrAuthenticationFailed
			}

			return &authenticate.Authentication{
				Principal: &identity.Principal{ID: identity.UserID("id-" + creds.Username), Username: creds.Username},
				Time:      time.Now(),
			}, nil
		}).AnyTimes()

	return h
}

// engine is the policy engine the chain judges by: a pre-authentication
// policy that counts and allows, and the lockout when the row set one.
func (h *loginGuardHarness) engine(t *testing.T) *policy.Engine {
	t.Helper()

	counter := NewMockPolicy(gomock.NewController(t))
	counter.EXPECT().Name().Return("test: counts pre-authentication").AnyTimes()
	counter.EXPECT().Phases().Return([]policy.Phase{policy.PreAuthentication}).AnyTimes()
	counter.EXPECT().Evaluate(gomock.Any(), gomock.Any()).DoAndReturn(
		func(context.Context, *policy.Input) policy.Decision {
			h.preAuthCalls.Add(1)

			return policy.Decision{Outcome: policy.Allow}
		}).AnyTimes()

	policies := []policy.Policy{counter}
	if h.lockout != nil {
		policies = append(policies, h.lockout)
	}

	return engineOf(t, policies...)
}

// chain builds form login and Basic over the harness, with opts applied last.
func (h *loginGuardHarness) chain(
	t *testing.T,
	loginOpts []httpsec.LoginOption,
	basicOpts []httpsec.BasicAuthOption,
	opts ...httpsec.Option,
) *httpsec.Chain {
	t.Helper()

	c, err := httpsec.New(append([]httpsec.Option{
		httpsec.WithLogger(slog.New(h.logs)),
		httpsec.WithRefusalLogReporter(h.report),
		httpsec.WithPolicyEngine(h.engine(t)),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: h.authn,
			Sessions:      h.sessions,
			Tokens:        h.tokens,
			Attempts:      h.attempts,
		}, loginOpts...),
		httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: h.authn, Attempts: h.attempts}, basicOpts...),
	}, opts...)...)
	require.NoError(t, err)

	return c
}

func (h *loginGuardHarness) report(key string, suppressed int) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.reported[key] += suppressed
}

func (h *loginGuardHarness) reportedFor(key string) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.reported[key]
}

// fromSource sends req as if from addr; an empty addr is a request with no
// client address at all.
func fromSource(req *http.Request, addr string) *http.Request {
	req.RemoteAddr = ""
	if addr != "" {
		req.RemoteAddr = net.JoinHostPort(addr, "51000")
	}

	return req
}

// formLoginFrom posts a form login for username from the guard test's source.
func formLoginFrom(t *testing.T, c *httpsec.Chain, addr, username, password string) served {
	t.Helper()

	return serve(t, c, fromSource(formRequest(t.Context(), httpsec.DefaultLoginPath,
		"username="+username+"&password="+password), addr))
}

// basicFrom sends a Basic credential for username from addr.
func basicFrom(t *testing.T, c *httpsec.Chain, addr, username, password string) served {
	t.Helper()

	return serve(t, c, fromSource(basicRequest(t.Context(), username, password), addr))
}

// failForm makes n failed form logins, each for its own username, and
// requires that none was throttled.
func failForm(t *testing.T, c *httpsec.Chain, n int, prefix string) {
	t.Helper()

	for i := range n {
		out := formLoginFrom(t, c, loginGuardSource, fmt.Sprintf("%s%d", prefix, i+1), "wrong")
		require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "failure %d", i+1)
		require.NotErrorIs(t, out.err, ratelimit.ErrThrottled, "failure %d is within the allowance", i+1)
	}
}

// failBasic makes n failed Basic attempts and requires that none was
// throttled.
func failBasic(t *testing.T, c *httpsec.Chain, n int) {
	t.Helper()

	for i := range n {
		out := basicFrom(t, c, loginGuardSource, fmt.Sprintf("basic%d", i+1), "wrong")
		require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "Basic failure %d", i+1)
		require.NotErrorIs(t, out.err, ratelimit.ErrThrottled, "Basic failure %d is within the allowance", i+1)
	}
}

// memLimiter is an in-memory limiter allowing limit failures per window.
func memLimiter(t *testing.T, limit int, window time.Duration) ratelimit.Limiter {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(limit, window,
		ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)

	return l
}

// requireThrottled requires a refusal as a throttled source, answered 401.
func requireThrottled(t *testing.T, out served) {
	t.Helper()

	require.ErrorIs(t, out.err, ratelimit.ErrThrottled)
	assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
	assert.False(t, out.handlerRan)
}

// TestChain_PasswordLoginGuard pins the password-login source guard form login
// and Basic share: what spends the allowance, what does not, where the check
// sits, and what a refusal carries.
func TestChain_PasswordLoginGuard(t *testing.T) {
	t.Parallel()

	type counts struct{ authn, preAuth int64 }

	type testCase struct {
		name      string
		arrange   func(t *testing.T, h *loginGuardHarness)
		loginOpts func(t *testing.T) []httpsec.LoginOption
		basicOpts func(t *testing.T) []httpsec.BasicAuthOption
		// act runs everything before the request under test, and returns the
		// counts at that point, then the outcome of that request.
		act    func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served)
		assert func(t *testing.T, h *loginGuardHarness, before counts, out served)
	}

	snapshot := func(h *loginGuardHarness) counts {
		return counts{authn: h.authnCalls.Load(), preAuth: h.preAuthCalls.Load()}
	}

	cases := []testCase{
		{
			name: "spraying one password across 50 accounts throttles the 51st",
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				failForm(t, c, 50, "user")
				before := snapshot(h)

				return before, formLoginFrom(t, c, loginGuardSource, "user51", "wrong")
			},
			assert: func(t *testing.T, h *loginGuardHarness, before counts, out served) {
				requireThrottled(t, out)
				assert.Equal(t, before, snapshot(h),
					"neither the pre-authentication phase nor the password is evaluated")
			},
		},
		{
			name: "form login and Basic share one allowance",
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				failForm(t, c, 30, "user")
				failBasic(t, c, 20)

				return snapshot(h), formLoginFrom(t, c, loginGuardSource, "next", "wrong")
			},
			assert: func(t *testing.T, _ *loginGuardHarness, _ counts, out served) {
				requireThrottled(t, out)
			},
		},
		{
			name: "successes spend nothing",
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				for i := range 100 {
					out := formLoginFrom(t, c, loginGuardSource, fmt.Sprintf("ok%d", i), loginGuardRightPassword)
					require.NoError(t, out.err, "success %d", i+1)
				}

				failForm(t, c, 49, "user")

				return snapshot(h), formLoginFrom(t, c, loginGuardSource, "user50", "wrong")
			},
			assert: func(t *testing.T, _ *loginGuardHarness, _ counts, out served) {
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				assert.NotErrorIs(t, out.err, ratelimit.ErrThrottled, "the 50th failure is still within the allowance")
			},
		},
		{
			name: "locked-account refusals count against the source",
			arrange: func(t *testing.T, h *loginGuardHarness) {
				lockout, err := policy.NewAccountLockoutPolicy(
					policy.WithAttemptStore(h.attempts), policy.WithFixedLockout(1, time.Hour))
				require.NoError(t, err)

				h.lockout = lockout
				require.NoError(t, h.attempts.RecordFailure(t.Context(), "ada", time.Now()))
			},
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				for i := range 50 {
					out := formLoginFrom(t, c, loginGuardSource, "ada", loginGuardRightPassword)
					require.ErrorIs(t, out.err, policy.ErrAccountLocked, "locked refusal %d", i+1)
					require.NotErrorIs(t, out.err, ratelimit.ErrThrottled, "locked refusal %d", i+1)
				}

				return snapshot(h), formLoginFrom(t, c, loginGuardSource, "bob", loginGuardRightPassword)
			},
			assert: func(t *testing.T, h *loginGuardHarness, before counts, out served) {
				requireThrottled(t, out)
				assert.Zero(t, h.authnCalls.Load(), "a locked account's password is never checked")
				assert.Equal(t, before, snapshot(h))
			},
		},
		{
			name: "a consumer limiter for form login leaves Basic on the default",
			loginOpts: func(t *testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{httpsec.WithLoginLimiter(memLimiter(t, 10, 15*time.Minute))}
			},
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				failForm(t, c, 10, "user")
				requireThrottled(t, formLoginFrom(t, c, loginGuardSource, "user11", "wrong"))

				return snapshot(h), basicFrom(t, c, loginGuardSource, "ada", "wrong")
			},
			assert: func(t *testing.T, _ *loginGuardHarness, _ counts, out served) {
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				assert.NotErrorIs(t, out.err, ratelimit.ErrThrottled,
					"Basic counts against the default limiter, which the form failures did not touch")
			},
		},
		{
			name: "a consumer limiter for Basic leaves form login on the default",
			basicOpts: func(t *testing.T) []httpsec.BasicAuthOption {
				return []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter(memLimiter(t, 1, time.Minute))}
			},
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				failBasic(t, c, 1)
				requireThrottled(t, basicFrom(t, c, loginGuardSource, "ada", "wrong"))

				return snapshot(h), formLoginFrom(t, c, loginGuardSource, "ada", "wrong")
			},
			assert: func(t *testing.T, _ *loginGuardHarness, _ counts, out served) {
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				assert.NotErrorIs(t, out.err, ratelimit.ErrThrottled)
			},
		},
		{
			name: "an unattributable source is refused before the password is evaluated",
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				return snapshot(h), formLoginFrom(t, c, "", "ada", loginGuardRightPassword)
			},
			assert: func(t *testing.T, h *loginGuardHarness, before counts, out served) {
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				assert.Equal(t, before, snapshot(h),
					"neither the pre-authentication phase nor the password is evaluated")

				rec, ok := recordAt(h.logs.records(), slog.LevelError,
					"httpsec: refusing a request whose client address cannot be attributed")
				require.True(t, ok, "the unattributable refusal is recorded")

				flow, _ := attrValue(rec, "flow")
				assert.Equal(t, passwordLoginNamespace, flow.String())
			},
		},
		{
			name: "a throttled Basic source is still challenged",
			basicOpts: func(t *testing.T) []httpsec.BasicAuthOption {
				return []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter(memLimiter(t, 1, time.Minute))}
			},
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				failBasic(t, c, 1)

				return snapshot(h), basicFrom(t, c, loginGuardSource, "ada", loginGuardRightPassword)
			},
			assert: func(t *testing.T, h *loginGuardHarness, before counts, out served) {
				requireThrottled(t, out)
				assert.Equal(t, `Basic realm="Restricted"`, out.rec.Header().Get("WWW-Authenticate"))
				assert.Equal(t, before, snapshot(h))
			},
		},
		{
			name: "a malformed Basic header is refused before the guard is consulted",
			basicOpts: func(t *testing.T) []httpsec.BasicAuthOption {
				// A strict double with no expectations: any Exceeded or
				// RecordFailure call fails the row.
				return []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter(NewMockLimiter(gomock.NewController(t)))}
			},
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				return snapshot(h), serve(t, c, fromSource(rawBasicRequest(t.Context(), "Basic !!!"), loginGuardSource))
			},
			assert: func(t *testing.T, h *loginGuardHarness, before counts, out served) {
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				assert.Equal(t, `Basic realm="Restricted"`, out.rec.Header().Get("WWW-Authenticate"))
				assert.Equal(t, before, snapshot(h))
			},
		},
		{
			name: "the guard's held-back throttle records are flushed with the chain's",
			loginOpts: func(t *testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{httpsec.WithLoginLimiter(memLimiter(t, 1, time.Minute))}
			},
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				failForm(t, c, 1, "user")

				var last served
				for range 3 {
					last = formLoginFrom(t, c, loginGuardSource, "ada", "wrong")
					requireThrottled(t, last)
				}

				c.FlushRefusalLogs()

				return snapshot(h), last
			},
			assert: func(t *testing.T, h *loginGuardHarness, _ counts, _ served) {
				assert.Equal(t, 2, h.reportedFor("throttled:"+passwordLoginNamespace+":"+loginGuardSource),
					"the first throttle is written, the other two are held back and reported by the flush")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newLoginGuardHarness(t)
			if tc.arrange != nil {
				tc.arrange(t, h)
			}

			var (
				loginOpts []httpsec.LoginOption
				basicOpts []httpsec.BasicAuthOption
			)

			if tc.loginOpts != nil {
				loginOpts = tc.loginOpts(t)
			}

			if tc.basicOpts != nil {
				basicOpts = tc.basicOpts(t)
			}

			c := h.chain(t, loginOpts, basicOpts)

			before, out := tc.act(t, h, c)
			tc.assert(t, h, before, out)
		})
	}
}

// TestChain_PasswordLoginFactoryNamespace pins that the chain's factory is
// asked once for the password-login limiter, with its default limit and
// window, however many endpoints share it.
//
// The factory records every call and builds each in memory: other limiters
// the chain may ask for are not this test's concern, so it looks the
// password-login call up rather than counting every call.
func TestChain_PasswordLoginFactoryNamespace(t *testing.T) {
	t.Parallel()

	var (
		mu    sync.Mutex
		asked []limiterAsked
	)

	memory := ratelimit.MemoryLimiterFactory(
		ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))

	f := NewMockLimiterFactory(gomock.NewController(t))
	f.EXPECT().NewLimiter(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(namespace string, limit int, window time.Duration) (ratelimit.Limiter, error) {
			mu.Lock()
			asked = append(asked, limiterAsked{namespace, limit, window})
			mu.Unlock()

			return memory.NewLimiter(namespace, limit, window)
		}).AnyTimes()

	h := newLoginGuardHarness(t)
	h.chain(t, nil, nil, httpsec.WithRateLimiterFactory(f))

	mu.Lock()
	defer mu.Unlock()

	var login []limiterAsked

	for _, a := range asked {
		if a.namespace == passwordLoginNamespace {
			login = append(login, a)
		}
	}

	require.Len(t, login, 1, "form login and Basic share one limiter, asked for once")
	assert.Equal(t, limiterAsked{passwordLoginNamespace, 50, 15 * time.Minute}, login[0])
}

// TestChain_PasswordLoginLimiterOptions pins that an endpoint's own limiter
// must be a limiter: a nil one, typed nil included, is a configuration error
// naming the option.
func TestChain_PasswordLoginLimiterOptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		loginOpts []httpsec.LoginOption
		basicOpts []httpsec.BasicAuthOption
		assert    func(t *testing.T, c *httpsec.Chain, err error)
	}

	refusedNaming := func(option string) func(t *testing.T, c *httpsec.Chain, err error) {
		return func(t *testing.T, c *httpsec.Chain, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), option, "the error names the option to change")
			assert.Nil(t, c)
		}
	}

	cases := []testCase{
		{
			name:      "nil login limiter",
			loginOpts: []httpsec.LoginOption{httpsec.WithLoginLimiter(nil)},
			assert:    refusedNaming("WithLoginLimiter"),
		},
		{
			name:      "typed-nil Basic limiter",
			basicOpts: []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter((*ratelimit.MemoryLimiter)(nil))},
			assert:    refusedNaming("WithBasicAuthLimiter"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newLoginGuardHarness(t)

			c, err := httpsec.New(
				httpsec.WithLogger(slog.New(slog.DiscardHandler)),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
				}, tc.loginOpts...),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: h.authn, Attempts: h.attempts},
					tc.basicOpts...),
			)
			tc.assert(t, c, err)
		})
	}
}

// The guess presented for a locked account, and the reference hash the
// password provider is built with, so a row can say which hash a password was
// verified against.
const lockedGuess = "a guess at a locked account"

var lockReferenceHash = []byte("reference-hash")

// errPreAuthStoreDown is a pre-authentication deny that is not a lock.
var errPreAuthStoreDown = errors.New("test: attempt store unavailable")

// lockResponseHarness is a chain whose pre-authentication phase denies ada,
// over an authenticator that is either a Manager over the password provider,
// whose encoder and user loader are strict doubles, or a bare Authenticator
// offering no decoy.
type lockResponseHarness struct {
	enc   *MockEncoder
	users *MockUserLoader
	authn authenticate.Authenticator
	logs  *capturingHandler
}

// newLockResponseHarness builds the authenticator. With decoy, the password
// provider's reference hash is built once at construction; every row says how
// often it expects Match.
func newLockResponseHarness(t *testing.T, decoy bool) *lockResponseHarness {
	t.Helper()

	ctrl := gomock.NewController(t)
	h := &lockResponseHarness{
		enc:   NewMockEncoder(ctrl),
		users: NewMockUserLoader(ctrl),
		logs:  &capturingHandler{},
	}

	if !decoy {
		h.authn = NewMockAuthenticator(ctrl)

		return h
	}

	h.enc.EXPECT().Encode(gomock.Any()).Return(lockReferenceHash, nil).Times(1)

	provider, err := authenticate.NewUsernamePasswordAuthenticator(h.users,
		authenticate.WithPasswordEncoder(h.enc),
		authenticate.WithPasswordAuthenticatorLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)

	m, err := authenticate.NewManager(provider)
	require.NoError(t, err)

	h.authn = m

	return h
}

// chain builds form login and Basic over the harness's authenticator, judged
// by engine, with opts applied last.
func (h *lockResponseHarness) chain(t *testing.T, engine *policy.Engine, opts ...httpsec.Option) (*httpsec.Chain, error) {
	t.Helper()

	ctrl := gomock.NewController(t)

	sessions, err := session.NewManager(session.WithStore(NewMockStore(ctrl)))
	require.NoError(t, err)

	attempts := policy.NewMemoryAttemptStore()

	base := []httpsec.Option{
		httpsec.WithLogger(slog.New(h.logs)),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: h.authn, Sessions: sessions, Tokens: NewMockGenerator(ctrl), Attempts: attempts,
		}),
		httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: h.authn, Attempts: attempts}),
	}
	if engine != nil {
		base = append(base, httpsec.WithPolicyEngine(engine))
	}

	return httpsec.New(append(base, opts...)...)
}

// lockingAda is an engine whose fixed lockout holds ada locked.
func lockingAda(t *testing.T) *policy.Engine {
	t.Helper()

	attempts := policy.NewMemoryAttemptStore()
	require.NoError(t, attempts.RecordFailure(t.Context(), "ada", time.Now()))

	lockout, err := policy.NewAccountLockoutPolicy(
		policy.WithAttemptStore(attempts), policy.WithFixedLockout(1, time.Hour))
	require.NoError(t, err)

	return engineOf(t, lockout)
}

// TestChain_LockResponse pins how form login and Basic answer a locked
// account: by default as a wrong password, at the cost of the same password
// work, and as the lock itself, answered 429, only when the consumer chose to
// disclose it.
func TestChain_LockResponse(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		engine  func(t *testing.T) *policy.Engine
		opts    []httpsec.Option
		basic   bool
		matches int
		assert  func(t *testing.T, out served)
	}

	concealed := func(t *testing.T, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		require.ErrorIs(t, out.err, policy.ErrAccountLocked,
			"the consumer's own handler can still tell it is a lock")
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err), "as for a wrong password")
		assert.False(t, out.handlerRan)
	}

	disclosed := func(t *testing.T, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, policy.ErrAccountLocked)
		assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		assert.Equal(t, http.StatusTooManyRequests, httpsec.StatusForError(out.err))

		var lockout *policy.LockoutError
		assert.ErrorAs(t, out.err, &lockout, "the policy's own refusal, wait and all")
	}

	cases := []testCase{
		{
			name:    "form login answers a lock as a wrong password, after a decoy verification",
			engine:  lockingAda,
			matches: 1,
			assert:  concealed,
		},
		{
			name:    "Basic answers a lock as a wrong password, challenged",
			engine:  lockingAda,
			basic:   true,
			matches: 1,
			assert: func(t *testing.T, out served) {
				concealed(t, out)
				assert.Equal(t, `Basic realm="Restricted"`, out.rec.Header().Get("WWW-Authenticate"))
			},
		},
		{
			name:   "a disclosed form-login lock is the lock alone, with no decoy",
			engine: lockingAda,
			opts:   []httpsec.Option{httpsec.WithLockDisclosure()},
			assert: disclosed,
		},
		{
			name:   "a disclosed Basic lock has no challenge",
			engine: lockingAda,
			opts:   []httpsec.Option{httpsec.WithLockDisclosure()},
			basic:  true,
			assert: func(t *testing.T, out served) {
				disclosed(t, out)
				assert.Empty(t, out.rec.Header().Get("WWW-Authenticate"),
					"WWW-Authenticate belongs to a 401, and this is a 429")
			},
		},
		{
			name: "another pre-authentication deny is unchanged",
			engine: func(t *testing.T) *policy.Engine {
				return denyingIn(t, policy.PreAuthentication, errPreAuthStoreDown)
			},
			assert: func(t *testing.T, out served) {
				require.ErrorIs(t, out.err, errPreAuthStoreDown)
				assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "no join")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newLockResponseHarness(t, true)

			// The decoy is the presented password against the reference hash,
			// and only that: the user loader is a strict double, so loading
			// ada, which a real verification would, fails the row.
			if tc.matches > 0 {
				h.enc.EXPECT().Match(lockedGuess, lockReferenceHash).Return(false).Times(tc.matches)
			}

			c, err := h.chain(t, tc.engine(t), tc.opts...)
			require.NoError(t, err)

			if tc.basic {
				tc.assert(t, basicFrom(t, c, loginGuardSource, "ada", lockedGuess))

				return
			}

			tc.assert(t, formLoginFrom(t, c, loginGuardSource, "ada", lockedGuess))
		})
	}
}

// msgNoDecoyFragment is part of the warning construction writes when a lock refusal could be
// told apart from a wrong password by its timing.
const msgNoDecoyFragment = "timing"

// TestChain_LockResponseWarning pins that construction warns, once per
// endpoint, when locks are concealed but the authenticator cannot spend the
// decoy that would make the concealment hold for timing too.
func TestChain_LockResponseWarning(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		decoy  bool
		opts   []httpsec.Option
		assert func(t *testing.T, warnings []slog.Record)
	}

	cases := []testCase{
		{
			name: "an authenticator without a decoy warns once per endpoint",
			assert: func(t *testing.T, warnings []slog.Record) {
				require.Len(t, warnings, 2, "one for form login, one for Basic")

				var options []string

				for _, w := range warnings {
					v, ok := attrValue(w, "option")
					require.True(t, ok)

					options = append(options, v.String())
				}

				assert.ElementsMatch(t, []string{"EnableFormLogin", "EnableBasicAuth"}, options)
			},
		},
		{
			name: "disclosed locks need no decoy, so nothing is warned",
			opts: []httpsec.Option{httpsec.WithLockDisclosure()},
			assert: func(t *testing.T, warnings []slog.Record) {
				assert.Empty(t, warnings)
			},
		},
		{
			name:  "an authenticator offering a decoy is not warned about",
			decoy: true,
			assert: func(t *testing.T, warnings []slog.Record) {
				assert.Empty(t, warnings)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newLockResponseHarness(t, tc.decoy)

			_, err := h.chain(t, nil, tc.opts...)
			require.NoError(t, err)

			var warnings []slog.Record

			for _, r := range h.logs.records() {
				if r.Level == slog.LevelWarn && strings.Contains(r.Message, msgNoDecoyFragment) {
					warnings = append(warnings, r)
				}
			}

			tc.assert(t, warnings)
		})
	}
}
