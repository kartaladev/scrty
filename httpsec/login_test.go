package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// passwordLoginNamespace is the flow and factory namespace the login guard is
// built under.
const passwordLoginNamespace = "password-login"

// basicFrom sends a Basic credential for username from addr.
func basicFrom(t *testing.T, c *httpsec.Chain, addr, username, password string) served {
	t.Helper()

	return serve(t, c, fromSource(basicRequest(t.Context(), username, password), addr))
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
				lockoutPolicy, err := lockout.New(
					lockout.WithAttemptStore(h.attempts), lockout.WithSliding(1, time.Hour))
				require.NoError(t, err)

				h.lockout = lockoutPolicy
				require.NoError(t, h.attempts.RecordFailure(t.Context(), "ada", time.Now()))
			},
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				for i := range 50 {
					out := formLoginFrom(t, c, loginGuardSource, "ada", loginGuardRightPassword)
					require.ErrorIs(t, out.err, lockout.ErrAccountLocked, "locked refusal %d", i+1)
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
			name: "Basic locked refusals count against the source",
			arrange: func(t *testing.T, h *loginGuardHarness) {
				lockoutPolicy, err := lockout.New(
					lockout.WithAttemptStore(h.attempts), lockout.WithSliding(1, time.Hour))
				require.NoError(t, err)

				h.lockout = lockoutPolicy
				require.NoError(t, h.attempts.RecordFailure(t.Context(), "ada", time.Now()))
			},
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				for i := range 50 {
					out := basicFrom(t, c, loginGuardSource, "ada", loginGuardRightPassword)
					require.ErrorIs(t, out.err, lockout.ErrAccountLocked, "locked Basic refusal %d", i+1)
					require.NotErrorIs(t, out.err, ratelimit.ErrThrottled, "locked Basic refusal %d", i+1)
				}

				return snapshot(h), basicFrom(t, c, loginGuardSource, "bob", loginGuardRightPassword)
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
			name: "an unattributable source under a consumer limiter for form login is recorded under the endpoint's flow",
			loginOpts: func(t *testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{httpsec.WithLoginLimiter(memLimiter(t, 1, time.Minute))}
			},
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				return snapshot(h), formLoginFrom(t, c, "", "ada", loginGuardRightPassword)
			},
			assert: func(t *testing.T, h *loginGuardHarness, _ counts, _ served) {
				rec, ok := recordAt(h.logs.records(), slog.LevelError,
					"httpsec: refusing a request whose client address cannot be attributed")
				require.True(t, ok, "the refusal is recorded")

				flow, _ := attrValue(rec, "flow")
				assert.Equal(t, "password-login-form", flow.String())
			},
		},
		{
			name: "a failing consumer limiter for form login is recorded under the endpoint's flow",
			loginOpts: func(t *testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{httpsec.WithLoginLimiter(limiterFailing(t))}
			},
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				return snapshot(h), formLoginFrom(t, c, loginGuardSource, "ada", loginGuardRightPassword)
			},
			assert: func(t *testing.T, h *loginGuardHarness, _ counts, _ served) {
				rec, ok := recordAt(h.logs.records(), slog.LevelError,
					"httpsec: the rate limiter could not answer")
				require.True(t, ok, "the refusal is recorded")

				flow, _ := attrValue(rec, "flow")
				assert.Equal(t, "password-login-form", flow.String())
			},
		},
		{
			name: "an unattributable source under a consumer limiter for Basic is recorded under the endpoint's flow",
			basicOpts: func(t *testing.T) []httpsec.BasicAuthOption {
				return []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter(memLimiter(t, 1, time.Minute))}
			},
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				return snapshot(h), basicFrom(t, c, "", "ada", loginGuardRightPassword)
			},
			assert: func(t *testing.T, h *loginGuardHarness, _ counts, _ served) {
				rec, ok := recordAt(h.logs.records(), slog.LevelError,
					"httpsec: refusing a request whose client address cannot be attributed")
				require.True(t, ok, "the refusal is recorded")

				flow, _ := attrValue(rec, "flow")
				assert.Equal(t, "password-login-basic", flow.String())
			},
		},
		{
			name: "a failing consumer limiter for Basic is recorded under the endpoint's flow",
			basicOpts: func(t *testing.T) []httpsec.BasicAuthOption {
				return []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter(limiterFailing(t))}
			},
			act: func(t *testing.T, h *loginGuardHarness, c *httpsec.Chain) (counts, served) {
				return snapshot(h), basicFrom(t, c, loginGuardSource, "ada", loginGuardRightPassword)
			},
			assert: func(t *testing.T, h *loginGuardHarness, _ counts, _ served) {
				rec, ok := recordAt(h.logs.records(), slog.LevelError,
					"httpsec: the rate limiter could not answer")
				require.True(t, ok, "the refusal is recorded")

				flow, _ := attrValue(rec, "flow")
				assert.Equal(t, "password-login-basic", flow.String())
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

				require.NoError(t, c.FlushRefusalLogs())

				return snapshot(h), last
			},
			assert: func(t *testing.T, h *loginGuardHarness, _ counts, _ served) {
				assert.Equal(t, 2, h.reportedFor("throttled:"+passwordLoginNamespace+"-form:"+loginGuardSource),
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

	f, askedFor := recordingLimiterFactory(t)

	h := newLoginGuardHarness(t)
	h.chain(t, nil, nil, httpsec.WithRateLimiterFactory(f))

	login := askedFor(passwordLoginNamespace)

	require.Len(t, login, 1, "form login and Basic share one limiter, asked for once")
	assert.Equal(t, limiterAsked{passwordLoginNamespace, 50, 15 * time.Minute}, login[0])
}

// TestChain_FlowLimiterWinsOverFactory pins that a limiter given to a flow's
// own option is used instead of the chain's factory: when every endpoint has
// its own, the factory is never asked for the password-login limiter.
func TestChain_FlowLimiterWinsOverFactory(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		loginOpts func(t *testing.T) []httpsec.LoginOption
		basicOpts func(t *testing.T) []httpsec.BasicAuthOption
		assert    func(t *testing.T, asked []limiterAsked)
	}

	cases := []testCase{
		{
			name: "both endpoints given their own limiter",
			loginOpts: func(t *testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{httpsec.WithLoginLimiter(memLimiter(t, 10, 15*time.Minute))}
			},
			basicOpts: func(t *testing.T) []httpsec.BasicAuthOption {
				return []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter(memLimiter(t, 10, 15*time.Minute))}
			},
			assert: func(t *testing.T, asked []limiterAsked) {
				assert.Empty(t, asked, "the factory is not asked for a limiter nothing would use")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, askedFor := recordingLimiterFactory(t)

			h := newLoginGuardHarness(t)
			h.chain(t, tc.loginOpts(t), tc.basicOpts(t), httpsec.WithRateLimiterFactory(f))

			tc.assert(t, askedFor(passwordLoginNamespace))
		})
	}
}

// recordingLimiterFactory returns a factory that builds every limiter in
// memory and records each request, and a lookup of the requests made for one
// namespace. Callers look a namespace up rather than count every request:
// other limiters the chain may ask for are not their concern.
func recordingLimiterFactory(t *testing.T) (ratelimit.LimiterFactory, func(namespace string) []limiterAsked) {
	t.Helper()

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

	return f, func(namespace string) []limiterAsked {
		mu.Lock()
		defer mu.Unlock()

		var out []limiterAsked

		for _, a := range asked {
			if a.namespace == namespace {
				out = append(out, a)
			}
		}

		return out
	}
}

// conflictCheckingFactory returns a factory that builds every limiter in
// memory and refuses a namespace asked for again with a different limit or
// window, wrapping ratelimit.ErrConfig, as a storage-backed factory does when
// two policies would share one bucket, and refuses a namespace containing a
// colon, as the Redis factory does. A namespace asked for again with the
// same policy gets the limiter it built the first time, so a shared bucket is
// observable. It also returns a lookup of the requests made for one namespace.
func conflictCheckingFactory(t *testing.T) (ratelimit.LimiterFactory, func(namespace string) []limiterAsked) {
	t.Helper()

	type built struct {
		asked   limiterAsked
		limiter ratelimit.Limiter
	}

	var (
		mu    sync.Mutex
		calls []limiterAsked
		known = map[string]built{}
	)

	memory := ratelimit.MemoryLimiterFactory(
		ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))

	f := NewMockLimiterFactory(gomock.NewController(t))
	f.EXPECT().NewLimiter(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(namespace string, limit int, window time.Duration) (ratelimit.Limiter, error) {
			mu.Lock()
			defer mu.Unlock()

			ask := limiterAsked{namespace, limit, window}
			calls = append(calls, ask)

			if strings.Contains(namespace, ":") {
				return nil, fmt.Errorf("%w: the namespace %q contains a colon, which separates it from the key",
					ratelimit.ErrConfig, namespace)
			}

			if prior, ok := known[namespace]; ok {
				if prior.asked != ask {
					return nil, fmt.Errorf("%w: namespace %q is already built with %d per %s, and was asked for %d per %s",
						ratelimit.ErrConfig, namespace, prior.asked.limit, prior.asked.window, limit, window)
				}

				return prior.limiter, nil
			}

			l, err := memory.NewLimiter(namespace, limit, window)
			if err != nil {
				return nil, err
			}

			known[namespace] = built{ask, l}

			return l, nil
		}).AnyTimes()

	return f, func(namespace string) []limiterAsked {
		mu.Lock()
		defer mu.Unlock()

		var out []limiterAsked

		for _, a := range calls {
			if a.namespace == namespace {
				out = append(out, a)
			}
		}

		return out
	}
}

// TestChain_PasswordLoginOwnLimiterUnderSharedFactory pins that an endpoint
// given its own limiter runs under a flow of its own, so a factory that
// refuses one namespace with two policies still builds the chain, and the
// endpoint's guard and IPv6 aggregate share no bucket with the other's.
func TestChain_PasswordLoginOwnLimiterUnderSharedFactory(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		loginOpts func(t *testing.T) []httpsec.LoginOption
		basicOpts func(t *testing.T) []httpsec.BasicAuthOption
		assert    func(t *testing.T, c *httpsec.Chain, err error, askedFor func(string) []limiterAsked)
	}

	// rotate fails n logins through send, each from its own /64 of
	// 2001:db8:1::/56, requiring that none was throttled.
	rotate := func(t *testing.T, n int, send func(addr string) served) {
		t.Helper()

		for i := 1; i <= n; i++ {
			out := send(fmt.Sprintf("2001:db8:1:%x::1", i))
			require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "failure %d", i)
			require.NotErrorIs(t, out.err, ratelimit.ErrThrottled, "failure %d is within the aggregate", i)
		}
	}

	cases := []testCase{
		{
			name: "own form limiter, default Basic",
			loginOpts: func(t *testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{httpsec.WithLoginLimiter(memLimiter(t, 10, time.Minute))}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error, askedFor func(string) []limiterAsked) {
				require.NoError(t, err)
				assert.NotNil(t, c)
				assert.Equal(t, []limiterAsked{{"password-login", 50, 15 * time.Minute}},
					askedFor("password-login"))
				assert.Equal(t, []limiterAsked{{"password-login-ipv6-aggregate", 200, 15 * time.Minute}},
					askedFor("password-login-ipv6-aggregate"))
				assert.Equal(t, []limiterAsked{{"password-login-form-ipv6-aggregate", 40, time.Minute}},
					askedFor("password-login-form-ipv6-aggregate"))
			},
		},
		{
			name: "equal own limiters on both endpoints",
			loginOpts: func(t *testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{httpsec.WithLoginLimiter(memLimiter(t, 10, time.Minute))}
			},
			basicOpts: func(t *testing.T) []httpsec.BasicAuthOption {
				return []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter(memLimiter(t, 10, time.Minute))}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error, askedFor func(string) []limiterAsked) {
				require.NoError(t, err)
				assert.Equal(t, []limiterAsked{{"password-login-form-ipv6-aggregate", 40, time.Minute}},
					askedFor("password-login-form-ipv6-aggregate"))
				assert.Equal(t, []limiterAsked{{"password-login-basic-ipv6-aggregate", 40, time.Minute}},
					askedFor("password-login-basic-ipv6-aggregate"))

				rotate(t, 40, func(addr string) served { return formLoginFrom(t, c, addr, "user", "wrong") })
				requireThrottled(t, formLoginFrom(t, c, "2001:db8:1:ff::1", "user", "wrong"))

				out := basicFrom(t, c, "2001:db8:1:ff::1", "user", "wrong")
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed,
					"form login's exhausted aggregate leaves Basic's bucket untouched")
				assert.NotErrorIs(t, out.err, ratelimit.ErrThrottled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, askedFor := conflictCheckingFactory(t)
			h := newLoginGuardHarness(t)

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

			c, err := h.tryChain(t, loginOpts, basicOpts, httpsec.WithRateLimiterFactory(f))
			tc.assert(t, c, err, askedFor)
		})
	}
}

// TestChain_PasswordLoginAggregate pins the IPv6 aggregate of the
// password-login guard: it is requested at four times the shared limit by
// default, it throttles a client rotating through the /64s of one /56, and
// for an endpoint given its own limiter it is sized from that limiter's
// policy under a namespace of its own, skipped with one warning when it reports none, and refused under an
// explicit WithIPv6Aggregate.
func TestChain_PasswordLoginAggregate(t *testing.T) {
	t.Parallel()

	const aggregateNamespace = "password-login-ipv6-aggregate"

	type built struct {
		chain      *httpsec.Chain
		err        error
		aggregates []limiterAsked
		warnings   []slog.Record
	}

	type testCase struct {
		name      string
		loginOpts func(t *testing.T) []httpsec.LoginOption
		basicOpts func(t *testing.T) []httpsec.BasicAuthOption
		opts      []httpsec.Option
		assert    func(t *testing.T, b built)
	}

	noPolicy := func(t *testing.T) ratelimit.Limiter { return NewMockLimiter(gomock.NewController(t)) }

	warnedAbout := func(t *testing.T, b built, option string) {
		t.Helper()

		require.Len(t, b.warnings, 1, "exactly one warning, for the one limiter that reports no policy")

		got, ok := attrValue(b.warnings[0], "option")
		require.True(t, ok)
		assert.Equal(t, option, got.String(), "the warning names the endpoint option the limiter was given to")
	}

	// shared is the aggregate the chain still builds for the endpoint that
	// kept the shared default limiter.
	shared := limiterAsked{aggregateNamespace, 200, 15 * time.Minute}

	// rotate fails n form logins, each from its own /64 of 2001:db8:1::/56.
	rotate := func(t *testing.T, c *httpsec.Chain, n int) {
		t.Helper()

		for i := 1; i <= n; i++ {
			out := formLoginFrom(t, c, fmt.Sprintf("2001:db8:1:%x::1", i), "user", "wrong")
			require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "failure %d", i)
			require.NotErrorIs(t, out.err, ratelimit.ErrThrottled, "failure %d is within the aggregate", i)
		}
	}

	cases := []testCase{
		{
			name: "default aggregate requested",
			assert: func(t *testing.T, b built) {
				require.NoError(t, b.err)
				assert.Equal(t, []limiterAsked{shared}, b.aggregates,
					"form login and Basic share one aggregate, four times 50 per 15 minutes")
				assert.Empty(t, b.warnings)
			},
		},
		{
			name: "rotating /64s inside one /56",
			assert: func(t *testing.T, b built) {
				require.NoError(t, b.err)
				rotate(t, b.chain, 200)

				requireThrottled(t, formLoginFrom(t, b.chain, "2001:db8:1:ff::1", "user", "wrong"))
				out := formLoginFrom(t, b.chain, "2001:db8:2:1::1", "user", "wrong")
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "another /56 has its own aggregate")
				assert.NotErrorIs(t, out.err, ratelimit.ErrThrottled)
			},
		},
		{
			name: "aggregate turned off",
			opts: []httpsec.Option{httpsec.WithoutIPv6Aggregate()},
			assert: func(t *testing.T, b built) {
				require.NoError(t, b.err)
				assert.Empty(t, b.aggregates)
				rotate(t, b.chain, 201)
			},
		},
		{
			name: "login limiter with a policy",
			loginOpts: func(t *testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{httpsec.WithLoginLimiter(memLimiter(t, 10, time.Minute))}
			},
			assert: func(t *testing.T, b built) {
				require.NoError(t, b.err)
				assert.ElementsMatch(t, []limiterAsked{{"password-login-form-ipv6-aggregate", 40, time.Minute}, shared}, b.aggregates,
					"form login's aggregate is four times its own limiter; Basic keeps the shared one")
			},
		},
		{
			name: "Basic limiter with a policy",
			basicOpts: func(t *testing.T) []httpsec.BasicAuthOption {
				return []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter(memLimiter(t, 10, time.Minute))}
			},
			assert: func(t *testing.T, b built) {
				require.NoError(t, b.err)
				assert.ElementsMatch(t, []limiterAsked{{"password-login-basic-ipv6-aggregate", 40, time.Minute}, shared}, b.aggregates,
					"Basic's aggregate is four times its own limiter; form login keeps the shared one")
			},
		},
		{
			name: "login limiter without a policy",
			loginOpts: func(t *testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{httpsec.WithLoginLimiter(noPolicy(t))}
			},
			assert: func(t *testing.T, b built) {
				require.NoError(t, b.err)
				assert.Equal(t, []limiterAsked{shared}, b.aggregates, "only Basic's shared default has an aggregate")
				warnedAbout(t, b, "EnableFormLogin")
			},
		},
		{
			name: "Basic limiter without a policy",
			basicOpts: func(t *testing.T) []httpsec.BasicAuthOption {
				return []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter(noPolicy(t))}
			},
			assert: func(t *testing.T, b built) {
				require.NoError(t, b.err)
				assert.Equal(t, []limiterAsked{shared}, b.aggregates, "only form login's shared default has an aggregate")
				warnedAbout(t, b, "EnableBasicAuth")
			},
		},
		{
			name: "login limiter without a policy under an explicit aggregate",
			loginOpts: func(t *testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{httpsec.WithLoginLimiter(noPolicy(t))}
			},
			opts: []httpsec.Option{httpsec.WithIPv6Aggregate(56, 4)},
			assert: func(t *testing.T, b built) {
				require.ErrorIs(t, b.err, httpsec.ErrConfig)
				assert.Contains(t, b.err.Error(), "WithIPv6Aggregate")
				assert.Contains(t, b.err.Error(), "EnableFormLogin")
				assert.Nil(t, b.chain)
			},
		},
		{
			name: "Basic limiter without a policy under an explicit aggregate",
			basicOpts: func(t *testing.T) []httpsec.BasicAuthOption {
				return []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter(noPolicy(t))}
			},
			opts: []httpsec.Option{httpsec.WithIPv6Aggregate(56, 4)},
			assert: func(t *testing.T, b built) {
				require.ErrorIs(t, b.err, httpsec.ErrConfig)
				assert.Contains(t, b.err.Error(), "WithIPv6Aggregate")
				assert.Contains(t, b.err.Error(), "EnableBasicAuth")
				assert.Nil(t, b.chain)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, askedFor := recordingLimiterFactory(t)
			h := newLoginGuardHarness(t)

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

			c, err := h.tryChain(t, loginOpts, basicOpts,
				append([]httpsec.Option{httpsec.WithRateLimiterFactory(f)}, tc.opts...)...)

			var warnings []slog.Record

			for _, r := range h.logs.records() {
				if r.Level == slog.LevelWarn && strings.Contains(r.Message, "IPv6 aggregate") {
					warnings = append(warnings, r)
				}
			}

			var aggregates []limiterAsked
			for _, ns := range []string{
				aggregateNamespace, "password-login-form-ipv6-aggregate", "password-login-basic-ipv6-aggregate",
			} {
				aggregates = append(aggregates, askedFor(ns)...)
			}

			tc.assert(t, built{chain: c, err: err, aggregates: aggregates, warnings: warnings})
		})
	}
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

// errPreAuthStoreDown is a pre-authentication deny that is not a lock.
var errPreAuthStoreDown = errors.New("test: attempt store unavailable")

// lockResponseHarness is a chain whose pre-authentication phase denies ada,
// over an authenticator that is either a FirstOf over the password provider,
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
		authenticate.WithPasswordLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)

	m, err := authenticate.NewFirstOf(provider)
	require.NoError(t, err)

	h.authn = m

	return h
}

// chain builds form login and Basic over the harness's authenticator, judged
// by engine, with opts applied last.
func (h *lockResponseHarness) chain(t *testing.T, engine *policy.Engine, opts ...httpsec.Option) (*httpsec.Chain, error) {
	t.Helper()

	ctrl := gomock.NewController(t)

	sessions, err := session.New(session.WithStore(NewMockStore(ctrl)))
	require.NoError(t, err)

	attempts := lockout.NewMemoryAttemptStore()

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

// lockingAda is an engine whose sliding lockout holds ada locked.
func lockingAda(t *testing.T) *policy.Engine {
	t.Helper()

	attempts := lockout.NewMemoryAttemptStore()
	require.NoError(t, attempts.RecordFailure(t.Context(), "ada", time.Now()))

	lockoutPolicy, err := lockout.New(
		lockout.WithAttemptStore(attempts), lockout.WithSliding(1, time.Hour))
	require.NoError(t, err)

	return engineOf(t, lockoutPolicy)
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
		require.ErrorIs(t, out.err, lockout.ErrAccountLocked,
			"the consumer's own handler can still tell it is a lock")
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err), "as for a wrong password")
		assert.False(t, out.handlerRan)
	}

	disclosed := func(t *testing.T, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, lockout.ErrAccountLocked)
		assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		assert.Equal(t, http.StatusTooManyRequests, httpsec.StatusForError(out.err))

		var lockoutPolicy *lockout.Error
		assert.ErrorAs(t, out.err, &lockoutPolicy, "the policy's own refusal, wait and all")
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
		name  string
		decoy bool
		// authn, when set, replaces the harness's authenticator.
		authn  func(t *testing.T) authenticate.Authenticator
		opts   []httpsec.Option
		assert func(t *testing.T, warnings []slog.Record)
	}

	oncePerEndpoint := func(t *testing.T, warnings []slog.Record) {
		t.Helper()

		require.Len(t, warnings, 2, "one for form login, one for Basic")

		var options []string

		for _, w := range warnings {
			v, ok := attrValue(w, "option")
			require.True(t, ok)

			options = append(options, v.String())
		}

		assert.ElementsMatch(t, []string{"EnableFormLogin", "EnableBasicAuth"}, options)
	}

	cases := []testCase{
		{
			name:   "an authenticator without a decoy warns once per endpoint",
			assert: oncePerEndpoint,
		},
		{
			name: "a manager without a decoy delegate warns once per endpoint",
			authn: func(t *testing.T) authenticate.Authenticator {
				m, err := authenticate.NewFirstOf(NewMockAuthenticator(gomock.NewController(t)))
				require.NoError(t, err)

				return m
			},
			assert: oncePerEndpoint,
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
			if tc.authn != nil {
				h.authn = tc.authn(t)
			}

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

// TestFormLogin pins which requests form login claims, and how it reads the
// credentials out of the ones it does.
func TestFormLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []httpsec.LoginOption
		wire    func(t *testing.T, h *authHarness)
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, s served)
	}

	cases := []testCase{
		{
			name: "a correct login answers with the token and never calls the handler",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "username=ada&password=s3cret")
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.False(t, s.handlerRan,
					"a login is this library's own endpoint, so the application never sees it")
				assert.Equal(t, http.StatusOK, s.rec.Code)
				assert.Equal(t, "application/json", s.rec.Header().Get("Content-Type"))
				assert.Equal(t, "no-store", s.rec.Header().Get("Cache-Control"))

				var body loginBody
				require.NoError(t, json.Unmarshal(s.rec.Body.Bytes(), &body))
				assert.Equal(t, "issued-token", body.AccessToken)
				assert.Empty(t, body.RefreshToken,
					"the field is present and empty, so a client need not change when one is issued")
				assert.False(t, body.ValidUntil.IsZero(), "the session's idle expiry is reported")
			},
		},
		{
			name: "a GET on the login path is not a login",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return httptest.NewRequestWithContext(ctx, http.MethodGet, "/login", nil)
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan, "the request continues to the handler untouched")
				assert.Equal(t, http.StatusOK, s.rec.Code)
				assert.Empty(t, s.rec.Body.String())
			},
		},
		{
			name: "a POST on another path is not a login",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/orders", "username=ada&password=s3cret")
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan)
			},
		},
		{
			name: "consumer field names",
			opts: []httpsec.LoginOption{httpsec.WithLoginParams("email", "secret")},
			wire: func(_ *testing.T, h *authHarness) {
				h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, c identity.Credentials) (*authenticate.Authentication, error) {
						up, ok := c.(*identity.UsernamePassword)
						require.True(t, ok)
						assert.Equal(t, "ada@example.com", up.Username)

						return &authenticate.Authentication{Principal: testPrincipal()}, nil
					})
				h.attempts.EXPECT().Reset(gomock.Any(), "ada@example.com").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "email=ada%40example.com&secret=s3cret")
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
			},
		},
		{
			name: "a JSON body when the form yields neither field",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			request: func(ctx context.Context) *http.Request {
				return jsonRequest(ctx, "/login", `{"username":"ada","password":"s3cret"}`)
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
			},
		},
		{
			name: "a JSON body without a JSON content type is not read as one",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/login",
					strings.NewReader(`{"username":"ada","password":"s3cret"}`))
				req.Header.Set("Content-Type", "text/plain")

				return req
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrCredentialsMissing,
					"the body says what it is, and this one does not say JSON")
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "a consumer responder replaces the body",
			opts: []httpsec.LoginOption{
				httpsec.WithLoginResponder(func(ex *httpsec.Exchange, r httpsec.LoginResult) error {
					ex.Writer.SetHeader("Content-Type", "text/plain")
					ex.Writer.WriteHeader(http.StatusCreated)
					_, err := ex.Writer.Write([]byte(r.Token))

					return err
				}),
			},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "username=ada&password=s3cret")
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusCreated, s.rec.Code)
				assert.Equal(t, "text/plain", s.rec.Header().Get("Content-Type"))
				assert.Equal(t, "issued-token", s.rec.Body.String())
			},
		},
		{
			name: "a consumer login path leaves the default passing through",
			opts: []httpsec.LoginOption{httpsec.WithLoginRequestPath("/session")},
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "username=ada&password=s3cret")
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan, "the consumer moved the endpoint, so /login is theirs")
			},
		},
		{
			name: "the consumer login path answers the login",
			opts: []httpsec.LoginOption{httpsec.WithLoginRequestPath("/session")},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/session", "username=ada&password=s3cret")
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.False(t, s.handlerRan)
				assert.Equal(t, http.StatusOK, s.rec.Code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			tc.wire(t, h)

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps(), tc.opts...),
			)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, tc.request(t.Context())))
		})
	}
}

// TestFormLoginSequence pins the order of the steps, because the order is what
// the guarantees rest on: a locked account is refused before its password is
// tested, and bookkeeping never decides the outcome.
func TestFormLoginSequence(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		engine func(t *testing.T) *policy.Engine
		opts   []httpsec.Option
		wire   func(t *testing.T, h *authHarness)
		assert func(t *testing.T, h *authHarness, s served)
	}

	cases := []testCase{
		{
			name: "a locked account is never probed",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return denyingIn(t, policy.PreAuthentication, lockout.ErrAccountLocked)
			},
			// No expectation on the authenticator at all: any call to it fails
			// the test, which is what "the password is never checked" means.
			wire: func(*testing.T, *authHarness) {},
			assert: func(t *testing.T, _ *authHarness, s served) {
				// By default a lock is concealed as a wrong password, and stays
				// identifiable as a lock to the consumer's own handler.
				require.ErrorIs(t, s.err, lockout.ErrAccountLocked)
				require.ErrorIs(t, s.err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			// Pre-authentication has no session to mark a challenge on, so an
			// enforced one refuses nothing there: the credential is checked
			// and the login goes on. Only an unenforced kind is refused, which
			// TestUnenforcedChallengeAtRuntime pins.
			name: "a pre-authentication challenge of an enforced kind lets the login go on",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return challengingIn(t, policy.PreAuthentication, policy.ChallengePasswordChange)
			},
			opts: []httpsec.Option{httpsec.EnableGateForTest(policy.ChallengePasswordChange)},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			assert: func(t *testing.T, _ *authHarness, s served) {
				t.Helper()

				var ch *httpsec.ChallengeError
				require.NotErrorAs(t, s.err, &ch, "the phase has no session to challenge")
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
			},
		},
		{
			name:   "a wrong password records one failed attempt",
			engine: func(*testing.T) *policy.Engine { return nil },
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticationFailed()
				h.attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).
					Return(nil).Times(1)
			},
			assert: func(t *testing.T, _ *authHarness, s served) {
				require.ErrorIs(t, s.err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name:   "a correct password clears the attempts",
			engine: func(*testing.T) *policy.Engine { return nil },
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil).Times(1)
				h.expectSessionOpened("issued-token")
			},
			assert: func(t *testing.T, _ *authHarness, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
			},
		},
		{
			name:   "an attempt store that cannot record does not change the outcome",
			engine: func(*testing.T) *policy.Engine { return nil },
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticationFailed()
				h.attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).
					Return(errors.New("attempts: store unreachable"))
			},
			assert: func(t *testing.T, h *authHarness, s served) {
				require.ErrorIs(t, s.err, authenticate.ErrAuthenticationFailed,
					"a broken ledger must not turn a wrong password into a server fault")
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))

				r, ok := recordAt(h.logs.records(), slog.LevelError,
					"httpsec: a failed login attempt could not be recorded")
				require.True(t, ok,
					"the lockout count has stopped moving, and only this record says so")
				assert.Positive(t, r.NumAttrs())
			},
		},
		{
			name:   "an attempt store that cannot clear does not change the outcome",
			engine: func(*testing.T) *policy.Engine { return nil },
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").
					Return(errors.New("attempts: store unreachable"))
				h.expectSessionOpened("issued-token")
			},
			assert: func(t *testing.T, h *authHarness, s served) {
				require.NoError(t, s.err, "a broken ledger must not refuse a correct password")
				assert.Equal(t, http.StatusOK, s.rec.Code)

				_, ok := recordAt(h.logs.records(), slog.LevelError,
					"httpsec: failed login attempts could not be cleared")
				assert.True(t, ok)
			},
		},
		{
			name: "a post-authentication deny refuses without creating a session",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return denyingIn(t, policy.PostAuthentication, policy.ErrTooManySessions)
			},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				// No expectation on the store or the generator: a login the
				// policy refused must mint neither a session nor a token.
			},
			assert: func(t *testing.T, _ *authHarness, s served) {
				require.ErrorIs(t, s.err, policy.ErrTooManySessions)
				assert.Equal(t, http.StatusTooManyRequests, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
				assert.Empty(t, s.rec.Body.String())
			},
		},
		{
			name: "a post-authentication challenge refuses with the pending session and the token",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return challengingIn(t, policy.PostAuthentication, policy.ChallengeMFA)
			},
			opts: []httpsec.Option{httpsec.EnableGateForTest(policy.ChallengeMFA)},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				h.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(nil)
				h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).
					Return("issued-token", nil)
			},
			assert: func(t *testing.T, _ *authHarness, s served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, s.err, &ch)
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				require.NotNil(t, ch.Session, "the caller answers the challenge on this session")
				assert.Equal(t, session.MFAPending, ch.Session.MFA)
				assert.Equal(t, "issued-token", ch.Token)
				assert.False(t, s.handlerRan)
				assert.Empty(t, s.rec.Body.String(),
					"a challenged login is a refusal, so no success document is written")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			tc.wire(t, h)

			opts := []httpsec.Option{
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps()),
			}
			if e := tc.engine(t); e != nil {
				opts = append(opts, httpsec.WithPolicyEngine(e))
			}

			chain, err := httpsec.New(append(opts, tc.opts...)...)
			require.NoError(t, err)

			tc.assert(t, h, serve(t, chain, formRequest(t.Context(), "/login", "username=ada&password=s3cret")))
		})
	}
}

// jsonLoginOfSize builds a JSON login document padded to at least n bytes, so
// a test can post a body of a chosen size that still carries real credentials.
func jsonLoginOfSize(n int) string {
	const shell = `{"username":"ada","password":"s3cret","note":""}`

	if n <= len(shell) {
		return shell
	}

	return `{"username":"ada","password":"s3cret","note":"` +
		strings.Repeat("p", n-len(shell)) + `"}`
}

// TestFormLoginBody pins the bound on an unauthenticated endpoint. An
// unbounded read here is a memory-exhaustion path that costs an attacker no
// credential at all, so the bound applies before anything is parsed.
func TestFormLoginBody(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []httpsec.LoginOption
		wire    func(t *testing.T, h *authHarness)
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, s served)
	}

	cases := []testCase{
		{
			name: "a 1 MiB body under the default limit is refused unparsed",
			// No expectation on the authenticator: an oversized body must not
			// reach a credential check at all.
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return jsonRequest(ctx, "/login", jsonLoginOfSize(1<<20))
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrRequestTooLarge)
				assert.Equal(t, http.StatusRequestEntityTooLarge, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "a body one byte over the default limit is refused",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return jsonRequest(ctx, "/login", jsonLoginOfSize(int(httpsec.DefaultLoginBodyLimit)+1))
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrRequestTooLarge)
			},
		},
		{
			name: "a body just under the default limit logs in normally",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			request: func(ctx context.Context) *http.Request {
				return jsonRequest(ctx, "/login", jsonLoginOfSize(int(httpsec.DefaultLoginBodyLimit)-1))
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
			},
		},
		{
			name: "a raised limit parses a 100 KiB body",
			opts: []httpsec.LoginOption{httpsec.WithLoginBodyLimit(256 << 10)},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			request: func(ctx context.Context) *http.Request {
				return jsonRequest(ctx, "/login", jsonLoginOfSize(100<<10))
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
			},
		},
		{
			name: "no credentials at all",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "")
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrCredentialsMissing)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "an identifier with no password",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "username=ada")
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrCredentialsMissing,
					"half a credential is not a credential to test")
			},
		},
		{
			name: "an undecodable JSON body",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return jsonRequest(ctx, "/login", `{"username":"ada",`)
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrCredentialsMissing)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(s.err))
			},
		},
		{
			name: "a JSON body whose credential members are not strings",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return jsonRequest(ctx, "/login", `{"username":1,"password":true}`)
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrCredentialsMissing,
					"a number is not an identifier, and coercing one would invent a login")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			tc.wire(t, h)

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps(), tc.opts...),
			)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, tc.request(t.Context())))
		})
	}
}

// TestFormLoginResponse pins the document a login succeeds with, and that a
// consumer replaces it whole rather than having it reshaped.
func TestFormLoginResponse(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(t *testing.T) []httpsec.LoginOption
		assert func(t *testing.T, opened *session.Session, s served)
	}

	cases := []testCase{
		{
			name: "the default document carries the token, an empty refresh field and the idle expiry",
			opts: func(*testing.T) []httpsec.LoginOption { return nil },
			assert: func(t *testing.T, opened *session.Session, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
				assert.Equal(t, "application/json", s.rec.Header().Get("Content-Type"))
				assert.Equal(t, "no-store", s.rec.Header().Get("Cache-Control"),
					"the response carries the access token, so no cache may keep it")

				var body loginBody
				require.NoError(t, json.Unmarshal(s.rec.Body.Bytes(), &body))
				assert.Equal(t, "issued-token", body.AccessToken)
				assert.Empty(t, body.RefreshToken)

				require.NotNil(t, opened)
				assert.WithinDuration(t, opened.IdleExpiresAt, body.ValidUntil, time.Second,
					"valid_until is the session's idle expiry, not the token's")

				var members map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(s.rec.Body.Bytes(), &members))
				assert.ElementsMatch(t,
					[]string{"access_token", "refresh_token", "valid_until"},
					slices.Collect(maps.Keys(members)),
					"the member names are the documented contract of the default")
			},
		},
		{
			name: "a consumer responder replaces the document whole",
			opts: func(*testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{
					httpsec.WithLoginResponder(func(ex *httpsec.Exchange, r httpsec.LoginResult) error {
						ex.Writer.SetHeader("Content-Type", "text/plain")
						ex.Writer.WriteHeader(http.StatusOK)
						_, err := ex.Writer.Write([]byte("token=" + r.Token +
							" session=" + r.Session.ID))

						return err
					}),
				}
			},
			assert: func(t *testing.T, opened *session.Session, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, "text/plain", s.rec.Header().Get("Content-Type"))
				assert.Empty(t, s.rec.Header().Get("Cache-Control"), "a consumer responder owns its headers")
				require.NotNil(t, opened)
				assert.Equal(t, "token=issued-token session="+opened.ID, s.rec.Body.String(),
					"the responder is handed both the token and the session it belongs to")
			},
		},
		{
			name: "a responder that fails leaves the chain as the request's refusal",
			opts: func(*testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{
					httpsec.WithLoginResponder(func(*httpsec.Exchange, httpsec.LoginResult) error {
						return errors.New("responder: template missing")
					}),
				}
			},
			assert: func(t *testing.T, _ *session.Session, s served) {
				require.Error(t, s.err)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(s.err),
					"a response that could not be written is a server fault, not a quiet 200")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opened *session.Session

			h := newAuthHarness(t)
			h.expectAuthenticated(testPrincipal())
			h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
			h.store.EXPECT().Create(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, s *session.Session) error {
					opened = s

					return nil
				})
			h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).
				Return("issued-token", nil)

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps(), tc.opts(t)...),
			)
			require.NoError(t, err)

			s := serve(t, chain, formRequest(t.Context(), "/login", "username=ada&password=s3cret"))
			tc.assert(t, opened, s)
		})
	}
}

// TestFormLoginIgnoresQueryCredentials pins that a credential in the URL query
// never authenticates.
//
// net/http's FormValue merges the query into the parsed form, so a login bound
// through it accepts a password that every access log, proxy log and browser
// history along the way has already recorded, and that the next page sends in
// its Referer. Form login binds from the body alone; the query is not a form
// field.
func TestFormLoginIgnoresQueryCredentials(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		wire    func(t *testing.T, h *authHarness)
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, s served)
	}

	// No expectation is wired on the authenticator for a refused row: any call
	// to it fails the case, which is what "the credential was never read" means.
	neverAuthenticates := func(*testing.T, *authHarness) {}

	refusedAsMissing := func(t *testing.T, s served) {
		require.ErrorIs(t, s.err, httpsec.ErrCredentialsMissing)
		assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(s.err))
		assert.False(t, s.handlerRan)
	}

	loggedIn := func(t *testing.T, s served) {
		require.NoError(t, s.err)
		assert.Equal(t, http.StatusOK, s.rec.Code)
		assert.False(t, s.handlerRan)
	}

	succeeds := func(_ *testing.T, h *authHarness) {
		h.expectAuthenticated(testPrincipal())
		h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
		h.expectSessionOpened("issued-token")
	}

	cases := []testCase{
		{
			name: "credentials in the query alone do not authenticate",
			wire: neverAuthenticates,
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login?username=ada&password=s3cret", "")
			},
			assert: refusedAsMissing,
		},
		{
			name: "credentials in the body still authenticate",
			wire: succeeds,
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "username=ada&password=s3cret")
			},
			assert: loggedIn,
		},
		{
			name: "a query pair cannot complete a half-filled body",
			wire: neverAuthenticates,
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login?password=s3cret", "username=ada")
			},
			assert: refusedAsMissing,
		},
		{
			name: "an unrelated query parameter is harmless",
			wire: succeeds,
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login?next=/home", "username=ada&password=s3cret")
			},
			assert: loggedIn,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			tc.wire(t, h)

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps()),
			)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, tc.request(t.Context())))
		})
	}
}

// expectCancelThenFail wires the harness so the client hangs up after sending
// its guess: the authenticator cancels the request context and refuses, and
// the attempt store honours cancellation the way a SQL driver does. It returns
// the context the store was handed, valid once the request has been served.
func expectCancelThenFail(h *authHarness, cancel context.CancelFunc) *context.Context {
	var recorded context.Context

	h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
			cancel()

			return nil, authenticate.ErrAuthenticationFailed
		})
	h.attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).
		DoAndReturn(func(ctx context.Context, _ string, _ time.Time) error {
			recorded = ctx

			return ctx.Err()
		})

	return &recorded
}

// serveOn runs req through chain on an exchange built from ctx, because the
// exchange's context, not the request's, is what the interceptors act on.
func serveOn(ctx context.Context, chain *httpsec.Chain, req *http.Request) {
	run := chain.Assemble(func(*httpsec.Exchange) error { return nil })
	ex := httpsec.NewExchange(ctx,
		httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))
	_ = run(ex)
}

// TestLogin_RecordsFailureOnUncancellableContext pins that a client which
// disconnects right after sending a wrong password is still charged for it,
// on form login and on Basic authentication alike.
//
// Not rows of TestFormLogin: the client hangs up mid-request.
func TestLogin_RecordsFailureOnUncancellableContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		option func(h *authHarness) httpsec.Option
		// request builds the wrong-password request the client hangs up after.
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, recorded context.Context)
	}

	failureReachedStore := func(t *testing.T, recorded context.Context) {
		require.NotNil(t, recorded, "the failure must reach the attempt store")
		assert.NoError(t, recorded.Err(),
			"the failure must be recorded on a context the client cannot cancel")
	}

	cases := []testCase{
		{
			name:   "form login",
			option: func(h *authHarness) httpsec.Option { return httpsec.EnableFormLogin(h.formLoginDeps()) },
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "username=ada&password=wrong")
			},
			assert: failureReachedStore,
		},
		{
			name:   "basic",
			option: func(h *authHarness) httpsec.Option { return httpsec.EnableBasicAuth(h.basicAuthDeps()) },
			request: func(ctx context.Context) *http.Request {
				return basicRequest(ctx, "ada", "wrong")
			},
			assert: failureReachedStore,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			recorded := expectCancelThenFail(h, cancel)

			chain, err := httpsec.New(httpsec.WithLogger(h.logger()), tc.option(h))
			require.NoError(t, err)

			serveOn(ctx, chain, tc.request(ctx))

			tc.assert(t, *recorded)
		})
	}
}

func TestLoginFields_NeverShowsThePassword(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		opts  []httpsec.LoginOption
		param string
		req   func(t *testing.T) *http.Request
	}{
		{
			name:  "JSON, default parameter",
			param: "password",
			req: func(t *testing.T) *http.Request {
				return jsonRequest(t.Context(), "/login", `{"username":"ada","password":"pw","remember":true}`)
			},
		},
		{
			name:  "form, default parameter",
			param: "password",
			req: func(t *testing.T) *http.Request {
				return formRequest(t.Context(), "/login", "username=ada&password=pw&remember=true")
			},
		},
		{
			name:  "JSON, configured parameter",
			param: "secret",
			opts:  []httpsec.LoginOption{httpsec.WithLoginParams("who", "secret")},
			req: func(t *testing.T) *http.Request {
				return jsonRequest(t.Context(), "/login", `{"who":"ada","secret":"pw","remember":true}`)
			},
		},
		{
			name:  "form, configured parameter",
			param: "secret",
			opts:  []httpsec.LoginOption{httpsec.WithLoginParams("who", "secret")},
			req: func(t *testing.T) *http.Request {
				return formRequest(t.Context(), "/login", "who=ada&secret=pw&remember=true")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			h.expectAuthenticated(testPrincipal())
			h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
			h.expectSessionOpened("tok")

			var (
				called         bool
				password       any
				hasPassword    bool
				remember       any
				hasRemember    bool
				gotEx          *httpsec.Exchange
				missing, found bool
			)

			opts := append(tc.opts, httpsec.WithLoginLifetime(func(ex *httpsec.Exchange, f httpsec.LoginFields) time.Duration {
				called, gotEx = true, ex
				password, hasPassword = f.Value(tc.param)
				remember, hasRemember = f.Value("remember")
				_, found = f.Value("nonexistent")
				_, missing = f.Value("")

				return 0
			}))

			chain, err := httpsec.New(httpsec.EnableFormLogin(h.formLoginDeps(), opts...))
			require.NoError(t, err)

			out := serve(t, chain, tc.req(t))
			require.NoError(t, out.err)

			require.True(t, called)
			assert.NotNil(t, gotEx)
			assert.False(t, hasPassword, "the password parameter is not reported")
			assert.Nil(t, password)
			assert.True(t, hasRemember)
			assert.NotNil(t, remember)
			assert.False(t, found)
			assert.False(t, missing)
		})
	}
}
