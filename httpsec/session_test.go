package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// runChainCapturingContext assembles a chain whose one interceptor publishes a
// session and continues, and whose terminal captures the context the handler
// would be called with. It is what every case here inspects: the chain must
// hand the handler a context derived from the one the exchange started with.
func runChainCapturingContext(ctx context.Context, t *testing.T) (context.Context, error) {
	t.Helper()

	publisher := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		ex.SetContext(httpsec.WithSession(ex.Context(), &session.Session{ID: "sess-1"}))
		return next(ex)
	})

	chain, err := httpsec.New(httpsec.RegisterInterceptor(publisher, httpsec.OrderBearerToken))
	require.NoError(t, err)

	var seen context.Context
	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		seen = ex.Context()
		return nil
	})

	err = run(httpsec.NewExchange(ctx, stubRequest{}, &stubWriter{}))
	require.NotNil(t, seen, "the handler must have been reached")
	return seen, err
}

func TestChainContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, seen context.Context, err error)
	}

	cases := []testCase{
		{
			name: "an upstream value survives the chain",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, ctxKey("request-id"), "r-7")
			},
			assert: func(t *testing.T, seen context.Context, err error) {
				require.NoError(t, err)
				assert.Equal(t, "r-7", seen.Value(ctxKey("request-id")))
			},
		},
		{
			name: "state an interceptor adds reaches the handler",
			assert: func(t *testing.T, seen context.Context, err error) {
				require.NoError(t, err)

				s, ok := httpsec.SessionFromContext(seen)
				require.True(t, ok)
				assert.Equal(t, "sess-1", s.ID)
			},
		},
		{
			name: "an interceptor's state does not displace an upstream value",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, ctxKey("request-id"), "r-8")
			},
			assert: func(t *testing.T, seen context.Context, err error) {
				require.NoError(t, err)

				_, ok := httpsec.SessionFromContext(seen)
				require.True(t, ok)
				assert.Equal(t, "r-8", seen.Value(ctxKey("request-id")))
			},
		},
		{
			name: "cancellation reaches an in-flight lookup",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			assert: func(t *testing.T, seen context.Context, err error) {
				require.NoError(t, err)
				require.ErrorIs(t, seen.Err(), context.Canceled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			seen, err := runChainCapturingContext(ctx, t)
			tc.assert(t, seen, err)
		})
	}
}

func TestSessionFromContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, s *session.Session, ok bool)
	}

	cases := []testCase{
		{
			name: "no session published",
			assert: func(t *testing.T, s *session.Session, ok bool) {
				assert.False(t, ok)
				assert.Nil(t, s)
			},
		},
		{
			name: "a published session is read back",
			ctx: func(ctx context.Context) context.Context {
				return httpsec.WithSession(ctx, &session.Session{ID: "sess-2"})
			},
			assert: func(t *testing.T, s *session.Session, ok bool) {
				require.True(t, ok)
				require.NotNil(t, s)
				assert.Equal(t, "sess-2", s.ID)
			},
		},
		{
			name: "a nil session is reported absent, not present and empty",
			ctx: func(ctx context.Context) context.Context {
				return httpsec.WithSession(ctx, nil)
			},
			assert: func(t *testing.T, s *session.Session, ok bool) {
				assert.False(t, ok, "a caller ignoring ok must not be handed something it reads as a live session")
				assert.Nil(t, s)
			},
		},
		{
			name: "a later publication replaces an earlier one",
			ctx: func(ctx context.Context) context.Context {
				ctx = httpsec.WithSession(ctx, &session.Session{ID: "sess-old"})
				return httpsec.WithSession(ctx, &session.Session{ID: "sess-new"})
			},
			assert: func(t *testing.T, s *session.Session, ok bool) {
				require.True(t, ok)
				require.NotNil(t, s)
				assert.Equal(t, "sess-new", s.ID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			s, ok := httpsec.SessionFromContext(ctx)
			tc.assert(t, s, ok)
		})
	}
}

// activityCountingStore counts the activity writes that reach the wrapped
// store.
type activityCountingStore struct {
	session.Store

	writes atomic.Int32
}

func (s *activityCountingStore) RecordActivity(
	ctx context.Context, sessionID string, lastAccessed, idleExpires, olderThan time.Time,
) error {
	s.writes.Add(1)

	return s.Store.RecordActivity(ctx, sessionID, lastAccessed, idleExpires, olderThan)
}

// TestSessionTouchHonoursTheManagersInterval pins that the chain's activity
// write-back goes through the manager's activity interval, so requests closer
// together than it persist activity once.
//
// Not rows of TestSessionTouch: it runs on a real manager and a fake clock.
func TestSessionTouchHonoursTheManagersInterval(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.Option
		assert func(t *testing.T, afterSecond, afterThird int32)
	}

	cases := []testCase{
		{
			name: "a one-minute interval persists two requests ten seconds apart once, and a third a minute later again",
			opts: []session.Option{session.WithTouchInterval(time.Minute)},
			assert: func(t *testing.T, afterSecond, afterThird int32) {
				assert.EqualValues(t, 1, afterSecond)
				assert.EqualValues(t, 2, afterThird)
			},
		},
		{
			name: "with no interval every request persists",
			assert: func(t *testing.T, afterSecond, afterThird int32) {
				assert.EqualValues(t, 2, afterSecond)
				assert.EqualValues(t, 3, afterThird)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC))
			store := &activityCountingStore{Store: session.NewMemoryStore(session.WithMemoryStoreClock(clk))}

			sessions, err := session.New(append([]session.Option{
				session.WithClock(clk), session.WithStore(store),
			}, tc.opts...)...)
			require.NoError(t, err)

			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
				Return(storedUser(), nil).AnyTimes()

			chain, err := httpsec.New(
				httpsec.WithClock(clk),
				httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}))
			require.NoError(t, err)

			s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			request := func() {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil)
				req.Header.Set("Authorization", "Bearer "+s.ID)

				out := serve(t, chain, req)
				require.NoError(t, out.err)
				require.True(t, out.handlerRan)
			}

			// Just past the interval since the session's last recorded access,
			// so the first request's write is unambiguously due.
			clk.Advance(time.Minute + time.Second)
			request()
			clk.Advance(10 * time.Second)
			request()

			afterSecond := store.writes.Load()

			clk.Advance(50 * time.Second) // a minute after the first request
			request()

			tc.assert(t, afterSecond, store.writes.Load())
		})
	}
}

// errGuardRefused is what an interceptor inside the touch refuses with, so a
// test can tell the chain's own refusal from anything the write-back did.
var errGuardRefused = errors.New("sessiontouch_test: refused by a guard")

// errStoreUnreachable is what the store fails the activity write-back with.
var errStoreUnreachable = errors.New("sessiontouch_test: store unreachable")

// TestSessionTouch pins the activity write-back: it runs after everything
// inside it, it runs for a refused request too, and it never changes what the
// request answered with.
func TestSessionTouch(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		wire    func(t *testing.T, h *authHarness, saved *activityWrites)
		inner   []httpsec.Option
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, s served, saved *activityWrites)
	}

	authenticated := func(ctx context.Context) *http.Request {
		return bearerRequest(ctx, "Bearer a-token")
	}

	advanced := func(t *testing.T, saved *activityWrites) {
		t.Helper()

		records := saved.all()
		require.Len(t, records, 1, "activity is recorded once per request")
		assert.Equal(t, testJTI, records[0].id, "the activity is recorded on the request's session")
		assert.True(t, records[0].idleExpires.After(time.Now().Add(20*time.Minute)),
			"the idle deadline was moved to now plus the manager's idle timeout")
		assert.True(t, records[0].lastAccessed.After(time.Now().Add(-time.Minute)),
			"the last-access time was moved to now")
		assert.True(t, records[0].olderThan.Equal(records[0].lastAccessed),
			"with no touch interval the write is conditional on nothing newer than now")
	}

	cases := []testCase{
		{
			name: "a completed request advances the idle deadline",
			wire: func(_ *testing.T, h *authHarness, saved *activityWrites) {
				h.expectVerified()
				h.expectResolvedSession(touchableSession())
				h.expectActivity(saved, nil)
			},
			request: authenticated,
			assert: func(t *testing.T, s served, saved *activityWrites) {
				require.NoError(t, s.err)
				require.True(t, s.handlerRan)
				advanced(t, saved)
			},
		},
		{
			name: "a request refused by a guard still advances it",
			wire: func(_ *testing.T, h *authHarness, saved *activityWrites) {
				h.expectVerified()
				h.expectResolvedSession(touchableSession())
				h.expectActivity(saved, nil)
			},
			inner: []httpsec.Option{
				httpsec.RegisterInterceptor(
					httpsec.InterceptorFunc(func(*httpsec.Exchange, httpsec.Next) error {
						return errGuardRefused
					}),
					httpsec.OrderAuthorizer),
			},
			request: authenticated,
			assert: func(t *testing.T, s served, saved *activityWrites) {
				require.ErrorIs(t, s.err, errGuardRefused)
				assert.False(t, s.handlerRan)
				advanced(t, saved)
			},
		},
		{
			name: "a touch failure after a 200 changes neither the response nor the error",
			wire: func(_ *testing.T, h *authHarness, saved *activityWrites) {
				h.expectVerified()
				h.expectResolvedSession(touchableSession())
				h.expectActivity(saved, errStoreUnreachable)
			},
			inner: []httpsec.Option{
				httpsec.RegisterInterceptor(
					httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
						ex.Writer.WriteHeader(http.StatusOK)

						return nil
					}),
					httpsec.OrderAuthorizer),
			},
			request: authenticated,
			assert: func(t *testing.T, s served, saved *activityWrites) {
				require.NoError(t, s.err,
					"bookkeeping that could not be written must not turn a served request into a fault")
				assert.Equal(t, http.StatusOK, s.rec.Code)
				assert.NotEmpty(t, saved.all(), "the write-back was attempted")
			},
		},
		{
			name: "a request with no session touches nothing",
			// No expectation on the store at all: any write fails the case.
			wire: func(*testing.T, *authHarness, *activityWrites) {},
			request: func(ctx context.Context) *http.Request {
				return bearerRequest(ctx, "")
			},
			assert: func(t *testing.T, s served, saved *activityWrites) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan)
				assert.Empty(t, saved.all())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			saved := &activityWrites{}
			tc.wire(t, h, saved)

			opts := append([]httpsec.Option{
				httpsec.WithLogger(h.logger()),
				httpsec.EnableBearerToken(h.bearerTokenDeps()),
			}, tc.inner...)

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, tc.request(t.Context())), saved)
		})
	}
}

// TestTouchIntervalWiring pins that a chain refuses to build when its session
// manager coalesces activity over an interval an idle policy does not exceed.
func TestTouchIntervalWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		interval time.Duration
		idle     []time.Duration
		assert   func(t *testing.T, err error)
	}

	builds := func(t *testing.T, err error) {
		t.Helper()

		require.NoError(t, err)
	}

	refused := func(interval, idle string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), interval)
			assert.Contains(t, err.Error(), idle)
		}
	}

	cases := []testCase{
		{
			name:     "idle policy shorter than the interval is refused",
			interval: 10 * time.Minute,
			idle:     []time.Duration{5 * time.Minute},
			assert:   refused("10m0s", "5m0s"),
		},
		{
			name:     "idle policy equal to the interval is refused",
			interval: 10 * time.Minute,
			idle:     []time.Duration{10 * time.Minute},
			assert:   refused("10m0s", "10m0s"),
		},
		{
			name:     "idle policy longer than the interval builds",
			interval: 10 * time.Minute,
			idle:     []time.Duration{15 * time.Minute},
			assert:   builds,
		},
		{
			name:     "the shortest of several idle policies decides",
			interval: 10 * time.Minute,
			idle:     []time.Duration{time.Hour, 5 * time.Minute},
			assert:   refused("10m0s", "5m0s"),
		},
		{
			name:     "no interval builds with a short idle policy",
			interval: 0,
			idle:     []time.Duration{5 * time.Minute},
			assert:   builds,
		},
		{
			name:     "an interval with no idle policy builds",
			interval: 10 * time.Minute,
			assert:   builds,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessions, err := session.New(
				session.WithStore(session.NewMemoryStore()),
				session.WithTouchInterval(tc.interval),
			)
			require.NoError(t, err)

			var policies []policy.Policy

			for _, idle := range tc.idle {
				p, err := policy.NewIdleTimeout(policy.WithIdleTimeout(idle))
				require.NoError(t, err)

				policies = append(policies, p)
			}

			_, err = httpsec.New(
				httpsec.WithSessions(sessions),
				httpsec.WithPolicyEngine(engineOf(t, policies...)),
			)
			tc.assert(t, err)
		})
	}
}
