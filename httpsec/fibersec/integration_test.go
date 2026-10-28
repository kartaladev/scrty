package fibersec_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// outcome is what one request through the fiber app produced.
type outcome struct {
	status   int
	routeRan bool
}

// errInnerRefusal is what a consumer interceptor inside the session bearer
// refuses with.
var errInnerRefusal = errors.New("fibersec_test: refused inside the bearer")

// sessionClock is a controlled clock for the session manager and its store. It
// is only ever read, so After never fires.
type sessionClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *sessionClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *sessionClock) After(time.Duration) <-chan time.Time { return nil }

func (c *sessionClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

// referenceDeployment is a memory-backed session manager on a controlled clock,
// one live session, and the options that authenticate by that session's
// reference.
type referenceDeployment struct {
	clock *sessionClock
	store *session.MemoryStore
	live  *session.Session
	opts  []httpsec.Option
}

func newReferenceDeployment(t *testing.T, extra ...httpsec.Option) *referenceDeployment {
	t.Helper()

	clk := &sessionClock{now: time.Date(2026, time.October, 22, 9, 0, 0, 0, time.UTC)}
	store := session.NewMemoryStore(session.WithMemoryStoreClock(clk))

	sessions, err := session.New(session.WithStore(store), session.WithClock(clk))
	require.NoError(t, err)

	live, err := sessions.Create(t.Context(), "u-1")
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
		Return(&identity.Details{ID: "u-1", Username: "ada", Name: "Ada", Active: true}, nil).
		AnyTimes()

	opts := append([]httpsec.Option{
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
	}, extra...)

	return &referenceDeployment{clock: clk, store: store, live: live, opts: opts}
}

// lastAccess reads the last-access time the store holds for the live session.
func (d *referenceDeployment) lastAccess(t *testing.T) time.Time {
	t.Helper()

	stored, err := d.store.Load(context.WithoutCancel(t.Context()), d.live.ID)
	require.NoError(t, err)

	return stored.LastAccessedAt
}

// attributedClients lets the app read a client address from X-Forwarded-For
// off fiber's in-memory peer, which is the unspecified address the session
// bearer refuses to attribute a request to.
var attributedClients = fiber.Config{
	TrustProxy:         true,
	TrustProxyConfig:   fiber.TrustProxyConfig{Proxies: []string{"0.0.0.0"}},
	ProxyHeader:        fiber.HeaderXForwardedFor,
	EnableIPValidation: true,
}

func referenceRequest(ctx context.Context, reference string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/orders", nil)
	req.Header.Set(fiber.HeaderXForwardedFor, "198.51.100.7")
	req.Header.Set("Authorization", "Bearer "+reference)

	return req
}

// TestSessionReferenceBearer pins that the adapter serves a request
// authenticated by an opaque session reference, and answers an unknown one 401.
func TestSessionReferenceBearer(t *testing.T) {
	t.Parallel()

	unknown := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))

	type testCase struct {
		name      string
		reference func(d *referenceDeployment) string
		assert    func(t *testing.T, d *referenceDeployment, out *outcome, published *session.Session)
	}

	cases := []testCase{
		{
			name:      "a live reference reaches the handler with the session published",
			reference: func(d *referenceDeployment) string { return d.live.ID },
			assert: func(t *testing.T, d *referenceDeployment, out *outcome, published *session.Session) {
				assert.Equal(t, http.StatusOK, out.status)
				require.True(t, out.routeRan)
				require.NotNil(t, published, "the session is published to the route")
				assert.Equal(t, d.live.ID, published.ID)
			},
		},
		{
			name:      "an unknown reference is answered 401 and the handler never runs",
			reference: func(*referenceDeployment) string { return unknown },
			assert: func(t *testing.T, _ *referenceDeployment, out *outcome, _ *session.Session) {
				assert.Equal(t, http.StatusUnauthorized, out.status)
				assert.False(t, out.routeRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newReferenceDeployment(t)
			out := &outcome{}

			var published *session.Session

			app := fiber.New(attributedClients)
			app.Use(fibersec.Middleware(newChain(t, d.opts...)))
			app.Get("/orders", func(fc fiber.Ctx) error {
				published, _ = httpsec.SessionFromContext(fc.Context())
				out.routeRan = true

				return fc.SendStatus(http.StatusOK)
			})

			out.status = serve(t, app, referenceRequest(t.Context(), tc.reference(d))).status
			tc.assert(t, d, out, published)
		})
	}
}

// TestActivityRecordedAfterTheHandler pins that a session's activity is
// written once the handler has returned, and also when an interceptor inside
// the bearer refused the request.
//
// It stands apart from TestSessionReferenceBearer: each case moves the clock
// between opening the session and serving it.
func TestActivityRecordedAfterTheHandler(t *testing.T) {
	t.Parallel()

	const elapsed = 10 * time.Minute

	type testCase struct {
		name   string
		extra  []httpsec.Option
		assert func(t *testing.T, out *outcome, duringHandler, after, started time.Time)
	}

	cases := []testCase{
		{
			name: "a served request advances it after the response",
			assert: func(t *testing.T, out *outcome, duringHandler, after, started time.Time) {
				require.True(t, out.routeRan)
				assert.Equal(t, http.StatusOK, out.status)
				assert.True(t, duringHandler.Equal(started), "unchanged while the handler runs")
				assert.True(t, after.Equal(started.Add(elapsed)), "advanced to the request's time afterwards")
			},
		},
		{
			name: "a request refused by an interceptor inside the bearer still advances it",
			extra: []httpsec.Option{
				httpsec.RegisterInterceptor(refusing(errInnerRefusal, nil), httpsec.OrderAuthorizer),
			},
			assert: func(t *testing.T, out *outcome, _, after, started time.Time) {
				assert.False(t, out.routeRan)
				assert.NotEqual(t, http.StatusOK, out.status)
				assert.True(t, after.Equal(started.Add(elapsed)), "a refused caller was still there")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newReferenceDeployment(t, tc.extra...)
			started := d.lastAccess(t)
			d.clock.advance(elapsed)

			out := &outcome{}

			var duringHandler time.Time

			app := fiber.New(attributedClients)
			app.Use(fibersec.Middleware(newChain(t, d.opts...)))
			app.Get("/orders", func(fc fiber.Ctx) error {
				duringHandler = d.lastAccess(t)
				out.routeRan = true

				return fc.SendStatus(http.StatusOK)
			})

			out.status = serve(t, app, referenceRequest(t.Context(), d.live.ID)).status
			tc.assert(t, out, duringHandler, d.lastAccess(t), started)
		})
	}
}

// TestFiber_RecoveryCooldownHoldsForEveryPathFiberRoutesToTheMarkedRoute pins
// that a route marked for the recovery cool-down stays refused under every
// spelling fiber's default routing sends to it: letter case and trailing
// slashes are the same route to fiber, so they must be to the cool-down.
//
// It stands apart from TestSessionReferenceBearer: each case seeds a completed
// recovery and marks a route for its cool-down.
func TestFiber_RecoveryCooldownHoldsForEveryPathFiberRoutesToTheMarkedRoute(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		path   string
		assert func(t *testing.T, res response, routeRan bool)
	}

	refused := func(t *testing.T, res response, routeRan bool) {
		t.Helper()

		assert.Equal(t, http.StatusForbidden, res.status)
		assert.False(t, routeRan, "the marked route did not run during the cool-down")
	}

	cases := []testCase{
		{name: "the marked spelling", path: "/account/email", assert: refused},
		{name: "upper case", path: "/Account/Email", assert: refused},
		{name: "one trailing slash", path: "/account/email/", assert: refused},
		{name: "two trailing slashes", path: "/account/email//", assert: refused},
		{
			name: "a route that is not marked is served",
			path: "/account/name",
			assert: func(t *testing.T, res response, _ bool) {
				t.Helper()

				assert.Equal(t, http.StatusNoContent, res.status)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			records := recovery.NewMemoryRecordStore()

			rid, err := id.NewV7Generator().NewID()
			require.NoError(t, err)

			completedAt := time.Now().Add(-time.Hour)
			require.NoError(t, records.Insert(t.Context(), recovery.Record{
				ID: rid, User: "u-1", StartedAt: completedAt, NotBefore: completedAt, CompletedAt: completedAt,
			}))

			opts, _ := authenticated(t)
			opts = append(opts, httpsec.EnableRecoveryCooldown(
				records, 48*time.Hour, httpsec.Route{Method: http.MethodGet, Path: "/account/email"}))

			var routeRan bool

			app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
			app.Use(fibersec.Middleware(newChain(t, opts...)))

			handler := func(fc fiber.Ctx) error {
				routeRan = true

				return fc.SendStatus(http.StatusNoContent)
			}
			app.Get("/account/email", handler)
			app.Get("/account/name", handler)

			res := serve(t, app, bearerRequest(t.Context(), http.MethodGet, tc.path))

			tc.assert(t, res, routeRan)
		})
	}
}
