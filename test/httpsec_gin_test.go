package test_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
	"github.com/kartaladev/scrty/session"
	httpsecconformance "github.com/kartaladev/scrty/test/httpsecconformance"
	identitytest "github.com/kartaladev/scrty/test/identity"
)

// TestMain puts gin in test mode, so the output of a failing row is the row's
// and not gin's start-up banner.
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	os.Exit(m.Run())
}

// ginAdapter runs the conformance table on the gin integration.
//
// Nothing here configures error handling: gin's own error channel is where a
// refusal goes, and the collecting middleware only reads it. What a client is
// answered is therefore whatever the adapter's default does, which is what the
// table compares against net/http.
type ginAdapter struct{}

func (ginAdapter) Serve(
	t *testing.T,
	spec httpsecconformance.ChainSpec,
	req httpsecconformance.RequestSpec,
) httpsecconformance.Result {
	t.Helper()

	var res httpsecconformance.Result

	chain := spec.NewChain(t)

	engine := gin.New()

	if spec.Upstream {
		engine.Use(ginUpstream())
	}

	// Outside the chain, so it still sees a refused request: it runs the rest
	// of the handlers and reads what they left on gin's error channel.
	engine.Use(ginCollecting(&res))
	engine.Use(ginsec.Middleware(chain))

	for _, route := range spec.Routes {
		engine.Handle(route.Method, route.Path, ginRoute(&res, route, spec)...)
	}

	if spec.NoRoute {
		engine.NoRoute(func(gc *gin.Context) {
			res.NoRouteRan = true

			_, _ = gc.Writer.WriteString(httpsecconformance.NoRouteBody)
		})
	}

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, nethttpRequest(t, req))

	res.Status, res.Header, res.Body = rec.Code, rec.Header(), rec.Body.String()

	return res
}

// ginRoute is one application route, preceded by the guard the scenario asked
// for.
func ginRoute(
	res *httpsecconformance.Result,
	route httpsecconformance.Route,
	spec httpsecconformance.ChainSpec,
) []gin.HandlerFunc {
	var handlers []gin.HandlerFunc

	if spec.Guard.Kind != httpsecconformance.GuardNone && spec.Guard.Path == route.Path {
		handlers = append(handlers, ginGuard(spec.Guard))
	}

	return append(handlers, func(gc *gin.Context) {
		res.RouteRan = true
		httpsecconformance.ReadContext(gc.Request.Context(), res)

		if route.Status != 0 {
			gc.Status(route.Status)
		}

		if route.Body != "" {
			_, _ = gc.Writer.WriteString(route.Body)
		}
	})
}

// ginGuard builds the guard the scenario named, with gin's own defaults: the
// refusal on the error channel and the mapped status set but not committed.
func ginGuard(spec httpsecconformance.GuardSpec) gin.HandlerFunc {
	guards := ginsec.NewGuards(spec.Authorizer)

	if spec.Kind == httpsecconformance.GuardAuthenticated {
		return guards.RequireAuthenticated()
	}

	return guards.
		ResourcePrivileges(httpsecconformance.GuardGroup, httpsecconformance.GuardResource).
		RequireOne(httpsecconformance.GuardPrivilegeName)
}

// ginCollecting reads gin's error channel once everything behind it has run,
// which is where a gin consumer already handles every other error. It writes
// nothing, so the adapter's own answer stands.
func ginCollecting(res *httpsecconformance.Result) gin.HandlerFunc {
	return func(gc *gin.Context) {
		gc.Next()

		if len(gc.Errors) > 0 {
			res.Refusal = gc.Errors[0].Err
		}
	}
}

// ginUpstream is middleware outside the chain, standing in for a consumer's own
// tracing: what it publishes must still be readable behind the chain.
func ginUpstream() gin.HandlerFunc {
	return func(gc *gin.Context) {
		gc.Request = gc.Request.WithContext(context.WithValue(gc.Request.Context(),
			httpsecconformance.UpstreamKey{}, httpsecconformance.UpstreamValue))

		gc.Next()
	}
}

// TestConformanceGin runs the reference table on gin. A row that fails here and
// passes on net/http is a defect in the gin integration, which is the whole
// reason the table is shared.
func TestConformanceGin(t *testing.T) {
	t.Parallel()

	httpsecconformance.Run(t, ginAdapter{})
}

// sessionReferenceFixture is a chain in the session-reference bearer mode over
// the memory session store and the in-memory identity store, holding two
// session references of one user: one live, and one superseded by a renewal
// whose window has ended. Each is in a family of its own, so presenting the
// reused one revokes nothing the live one depends on.
type sessionReferenceFixture struct {
	chain    *httpsec.Chain
	sessions *session.Manager
	live     string
	reused   string
	// successor is the identifier the rotation of the reused session issued;
	// refusing reuse revokes its family, so it stops loading too.
	successor string
}

func newSessionReferenceFixture(t *testing.T) sessionReferenceFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC))

	sessions, err := session.NewManager(session.WithClock(clk),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
	require.NoError(t, err)

	users := identitytest.NewInMemoryStore()
	user, err := users.Provision(t.Context(), "ada")
	require.NoError(t, err)

	live, err := sessions.Create(t.Context(), user.ID, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	reused, err := sessions.Create(t.Context(), user.ID, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	successor, _, err := sessions.RotateWithGrace(t.Context(), reused, 30*time.Second)
	require.NoError(t, err)

	clk.Advance(31 * time.Second)

	chain, err := httpsec.New(
		httpsec.WithClock(clk),
		httpsec.WithLogger(slog.New(slog.DiscardHandler)),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
	)
	require.NoError(t, err)

	return sessionReferenceFixture{
		chain: chain, sessions: sessions, live: live.ID, reused: reused.ID, successor: successor.ID,
	}
}

// TestSessionBearerGin runs the session-reference bearer through the gin
// integration: a live reference reaches the route with its session, and a
// reused one is refused 401. The integration needs no change for the mode.
func TestSessionBearerGin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		reference func(f sessionReferenceFixture) string
		assert    func(t *testing.T, f sessionReferenceFixture, rec *httptest.ResponseRecorder, seen string)
	}

	cases := []testCase{
		{
			name:      "a live reference authenticates",
			reference: func(f sessionReferenceFixture) string { return f.live },
			assert: func(t *testing.T, f sessionReferenceFixture, rec *httptest.ResponseRecorder, seen string) {
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.Equal(t, f.live, seen, "the route sees the referenced session")
			},
		},
		{
			name:      "a reused reference is refused",
			reference: func(f sessionReferenceFixture) string { return f.reused },
			assert: func(t *testing.T, f sessionReferenceFixture, rec *httptest.ResponseRecorder, seen string) {
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
				assert.Empty(t, seen, "the route never ran")

				_, err := f.sessions.Load(t.Context(), f.successor)
				require.ErrorIs(t, err, session.ErrSessionNotFound, "the family was revoked, successor included")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSessionReferenceFixture(t)

			var seen string

			engine := gin.New()
			engine.Use(ginsec.Middleware(f.chain))
			engine.GET("/orders", func(gc *gin.Context) {
				if s, ok := httpsec.SessionFromContext(gc.Request.Context()); ok {
					seen = s.ID
				}

				gc.Status(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil)
			req.Header.Set("Authorization", "Bearer "+tc.reference(f))

			rec := httptest.NewRecorder()
			engine.ServeHTTP(rec, req)

			tc.assert(t, f, rec, seen)
		})
	}
}

// referenceUnknownTo is the n-th well-formed session identifier no session
// answers to.
func referenceUnknownTo(n int) string {
	raw := make([]byte, 32)
	binary.BigEndian.PutUint32(raw, uint32(n)) //nolint:gosec // n is a small non-negative loop index

	return base64.RawURLEncoding.EncodeToString(raw)
}

// TestSessionBearerFloodedSourceGin runs the per-source throttle through the
// gin integration: a source that presented 100 unknown references is refused
// even with a live one, and a source that did not is served.
func TestSessionBearerFloodedSourceGin(t *testing.T) {
	t.Parallel()

	f := newSessionReferenceFixture(t)

	engine := gin.New()
	engine.Use(ginsec.Middleware(f.chain))
	engine.GET("/orders", func(gc *gin.Context) { gc.Status(http.StatusOK) })

	send := func(remote, reference string) int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil)
		req.RemoteAddr = remote + ":51000"
		req.Header.Set("Authorization", "Bearer "+reference)

		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)

		return rec.Code
	}

	for i := range 100 {
		require.Equal(t, http.StatusUnauthorized, send("203.0.113.7", referenceUnknownTo(i)))
	}

	assert.Equal(t, http.StatusUnauthorized, send("203.0.113.7", f.live), "the flooded source is refused")
	assert.Equal(t, http.StatusOK, send("198.51.100.4", f.live), "another source is served")
}
