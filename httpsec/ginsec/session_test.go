package ginsec_test

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

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// errInnerRefusal is what a consumer interceptor inside the session bearer
// refuses with.
var errInnerRefusal = errors.New("ginsec_test: refused inside the bearer")

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

func referenceRequest(ctx context.Context, reference string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/orders", nil)
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
		assert    func(t *testing.T, d *referenceDeployment, out *served, published *session.Session)
	}

	cases := []testCase{
		{
			name:      "a live reference reaches the handler with the session published",
			reference: func(d *referenceDeployment) string { return d.live.ID },
			assert: func(t *testing.T, d *referenceDeployment, out *served, published *session.Session) {
				assert.Equal(t, http.StatusOK, out.rec.Code)
				require.True(t, out.routeRan)
				require.NotNil(t, published, "the session is published to the route")
				assert.Equal(t, d.live.ID, published.ID)
			},
		},
		{
			name:      "an unknown reference is answered 401 and the handler never runs",
			reference: func(*referenceDeployment) string { return unknown },
			assert: func(t *testing.T, _ *referenceDeployment, out *served, _ *session.Session) {
				assert.Equal(t, http.StatusUnauthorized, out.rec.Code)
				assert.False(t, out.routeRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newReferenceDeployment(t)
			out := &served{}

			var published *session.Session

			eng := gin.New()
			eng.Use(ginsec.Middleware(newChain(t, d.opts...)))
			eng.GET("/orders", func(gc *gin.Context) {
				published, _ = httpsec.SessionFromContext(gc.Request.Context())
				out.routeRan = true
				gc.Status(http.StatusOK)
			})

			out.rec = serve(eng, referenceRequest(t.Context(), tc.reference(d)))
			tc.assert(t, d, out, published)
		})
	}
}

// TestActivityRecordedAfterTheHandler pins that a session's activity is
// written once the handler has returned, and also when an interceptor inside
// the bearer refused the request.
func TestActivityRecordedAfterTheHandler(t *testing.T) {
	t.Parallel()

	const elapsed = 10 * time.Minute

	type testCase struct {
		name   string
		extra  []httpsec.Option
		assert func(t *testing.T, out *served, duringHandler, after, started time.Time)
	}

	cases := []testCase{
		{
			name: "a served request advances it after the response",
			assert: func(t *testing.T, out *served, duringHandler, after, started time.Time) {
				require.True(t, out.routeRan)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.True(t, duringHandler.Equal(started), "unchanged while the handler runs")
				assert.True(t, after.Equal(started.Add(elapsed)), "advanced to the request's time afterwards")
			},
		},
		{
			name: "a request refused by an interceptor inside the bearer still advances it",
			extra: []httpsec.Option{
				httpsec.RegisterInterceptor(refusing(errInnerRefusal, nil), httpsec.OrderAuthorizer),
			},
			assert: func(t *testing.T, out *served, _, after, started time.Time) {
				assert.False(t, out.routeRan)
				assert.NotEqual(t, http.StatusOK, out.rec.Code)
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

			out := &served{}

			var duringHandler time.Time

			eng := gin.New()
			eng.Use(ginsec.Middleware(newChain(t, d.opts...)))
			eng.GET("/orders", func(gc *gin.Context) {
				duringHandler = d.lastAccess(t)
				out.routeRan = true
				gc.Status(http.StatusOK)
			})

			out.rec = serve(eng, referenceRequest(t.Context(), d.live.ID))
			tc.assert(t, out, duringHandler, d.lastAccess(t), started)
		})
	}
}
