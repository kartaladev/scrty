package fibersec_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// retryOnlyStore is a session store whose authenticator's read fails while fail says so.
type retryOnlyStore struct {
	session.Store

	fail func() bool
}

func (s retryOnlyStore) Load(ctx context.Context, sid string) (*session.Session, error) {
	if s.fail() {
		return nil, errors.New("store down")
	}

	return s.Store.Load(ctx, sid)
}

// retryOnlyRig is a chain with the stream on this adapter, behind a real server.
type retryOnlyRig struct {
	chain *httpsec.Chain
	url   string
	sid   string
	down  *atomic.Bool
}

func newRetryOnlyRig(t *testing.T) retryOnlyRig {
	t.Helper()

	// began answers as a consumer does whose interceptor began a response and then returned an error.
	began := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if ex.Request.Header("X-Begin") == "" {
			return next(ex)
		}

		ex.Writer.SetHeader("Content-Type", "text/plain")
		ex.Writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = ex.Writer.Write([]byte("maintenance"))

		return errors.New("consumer: under maintenance")
	}), httpsec.After(httpsec.OrderBearerToken))

	// deferredCancel is the ordinary context a consumer's interceptor makes.
	deferredCancel := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if ex.Request.Header("X-Deferred-Cancel") == "" {
			return next(ex)
		}

		ctx, cancel := context.WithTimeout(ex.Context(), time.Minute)
		defer cancel()

		ex.SetContext(ctx)

		return next(ex)
	}), httpsec.After(httpsec.OrderCSRF))

	// refusedOutside refuses on the way out, around what answered with a retry.
	refusedOutside := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		err := next(ex)

		if ex.Request.Header("X-Refuse-Outside") != "" {
			return httpsec.ErrCrossSiteStream
		}

		return err
	}), httpsec.Before(httpsec.OrderCORS))

	down := &atomic.Bool{}
	store := retryOnlyStore{Store: must.Must(session.NewMemoryStore()), fail: down.Load}
	sessions := must.Must(session.New(session.WithStore(store),
		session.WithIdleTimeout(30*time.Minute), session.WithAbsoluteTimeout(12*time.Hour)))

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().Return(
		&identity.Details{ID: "u-1", Active: true}, nil)

	chain := must.Must(httpsec.New(
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableSessionSignals(httpsec.SessionSignals{MaxPerSignIn: 1, Heartbeat: 5 * time.Second}),
		httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{"http://example.com"}, AllowCredentials: true}),
		began, deferredCancel, refusedOutside,
	))

	s := must.Must(sessions.Create(t.Context(), identity.UserID("u-1"), session.WithFirstFactor(factor.Password)))

	return retryOnlyRig{chain: chain, url: retryOnlyURL(t, chain), sid: s.ID, down: down}
}

// ask asks for the stream cross-origin, with the headers named set.
func (r retryOnlyRig) ask(ctx context.Context, t *testing.T, headers ...string) *http.Response {
	t.Helper()

	req := must.Must(http.NewRequestWithContext(ctx, http.MethodGet, r.url+httpsec.DefaultSessionSignalsPath, http.NoBody))
	req.Header.Set("Authorization", "Bearer "+r.sid)
	req.Header.Set("Origin", "http://example.com")

	for _, name := range headers {
		req.Header.Set(name, "1")
	}

	client := &http.Client{Transport: &http.Transport{}}
	t.Cleanup(client.CloseIdleConnections)

	resp, err := client.Do(req)
	require.NoError(t, err)

	return resp
}

// requireRetryOnly asserts resp is 200 with the stream's headers, CORS's and a body of one retry.
func requireRetryOnly(t *testing.T, resp *http.Response) {
	t.Helper()

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	assert.Equal(t, "http://example.com", resp.Header.Get("Access-Control-Allow-Origin"), "a cross-origin EventSource could not read it")
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
	assert.True(t, strings.HasPrefix(string(body), "retry: "), "body: %q", body)
	assert.Equal(t, 1, strings.Count(string(body), "\n\n"), "body: %q", body)
}

// TestSessionSignals_Caps_RetryOnlyOnThisAdapter is a request for the stream that cannot be served now,
// over a real connection of this adapter.
func TestSessionSignals_Caps_RetryOnlyOnThisAdapter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, r retryOnlyRig)
	}

	cases := []testCase{
		{
			name: "a cap",
			assert: func(t *testing.T, r retryOnlyRig) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				first := r.ask(ctx, t)
				defer func() { _ = first.Body.Close() }()

				require.Equal(t, http.StatusOK, first.StatusCode)

				line := make([]byte, 16)
				_, err := first.Body.Read(line)
				require.NoError(t, err)

				requireRetryOnly(t, r.ask(t.Context(), t))
				assert.EqualValues(t, 1, r.chain.SessionSignalStats().RefusedByCap)
			},
		},
		{
			name: "a dependency failure",
			assert: func(t *testing.T, r retryOnlyRig) {
				r.down.Store(true)

				requireRetryOnly(t, r.ask(t.Context(), t))
				assert.EqualValues(t, 1, r.chain.SessionSignalStats().ReloadFailures)
			},
		},
		{
			name: "a dependency failure behind an interceptor's deferred cancel",
			assert: func(t *testing.T, r retryOnlyRig) {
				r.down.Store(true)

				requireRetryOnly(t, r.ask(t.Context(), t, "X-Deferred-Cancel"))
				assert.EqualValues(t, 1, r.chain.SessionSignalStats().ReloadFailures)
			},
		},
		{
			name: "after a close",
			assert: func(t *testing.T, r retryOnlyRig) {
				require.NoError(t, r.chain.CloseSessionSignals(t.Context()))

				resp := r.ask(t.Context(), t)
				assert.True(t, resp.Close, "Connection: close")
				requireRetryOnly(t, resp)
			},
		},
		{
			name: "a chain that refuses around the answer sends only the refusal",
			assert: func(t *testing.T, r retryOnlyRig) {
				r.down.Store(true)

				resp := r.ask(t.Context(), t, "X-Refuse-Outside")
				defer func() { _ = resp.Body.Close() }()

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)

				assert.Equal(t, http.StatusForbidden, resp.StatusCode)
				assert.NotContains(t, string(body), "retry:", "a body wrote over the refusal")
			},
		},
		{
			name: "a response a consumer began keeps its headers",
			assert: func(t *testing.T, r retryOnlyRig) {
				resp := r.ask(t.Context(), t, "X-Begin")
				defer func() { _ = resp.Body.Close() }()

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)

				assert.Equal(t, "maintenance", string(body))
				assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
				assert.Empty(t, resp.Header.Get("X-Accel-Buffering"))
				assert.Empty(t, resp.Header.Get("Cache-Control"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newRetryOnlyRig(t))
		})
	}
}

// retryOnlyURL serves the chain with the adapter's error handler, and answers 404 past it.
func retryOnlyURL(t *testing.T, chain *httpsec.Chain) string {
	t.Helper()

	app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
	app.Use(fibersec.Middleware(chain))
	app.Use(func(c fiber.Ctx) error { return c.SendStatus(http.StatusNotFound) })

	return "http://" + serveFiber(t, app)
}
