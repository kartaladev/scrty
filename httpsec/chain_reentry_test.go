package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// reentryChain builds a chain whose only consumer interceptor counts the runs
// that reach it, at the outermost slot, so every run the chain starts is
// counted before any built-in could stop it.
func reentryChain(t *testing.T, runs *atomic.Int32) *httpsec.Chain {
	t.Helper()

	c, err := httpsec.New(httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
		func(ex *httpsec.Exchange, next httpsec.Next) error {
			runs.Add(1)
			return next(ex)
		}), httpsec.Order(1)))
	require.NoError(t, err)

	return c
}

// reentryOutcome is what a case's request produced.
type reentryOutcome struct {
	status  int
	a, b    int32
	handled int32
}

// TestChain_ReentryPassesThrough pins that a chain entered again on a request
// it is already running on, for the same method and escaped path, passes the
// request straight on, while a different chain, or the same chain for another
// method or path, runs in full.
func TestChain_ReentryPassesThrough(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// build wraps the application's handler in chains a and b as the case
		// mounts them, and returns the handler a request is sent to.
		build  func(t *testing.T, a, b *httpsec.Chain, handled *atomic.Int32) http.Handler
		method string
		target string
		assert func(t *testing.T, got reentryOutcome)
	}

	app := func(handled *atomic.Int32) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handled.Add(1)
			w.WriteHeader(http.StatusNoContent)
		})
	}

	cases := []testCase{
		{
			name: "same chain nested",
			build: func(_ *testing.T, a, _ *httpsec.Chain, handled *atomic.Int32) http.Handler {
				return a.Middleware()(a.Middleware()(app(handled)))
			},
			assert: func(t *testing.T, got reentryOutcome) {
				assert.Equal(t, http.StatusNoContent, got.status)
				assert.EqualValues(t, 1, got.a, "runs of the chain")
				assert.EqualValues(t, 1, got.handled, "handler calls")
			},
		},
		{
			name: "same chain nested on a HEAD request",
			build: func(_ *testing.T, a, _ *httpsec.Chain, handled *atomic.Int32) http.Handler {
				return a.Middleware()(a.Middleware()(app(handled)))
			},
			method: http.MethodHead,
			assert: func(t *testing.T, got reentryOutcome) {
				assert.EqualValues(t, 1, got.a, "runs of the chain")
				assert.EqualValues(t, 1, got.handled, "handler calls")
			},
		},
		{
			name: "different chain nested",
			build: func(_ *testing.T, a, b *httpsec.Chain, handled *atomic.Int32) http.Handler {
				return a.Middleware()(b.Middleware()(app(handled)))
			},
			assert: func(t *testing.T, got reentryOutcome) {
				assert.Equal(t, http.StatusNoContent, got.status)
				assert.EqualValues(t, 1, got.a, "runs of the outer chain")
				assert.EqualValues(t, 1, got.b, "runs of the inner chain")
				assert.EqualValues(t, 1, got.handled, "handler calls")
			},
		},
		{
			name: "same chain again inside a different one",
			build: func(_ *testing.T, a, b *httpsec.Chain, handled *atomic.Int32) http.Handler {
				return a.Middleware()(b.Middleware()(a.Middleware()(app(handled))))
			},
			assert: func(t *testing.T, got reentryOutcome) {
				assert.Equal(t, http.StatusNoContent, got.status)
				assert.EqualValues(t, 1, got.a, "runs of the chain mounted twice")
				assert.EqualValues(t, 1, got.b, "runs of the chain between")
				assert.EqualValues(t, 1, got.handled, "handler calls")
			},
		},
		{
			name: "same chain on an in-process forward to another path",
			build: func(_ *testing.T, a, _ *httpsec.Chain, handled *atomic.Int32) http.Handler {
				other := a.Middleware()(app(handled))

				return a.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fwd := r.Clone(r.Context())
					fwd.URL.Path, fwd.URL.RawPath = "/other", ""
					other.ServeHTTP(w, fwd)
				}))
			},
			assert: func(t *testing.T, got reentryOutcome) {
				assert.Equal(t, http.StatusNoContent, got.status)
				assert.EqualValues(t, 2, got.a, "runs of the chain, one per path")
				assert.EqualValues(t, 1, got.handled, "handler calls")
			},
		},
		{
			name: "same chain on an in-process forward with another method",
			build: func(_ *testing.T, a, _ *httpsec.Chain, handled *atomic.Int32) http.Handler {
				other := a.Middleware()(app(handled))

				return a.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fwd := r.Clone(r.Context())
					fwd.Method = http.MethodHead
					other.ServeHTTP(w, fwd)
				}))
			},
			assert: func(t *testing.T, got reentryOutcome) {
				assert.EqualValues(t, 2, got.a, "runs of the chain, one per method")
				assert.EqualValues(t, 1, got.handled, "handler calls")
			},
		},
		{
			name: "the request's context used again after its run returned",
			build: func(t *testing.T, a, _ *httpsec.Chain, handled *atomic.Int32) http.Handler {
				var kept context.Context

				first := a.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					kept = context.WithoutCancel(r.Context())
				}))
				second := a.Middleware()(app(handled))

				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					first.ServeHTTP(httptest.NewRecorder(), r)
					require.NotNil(t, kept)
					// The run that marked kept is over, so a request sent on it
					// later, for the same method and path, is judged in full.
					second.ServeHTTP(w, r.WithContext(kept))
				})
			},
			assert: func(t *testing.T, got reentryOutcome) {
				assert.Equal(t, http.StatusNoContent, got.status)
				assert.EqualValues(t, 2, got.a, "runs of the chain")
				assert.EqualValues(t, 1, got.handled, "handler calls")
			},
		},
		{
			name: "dot segment refused at the outer entry",
			build: func(_ *testing.T, a, _ *httpsec.Chain, handled *atomic.Int32) http.Handler {
				return a.Middleware()(a.Middleware()(app(handled)))
			},
			target: "/a/%2e%2e/b",
			assert: func(t *testing.T, got reentryOutcome) {
				assert.Equal(t, http.StatusBadRequest, got.status)
				assert.EqualValues(t, 0, got.a, "runs of the chain")
				assert.EqualValues(t, 0, got.handled, "handler calls")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var runsA, runsB, handled atomic.Int32

			h := tc.build(t, reentryChain(t, &runsA), reentryChain(t, &runsB), &handled)

			method, target := tc.method, tc.target
			if method == "" {
				method = http.MethodGet
			}

			if target == "" {
				target = "/x"
			}

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, target, nil))

			tc.assert(t, reentryOutcome{status: rec.Code, a: runsA.Load(), b: runsB.Load(), handled: handled.Load()})
		})
	}
}

// TestChain_ReentryStreamOnDoubleMount pins that the session signal stream,
// served by a chain mounted twice, opens once and ends when its client leaves.
func TestChain_ReentryStreamOnDoubleMount(t *testing.T) {
	t.Parallel()

	var (
		fixture *signalsFixture
		runs    atomic.Int32
	)

	f := newSignalsFixture(t, signalsSetup{
		opts: func(f *signalsFixture) []httpsec.Option {
			fixture = f

			return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
				func(ex *httpsec.Exchange, next httpsec.Next) error {
					runs.Add(1)
					return next(ex)
				}), httpsec.Order(1))}
		},
		// The chain is mounted a second time outside its own mount.
		wrapHandler: func(h http.Handler) http.Handler { return fixture.chain.Middleware()(h) },
	})

	s := f.signIn(t, "u-1")

	resp, cancel := f.openStream(t, s.ID)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	f.requireOpen(t)

	cancel()
	f.waitDone(t)

	assert.EqualValues(t, 1, runs.Load(), "runs of the chain mounted twice")

	// A request to the application's own route through the same double mount
	// runs the chain once too.
	runs.Store(0)

	got := f.send(t.Context(), t, http.MethodGet, "/app", s.ID)
	f.waitDone(t)

	assert.Equal(t, signalsDownstreamStatus, got.StatusCode)
	assert.EqualValues(t, 1, runs.Load(), "runs of the chain mounted twice")
}

// TestChain_ExchangeRunAgainRunsInFull pins that an exchange run through a
// chain a second time, after its first run returned, is judged in full: the
// first run's mark is still on its context, and is over.
func TestChain_ExchangeRunAgainRunsInFull(t *testing.T) {
	t.Parallel()

	var runs atomic.Int32

	c := reentryChain(t, &runs)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
	ex := httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(r), httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))
	run := c.Assemble(func(*httpsec.Exchange) error { return nil })

	for range 2 {
		require.NoError(t, run(ex))
	}

	assert.EqualValues(t, 2, runs.Load(), "runs of the chain")
}
