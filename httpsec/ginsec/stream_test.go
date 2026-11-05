package ginsec_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
)

const (
	// streamWriteTimeout is the write timeout every stream's server runs under.
	streamWriteTimeout = 3 * time.Second

	// streamBound fails a test that would otherwise wait for ever. No test waits for
	// it to pass.
	streamBound = 10 * time.Second

	// streamEvent is one event as a stream writes it, and streamLine its first
	// line as the client reads it.
	streamEvent = "data: e\n\n"
	streamLine  = "data: e\n"
)

// serveStream puts serve in the chain in front of a gin engine on a real server,
// under streamWriteTimeout, because gin's writer has to reach a real connection's
// deadline for any of this to mean anything.
func serveStream(t *testing.T, serve func(ex *httpsec.Exchange) error) *httptest.Server {
	t.Helper()

	chain, err := httpsec.New(httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error { return serve(ex) }),
		httpsec.OrderBearerToken))
	require.NoError(t, err)

	engine := gin.New()
	engine.Use(ginsec.Middleware(chain))
	engine.GET("/stream", func(*gin.Context) {})

	srv := httptest.NewUnstartedServer(engine)
	srv.Config.WriteTimeout = streamWriteTimeout
	srv.Start()
	t.Cleanup(srv.Close)

	return srv
}

// openStream sends the request on ctx, leaving the body for the row to read. The
// whole exchange is bounded by streamBound, so a response that never comes or never
// ends fails the row instead of hanging it.
//
// The body is closed when the test ends, which the bodyclose linter cannot see, so the
// directive below marks the response as handled.
// bodyclose:handled
func openStream(ctx context.Context, t *testing.T, srv *httptest.Server) *http.Response {
	t.Helper()

	return openStreamWithin(ctx, t, srv, streamBound)
}

// openStreamWithin is openStream for a row that lasts longer than streamBound.
//
// The body is closed when the test ends, which the bodyclose linter cannot see, so the
// directive below marks the response as handled.
// bodyclose:handled
func openStreamWithin(ctx context.Context, t *testing.T, srv *httptest.Server, bound time.Duration) *http.Response {
	t.Helper()

	ctx, cancel := context.WithTimeout(ctx, bound)
	t.Cleanup(cancel)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/stream", http.NoBody)
	require.NoError(t, err)

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)

	t.Cleanup(func() { _ = resp.Body.Close() })

	return resp
}

// hold is how a body waits for ch. The server cannot close while its handler runs,
// so a body that waited for ever would hang the test's cleanup: it reports and
// returns instead.
func hold(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(streamBound):
		t.Errorf("a body timed out waiting for %s", what)
	}
}

func writeAndFlush(w httpsec.EventWriter) error {
	if _, err := io.WriteString(w, streamEvent); err != nil {
		return err
	}

	return w.Flush()
}

// TestGin_Stream is the stream through ginsec.Middleware. Gin uses the net/http
// writer, so what these rows prove is that it reaches gin's: that
// http.ResponseController gets from gin's writer to the connection.
func TestGin_Stream(t *testing.T) {
	t.Parallel()

	const (
		beatGap = 5 * time.Second
		lasting = 30 * time.Second
	)

	cases := []struct {
		name   string
		assert func(t *testing.T)
	}{
		{
			name: "the client receives an event while the body is still running",
			assert: func(t *testing.T) {
				release, returned := make(chan struct{}), make(chan struct{})
				srv := serveStream(t, func(ex *httpsec.Exchange) error {
					defer close(returned)

					return ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						if err := writeAndFlush(w); err != nil {
							return err
						}

						hold(t, release, "the row's release")

						return nil
					})
				})

				r := bufio.NewReader(openStream(t.Context(), t, srv).Body)

				line, err := r.ReadString('\n')
				require.NoError(t, err)
				assert.Equal(t, streamLine, line)

				select {
				case <-returned:
					t.Error("Stream returned before its body did: the body runs inline")
				default:
				}

				close(release)

				_, err = io.ReadAll(r)
				require.NoError(t, err)
			},
		},
		{
			name: "a stream lives through gaps longer than the write timeout",
			assert: func(t *testing.T) {
				srv := serveStream(t, func(ex *httpsec.Exchange) error {
					return ex.Writer.Stream(ex.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
						for i := 0; ; i++ {
							if err := writeAndFlush(w); err != nil {
								return err
							}

							if i == int(lasting/beatGap) {
								return nil
							}

							select {
							case <-ctx.Done():
								return ctx.Err()
							case <-time.After(beatGap):
							}
						}
					})
				})

				start := time.Now()
				r := bufio.NewReader(openStreamWithin(t.Context(), t, srv, lasting+streamBound).Body)
				events := 0

				for {
					line, err := r.ReadString('\n')
					if errors.Is(err, io.EOF) {
						break
					}

					require.NoError(t, err, "the stream was cut after %v and %d events", time.Since(start), events)

					if line == streamLine {
						events++
					}
				}

				assert.Equal(t, int(lasting/beatGap)+1, events)
				assert.GreaterOrEqual(t, time.Since(start), lasting)
			},
		},
		{
			name: "an ordinary response is still ended by the write timeout",
			assert: func(t *testing.T) {
				srv := serveStream(t, func(ex *httpsec.Exchange) error {
					_, _ = io.WriteString(ex.Writer, "before")

					// The sleep is the behaviour under test: time passing with no
					// stream to move the deadline.
					time.Sleep(streamWriteTimeout + time.Second)

					_, _ = io.WriteString(ex.Writer, "after")

					return nil
				})

				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/stream", http.NoBody)
				require.NoError(t, err)

				resp, err := srv.Client().Do(req)
				if err == nil {
					defer func() { _ = resp.Body.Close() }()

					_, err = io.ReadAll(resp.Body)
				}

				require.Error(t, err, "the deadline passed before anything could be written")
			},
		},
		{
			name: "the client leaving ends the body's context",
			assert: func(t *testing.T) {
				ended := make(chan struct{})
				srv := serveStream(t, func(ex *httpsec.Exchange) error {
					return ex.Writer.Stream(ex.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
						if err := writeAndFlush(w); err != nil {
							return err
						}

						hold(t, ctx.Done(), "the client to leave")
						close(ended)

						return ctx.Err()
					})
				})

				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				line, err := bufio.NewReader(openStream(ctx, t, srv).Body).ReadString('\n')
				require.NoError(t, err)
				require.Equal(t, streamLine, line)

				cancel()

				select {
				case <-ended:
				case <-time.After(time.Second):
					t.Fatal("the body's context did not end within a second of the client leaving")
				}
			},
		},
		{
			name: "headers set before Stream are sent, and those set after it are not",
			assert: func(t *testing.T) {
				release := make(chan struct{})
				srv := serveStream(t, func(ex *httpsec.Exchange) error {
					ex.Writer.SetHeader("Cache-Control", "no-store")
					ex.Writer.SetHeader("Access-Control-Allow-Origin", "https://app.example")

					return ex.Writer.Stream(ex.Context(), func(context.Context, httpsec.EventWriter) error {
						ex.Writer.SetHeader("X-Too-Late", "yes")
						hold(t, release, "the row's release")

						return nil
					})
				})

				// Bounded, so a head that waits for a body waiting on release fails on
				// this request's deadline instead of hanging.
				boundedCtx, cancel := context.WithTimeout(t.Context(), streamBound)
				defer cancel()

				req, err := http.NewRequestWithContext(boundedCtx, http.MethodGet, srv.URL+"/stream", http.NoBody)
				require.NoError(t, err)

				resp, err := srv.Client().Do(req)

				close(release)
				require.NoError(t, err, "the response's head did not arrive before the body returned")

				defer func() { _ = resp.Body.Close() }()

				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
				assert.Equal(t, "https://app.example", resp.Header.Get("Access-Control-Allow-Origin"))
				assert.Empty(t, resp.Header.Get("X-Too-Late"))
			},
		},
		{
			name: "Stream after Write fails and adds nothing",
			assert: func(t *testing.T) {
				got := make(chan error, 1)
				srv := serveStream(t, func(ex *httpsec.Exchange) error {
					_, _ = io.WriteString(ex.Writer, "written")

					got <- ex.Writer.Stream(ex.Context(), func(context.Context, httpsec.EventWriter) error {
						return errors.New("this body must not run")
					})

					return nil
				})

				body, err := io.ReadAll(openStream(t.Context(), t, srv).Body)
				require.NoError(t, err)
				assert.Equal(t, "written", string(body))
				require.ErrorIs(t, <-got, httpsec.ErrStreamingStarted)
			},
		},
		{
			name: "a second Stream fails, and Write after a stream reaches nothing",
			assert: func(t *testing.T) {
				second, write := make(chan error, 1), make(chan error, 1)
				srv := serveStream(t, func(ex *httpsec.Exchange) error {
					if err := ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						return writeAndFlush(w)
					}); err != nil {
						return err
					}

					second <- ex.Writer.Stream(ex.Context(), func(context.Context, httpsec.EventWriter) error {
						return errors.New("this body must not run")
					})

					_, err := io.WriteString(ex.Writer, "after")
					write <- err

					return nil
				})

				body, err := io.ReadAll(openStream(t.Context(), t, srv).Body)
				require.NoError(t, err)
				assert.Equal(t, streamEvent, string(body))
				require.ErrorIs(t, <-second, httpsec.ErrStreamingStarted)
				require.ErrorIs(t, <-write, httpsec.ErrStreamingStarted)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t)
		})
	}
}

// TestGin_StreamContract pins, through ginsec.Middleware, the promise every adapter
// keeps to a caller that holds something for its body to free: if Stream returns nil
// the body has run, exactly once. On gin it has returned by the time a chain could
// refuse or anything could panic through it.
func TestGin_StreamContract(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		outer  func(ex *httpsec.Exchange, next httpsec.Next) error
		body   func(w httpsec.EventWriter) error
		assert func(t *testing.T, events string, readErr error, got error)
	}{
		{
			name: "a body that returns an error has run, and Stream returns nil",
			body: func(httpsec.EventWriter) error { return errors.New("the body's own failure") },
			assert: func(t *testing.T, _ string, readErr error, got error) {
				require.NoError(t, readErr)
				require.NoError(t, got)
			},
		},
		{
			name: "a chain that refuses after Stream has run the body once, and the stream stands",
			outer: func(ex *httpsec.Exchange, next httpsec.Next) error {
				if err := next(ex); err != nil {
					return err
				}

				return httpsec.ErrRequestTooLarge
			},
			body: writeAndFlush,
			assert: func(t *testing.T, events string, readErr error, got error) {
				require.NoError(t, readErr)
				require.NoError(t, got)
				assert.Equal(t, streamEvent, events)
			},
		},
		{
			name: "a body that panics has run once, ends the response and leaves the server running",
			body: func(w httpsec.EventWriter) error {
				if err := writeAndFlush(w); err != nil {
					return err
				}

				panic(http.ErrAbortHandler)
			},
			assert: func(t *testing.T, events string, readErr error, _ error) {
				require.Error(t, readErr, "the response did not end as if it were complete")
				assert.Equal(t, streamEvent, events)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var runs atomic.Int64

			got := make(chan error, 1)
			opts := []httpsec.Option{httpsec.RegisterInterceptor(
				httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
					err := ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						runs.Add(1)

						return tc.body(w)
					})
					got <- err

					return err
				}), httpsec.OrderBearerToken)}

			if tc.outer != nil {
				opts = append(opts, httpsec.RegisterInterceptor(httpsec.InterceptorFunc(tc.outer), httpsec.OrderJWKS))
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			engine := gin.New()
			engine.Use(ginsec.Middleware(chain))
			engine.GET("/stream", func(*gin.Context) {})

			srv := httptest.NewServer(engine)
			t.Cleanup(srv.Close)

			events, readErr := io.ReadAll(openStream(t.Context(), t, srv).Body)

			var returned error

			select {
			case returned = <-got:
			default:
			}

			tc.assert(t, string(events), readErr, returned)
			assert.Equal(t, int64(1), runs.Load())
		})
	}
}

// TestGin_StreamCannotFlush pins that gin's own writer, which always has a Flush, does
// not hide that what it wraps cannot flush: gin's does nothing then, and returns no
// error to say so, so a stream over it would deliver nothing and never say why. A
// wrapper a consumer puts outside the engine that has Unwrap keeps working.
func TestGin_StreamCannotFlush(t *testing.T) {
	t.Parallel()

	unsupported := func(t *testing.T, resp *http.Response, body string, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrStreamingUnsupported)
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "nothing had been written")
		assert.Empty(t, body)
	}

	cases := []struct {
		name   string
		mount  func(http.Handler) http.Handler
		assert func(t *testing.T, resp *http.Response, body string, err error)
	}{
		{
			name: "http.TimeoutHandler outside the engine",
			mount: func(next http.Handler) http.Handler {
				return http.TimeoutHandler(next, streamBound, "timed out")
			},
			assert: unsupported,
		},
		{
			name: "a wrapper with neither Flush nor Unwrap outside the engine",
			mount: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(bareWriter{w}, r)
				})
			},
			assert: unsupported,
		},
		{
			name: "a wrapper with Unwrap outside the engine keeps working",
			mount: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(unwrappingWriter{w}, r)
				})
			},
			assert: func(t *testing.T, resp *http.Response, body string, err error) {
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, streamEvent, body)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := make(chan error, 1)

			chain, err := httpsec.New(httpsec.RegisterInterceptor(
				httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
					err := ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						return writeAndFlush(w)
					})
					got <- err

					if err != nil {
						ex.Writer.WriteHeader(http.StatusNotImplemented)
					}

					return nil
				}), httpsec.OrderBearerToken))
			require.NoError(t, err)

			engine := gin.New()
			engine.Use(ginsec.Middleware(chain))
			engine.GET("/stream", func(*gin.Context) {})

			srv := httptest.NewServer(tc.mount(engine))
			t.Cleanup(srv.Close)

			resp := openStream(t.Context(), t, srv)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			tc.assert(t, resp, string(body), <-got)
		})
	}
}

// bareWriter hides everything of the writer it wraps but the three methods of
// http.ResponseWriter, as a consumer's logging or metrics wrapper does.
type bareWriter struct{ http.ResponseWriter }

// unwrappingWriter is the same wrapper with the method that lets
// http.ResponseController reach past it.
type unwrappingWriter struct{ http.ResponseWriter }

func (u unwrappingWriter) Unwrap() http.ResponseWriter { return u.ResponseWriter }

// flushErrorOnly can flush through FlushError and has no Flush, which gin's own Flush
// does not look for.
type flushErrorOnly struct{ http.ResponseWriter }

func (f flushErrorOnly) FlushError() error {
	return http.NewResponseController(f.ResponseWriter).Flush()
}

// notSupportedAtRunTime says it cannot flush only when asked, and gin's Flush would
// not ask.
type notSupportedAtRunTime struct{ http.ResponseWriter }

func (notSupportedAtRunTime) FlushError() error { return http.ErrNotSupported }

// TestGin_StreamBeneathTheEngine pins what gin's writer does over each kind of writer
// below it, on a real server and whether or not gin has a route for the path. gin
// holds the status until something writes, 404 for a path with no route, and its Flush
// looks only for http.Flusher and reports nothing. So an event must be seen arriving
// while the body is still running: a body that returned would flush it anyway.
func TestGin_StreamBeneathTheEngine(t *testing.T) {
	t.Parallel()

	const answer = "an ordinary answer"

	wrapping := func(wrapper func(http.ResponseWriter) http.ResponseWriter) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(wrapper(w), r)
			})
		}
	}

	delivers := func(t *testing.T, resp *http.Response, r *bufio.Reader, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Stream names 200 whatever gin holds")

		line, err := r.ReadString('\n')
		require.NoError(t, err)
		assert.Equal(t, streamLine, line)
	}

	refuses := func(t *testing.T, resp *http.Response, r *bufio.Reader, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrStreamingUnsupported)
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "nothing had been written")

		body, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, answer, string(body))
	}

	cases := []struct {
		name   string
		path   string
		mount  func(http.Handler) http.Handler
		assert func(t *testing.T, resp *http.Response, r *bufio.Reader, err error)
	}{
		{
			name:   "the server's own writer, on a path with a route",
			path:   "/stream",
			assert: delivers,
		},
		{
			name:   "the server's own writer, on a path with no route: 200 is named",
			path:   "/no-route",
			assert: delivers,
		},
		{
			name:   "a wrapper with only FlushError delivers",
			path:   "/stream",
			mount:  wrapping(func(w http.ResponseWriter) http.ResponseWriter { return flushErrorOnly{w} }),
			assert: delivers,
		},
		{
			name:   "a wrapper with only FlushError, on a path with no route: 200 is named",
			path:   "/no-route",
			mount:  wrapping(func(w http.ResponseWriter) http.ResponseWriter { return flushErrorOnly{w} }),
			assert: delivers,
		},
		{
			name:   "a wrapper with only Unwrap delivers",
			path:   "/stream",
			mount:  wrapping(func(w http.ResponseWriter) http.ResponseWriter { return unwrappingWriter{w} }),
			assert: delivers,
		},
		{
			name:   "a wrapper with only Unwrap, on a path with no route: 200 is named",
			path:   "/no-route",
			mount:  wrapping(func(w http.ResponseWriter) http.ResponseWriter { return unwrappingWriter{w} }),
			assert: delivers,
		},
		{
			name:   "a wrapper that says so only when asked to flush leaves an ordinary answer possible",
			path:   "/stream",
			mount:  wrapping(func(w http.ResponseWriter) http.ResponseWriter { return notSupportedAtRunTime{w} }),
			assert: refuses,
		},
		{
			name:   "the same, on a path with no route",
			path:   "/no-route",
			mount:  wrapping(func(w http.ResponseWriter) http.ResponseWriter { return notSupportedAtRunTime{w} }),
			assert: refuses,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			release := make(chan struct{})
			got := make(chan error, 1)

			chain, err := httpsec.New(httpsec.RegisterInterceptor(
				httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
					err := ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						got <- nil

						if err := writeAndFlush(w); err != nil {
							return err
						}

						hold(t, release, "the row's release")

						return nil
					})
					if err != nil {
						got <- err

						ex.Writer.WriteHeader(http.StatusNotImplemented)
						_, _ = io.WriteString(ex.Writer, answer)
					}

					return nil
				}), httpsec.OrderBearerToken))
			require.NoError(t, err)

			engine := gin.New()
			engine.Use(ginsec.Middleware(chain))
			engine.GET("/stream", func(*gin.Context) {})

			var handler http.Handler = engine
			if tc.mount != nil {
				handler = tc.mount(handler)
			}

			srv := httptest.NewServer(handler)
			t.Cleanup(srv.Close)

			releaseOnce := sync.OnceFunc(func() { close(release) })
			t.Cleanup(releaseOnce)

			ctx, cancel := context.WithTimeout(t.Context(), streamBound)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+tc.path, http.NoBody)
			require.NoError(t, err)

			resp, err := srv.Client().Do(req)
			require.NoError(t, err, "neither the head nor a refusal reached the client while the body ran")

			defer func() { _ = resp.Body.Close() }()

			tc.assert(t, resp, bufio.NewReader(resp.Body), <-got)
		})
	}
}

// heldHeadWriter chooses its encoding at the first write, and holds the status until
// then, so its Flush does nothing before it, as a compression middleware's does.
type heldHeadWriter struct {
	http.ResponseWriter

	status int
	begun  bool
}

func (h *heldHeadWriter) WriteHeader(status int) { h.status = status }

func (h *heldHeadWriter) Write(b []byte) (int, error) {
	if !h.begun {
		h.begun = true
		h.Header().Set("Content-Encoding", "chosen-at-first-write")
		h.ResponseWriter.WriteHeader(h.status)
	}

	return h.ResponseWriter.Write(b)
}

func (h *heldHeadWriter) Flush() {
	if h.begun {
		_ = http.NewResponseController(h.ResponseWriter).Flush()
	}
}

func (h *heldHeadWriter) Unwrap() http.ResponseWriter { return h.ResponseWriter }

// hookedUnwrappingWriter has a WriteHeader hook, a FlushError and an Unwrap, which is
// the shape of the wrappers a metrics or tracing middleware generates.
type hookedUnwrappingWriter struct {
	http.ResponseWriter

	hooks *atomic.Int64
}

func (h hookedUnwrappingWriter) WriteHeader(status int) {
	h.hooks.Add(1)
	h.Header().Set("X-From-Hook", "yes")
	h.ResponseWriter.WriteHeader(status)
}

func (h hookedUnwrappingWriter) FlushError() error {
	return http.NewResponseController(h.ResponseWriter).Flush()
}

func (h hookedUnwrappingWriter) Unwrap() http.ResponseWriter { return h.ResponseWriter }

// flushErrorOverGin is what a gin middleware that replaces c.Writer can add. Its
// FlushError is gin's Flush, which sends whatever status gin holds.
type flushErrorOverGin struct{ gin.ResponseWriter }

func (f flushErrorOverGin) FlushError() error {
	f.Flush()

	return nil
}

// superfluousLines counts net/http's complaints about a second status.
type superfluousLines struct{ n atomic.Int64 }

func (s *superfluousLines) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "superfluous") {
		s.n.Add(1)
	}

	return len(p), nil
}

// TestGin_StreamBeneathMiddlewareWrappers pins that a stream through gin's writer
// leaves a middleware's wrapper in charge of what it wraps, whether or not gin has a
// route for the path. The event is read while the body is still running, because a
// body that returned would flush it anyway.
func TestGin_StreamBeneathMiddlewareWrappers(t *testing.T) {
	t.Parallel()

	heldHead := func(w http.ResponseWriter, _ *atomic.Int64) http.ResponseWriter {
		return &heldHeadWriter{ResponseWriter: w}
	}
	hooked := func(w http.ResponseWriter, hooks *atomic.Int64) http.ResponseWriter {
		return hookedUnwrappingWriter{ResponseWriter: w, hooks: hooks}
	}

	headIsHeld := func(t *testing.T, resp *http.Response, _ int64, superfluous int64) {
		t.Helper()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "chosen-at-first-write", resp.Header.Get("Content-Encoding"),
			"the head was sent from beneath the wrapper")
		assert.Zero(t, superfluous, "net/http logged a second status")
	}

	hookRanOnce := func(t *testing.T, resp *http.Response, hooks int64, superfluous int64) {
		t.Helper()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, int64(1), hooks)
		assert.Equal(t, "yes", resp.Header.Get("X-From-Hook"))
		assert.Zero(t, superfluous, "net/http logged a second status")
	}

	cases := []struct {
		name   string
		path   string
		wrap   func(w http.ResponseWriter, hooks *atomic.Int64) http.ResponseWriter
		use    gin.HandlerFunc
		assert func(t *testing.T, resp *http.Response, hooks int64, superfluous int64)
	}{
		{
			name:   "a wrapper holding the head until its first write keeps it until then",
			path:   "/stream",
			wrap:   heldHead,
			assert: headIsHeld,
		},
		{
			name:   "the same, on a path with no route",
			path:   "/no-route",
			wrap:   heldHead,
			assert: headIsHeld,
		},
		{
			name:   "a wrapper with FlushError, Unwrap and a WriteHeader hook has its hook run once",
			path:   "/stream",
			wrap:   hooked,
			assert: hookRanOnce,
		},
		{
			name:   "the same, on a path with no route",
			path:   "/no-route",
			wrap:   hooked,
			assert: hookRanOnce,
		},
		{
			// A limit Middleware states: asked first, it sends what gin holds.
			name: "a gin middleware's wrapper adding FlushError, on a path with no route, streams under 404",
			path: "/no-route",
			use:  func(gc *gin.Context) { gc.Writer = flushErrorOverGin{gc.Writer} },
			assert: func(t *testing.T, resp *http.Response, _ int64, _ int64) {
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var hooks atomic.Int64

			release := make(chan struct{})

			chain, err := httpsec.New(httpsec.RegisterInterceptor(
				httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
					return ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						if err := writeAndFlush(w); err != nil {
							return err
						}

						hold(t, release, "the row's release")

						return nil
					})
				}), httpsec.OrderBearerToken))
			require.NoError(t, err)

			engine := gin.New()
			if tc.use != nil {
				engine.Use(tc.use)
			}

			engine.Use(ginsec.Middleware(chain))
			engine.GET("/stream", func(*gin.Context) {})

			var handler http.Handler = engine
			if tc.wrap != nil {
				handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					engine.ServeHTTP(tc.wrap(w, &hooks), r)
				})
			}

			lines := &superfluousLines{}

			srv := httptest.NewUnstartedServer(handler)
			srv.Config.ErrorLog = log.New(lines, "", 0)
			srv.Start()
			t.Cleanup(srv.Close)

			ctx, cancel := context.WithTimeout(t.Context(), streamBound)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+tc.path, http.NoBody)
			require.NoError(t, err)

			resp, err := srv.Client().Do(req)
			require.NoError(t, err, "the head did not reach the client while the body ran")

			defer func() { _ = resp.Body.Close() }()

			r := bufio.NewReader(resp.Body)

			line, err := r.ReadString('\n')
			require.NoError(t, err)
			assert.Equal(t, streamLine, line)

			close(release)

			_, err = io.ReadAll(r)
			require.NoError(t, err)

			tc.assert(t, resp, hooks.Load(), lines.n.Load())
		})
	}
}

// TestGin_StreamBodyEndsEarly pins that a body that does not return cannot leave a
// response that looks complete, on gin, whose Recovery catches a panic and returns as
// usual, over HTTP/1.1 and HTTP/2. What Recovery is handed is what the body panicked
// with.
func TestGin_StreamBodyEndsEarly(t *testing.T) {
	t.Parallel()

	ownBug := errors.New("a body's own bug")

	cases := []struct {
		name      string
		overHTTP2 bool
		recovers  bool
		end       func()
		assert    func(t *testing.T, recovered any)
	}{
		{
			name:     "over HTTP/1.1 under gin's Recovery",
			recovers: true,
			end:      func() { panic(ownBug) },
			assert:   func(t *testing.T, recovered any) { assert.Equal(t, ownBug, recovered) },
		},
		{
			name:      "over HTTP/2 under gin's Recovery",
			overHTTP2: true,
			recovers:  true,
			end:       func() { panic(ownBug) },
			assert:    func(t *testing.T, recovered any) { assert.Equal(t, ownBug, recovered) },
		},
		{
			name: "runtime.Goexit with no Recovery",
			end:  runtime.Goexit,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(httpsec.RegisterInterceptor(
				httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
					return ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						if err := writeAndFlush(w); err != nil {
							return err
						}

						tc.end()

						return nil
					})
				}), httpsec.OrderBearerToken))
			require.NoError(t, err)

			recovered := make(chan any, 1)

			engine := gin.New()
			if tc.recovers {
				engine.Use(gin.CustomRecoveryWithWriter(io.Discard, func(_ *gin.Context, err any) { recovered <- err }))
			}

			engine.Use(ginsec.Middleware(chain))
			engine.GET("/stream", func(*gin.Context) {})

			srv := httptest.NewUnstartedServer(engine)
			if tc.overHTTP2 {
				srv.EnableHTTP2 = true
				srv.StartTLS()
			} else {
				srv.Start()
			}

			t.Cleanup(srv.Close)

			resp := openStream(t.Context(), t, srv)
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			if tc.overHTTP2 {
				assert.Equal(t, 2, resp.ProtoMajor)
			}

			body, err := io.ReadAll(resp.Body)
			require.Error(t, err, "the response ended as if it were complete")
			assert.Equal(t, streamEvent, string(body), "the event flushed before the end was lost")

			if tc.assert != nil {
				tc.assert(t, <-recovered)
			}
		})
	}
}
