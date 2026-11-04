package fibersec_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	recoverer "github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
)

// streamWriteTimeout is the server write timeout every stream test runs under.
const streamWriteTimeout = 3 * time.Second

// serveFiber runs app on a real listener and returns the address it listens on.
// The server is shut down with the test.
func serveFiber(t *testing.T, app *fiber.App) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan error, 1)

	go func() {
		done <- app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true})
	}()

	t.Cleanup(func() {
		_ = app.ShutdownWithTimeout(time.Second)
		_ = ln.Close()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the server did not stop")
		}
	})

	return ln.Addr().String()
}

// TestFiber_StreamOutlivesWriteTimeout establishes, on the versions this module
// pins, what the adapter's stream rests on: a write deadline set on the
// connection replaces the one fasthttp sets for the whole response. It drives
// fiber directly, with no adapter, and the row without the call is what shows the
// row with it is testing something.
func TestFiber_StreamOutlivesWriteTimeout(t *testing.T) {
	t.Parallel()

	const (
		gap     = 5 * time.Second
		lasting = 30 * time.Second
		beats   = 7 // the first at once, then one per gap, across lasting
	)

	type outcome struct {
		read    int
		elapsed time.Duration
		err     error
	}

	cases := []struct {
		name   string
		extend bool
		assert func(t *testing.T, got outcome)
	}{
		{
			name:   "with no deadline call the server's write timeout cuts the stream",
			extend: false,
			assert: func(t *testing.T, got outcome) {
				t.Helper()

				t.Logf("cut after %v, having read %d comments: %v", got.elapsed, got.read, got.err)
				assert.Less(t, got.read, beats, "the stream ended before every comment arrived")
				assert.Less(t, got.elapsed, lasting, "the stream ended early")
			},
		},
		{
			name:   "a deadline moved forward before each flush keeps the stream open",
			extend: true,
			assert: func(t *testing.T, got outcome) {
				t.Helper()

				t.Logf("read %d comments in %v, then: %v", got.read, got.elapsed, got.err)
				assert.Equal(t, beats, got.read)
				assert.GreaterOrEqual(t, got.elapsed, lasting, "the stream stayed open for the whole run")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			app := fiber.New(fiber.Config{WriteTimeout: streamWriteTimeout})
			app.Get("/stream", func(fc fiber.Ctx) error {
				rctx := fc.RequestCtx()
				conn := rctx.Conn()

				return fc.SendStreamWriter(func(w *bufio.Writer) {
					for i := range beats {
						if i > 0 {
							time.Sleep(gap)
						}

						if tc.extend {
							if err := conn.SetWriteDeadline(time.Now().Add(httpsec.StreamWriteWindow)); err != nil {
								return
							}
						}

						if _, err := w.WriteString(":\n\n"); err != nil {
							return
						}

						if err := w.Flush(); err != nil {
							return
						}
					}
				})
			})

			addr := serveFiber(t, app)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/stream", http.NoBody)
			require.NoError(t, err)

			start := time.Now()

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)

			defer func() { _ = resp.Body.Close() }()

			got := outcome{}
			r := bufio.NewReader(resp.Body)

			for {
				line, err := r.ReadString('\n')
				if err != nil {
					got.err = err
					break
				}

				if line == ":\n" {
					got.read++
				}
			}

			got.elapsed = time.Since(start)

			if got.err == io.EOF {
				got.err = nil
			}

			tc.assert(t, got)
		})
	}
}

const (
	// streamBound fails a test that would otherwise wait for ever. No test waits
	// for it to pass.
	streamBound = 10 * time.Second

	// streamEvent is one event as a stream writes it, and streamLine its first
	// line as the client reads it.
	streamEvent = "data: e\n\n"
	streamLine  = "data: e\n"
)

// serveStreamChain puts serve in a chain in front of a fiber app on a real server
// under streamWriteTimeout, and answers refusals as the library's ErrorHandler
// does. It returns the stream's address and the app, for a row that shuts it down.
func serveStreamChain(t *testing.T, opts ...httpsec.Option) (string, *fiber.App) {
	t.Helper()

	chain, err := httpsec.New(opts...)
	require.NoError(t, err)

	app := fiber.New(fiber.Config{WriteTimeout: streamWriteTimeout, ErrorHandler: fibersec.ErrorHandler})
	app.Use(fibersec.Middleware(chain))
	app.Get("/ordinary", func(fc fiber.Ctx) error {
		return fc.SendStreamWriter(func(w *bufio.Writer) {
			_, _ = w.WriteString(streamEvent)
			_ = w.Flush()

			// The sleep is the behaviour under test: time passing with no stream
			// of the library's to move the deadline.
			time.Sleep(streamWriteTimeout + time.Second)

			_, _ = w.WriteString(streamEvent)
			_ = w.Flush()
		})
	})
	app.Get("/stream", func(fiber.Ctx) error { return nil })

	return "http://" + serveFiber(t, app) + "/stream", app
}

// streaming is a chain whose one interceptor runs serve at the slot a stream
// endpoint would sit in, leaving nothing behind it.
func streaming(serve func(ex *httpsec.Exchange) error) httpsec.Option {
	return httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error { return serve(ex) }),
		httpsec.OrderBearerToken)
}

// openStream sends the request on ctx, leaving the body for the row to read. The
// whole exchange is bounded by streamBound, so a response that never comes or
// never ends fails the row instead of hanging it.
func openStream(ctx context.Context, t *testing.T, url string) *http.Response {
	t.Helper()

	return openStreamWithin(ctx, t, url, streamBound)
}

// openStreamWithin is openStream for a row that lasts longer than streamBound.
func openStreamWithin(ctx context.Context, t *testing.T, url string, bound time.Duration) *http.Response {
	t.Helper()

	ctx, cancel := context.WithTimeout(ctx, bound)
	t.Cleanup(cancel)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	require.NoError(t, err)

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	resp, err := client.Do(req)
	require.NoError(t, err)

	t.Cleanup(func() { _ = resp.Body.Close() })

	return resp
}

func writeAndFlush(w httpsec.EventWriter) error {
	if _, err := io.WriteString(w, streamEvent); err != nil {
		return err
	}

	return w.Flush()
}

// countEvents reads a response until it ends.
func countEvents(body io.Reader) (int, error) {
	r := bufio.NewReader(body)
	events := 0

	for {
		line, err := r.ReadString('\n')
		if errors.Is(err, io.EOF) {
			return events, nil
		}

		if err != nil {
			return events, err
		}

		if line == streamLine {
			events++
		}
	}
}

// waitFor fails the test when ch does not close within streamBound.
func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(streamBound):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// hold is how a body waits for ch: it cannot end the test, but a body that waits
// for ever would hold the server's goroutines, so it reports and returns.
func hold(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(streamBound):
		t.Errorf("a body timed out waiting for %s", what)
	}
}

type streamCtxKey struct{}

// TestFiber_Stream is the fiber writer's stream, through fibersec.Middleware on a
// real server. Every row is its own conversation between the chain and a client,
// so each closure holds both sides, ordered by channels.
func TestFiber_Stream(t *testing.T) {
	t.Parallel()

	const (
		beatGap = 5 * time.Second
		lasting = 30 * time.Second
	)

	notThisBody := func(context.Context, httpsec.EventWriter) error {
		t.Error("Stream returned an error, and its body ran")

		return nil
	}

	cases := []struct {
		name   string
		assert func(t *testing.T)
	}{
		{
			name: "the client receives an event while the body is still running",
			assert: func(t *testing.T) {
				release, returned := make(chan struct{}), make(chan struct{})
				url, _ := serveStreamChain(t, streaming(func(ex *httpsec.Exchange) error {
					return ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						defer close(returned)

						if err := writeAndFlush(w); err != nil {
							return err
						}

						hold(t, release, "the row's release")

						return nil
					})
				}))

				r := bufio.NewReader(openStream(t.Context(), t, url).Body)

				line, err := r.ReadString('\n')
				require.NoError(t, err)
				assert.Equal(t, streamLine, line)

				select {
				case <-returned:
					t.Error("the event arrived only once the body had returned")
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
				url, _ := serveStreamChain(t, streaming(func(ex *httpsec.Exchange) error {
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
				}))

				start := time.Now()
				events, err := countEvents(openStreamWithin(t.Context(), t, url, lasting+streamBound).Body)

				require.NoError(t, err, "the stream was cut after %v and %d events", time.Since(start), events)
				assert.Equal(t, int(lasting/beatGap)+1, events)
				assert.GreaterOrEqual(t, time.Since(start), lasting)
			},
		},
		{
			name: "an ordinary response behind the chain is still ended by the write timeout",
			assert: func(t *testing.T) {
				url, _ := serveStreamChain(t, httpsec.RegisterInterceptor(
					httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error { return next(ex) }),
					httpsec.OrderBearerToken))

				events, err := countEvents(openStream(t.Context(), t, url[:len(url)-len("/stream")]+"/ordinary").Body)

				require.Error(t, err, "the second write came after the deadline")
				assert.Equal(t, 1, events)
			},
		},
		{
			name: "the body's context carries the chain's values and not its end",
			assert: func(t *testing.T) {
				body := make(chan context.Context, 1)
				proceed := make(chan struct{})
				url, _ := serveStreamChain(t, streaming(func(ex *httpsec.Exchange) error {
					ctx := context.WithValue(ex.Context(), streamCtxKey{}, "from the chain")

					return ex.Writer.Stream(ctx, func(ctx context.Context, _ httpsec.EventWriter) error {
						body <- ctx
						hold(t, proceed, "the row to proceed")

						return nil
					})
				}))

				resp := openStream(t.Context(), t, url)

				var ctx context.Context
				select {
				case ctx = <-body:
				case <-time.After(streamBound):
					t.Fatal("the body did not run")
				}

				assert.Equal(t, "from the chain", ctx.Value(streamCtxKey{}))
				require.NoError(t, ctx.Err(), "the chain has returned, and the stream is still open")

				close(proceed)

				_, err := io.ReadAll(resp.Body)
				require.NoError(t, err)

				waitFor(t, ctx.Done(), "the body's context to end once it had returned")
			},
		},
		{
			name: "the body starts only once the chain has returned",
			assert: func(t *testing.T) {
				started := make(chan struct{})
				early := make(chan bool, 1)
				outer := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					err := next(ex)

					// The bound is the passing path: a body that was going to start
					// early has had this long to do it.
					select {
					case <-started:
						early <- true
					case <-time.After(200 * time.Millisecond):
						early <- false
					}

					return err
				}), httpsec.OrderJWKS)

				url, _ := serveStreamChain(t, outer, streaming(func(ex *httpsec.Exchange) error {
					return ex.Writer.Stream(ex.Context(), func(context.Context, httpsec.EventWriter) error {
						close(started)

						return nil
					})
				}))

				_, err := io.ReadAll(openStream(t.Context(), t, url).Body)
				require.NoError(t, err)
				assert.False(t, <-early, "the body ran while the chain was still on the stack")
				waitFor(t, started, "the body to run")
			},
		},
		{
			name: "a chain that refuses after Stream runs the body once on an ended context, and the response is the refusal",
			assert: func(t *testing.T) {
				var (
					runs   atomic.Int64
					places atomic.Int64
				)

				ended := make(chan struct{})
				liveAtStart, wrote, flushed := make(chan error, 1), make(chan error, 1), make(chan error, 1)
				outer := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					if err := next(ex); err != nil {
						return err
					}

					return httpsec.ErrRequestTooLarge
				}), httpsec.OrderJWKS)

				url, _ := serveStreamChain(t, outer, streaming(func(ex *httpsec.Exchange) error {
					// What the stream endpoint does: a place taken before Stream, so that it
					// can answer a refusal, and freed when the body returns.
					places.Add(1)

					return ex.Writer.Stream(ex.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
						defer close(ended)
						defer places.Add(-1)

						runs.Add(1)
						liveAtStart <- ctx.Err()

						_, err := io.WriteString(w, streamEvent)
						wrote <- err
						flushed <- w.Flush()

						return nil
					})
				}))

				resp := openStream(t.Context(), t, url)

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
				assert.Empty(t, body, "nothing the body writes reaches the client")

				waitFor(t, ended, "the body of a refused stream to run")
				assert.Equal(t, int64(1), runs.Load())
				assert.Zero(t, places.Load(), "the place the endpoint took is still held")
				require.ErrorIs(t, <-liveAtStart, context.Canceled)
				require.Error(t, <-wrote, "a refused stream's write goes nowhere")
				require.Error(t, <-flushed, "a refused stream's flush goes nowhere")
			},
		},
		{
			name: "fiber's own error handler answers a refusal after Stream with its text, and nothing of the body",
			assert: func(t *testing.T) {
				ended := make(chan struct{})
				chain, err := httpsec.New(
					httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
						if err := next(ex); err != nil {
							return err
						}

						return httpsec.ErrRequestTooLarge
					}), httpsec.OrderJWKS),
					streaming(func(ex *httpsec.Exchange) error {
						return ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
							defer close(ended)

							return writeAndFlush(w)
						})
					}))
				require.NoError(t, err)

				app := fiber.New()
				app.Use(fibersec.Middleware(chain))
				app.Get("/stream", func(fiber.Ctx) error { return nil })

				resp := openStream(t.Context(), t, "http://"+serveFiber(t, app)+"/stream")

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
				assert.NotContains(t, string(body), streamEvent)
				assert.NotEmpty(t, body, "the handler's own answer")

				waitFor(t, ended, "the body of a refused stream to run")
			},
		},
		{
			name: "a body that panics on a refused stream leaves the refusal whole",
			assert: func(t *testing.T) {
				outer := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					if err := next(ex); err != nil {
						return err
					}

					return httpsec.ErrRequestTooLarge
				}), httpsec.OrderJWKS)

				started := make(chan struct{})
				url, _ := serveStreamChain(t, outer, streaming(func(ex *httpsec.Exchange) error {
					return ex.Writer.Stream(ex.Context(), func(context.Context, httpsec.EventWriter) error {
						close(started)
						panic("a body's own bug")
					})
				}))

				resp := openStream(t.Context(), t, url)

				body, err := io.ReadAll(resp.Body)
				waitFor(t, started, "the body of a refused stream to run")
				require.NoError(t, err, "the refusal was cut")
				assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
				assert.Empty(t, body)
			},
		},
		{
			name: "a chain that panics after Stream runs the body once on an ended context",
			assert: func(t *testing.T) {
				var runs atomic.Int64

				ended := make(chan struct{})
				live := make(chan error, 1)

				chain, err := httpsec.New(
					httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
						if err := next(ex); err != nil {
							return err
						}

						panic("an interceptor's own bug")
					}), httpsec.OrderJWKS),
					streaming(func(ex *httpsec.Exchange) error {
						return ex.Writer.Stream(ex.Context(), func(ctx context.Context, _ httpsec.EventWriter) error {
							defer close(ended)

							runs.Add(1)
							live <- ctx.Err()

							return nil
						})
					}))
				require.NoError(t, err)

				app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
				app.Use(recoverer.New())
				app.Use(fibersec.Middleware(chain))
				app.Get("/stream", func(fiber.Ctx) error { return nil })

				resp := openStream(t.Context(), t, "http://"+serveFiber(t, app)+"/stream")

				_, err = io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

				waitFor(t, ended, "the body of a stream under a panicking chain to run")
				assert.Equal(t, int64(1), runs.Load())
				require.ErrorIs(t, <-live, context.Canceled)
			},
		},
		{
			name: "a connection already gone when the chain returns runs the body once on an ended context",
			assert: func(t *testing.T) {
				var runs atomic.Int64

				ended := make(chan struct{})
				live, wrote := make(chan error, 1), make(chan error, 1)

				ln, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)

				accepted := &recordingListener{Listener: ln, conns: make(chan net.Conn, 1)}

				chain, err := httpsec.New(streaming(func(ex *httpsec.Exchange) error {
					err := ex.Writer.Stream(ex.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
						defer close(ended)

						runs.Add(1)
						live <- ctx.Err()

						_, werr := io.WriteString(w, streamEvent)
						wrote <- werr

						return nil
					})

					// The connection goes after Stream has returned nil, and before the
					// gate opens, so the body is the first to meet it.
					_ = (<-accepted.conns).Close()

					return err
				}))
				require.NoError(t, err)

				app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
				app.Use(fibersec.Middleware(chain))
				app.Get("/stream", func(fiber.Ctx) error { return nil })

				conn := serveOn(t, app, accepted)()
				require.NoError(t, conn.SetDeadline(time.Now().Add(streamBound)))

				_, err = io.WriteString(conn, rawStreamRequest)
				require.NoError(t, err)

				waitFor(t, ended, "the body of a stream whose connection had gone to run")
				assert.Equal(t, int64(1), runs.Load())
				require.ErrorIs(t, <-live, context.Canceled)
				require.Error(t, <-wrote, "a write on a connection that has gone goes nowhere")
			},
		},
		{
			name: "Stream returning an error never runs the body",
			assert: func(t *testing.T) {
				got := make(chan error, 1)
				url, _ := serveStreamChain(t, streaming(func(ex *httpsec.Exchange) error {
					ex.Writer.WriteHeader(http.StatusNoContent)
					got <- ex.Writer.Stream(ex.Context(), notThisBody)

					return nil
				}))

				assert.Equal(t, http.StatusNoContent, openStream(t.Context(), t, url).StatusCode)
				require.ErrorIs(t, <-got, httpsec.ErrStreamingStarted)
			},
		},
		{
			name: "the head arrives before anything is written, headers set before Stream with it",
			assert: func(t *testing.T) {
				release := make(chan struct{})
				url, _ := serveStreamChain(t, streaming(func(ex *httpsec.Exchange) error {
					ex.Writer.SetHeader("Cache-Control", "no-store")
					ex.Writer.SetHeader("Access-Control-Allow-Origin", "https://app.example")

					err := ex.Writer.Stream(ex.Context(), func(context.Context, httpsec.EventWriter) error {
						hold(t, release, "the row's release")

						return nil
					})

					ex.Writer.SetHeader("X-Too-Late", "yes")
					ex.Writer.AddHeader("X-Too-Late-Too", "yes")
					ex.Writer.SetCookie(&httpsec.Cookie{Name: "too-late", Value: "yes"})

					return err
				}))

				// Bounded, so a head that waits for a body waiting on release fails on
				// this request's deadline instead of hanging.
				boundedCtx, cancel := context.WithTimeout(t.Context(), streamBound)
				defer cancel()

				req, err := http.NewRequestWithContext(boundedCtx, http.MethodGet, url, http.NoBody)
				require.NoError(t, err)

				resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)

				close(release)
				require.NoError(t, err, "the response's head did not arrive before the body wrote anything")

				defer func() { _ = resp.Body.Close() }()

				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
				assert.Equal(t, "https://app.example", resp.Header.Get("Access-Control-Allow-Origin"))
				assert.Empty(t, resp.Header.Get("X-Too-Late"))
				assert.Empty(t, resp.Header.Get("X-Too-Late-Too"))
				assert.Empty(t, resp.Header.Get("Set-Cookie"))
			},
		},
		{
			name: "Stream after Write fails and adds nothing",
			assert: func(t *testing.T) {
				got := make(chan error, 1)
				url, _ := serveStreamChain(t, streaming(func(ex *httpsec.Exchange) error {
					_, _ = io.WriteString(ex.Writer, "written")
					got <- ex.Writer.Stream(ex.Context(), notThisBody)

					return nil
				}))

				body, err := io.ReadAll(openStream(t.Context(), t, url).Body)
				require.NoError(t, err)
				assert.Equal(t, "written", string(body))
				require.ErrorIs(t, <-got, httpsec.ErrStreamingStarted)
			},
		},
		{
			name: "Stream after WriteHeader fails and adds nothing",
			assert: func(t *testing.T) {
				got := make(chan error, 1)
				url, _ := serveStreamChain(t, streaming(func(ex *httpsec.Exchange) error {
					ex.Writer.WriteHeader(http.StatusTeapot)
					got <- ex.Writer.Stream(ex.Context(), notThisBody)

					return nil
				}))

				resp := openStream(t.Context(), t, url)

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, http.StatusTeapot, resp.StatusCode)
				assert.Empty(t, body)
				require.ErrorIs(t, <-got, httpsec.ErrStreamingStarted)
			},
		},
		{
			name: "a second Stream fails, and Write and WriteHeader after a stream reach nothing",
			assert: func(t *testing.T) {
				second, write := make(chan error, 1), make(chan error, 1)
				url, _ := serveStreamChain(t, streaming(func(ex *httpsec.Exchange) error {
					if err := ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						return writeAndFlush(w)
					}); err != nil {
						return err
					}

					second <- ex.Writer.Stream(ex.Context(), notThisBody)

					ex.Writer.WriteHeader(http.StatusTeapot)

					_, err := io.WriteString(ex.Writer, "after")
					write <- err

					return nil
				}))

				resp := openStream(t.Context(), t, url)

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, streamEvent, string(body))
				require.ErrorIs(t, <-second, httpsec.ErrStreamingStarted)
				require.ErrorIs(t, <-write, httpsec.ErrStreamingStarted)
			},
		},
		{
			name: "shutdown ends an open stream and is not held open by it",
			assert: func(t *testing.T) {
				opened, ended := make(chan struct{}), make(chan struct{})

				var endedWith atomic.Value

				url, app := serveStreamChain(t, streaming(func(ex *httpsec.Exchange) error {
					return ex.Writer.Stream(ex.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
						defer close(ended)

						if err := writeAndFlush(w); err != nil {
							return err
						}

						close(opened)
						hold(t, ctx.Done(), "shutdown to end its context")
						endedWith.Store(ctx.Err())

						return ctx.Err()
					})
				}))

				resp := openStream(t.Context(), t, url)
				waitFor(t, opened, "the stream to open")

				start := time.Now()

				require.NoError(t, app.ShutdownWithTimeout(streamBound), "the stream did not hold shutdown open")
				waitFor(t, ended, "the stream to end")

				assert.Less(t, time.Since(start), 5*time.Second)
				assert.Equal(t, context.Canceled, endedWith.Load())

				_, _ = io.ReadAll(resp.Body)
			},
		},
		{
			name: "a body that panics ends the response and leaves the server running",
			assert: func(t *testing.T) {
				var calls atomic.Int64

				url, _ := serveStreamChain(t, streaming(func(ex *httpsec.Exchange) error {
					if calls.Add(1) > 1 {
						ex.Writer.WriteHeader(http.StatusNoContent)

						return nil
					}

					return ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						if err := writeAndFlush(w); err != nil {
							return err
						}

						panic("a body's own bug")
					})
				}))

				// A goroutine of fasthttp's runs the body, where no framework recovers
				// and a panic would take the process down with it.
				_, err := io.ReadAll(openStream(t.Context(), t, url).Body)
				require.Error(t, err, "the response did not end as if it were complete")

				assert.Equal(t, http.StatusNoContent, openStream(t.Context(), t, url).StatusCode)
			},
		},
		{
			// The head goes out after the handlers have returned, and the body is
			// released as the chain returns, so a body can panic before there is any
			// head on the wire. The middleware before the chain holds fasthttp back until
			// that has happened, which is what a loaded machine does by chance.
			name: "a body that panics before the head has gone out still leaves the client the head and the event",
			assert: func(t *testing.T) {
				panicked := make(chan struct{})
				chain, err := httpsec.New(streaming(func(ex *httpsec.Exchange) error {
					return ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						if err := writeAndFlush(w); err != nil {
							return err
						}

						close(panicked)
						panic("a body's own bug")
					})
				}))
				require.NoError(t, err)

				app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
				app.Use(func(fc fiber.Ctx) error {
					err := fc.Next()

					hold(t, panicked, "the body to panic")

					// The bound is the passing path: a panic that was going to reach the
					// connection has had this long to do it.
					time.Sleep(100 * time.Millisecond)

					return err
				})
				app.Use(fibersec.Middleware(chain))
				app.Get("/stream", func(fiber.Ctx) error { return nil })

				resp := openStream(t.Context(), t, "http://"+serveFiber(t, app)+"/stream")
				assert.Equal(t, http.StatusOK, resp.StatusCode)

				events, err := countEvents(resp.Body)
				require.Error(t, err, "the response did not end as if it were complete")
				assert.Equal(t, 1, events, "the event flushed before the panic was lost")
			},
		},
		{
			// What require or t.FailNow does in a body. recover sees nothing, and fasthttp's
			// goroutine goes without closing its pipe, which nothing would then end.
			name: "a body that calls runtime.Goexit ends the response as cut, and the server keeps running",
			assert: func(t *testing.T) {
				var calls atomic.Int64

				url, _ := serveStreamChain(t, streaming(func(ex *httpsec.Exchange) error {
					if calls.Add(1) > 1 {
						ex.Writer.WriteHeader(http.StatusNoContent)

						return nil
					}

					return ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						if err := writeAndFlush(w); err != nil {
							return err
						}

						runtime.Goexit()

						return nil
					})
				}))

				resp := openStream(t.Context(), t, url)
				assert.Equal(t, http.StatusOK, resp.StatusCode)

				events, err := countEvents(resp.Body)
				require.Error(t, err, "the response ended as if it were complete")
				require.NotErrorIs(t, err, context.DeadlineExceeded, "the client was left hanging")
				assert.Equal(t, 1, events, "the event flushed before the end was lost")

				assert.Equal(t, http.StatusNoContent, openStream(t.Context(), t, url).StatusCode)
			},
		},
		{
			// An error handler that leaves the response alone leaves the stream's reader in
			// place, so the refused body's goroutine is still what ends the response.
			name: "a body that calls runtime.Goexit on a refused stream does not hang the refusal",
			assert: func(t *testing.T) {
				chain, err := httpsec.New(streaming(func(ex *httpsec.Exchange) error {
					if err := ex.Writer.Stream(ex.Context(), func(context.Context, httpsec.EventWriter) error {
						runtime.Goexit()

						return nil
					}); err != nil {
						return err
					}

					return httpsec.ErrRequestTooLarge
				}))
				require.NoError(t, err)

				app := fiber.New(fiber.Config{ErrorHandler: func(fiber.Ctx, error) error { return nil }})
				app.Use(fibersec.Middleware(chain))
				app.Get("/stream", func(fiber.Ctx) error { return nil })

				_, err = io.ReadAll(openStream(t.Context(), t, "http://"+serveFiber(t, app)+"/stream").Body)
				require.NoError(t, err, "a refused stream has no response of its own to cut")
			},
		},
		{
			// A limit fibersec's Middleware states: the gate has opened, so the error
			// handler's status goes out with the live stream. The test is there so that the
			// godoc changes with the behaviour.
			name: "fiber middleware outside the chain that fails after it returned cannot take the stream back",
			assert: func(t *testing.T) {
				chain, err := httpsec.New(streaming(func(ex *httpsec.Exchange) error {
					return ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						return writeAndFlush(w)
					})
				}))
				require.NoError(t, err)

				app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
				app.Use(func(fc fiber.Ctx) error {
					if err := fc.Next(); err != nil {
						return err
					}

					return fiber.ErrForbidden
				})
				app.Use(fibersec.Middleware(chain))
				app.Get("/stream", func(fiber.Ctx) error { return nil })

				resp := openStream(t.Context(), t, "http://"+serveFiber(t, app)+"/stream")
				assert.Equal(t, http.StatusForbidden, resp.StatusCode)

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, streamEvent, string(body))
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

// TestFiber_StreamAfterChainReturned pins the promise for a writer kept past its chain.
// A gate is opened by the chain returning, which has already happened, and the fiber
// context the writer holds may by then be another request's. So nothing starts, the
// body never runs, and the answer the chain gave stands.
func TestFiber_StreamAfterChainReturned(t *testing.T) {
	t.Parallel()

	// serve answers the request through a chain that keeps its writer, with kept handed
	// on as the chain returns, and with outer running in a middleware around the chain.
	serve := func(t *testing.T, outer func(httpsec.ResponseWriter)) (url string, kept <-chan httpsec.ResponseWriter) {
		t.Helper()

		writers := make(chan httpsec.ResponseWriter, 1)

		chain, err := httpsec.New(streaming(func(ex *httpsec.Exchange) error {
			writers <- ex.Writer

			return nil
		}))
		require.NoError(t, err)

		app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})

		if outer != nil {
			app.Use(func(fc fiber.Ctx) error {
				err := fc.Next()

				outer(<-writers)

				return err
			})
		}

		app.Use(fibersec.Middleware(chain))
		app.Get("/stream", func(fiber.Ctx) error { return nil })

		return "http://" + serveFiber(t, app) + "/stream", writers
	}

	cases := []struct {
		name   string
		assert func(t *testing.T, stream func(httpsec.ResponseWriter) error)
	}{
		{
			name: "from fiber middleware around the chain",
			assert: func(t *testing.T, stream func(httpsec.ResponseWriter) error) {
				got := make(chan error, 1)
				url, _ := serve(t, func(w httpsec.ResponseWriter) { got <- stream(w) })

				assert.Equal(t, http.StatusOK, openStream(t.Context(), t, url).StatusCode)
				require.ErrorIs(t, <-got, httpsec.ErrStreamingStarted)
			},
		},
		{
			name: "from another goroutine once the response has gone out",
			assert: func(t *testing.T, stream func(httpsec.ResponseWriter) error) {
				url, writers := serve(t, nil)

				assert.Equal(t, http.StatusOK, openStream(t.Context(), t, url).StatusCode)

				got := make(chan error, 1)
				w := <-writers

				go func() { got <- stream(w) }()

				require.ErrorIs(t, <-got, httpsec.ErrStreamingStarted)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var runs atomic.Int64

			tc.assert(t, func(w httpsec.ResponseWriter) error {
				return w.Stream(t.Context(), func(context.Context, httpsec.EventWriter) error {
					runs.Add(1)

					return nil
				})
			})

			assert.Zero(t, runs.Load(), "Stream returned an error, so its body must never run")
		})
	}
}

// TestFiber_StreamUnderAppTest pins what the middleware's documentation says of
// fiber's in-memory transport: it has nothing left to read once it has the request,
// so the reader takes that for the client leaving, and the body still runs once.
func TestFiber_StreamUnderAppTest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string

		// mount serves body on an app's /stream.
		mount  func(t *testing.T, app *fiber.App, body func(ctx context.Context, w httpsec.EventWriter) error)
		assert func(t *testing.T, resp *http.Response)
	}{
		{
			name: "a stream's context ends at once",
			mount: func(_ *testing.T, app *fiber.App, body func(ctx context.Context, w httpsec.EventWriter) error) {
				app.Get("/stream", func(fc fiber.Ctx) error {
					return fibersec.NewResponseWriter(fc).Stream(fc.Context(), body)
				})
			},
			assert: func(t *testing.T, resp *http.Response) {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			},
		},
		{
			name: "a chain that refuses after Stream answers the refusal",
			mount: func(t *testing.T, app *fiber.App, body func(ctx context.Context, w httpsec.EventWriter) error) {
				chain, err := httpsec.New(
					httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
						if err := next(ex); err != nil {
							return err
						}

						return httpsec.ErrRequestTooLarge
					}), httpsec.OrderJWKS),
					streaming(func(ex *httpsec.Exchange) error { return ex.Writer.Stream(ex.Context(), body) }))
				require.NoError(t, err)

				app.Use(fibersec.Middleware(chain))
				app.Get("/stream", func(fiber.Ctx) error { return nil })
			},
			assert: func(t *testing.T, resp *http.Response) {
				assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var runs atomic.Int64

			ended := make(chan error, 1)
			returned := make(chan struct{})

			app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
			tc.mount(t, app, func(ctx context.Context, _ httpsec.EventWriter) error {
				defer close(returned)

				runs.Add(1)
				hold(t, ctx.Done(), "the transport to run out")
				ended <- ctx.Err()

				return nil
			})

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/stream", http.NoBody)
			require.NoError(t, err)

			resp, err := app.Test(req, fiber.TestConfig{Timeout: streamBound})
			require.NoError(t, err)

			defer func() { _ = resp.Body.Close() }()

			tc.assert(t, resp)

			waitFor(t, returned, "the body to run")
			assert.Equal(t, int64(1), runs.Load())
			require.ErrorIs(t, <-ended, context.Canceled)
		})
	}
}

// TestFiber_StreamStatusIsOK pins that a stream answers 200 whatever fiber's
// context holds, as every adapter's does.
func TestFiber_StreamStatusIsOK(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Get("/stream", func(fc fiber.Ctx) error {
		fc.Status(http.StatusTeapot)

		return fibersec.NewResponseWriter(fc).Stream(fc.Context(),
			func(_ context.Context, w httpsec.EventWriter) error { return writeAndFlush(w) })
	})

	resp := openStream(t.Context(), t, "http://"+serveFiber(t, app)+"/stream")

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// selfSignedTLS is a server's configuration for the address the tests listen on.
func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "stream"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
}

// serveRaw runs app on a real listener, over TLS when asked, and returns how to
// dial it, for a row whose client has to do what net/http's will not: half-close,
// pipeline, or stop reading.
func serveRaw(t *testing.T, app *fiber.App, overTLS bool) func() net.Conn {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := ln.Addr().String()
	served := ln

	if overTLS {
		served = tls.NewListener(ln, selfSignedTLS(t))
	}

	serveListener(t, app, served)

	return func() net.Conn {
		t.Helper()

		raw, err := net.Dial("tcp", addr)
		require.NoError(t, err)

		var conn net.Conn = raw

		if overTLS {
			client := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the test's own certificate
			require.NoError(t, client.HandshakeContext(t.Context()))
			conn = client
		}

		t.Cleanup(func() { _ = conn.Close() })

		return conn
	}
}

// serveOn is serveRaw over a listener of the row's own, without TLS.
func serveOn(t *testing.T, app *fiber.App, ln net.Listener) func() net.Conn {
	t.Helper()

	serveListener(t, app, ln)

	return func() net.Conn {
		t.Helper()

		conn, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err)

		t.Cleanup(func() { _ = conn.Close() })

		return conn
	}
}

// serveListener runs app on ln. The server is shut down with the test.
func serveListener(t *testing.T, app *fiber.App, ln net.Listener) {
	t.Helper()

	done := make(chan error, 1)

	go func() {
		done <- app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true})
	}()

	t.Cleanup(func() {
		_ = app.ShutdownWithTimeout(time.Second)
		_ = ln.Close()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the server did not stop")
		}
	})
}

// recordingListener hands a row the server's end of each connection.
type recordingListener struct {
	net.Listener

	conns chan net.Conn
}

func (l *recordingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.conns <- conn
	}

	return conn, err
}

// stallListener makes the server's end of each connection behave as a socket does
// once the kernel's buffers are full and its client is not reading: a write blocks
// until released or until the connection's write deadline passes, whatever else the
// machine is doing and however much it has already sent. That is what a client
// slower than a deadline looks like, without pushing megabytes through loopback,
// where the kernel may answer a large transfer with ENOBUFS on a loaded machine.
type stallListener struct {
	net.Listener

	// stalled closes when the first write has blocked, and release lets every write
	// through.
	stalled chan struct{}
	release chan struct{}
	once    sync.Once
}

func newStallListener(t *testing.T) *stallListener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	return &stallListener{Listener: ln, stalled: make(chan struct{}), release: make(chan struct{})}
}

func (l *stallListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &stallConn{Conn: conn, l: l}, nil
}

// stallConn is what stallListener accepts. A deadline moved while a write is blocked
// is seen only when the old one passes: a row that needs a shorter one has it set
// before the write begins.
type stallConn struct {
	net.Conn

	l *stallListener

	mu       sync.Mutex
	deadline time.Time
}

func (c *stallConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()

	return c.Conn.SetWriteDeadline(deadline)
}

func (c *stallConn) Write(b []byte) (int, error) {
	c.l.once.Do(func() { close(c.l.stalled) })

	for {
		c.mu.Lock()
		deadline := c.deadline
		c.mu.Unlock()

		var passed <-chan time.Time
		if !deadline.IsZero() {
			timer := time.NewTimer(time.Until(deadline))
			defer timer.Stop()

			passed = timer.C
		}

		select {
		case <-c.l.release:
			return c.Conn.Write(b)
		case <-passed:
			c.mu.Lock()
			moved := !c.deadline.Equal(deadline)
			c.mu.Unlock()

			if !moved {
				return 0, os.ErrDeadlineExceeded
			}
		}
	}
}

const rawStreamRequest = "GET /stream HTTP/1.1\r\nHost: stream\r\n\r\n"

// closeWrite half-closes the client's side: it will send nothing more, and goes on
// reading.
func closeWrite(t *testing.T, conn net.Conn) {
	t.Helper()

	switch c := conn.(type) {
	case *net.TCPConn:
		require.NoError(t, c.CloseWrite())
	case *tls.Conn:
		require.NoError(t, c.CloseWrite())
	default:
		t.Fatalf("%T cannot half-close", conn)
	}
}

// TestFiber_StreamClientLeaves is the framework-adapters scenario with its time:
// the body ends within one heartbeat of the client going, over TCP and TLS, whether
// the client closes or only half-closes, and with nothing written to notice it.
func TestFiber_StreamClientLeaves(t *testing.T) {
	t.Parallel()

	const (
		heartbeat = 500 * time.Millisecond
		rounds    = 5
	)

	leave := func(_ *testing.T, conn net.Conn) { _ = conn.Close() }

	cases := []struct {
		name    string
		overTLS bool
		leave   func(t *testing.T, conn net.Conn)
	}{
		{name: "closing over TCP", leave: leave},
		{name: "closing over TLS", overTLS: true, leave: leave},
		{name: "half-closing over TCP", leave: closeWrite},
		{name: "half-closing over TLS", overTLS: true, leave: closeWrite},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			took := make([]time.Duration, 0, rounds)

			for range rounds {
				opened := make(chan struct{})
				ended := make(chan time.Time, 1)

				app := fiber.New()
				app.Get("/stream", func(fc fiber.Ctx) error {
					return fibersec.NewResponseWriter(fc).Stream(fc.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
						defer func() { ended <- time.Now() }()

						first := true

						for {
							if err := writeAndFlush(w); err != nil {
								return err
							}

							if first {
								close(opened)

								first = false
							}

							select {
							case <-ctx.Done():
								return ctx.Err()
							case <-time.After(heartbeat):
							}
						}
					})
				})

				conn := serveRaw(t, app, tc.overTLS)()

				_, err := io.WriteString(conn, rawStreamRequest)
				require.NoError(t, err)

				go func() { _, _ = io.Copy(io.Discard, conn) }()

				waitFor(t, opened, "the stream to open")

				at := time.Now()
				tc.leave(t, conn)

				select {
				case end := <-ended:
					took = append(took, end.Sub(at))
				case <-time.After(streamBound):
					t.Fatal("the body did not end after the client left")
				}
			}

			t.Logf("client leaving to body ending: %v", took)

			for _, d := range took {
				assert.LessOrEqual(t, d, heartbeat, "the spec's bound is one heartbeat")
			}
		})
	}
}

// TestFiber_StreamNoFalseAlarm pins that the reader takes nothing for the client
// leaving except the client leaving: no read deadline the server set, and no byte
// the client sends.
func TestFiber_StreamNoFalseAlarm(t *testing.T) {
	t.Parallel()

	const (
		short   = 200 * time.Millisecond
		lasting = 3 * short
	)

	// survives runs a stream that outlasts short and asserts the body's context lived
	// through it. send, when set, runs while the stream is open.
	survives := func(t *testing.T, config fiber.Config, overTLS bool, requestFirst bool, send func(conn net.Conn)) {
		t.Helper()

		var (
			alarm  atomic.Bool
			opened = make(chan struct{})
		)

		app := fiber.New(config)
		app.Get("/ordinary", func(fc fiber.Ctx) error { return fc.SendString("ordinary") })
		app.Get("/stream", func(fc fiber.Ctx) error {
			return fibersec.NewResponseWriter(fc).Stream(fc.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
				if err := writeAndFlush(w); err != nil {
					return err
				}

				close(opened)

				select {
				case <-ctx.Done():
					alarm.Store(true)

					return ctx.Err()
				case <-time.After(lasting):
				}

				return writeAndFlush(w)
			})
		})

		conn := serveRaw(t, app, overTLS)()
		require.NoError(t, conn.SetDeadline(time.Now().Add(streamBound)))

		r := bufio.NewReader(conn)

		if requestFirst {
			_, err := io.WriteString(conn, "GET /ordinary HTTP/1.1\r\nHost: stream\r\n\r\n")
			require.NoError(t, err)

			resp, err := http.ReadResponse(r, nil)
			require.NoError(t, err)

			_, err = io.ReadAll(resp.Body)
			require.NoError(t, err)
		}

		_, err := io.WriteString(conn, rawStreamRequest)
		require.NoError(t, err)

		resp, err := http.ReadResponse(r, nil)
		require.NoError(t, err)

		waitFor(t, opened, "the stream to open")

		if send != nil {
			send(conn)
		}

		events, err := countEvents(resp.Body)
		require.NoError(t, err)
		assert.False(t, alarm.Load(), "the body's context ended with the client still there")
		assert.Equal(t, 2, events)
	}

	cases := []struct {
		name   string
		assert func(t *testing.T)
	}{
		{
			name: "a read timeout shorter than the stream",
			assert: func(t *testing.T) {
				survives(t, fiber.Config{ReadTimeout: short}, false, false, nil)
			},
		},
		{
			name: "a read timeout shorter than the stream, over TLS",
			assert: func(t *testing.T) {
				survives(t, fiber.Config{ReadTimeout: short}, true, false, nil)
			},
		},
		{
			name: "a read timeout on a stream that is the connection's second request",
			assert: func(t *testing.T) {
				survives(t, fiber.Config{ReadTimeout: short}, false, true, nil)
			},
		},
		{
			name: "an idle timeout on a stream that is the connection's second request",
			assert: func(t *testing.T) {
				survives(t, fiber.Config{IdleTimeout: short}, false, true, nil)
			},
		},
		{
			name: "bytes the client sends while the stream is open are discarded",
			assert: func(t *testing.T) {
				survives(t, fiber.Config{}, false, false, func(conn net.Conn) {
					_, err := io.WriteString(conn, "GET /ordinary HTTP/1.1\r\nHost: stream\r\n\r\n")
					require.NoError(t, err)
				})
			},
		},
		{
			// Reads and fasthttp's writes run side by side on one tls.Conn here,
			// which is what -race is watching.
			name: "bytes the client sends over TLS are discarded beside the server's writes",
			assert: func(t *testing.T) {
				survives(t, fiber.Config{}, true, false, func(conn net.Conn) {
					_, err := io.WriteString(conn, "a request the server will never answer")
					require.NoError(t, err)
				})
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

// TestFiber_StreamOverTLSBesideReads has a body write a burst while the client keeps
// sending, so the reader and the socket's writes meet on the tls.Conn many times
// over under -race.
func TestFiber_StreamOverTLSBesideReads(t *testing.T) {
	t.Parallel()

	const bursts = 200

	app := fiber.New()
	app.Get("/stream", func(fc fiber.Ctx) error {
		return fibersec.NewResponseWriter(fc).Stream(fc.Context(), func(_ context.Context, w httpsec.EventWriter) error {
			for range bursts {
				if err := writeAndFlush(w); err != nil {
					return err
				}
			}

			return nil
		})
	})

	conn := serveRaw(t, app, true)()
	require.NoError(t, conn.SetDeadline(time.Now().Add(streamBound)))

	_, err := io.WriteString(conn, rawStreamRequest)
	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		defer close(done)

		for range bursts {
			if _, err := io.WriteString(conn, "x"); err != nil {
				return
			}
		}
	}()

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)

	events, err := countEvents(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, bursts, events)
	waitFor(t, done, "the client's writes")
}

// TestFiber_StreamConnectionCloses pins that a stream's connection serves nothing
// after it: the reader may have consumed what a client pipelined.
func TestFiber_StreamConnectionCloses(t *testing.T) {
	t.Parallel()

	// Long enough for the server to write the head under it on a loaded machine, which
	// a window short enough to pass unnoticed would not be.
	const window = time.Second

	cases := []struct {
		name string

		// wait is what the body does once it has written its event.
		wait   func(t *testing.T, ctx context.Context)
		assert func(t *testing.T, dial func() net.Conn, served *atomic.Int64)
	}{
		{
			name: "a GET says Connection: close, and a pipelined request is not served",
			wait: func(*testing.T, context.Context) {},
			assert: func(t *testing.T, dial func() net.Conn, served *atomic.Int64) {
				conn := dial()
				require.NoError(t, conn.SetDeadline(time.Now().Add(streamBound)))

				_, err := io.WriteString(conn, rawStreamRequest+"GET /ordinary HTTP/1.1\r\nHost: stream\r\n\r\n")
				require.NoError(t, err)

				r := bufio.NewReader(conn)

				resp, err := http.ReadResponse(r, nil)
				require.NoError(t, err)
				assert.True(t, resp.Close, "the response says the connection closes")

				events, err := countEvents(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, 1, events)

				_, err = r.ReadByte()
				require.ErrorIs(t, err, io.EOF, "the connection ended with the stream")
				assert.Zero(t, served.Load())
			},
		},
		{
			// fasthttp skips the body of a HEAD, and would go on to the next request on
			// the connection with the body still running and the window still on it.
			// The body can find the connection already closed, and runs anyway.
			name: "a HEAD says Connection: close, ends the body's context, and harms no later request",
			wait: func(t *testing.T, ctx context.Context) {
				hold(t, ctx.Done(), "the end of a response to a HEAD")
			},
			assert: func(t *testing.T, dial func() net.Conn, served *atomic.Int64) {
				conn := dial()
				require.NoError(t, conn.SetDeadline(time.Now().Add(streamBound)))

				_, err := io.WriteString(conn, "HEAD /stream HTTP/1.1\r\nHost: stream\r\n\r\n")
				require.NoError(t, err)

				r := bufio.NewReader(conn)

				head, err := http.NewRequestWithContext(t.Context(), http.MethodHead, "/", http.NoBody)
				require.NoError(t, err)

				resp, err := http.ReadResponse(r, head)
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.True(t, resp.Close, "the response says the connection closes")

				_, err = r.ReadByte()
				require.ErrorIs(t, err, io.EOF, "the connection ended with the response")

				// The sleep is the behaviour under test: the window passing, which is
				// what would break a next response on the same connection.
				time.Sleep(window + 100*time.Millisecond)

				next := dial()
				require.NoError(t, next.SetDeadline(time.Now().Add(streamBound)))

				_, err = io.WriteString(next, "GET /ordinary HTTP/1.1\r\nHost: stream\r\n\r\n")
				require.NoError(t, err)

				resp, err = http.ReadResponse(bufio.NewReader(next), nil)
				require.NoError(t, err)

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, "ordinary", string(body))
				assert.Equal(t, int64(1), served.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var served, runs atomic.Int64

			ended := make(chan struct{})

			app := fiber.New()
			app.Get("/stream", func(fc fiber.Ctx) error {
				return fibersec.NewResponseWriterWithStreamWindow(fc, window).Stream(fc.Context(),
					func(ctx context.Context, w httpsec.EventWriter) error {
						defer close(ended)

						runs.Add(1)

						if err := writeAndFlush(w); err != nil {
							return err
						}

						tc.wait(t, ctx)

						return nil
					})
			})
			app.Get("/ordinary", func(fc fiber.Ctx) error {
				served.Add(1)

				return fc.SendString("ordinary")
			})

			tc.assert(t, serveRaw(t, app, false), &served)

			waitFor(t, ended, "the body to run")
			assert.Equal(t, int64(1), runs.Load())
		})
	}
}

// TestFiber_StreamPanicLog pins what a panicking body leaves in the log: that it
// happened and where, and nothing of what it held. It is not parallel, because the
// log it reads is the process's default.
func TestFiber_StreamPanicLog(t *testing.T) {
	const (
		panicValue = "session-token-abc123"
		argument   = uint64(0xdeadbeefcafe)
	)

	var buf lockedBuffer

	old := slog.Default()

	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	app := fiber.New()
	app.Get("/stream", func(fc fiber.Ctx) error {
		return fibersec.NewResponseWriter(fc).Stream(fc.Context(), func(context.Context, httpsec.EventWriter) error {
			panicHolding(argument, panicValue)

			return nil
		})
	})

	conn := serveRaw(t, app, false)()
	require.NoError(t, conn.SetDeadline(time.Now().Add(streamBound)))

	_, err := io.WriteString(conn, rawStreamRequest)
	require.NoError(t, err)

	_, _ = io.Copy(io.Discard, conn)

	require.Eventually(t, func() bool { return strings.Contains(buf.String(), "panicked") },
		streamBound, 10*time.Millisecond, "the panic was not logged")

	logged := buf.String()

	assert.NotContains(t, logged, panicValue, "the panic's value is the body's, and can be a secret")
	assert.NotContains(t, logged, "deadbeefcafe", "a stack quotes the arguments of the frames it lists")
	assert.Contains(t, logged, "panicHolding", "the log still says where it happened")
}

//go:noinline
func panicHolding(_ uint64, value string) { panic(value) }

// lockedBuffer is the log's sink, which the server writes while the test reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// TestFiber_StreamFlushFailureEndsContext pins that the body learns of a failed
// write from its context as well as from the error. The reader usually gets there
// too, so this reaches past the server to the writer alone.
func TestFiber_StreamFlushFailureEndsContext(t *testing.T) {
	t.Parallel()

	failed := errors.New("connection gone")

	cases := []struct {
		name   string
		act    func(w httpsec.EventWriter) error
		conn   net.Conn
		assert func(t *testing.T, err error)
	}{
		{
			name: "a flush that fails",
			conn: deadlineConn{},
			act:  func(w httpsec.EventWriter) error { _, _ = w.Write([]byte("e")); return w.Flush() },
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, failed)
			},
		},
		{
			name: "a write too large for the buffer that fails",
			conn: deadlineConn{},
			act:  func(w httpsec.EventWriter) error { _, err := w.Write(make([]byte, 1<<16)); return err },
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, failed)
			},
		},
		{
			name: "a flush on a connection the server closed",
			conn: deadlineConn{err: net.ErrClosed},
			act:  func(w httpsec.EventWriter) error { return w.Flush() },
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, net.ErrClosed)
			},
		},
		{
			name: "a write on a connection the server closed",
			conn: deadlineConn{err: net.ErrClosed},
			act:  func(w httpsec.EventWriter) error { _, err := w.Write([]byte("e")); return err },
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, net.ErrClosed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			w := fibersec.NewEventWriter(bufio.NewWriter(failingWriter{err: failed}), tc.conn, time.Minute, cancel)

			tc.assert(t, tc.act(w))
			require.Error(t, ctx.Err(), "the failure did not end the body's context")
		})
	}
}

// failingWriter is a stream writer whose pipe has gone.
type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }

// deadlineConn is a connection that answers only for its write deadline.
type deadlineConn struct {
	net.Conn

	err error
}

func (d deadlineConn) SetWriteDeadline(time.Time) error { return d.err }

// fiberStack is every goroutine in this process running this package's code. The
// test package's own frames read fibersec_test, so they do not count.
func fiberStack() string {
	buf := make([]byte, 1<<20)
	stack := string(buf[:runtime.Stack(buf, true)])

	var found []string

	for g := range strings.SplitSeq(stack, "\n\n") {
		if strings.Contains(g, "httpsec/fibersec.") {
			found = append(found, g)
		}
	}

	return strings.Join(found, "\n\n")
}

// TestFiber_StreamWatcherExits pins that every goroutine of a stream goes when it
// does, on every way a stream ends, and whether or not the connection has closed
// yet. It is not parallel, so that no other test's stream is running to be counted:
// parallel tests wait until the serial ones have finished.
func TestFiber_StreamWatcherExits(t *testing.T) {
	const window = 500 * time.Millisecond

	// request opens a stream on a raw connection, and reads until it ends.
	request := func(t *testing.T, dial func() net.Conn) {
		t.Helper()

		conn := dial()
		require.NoError(t, conn.SetDeadline(time.Now().Add(streamBound)))

		_, err := io.WriteString(conn, rawStreamRequest)
		require.NoError(t, err)

		_, _ = io.Copy(io.Discard, conn)
	}

	goneSoon := func(t *testing.T) {
		t.Helper()

		var left string

		ok := assert.Eventually(t, func() bool {
			left = fiberStack()

			return left == ""
		}, streamBound, 10*time.Millisecond, "a goroutine of the stream is still running after it ended")
		if !ok {
			t.Log(left)
		}
	}

	cases := []struct {
		name   string
		assert func(t *testing.T)
	}{
		{
			name: "the body returning",
			assert: func(t *testing.T) {
				url, _ := serveStreamChain(t, streaming(func(ex *httpsec.Exchange) error {
					return ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						return writeAndFlush(w)
					})
				}))

				_, err := io.ReadAll(openStream(t.Context(), t, url).Body)
				require.NoError(t, err)

				goneSoon(t)
			},
		},
		{
			name: "the body panicking",
			assert: func(t *testing.T) {
				app := fiber.New()
				app.Get("/stream", func(fc fiber.Ctx) error {
					return fibersec.NewResponseWriter(fc).Stream(fc.Context(), func(context.Context, httpsec.EventWriter) error {
						panic("a body's own bug")
					})
				})

				request(t, serveRaw(t, app, false))
				goneSoon(t)
			},
		},
		{
			name: "the body calling runtime.Goexit",
			assert: func(t *testing.T) {
				app := fiber.New()
				app.Get("/stream", func(fc fiber.Ctx) error {
					return fibersec.NewResponseWriter(fc).Stream(fc.Context(), func(context.Context, httpsec.EventWriter) error {
						runtime.Goexit()

						return nil
					})
				})

				request(t, serveRaw(t, app, false))
				goneSoon(t)
			},
		},
		{
			name: "a flush failing on a client that stopped reading",
			assert: func(t *testing.T) {
				ended := make(chan struct{})
				app := fiber.New()
				app.Get("/stream", func(fc fiber.Ctx) error {
					return fibersec.NewResponseWriterWithStreamWindow(fc, window).Stream(fc.Context(),
						func(ctx context.Context, w httpsec.EventWriter) error {
							defer close(ended)

							for {
								if _, err := w.Write(make([]byte, 1<<20)); err != nil {
									return err
								}

								if err := w.Flush(); err != nil {
									return err
								}

								select {
								case <-ctx.Done():
									return ctx.Err()
								case <-time.After(10 * time.Millisecond):
								}
							}
						})
				})

				conn := serveRaw(t, app, false)()

				_, err := io.WriteString(conn, rawStreamRequest)
				require.NoError(t, err)

				waitFor(t, ended, "the failed write to end the stream")
				goneSoon(t)
			},
		},
		{
			name: "the client leaving",
			assert: func(t *testing.T) {
				opened := make(chan struct{})
				app := fiber.New()
				app.Get("/stream", func(fc fiber.Ctx) error {
					return fibersec.NewResponseWriter(fc).Stream(fc.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
						if err := writeAndFlush(w); err != nil {
							return err
						}

						close(opened)
						hold(t, ctx.Done(), "the client to leave")

						return ctx.Err()
					})
				})

				conn := serveRaw(t, app, false)()

				_, err := io.WriteString(conn, rawStreamRequest)
				require.NoError(t, err)

				waitFor(t, opened, "the stream to open")
				_ = conn.Close()

				goneSoon(t)
			},
		},
		{
			name: "shutdown",
			assert: func(t *testing.T) {
				opened := make(chan struct{})
				url, app := serveStreamChain(t, streaming(func(ex *httpsec.Exchange) error {
					return ex.Writer.Stream(ex.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
						if err := writeAndFlush(w); err != nil {
							return err
						}

						close(opened)
						hold(t, ctx.Done(), "shutdown")

						return ctx.Err()
					})
				}))

				resp := openStream(t.Context(), t, url)
				waitFor(t, opened, "the stream to open")

				require.NoError(t, app.ShutdownWithTimeout(streamBound))

				_, _ = io.ReadAll(resp.Body)

				goneSoon(t)
			},
		},
		{
			name: "a chain that refuses after Stream",
			assert: func(t *testing.T) {
				outer := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					if err := next(ex); err != nil {
						return err
					}

					return httpsec.ErrRequestTooLarge
				}), httpsec.OrderJWKS)

				url, _ := serveStreamChain(t, outer, streaming(func(ex *httpsec.Exchange) error {
					return ex.Writer.Stream(ex.Context(), func(context.Context, httpsec.EventWriter) error { return nil })
				}))

				_, err := io.ReadAll(openStream(t.Context(), t, url).Body)
				require.NoError(t, err)

				goneSoon(t)
			},
		},
		{
			// fasthttp is still stuck writing to a client that reads nothing, so the
			// connection stays open: only the read deadline can move the reader.
			name: "the body returning while the socket's write is stuck",
			assert: func(t *testing.T) {
				returned := make(chan struct{})
				app := fiber.New()
				app.Get("/stream", func(fc fiber.Ctx) error {
					return fibersec.NewResponseWriter(fc).Stream(fc.Context(), func(_ context.Context, w httpsec.EventWriter) error {
						defer close(returned)

						return writeAndFlush(w)
					})
				})

				ln := newStallListener(t)

				// The server's goroutine goes once the write is let through, before
				// the listener's cleanup waits for the server to stop.
				defer func() { close(ln.release) }()

				conn := serveOn(t, app, ln)()

				_, err := io.WriteString(conn, rawStreamRequest)
				require.NoError(t, err)

				waitFor(t, returned, "the body to return")
				waitFor(t, ln.stalled, "the server's first write")
				goneSoon(t)
			},
		},
		{
			name: "a chain that refuses after Stream, with a body that waits for its context",
			assert: func(t *testing.T) {
				ended := make(chan struct{})
				outer := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					if err := next(ex); err != nil {
						return err
					}

					return httpsec.ErrRequestTooLarge
				}), httpsec.OrderJWKS)

				url, _ := serveStreamChain(t, outer, streaming(func(ex *httpsec.Exchange) error {
					return ex.Writer.Stream(ex.Context(), func(ctx context.Context, _ httpsec.EventWriter) error {
						defer close(ended)

						hold(t, ctx.Done(), "its context to have ended already")

						return nil
					})
				}))

				_, err := io.ReadAll(openStream(t.Context(), t, url).Body)
				require.NoError(t, err)

				waitFor(t, ended, "the body of the refused stream to run")
				goneSoon(t)
			},
		},
		{
			name: "a connection already gone, with a body that waits for its context",
			assert: func(t *testing.T) {
				ended := make(chan struct{})

				ln, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)

				accepted := &recordingListener{Listener: ln, conns: make(chan net.Conn, 1)}

				chain, err := httpsec.New(streaming(func(ex *httpsec.Exchange) error {
					err := ex.Writer.Stream(ex.Context(), func(ctx context.Context, _ httpsec.EventWriter) error {
						defer close(ended)

						hold(t, ctx.Done(), "its context to have ended already")

						return nil
					})

					_ = (<-accepted.conns).Close()

					return err
				}))
				require.NoError(t, err)

				app := fiber.New()
				app.Use(fibersec.Middleware(chain))
				app.Get("/stream", func(fiber.Ctx) error { return nil })

				conn := serveOn(t, app, accepted)()

				_, err = io.WriteString(conn, rawStreamRequest)
				require.NoError(t, err)

				waitFor(t, ended, "the body of the stream to run")
				goneSoon(t)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t)
		})
	}
}

// TestFiber_StreamBodyMustNotReadExchange pins the contract on the body: what it
// needs from the exchange it copies before calling Stream, strings included,
// because on fiber what the request answers are views into buffers fasthttp hands to
// the next request. A value copied that way stays correct while later requests reuse
// them. Without strings.Clone this test fails, which is the hazard it pins.
func TestFiber_StreamBodyMustNotReadExchange(t *testing.T) {
	t.Parallel()

	const (
		alice = "alice-alice-alice"
		bobby = "BOBBY-BOBBY-BOBBY"

		reuseFor     = time.Second
		reuseWorkers = 8
	)

	copied := make(chan string, 1)
	opened, released, reused := make(chan struct{}), make(chan struct{}), make(chan struct{})

	chain, err := httpsec.New(httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
			if ex.Request.Path() != "/stream" {
				return next(ex)
			}

			who := strings.Clone(ex.Request.Header("X-Who"))

			return ex.Writer.Stream(ex.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
				if err := writeAndFlush(w); err != nil {
					return err
				}

				close(opened)
				hold(t, ctx.Done(), "the client to leave")

				// fasthttp gives the buffers back only once its own write has failed,
				// and a body can still be running then: that is the window.
				for writeAndFlush(w) == nil {
					time.Sleep(time.Millisecond)
				}

				close(released)
				hold(t, reused, "later requests to run")

				copied <- who

				return nil
			})
		}), httpsec.OrderBearerToken))
	require.NoError(t, err)

	app := fiber.New()
	app.Use(fibersec.Middleware(chain))
	app.Get("/other", func(fiber.Ctx) error { return nil })

	addr := serveFiber(t, app)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/stream", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("X-Who", alice)

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	resp, err := client.Do(req)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	waitFor(t, opened, "the stream to open")
	cancel()
	waitFor(t, released, "fasthttp to let go of the stream's buffers")

	// The buffers have gone back to a pool that is per processor: later requests reach
	// them only by running on enough of them, for long enough. The time is the
	// behaviour under test.
	var workers sync.WaitGroup

	stopAt := time.Now().Add(reuseFor)

	for range reuseWorkers {
		workers.Go(func() {
			for time.Now().Before(stopAt) {
				if !assert.NoError(t, requestAndReset(addr, bobby)) {
					return
				}
			}
		})
	}

	workers.Wait()

	close(reused)

	select {
	case got := <-copied:
		assert.Equal(t, alice, got, "the copied value was rewritten under the body")
	case <-time.After(streamBound):
		t.Fatal("the body did not report")
	}
}

// requestAndReset sends one request on a connection of its own, because fasthttp
// takes a pooled context per connection and not per request, and resets the connection
// instead of closing it. A closed one would leave its port in TIME_WAIT for half a
// minute, and a test running at this rate would use up the machine's ephemeral ports,
// failing whatever else on it binds or dials.
func requestAndReset(addr, who string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}

	defer func() { _ = conn.Close() }()

	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("not a TCP connection")
	}

	if err := tcp.SetLinger(0); err != nil {
		return err
	}

	if err := conn.SetDeadline(time.Now().Add(streamBound)); err != nil {
		return err
	}

	if _, err := io.WriteString(conn, "GET /other HTTP/1.1\r\nHost: stream\r\nX-Who: "+who+"\r\n\r\n"); err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return err
	}

	return resp.Body.Close()
}

// TestFiber_StreamDeadline pins what a stream does with the write deadline, under a
// write window short enough to pass inside the test.
func TestFiber_StreamDeadline(t *testing.T) {
	t.Parallel()

	const (
		window = time.Second
		gap    = window + 500*time.Millisecond
		events = 3
		large  = 1 << 18 // more than a buffer on the way can hold back
	)

	// Each of these moves one way: a body that does only that has nothing else
	// moving the deadline across its gaps.
	cases := []struct {
		name   string
		config fiber.Config
		serve  func(fc fiber.Ctx) error
		assert func(t *testing.T, url string)
	}{
		{
			name: "each Flush moves the deadline: an event is written, and flushed after the window",
			serve: func(fc fiber.Ctx) error {
				return fibersec.NewResponseWriterWithStreamWindow(fc, window).Stream(fc.Context(),
					func(ctx context.Context, w httpsec.EventWriter) error {
						for range events {
							if _, err := io.WriteString(w, streamEvent); err != nil {
								return err
							}

							select {
							case <-ctx.Done():
								return ctx.Err()
							case <-time.After(gap):
							}

							if err := w.Flush(); err != nil {
								return err
							}
						}

						return nil
					})
			},
			assert: func(t *testing.T, url string) {
				got, err := countEvents(openStreamWithin(t.Context(), t, url+"/stream", events*gap+streamBound).Body)

				require.NoError(t, err, "the stream was cut once the window had passed")
				assert.Equal(t, events, got)
			},
		},
		{
			name: "each Write moves the deadline: a body that never flushes goes on past the window",
			serve: func(fc fiber.Ctx) error {
				event := strings.Repeat(streamEvent, large/len(streamEvent))

				return fibersec.NewResponseWriterWithStreamWindow(fc, window).Stream(fc.Context(),
					func(ctx context.Context, w httpsec.EventWriter) error {
						for range events {
							select {
							case <-ctx.Done():
								return ctx.Err()
							case <-time.After(gap):
							}

							if _, err := io.WriteString(w, event); err != nil {
								return err
							}
						}

						return nil
					})
			},
			assert: func(t *testing.T, url string) {
				got, err := countEvents(openStreamWithin(t.Context(), t, url+"/stream", events*gap+streamBound).Body)

				require.NoError(t, err, "the stream was cut once the window had passed")
				assert.Equal(t, events*(large/len(streamEvent)), got)
			},
		},
		{
			name:   "with no write timeout, the window is not on the next connection",
			config: fiber.Config{},
			serve:  streamOneEvent(window),
			assert: func(t *testing.T, url string) {
				client := &http.Client{Transport: &http.Transport{MaxConnsPerHost: 1}}

				var reused bool

				resp := getWith(t, client, url+"/stream", nil)
				assert.True(t, resp.Close, "the stream's connection is not offered for reuse")

				got, err := countEvents(resp.Body)
				require.NoError(t, err)
				require.Equal(t, 1, got)

				// The sleep is the behaviour under test: the window passing.
				time.Sleep(gap)

				resp = getWith(t, client, url+"/ordinary", &reused)

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.False(t, reused, "a stream's connection ends with it")
				assert.Equal(t, "ordinary", string(body))
			},
		},
		{
			name:   "a server's write timeout still applies to the ordinary response after a stream",
			config: fiber.Config{WriteTimeout: time.Second},
			serve:  streamOneEvent(window),
			assert: func(t *testing.T, url string) {
				client := &http.Client{Transport: &http.Transport{MaxConnsPerHost: 1}}

				var reused bool

				got, err := countEvents(getWith(t, client, url+"/stream", nil).Body)
				require.NoError(t, err)
				require.Equal(t, 1, got)

				got, err = countEvents(getWith(t, client, url+"/slow", &reused).Body)

				assert.False(t, reused, "a stream's connection ends with it")
				require.Error(t, err, "the server's own deadline cut the ordinary response")
				assert.Equal(t, 1, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			app := fiber.New(tc.config)
			app.Get("/stream", tc.serve)
			app.Get("/ordinary", func(fc fiber.Ctx) error { return fc.SendString("ordinary") })
			app.Get("/slow", func(fc fiber.Ctx) error {
				return fc.SendStreamWriter(func(w *bufio.Writer) {
					_, _ = w.WriteString(streamEvent)
					_ = w.Flush()

					time.Sleep(2 * time.Second)

					_, _ = w.WriteString(streamEvent)
					_ = w.Flush()
				})
			})

			tc.assert(t, "http://"+serveFiber(t, app))
		})
	}
}

func streamOneEvent(window time.Duration) fiber.Handler {
	return func(fc fiber.Ctx) error {
		return fibersec.NewResponseWriterWithStreamWindow(fc, window).Stream(fc.Context(),
			func(_ context.Context, w httpsec.EventWriter) error { return writeAndFlush(w) })
	}
}

// TestFiber_StreamFirstDeadline pins why Stream sets the first deadline through
// RequestCtx, while the handler holds it, though the connection will not be reused.
// Setting it marks the response's deadline as a handler's. Unmarked, fasthttp sets
// its own write timeout once the handlers have returned, over what the body has by
// then set, so a first event that a slow client takes longer than that to read is
// cut. The middleware before the chain holds the handlers until the body has
// flushed, which is what puts fasthttp's call after the body's.
//
// The client's slowness is the stallListener's and not a large transfer's: the row
// passes on a machine of any speed, and with the deadline unmarked the head's write
// meets the server's write timeout on every run.
func TestFiber_StreamFirstDeadline(t *testing.T) {
	t.Parallel()

	const writeTimeout = 200 * time.Millisecond

	flushed := make(chan struct{})

	chain, err := httpsec.New(streaming(func(ex *httpsec.Exchange) error {
		return ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
			if err := writeAndFlush(w); err != nil {
				return err
			}

			close(flushed)

			return nil
		})
	}))
	require.NoError(t, err)

	app := fiber.New(fiber.Config{WriteTimeout: writeTimeout, ErrorHandler: fibersec.ErrorHandler})
	app.Use(func(fc fiber.Ctx) error {
		err := fc.Next()

		// The body is released as the chain returns, and this holds fasthttp back.
		hold(t, flushed, "the body's first flush")

		return err
	})
	app.Use(fibersec.Middleware(chain))
	app.Get("/stream", func(fiber.Ctx) error { return nil })

	ln := newStallListener(t)
	conn := serveOn(t, app, ln)()
	require.NoError(t, conn.SetDeadline(time.Now().Add(streamBound)))

	_, err = io.WriteString(conn, rawStreamRequest)
	require.NoError(t, err)

	waitFor(t, ln.stalled, "the server's first write")

	// The sleep is the behaviour under test: a client slower than the server's write
	// timeout, with a write in flight.
	time.Sleep(2 * writeTimeout)
	close(ln.release)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err, "the first event was cut under the server's write timeout")

	events, err := countEvents(resp.Body)
	require.NoError(t, err, "the first event was cut under the server's write timeout")
	assert.Equal(t, 1, events)
}

// getWith sends a request on client, reporting through reused whether it went on
// a connection that was already open.
func getWith(t *testing.T, client *http.Client, url string, reused *bool) *http.Response {
	t.Helper()

	ctx := t.Context()
	if reused != nil {
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { *reused = info.Reused },
		})
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)

	t.Cleanup(func() { _ = resp.Body.Close() })

	return resp
}
