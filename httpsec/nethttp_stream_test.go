package httpsec_test

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

const (
	// streamWriteTimeout is the write timeout every stream's server runs under.
	streamWriteTimeout = 3 * time.Second

	// streamBound fails a test that would otherwise wait for ever. No test waits
	// for it to pass.
	streamBound = 10 * time.Second

	// streamEvent is one event as a stream writes it, and streamLine its first
	// line as the client reads it.
	streamEvent = "data: e\n\n"
	streamLine  = "data: e\n"
)

// streamServer is a real server the row sends its requests to, because a
// recorder has no write deadline, no connection and no client to lose.
type streamServer struct {
	url    string
	client *http.Client
}

// startStreamServer serves h under streamWriteTimeout, over HTTP/2 when asked.
func startStreamServer(t *testing.T, overHTTP2 bool, h http.HandlerFunc) streamServer {
	t.Helper()

	srv := httptest.NewUnstartedServer(h)
	srv.Config.WriteTimeout = streamWriteTimeout

	if overHTTP2 {
		srv.EnableHTTP2 = true
		srv.StartTLS()
	} else {
		srv.Start()
	}

	t.Cleanup(srv.Close)

	return streamServer{url: srv.URL, client: srv.Client()}
}

// get opens a request on ctx, leaving the body for the row to read. The whole
// exchange is bounded by streamBound, so a response that never comes or never ends
// fails the row instead of hanging it.
//
// The body is closed when the test ends, which the bodyclose linter cannot see, so the
// directive below marks the response as handled.
// bodyclose:handled
func (s streamServer) get(ctx context.Context, t *testing.T, wantProto int) *http.Response {
	t.Helper()

	return s.getWithin(ctx, t, wantProto, streamBound)
}

// getWithin is get for a row that lasts longer than streamBound.
//
// The body is closed when the test ends, which the bodyclose linter cannot see, so the
// directive below marks the response as handled.
// bodyclose:handled
func (s streamServer) getWithin(ctx context.Context, t *testing.T, wantProto int, bound time.Duration) *http.Response {
	t.Helper()

	ctx, cancel := context.WithTimeout(ctx, bound)
	t.Cleanup(cancel)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, http.NoBody)
	require.NoError(t, err)

	resp, err := s.client.Do(req)
	require.NoError(t, err)
	require.Equal(t, wantProto, resp.ProtoMajor, "the row runs over the protocol it names")

	t.Cleanup(func() { _ = resp.Body.Close() })

	return resp
}

// protoMajor names the protocol a row runs over.
func protoMajor(overHTTP2 bool) int {
	if overHTTP2 {
		return 2
	}

	return 1
}

// waitFor fails the test when ch is not closed within streamBound.
func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(streamBound):
		t.Fatalf("timed out waiting for %s", what)
	}
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

// writeAndFlush writes one event, and flushes it.
func writeAndFlush(w httpsec.EventWriter) error {
	if _, err := io.WriteString(w, streamEvent); err != nil {
		return err
	}

	return w.Flush()
}

// countEvents reads a response until it ends, and reports how many events
// arrived and the error it ended with, nil for a clean end.
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

// TestHTTPResponseWriter_Stream is the net/http writer's stream, on real
// servers. Every row is its own conversation between a handler and a client, so
// each closure holds both sides, ordered by channels.
func TestHTTPResponseWriter_Stream(t *testing.T) {
	t.Parallel()

	const (
		beatGap = 5 * time.Second
		lasting = 30 * time.Second
	)

	// outlives is the row of a stream that writes every beatGap for lasting.
	outlives := func(t *testing.T, overHTTP2 bool) {
		t.Helper()

		srv := startStreamServer(t, overHTTP2, func(w http.ResponseWriter, r *http.Request) {
			_ = httpsec.NewHTTPResponseWriter(w).Stream(r.Context(), "", func(ctx context.Context, ew httpsec.EventWriter) error {
				for i := 0; ; i++ {
					if err := writeAndFlush(ew); err != nil {
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
		events, err := countEvents(srv.getWithin(t.Context(), t, protoMajor(overHTTP2), lasting+streamBound).Body)

		require.NoError(t, err)
		assert.Equal(t, int(lasting/beatGap)+1, events)
		assert.GreaterOrEqual(t, time.Since(start), lasting)
	}

	// A window short enough to pass between two steps of a body, which has nothing
	// else moving the deadline.
	const (
		window = time.Second
		gap    = window + 500*time.Millisecond
		steps  = 3
		large  = 1 << 18 // more than the buffers on the way can hold back
	)

	// idleAfterEvent is a handler whose stream writes one event and then writes
	// nothing for gap under window, before writing one more.
	idleAfterEvent := func(window, gap time.Duration) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			_ = httpsec.NewHTTPResponseWriterWithStreamWindow(w, window).
				Stream(r.Context(), "", func(ctx context.Context, ew httpsec.EventWriter) error {
					if err := writeAndFlush(ew); err != nil {
						return err
					}

					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(gap):
					}

					return writeAndFlush(ew)
				})
		}
	}

	// leaves is the row of a client that goes away from an open stream.
	leaves := func(t *testing.T, overHTTP2 bool) {
		t.Helper()

		ended := make(chan struct{})
		srv := startStreamServer(t, overHTTP2, func(w http.ResponseWriter, r *http.Request) {
			_ = httpsec.NewHTTPResponseWriter(w).Stream(r.Context(), "", func(ctx context.Context, ew httpsec.EventWriter) error {
				if err := writeAndFlush(ew); err != nil {
					return err
				}

				hold(t, ctx.Done(), "the client to leave")
				close(ended)

				return ctx.Err()
			})
		})

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		resp := srv.get(ctx, t, protoMajor(overHTTP2))
		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, streamLine, line)

		cancel()

		select {
		case <-ended:
		case <-time.After(time.Second):
			t.Fatal("the body's context did not end within a second of the client leaving")
		}
	}

	cases := []struct {
		name   string
		assert func(t *testing.T)
	}{
		{
			name: "the client receives an event while the body is still running",
			assert: func(t *testing.T) {
				release, returned := make(chan struct{}), make(chan struct{})
				srv := startStreamServer(t, false, func(w http.ResponseWriter, r *http.Request) {
					defer close(returned)

					_ = httpsec.NewHTTPResponseWriter(w).Stream(r.Context(), "", func(_ context.Context, ew httpsec.EventWriter) error {
						if err := writeAndFlush(ew); err != nil {
							return err
						}

						hold(t, release, "the row's release")

						return nil
					})
				})

				resp := srv.get(t.Context(), t, 1)
				r := bufio.NewReader(resp.Body)

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
				waitFor(t, returned, "Stream to return once its body had")
			},
		},
		{
			name: "Stream returns nil once a body has run, whatever it returned",
			assert: func(t *testing.T) {
				got := make(chan error, 1)
				srv := startStreamServer(t, false, func(w http.ResponseWriter, r *http.Request) {
					got <- httpsec.NewHTTPResponseWriter(w).Stream(r.Context(), "", func(context.Context, httpsec.EventWriter) error {
						return errors.New("the body's own failure")
					})
				})

				_, err := io.ReadAll(srv.get(t.Context(), t, 1).Body)
				require.NoError(t, err)
				require.NoError(t, <-got, "an error means the body never ran, and a caller would free its place twice")
			},
		},
		{
			name:   "over HTTP/1.1 a stream lives through gaps longer than the write timeout",
			assert: func(t *testing.T) { outlives(t, false) },
		},
		{
			name:   "over HTTP/2 a stream lives through gaps longer than the write timeout",
			assert: func(t *testing.T) { outlives(t, true) },
		},
		{
			name: "over HTTP/2 a window shorter than an idle gap resets the stream",
			assert: func(t *testing.T) {
				srv := startStreamServer(t, true, idleAfterEvent(time.Second, 3*time.Second))

				events, err := countEvents(srv.get(t.Context(), t, 2).Body)

				t.Logf("read %d events, then: %v", events, err)
				require.Error(t, err, "the deadline passing with no write in flight ends the stream")
				assert.Equal(t, 1, events)
			},
		},
		{
			name: "over HTTP/2 StreamWriteWindow outlasts the same idle gap",
			assert: func(t *testing.T) {
				srv := startStreamServer(t, true, idleAfterEvent(httpsec.StreamWriteWindow, 3*time.Second))

				events, err := countEvents(srv.get(t.Context(), t, 2).Body)

				require.NoError(t, err)
				assert.Equal(t, 2, events)
			},
		},
		{
			name: "over HTTP/1.1 a window shorter than an idle gap does not end the stream",
			assert: func(t *testing.T) {
				srv := startStreamServer(t, false, idleAfterEvent(time.Second, 3*time.Second))

				events, err := countEvents(srv.get(t.Context(), t, 1).Body)

				require.NoError(t, err, "the next write moves the deadline before it reaches the connection")
				assert.Equal(t, 2, events)
			},
		},
		{
			name: "each Flush moves the deadline: an event is written, and flushed after the window",
			assert: func(t *testing.T) {
				srv := startStreamServer(t, false, func(w http.ResponseWriter, r *http.Request) {
					_ = httpsec.NewHTTPResponseWriterWithStreamWindow(w, window).
						Stream(r.Context(), "", func(ctx context.Context, ew httpsec.EventWriter) error {
							for range steps {
								if _, err := io.WriteString(ew, streamEvent); err != nil {
									return err
								}

								select {
								case <-ctx.Done():
									return ctx.Err()
								case <-time.After(gap):
								}

								if err := ew.Flush(); err != nil {
									return err
								}
							}

							return nil
						})
				})

				events, err := countEvents(srv.getWithin(t.Context(), t, 1, steps*gap+streamBound).Body)

				require.NoError(t, err, "the stream was cut once the window had passed")
				assert.Equal(t, steps, events)
			},
		},
		{
			name: "each Write moves the deadline: a body that never flushes goes on past the window",
			assert: func(t *testing.T) {
				event := strings.Repeat(streamEvent, large/len(streamEvent))
				srv := startStreamServer(t, false, func(w http.ResponseWriter, r *http.Request) {
					_ = httpsec.NewHTTPResponseWriterWithStreamWindow(w, window).
						Stream(r.Context(), "", func(ctx context.Context, ew httpsec.EventWriter) error {
							for range steps {
								select {
								case <-ctx.Done():
									return ctx.Err()
								case <-time.After(gap):
								}

								if _, err := io.WriteString(ew, event); err != nil {
									return err
								}
							}

							return nil
						})
				})

				events, err := countEvents(srv.getWithin(t.Context(), t, 1, steps*gap+streamBound).Body)

				require.NoError(t, err, "the stream was cut once the window had passed")
				assert.Equal(t, steps*(large/len(streamEvent)), events)
			},
		},
		{
			name: "an ordinary response is still ended by the write timeout",
			assert: func(t *testing.T) {
				srv := startStreamServer(t, false, func(w http.ResponseWriter, _ *http.Request) {
					rw := httpsec.NewHTTPResponseWriter(w)
					_, _ = io.WriteString(rw, "before")

					// The sleep is the behaviour under test: time passing with no
					// stream to move the deadline.
					time.Sleep(streamWriteTimeout + time.Second)

					_, _ = io.WriteString(rw, "after")
				})

				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.url, http.NoBody)
				require.NoError(t, err)

				resp, err := srv.client.Do(req)
				if err == nil {
					defer func() { _ = resp.Body.Close() }()

					_, err = io.ReadAll(resp.Body)
				}

				require.Error(t, err, "the deadline passed before anything could be written")
			},
		},
		{
			name:   "over HTTP/1.1 the client leaving ends the body's context",
			assert: func(t *testing.T) { leaves(t, false) },
		},
		{
			name:   "over HTTP/2 the client leaving ends the body's context",
			assert: func(t *testing.T) { leaves(t, true) },
		},
		{
			name: "headers set before Stream are sent, and those set after it are not",
			assert: func(t *testing.T) {
				release := make(chan struct{})
				srv := startStreamServer(t, false, func(w http.ResponseWriter, r *http.Request) {
					rw := httpsec.NewHTTPResponseWriter(w)
					rw.SetHeader("Cache-Control", "no-store")
					rw.SetHeader("Access-Control-Allow-Origin", "https://app.example")

					_ = rw.Stream(r.Context(), "", func(context.Context, httpsec.EventWriter) error {
						rw.SetHeader("X-Too-Late", "yes")
						hold(t, release, "the row's release")

						return nil
					})
				})

				// The head arrives with the body still running, and nothing written
				// yet: Stream itself sends it.
				// Bounded, so a head that waits for a body waiting on release fails on
				// this request's deadline instead of hanging.
				boundedCtx, cancel := context.WithTimeout(t.Context(), streamBound)
				defer cancel()

				req, err := http.NewRequestWithContext(boundedCtx, http.MethodGet, srv.url, http.NoBody)
				require.NoError(t, err)

				resp, err := srv.client.Do(req)

				close(release)
				require.NoError(t, err, "the response's head did not arrive before the body returned")

				defer func() { _ = resp.Body.Close() }()

				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
				assert.Equal(t, "https://app.example", resp.Header.Get("Access-Control-Allow-Origin"))
				assert.Empty(t, resp.Header.Get("X-Too-Late"))
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

// TestHTTPResponseWriter_StreamStartedGuard pins that a stream starts once and
// only on a response that has not begun, and that nothing written around one
// corrupts it.
func TestHTTPResponseWriter_StreamStartedGuard(t *testing.T) {
	t.Parallel()

	noBody := func(context.Context, httpsec.EventWriter) error {
		t.Error("Stream returned an error, and its body ran")

		return nil
	}

	cases := []struct {
		name   string
		serve  func(ctx context.Context, rw httpsec.ResponseWriter) error
		assert func(t *testing.T, res *http.Response, body string, err error)
	}{
		{
			name: "Stream after Write fails and adds nothing",
			serve: func(ctx context.Context, rw httpsec.ResponseWriter) error {
				_, _ = io.WriteString(rw, "written")

				return rw.Stream(ctx, "", noBody)
			},
			assert: func(t *testing.T, _ *http.Response, body string, err error) {
				require.ErrorIs(t, err, httpsec.ErrStreamingStarted)
				assert.Equal(t, "written", body)
			},
		},
		{
			name: "Stream after WriteHeader fails and adds nothing",
			serve: func(ctx context.Context, rw httpsec.ResponseWriter) error {
				rw.WriteHeader(http.StatusTeapot)

				return rw.Stream(ctx, "", noBody)
			},
			assert: func(t *testing.T, res *http.Response, body string, err error) {
				require.ErrorIs(t, err, httpsec.ErrStreamingStarted)
				assert.Equal(t, http.StatusTeapot, res.StatusCode)
				assert.Empty(t, body)
			},
		},
		{
			name: "a second Stream fails and adds nothing",
			serve: func(ctx context.Context, rw httpsec.ResponseWriter) error {
				if err := rw.Stream(ctx, "", func(_ context.Context, ew httpsec.EventWriter) error {
					return writeAndFlush(ew)
				}); err != nil {
					return err
				}

				return rw.Stream(ctx, "", noBody)
			},
			assert: func(t *testing.T, _ *http.Response, body string, err error) {
				require.ErrorIs(t, err, httpsec.ErrStreamingStarted)
				assert.Equal(t, streamEvent, body)
			},
		},
		{
			name: "a Stream inside a stream's body fails and adds nothing",
			serve: func(ctx context.Context, rw httpsec.ResponseWriter) error {
				var inner error

				if err := rw.Stream(ctx, "", func(ctx context.Context, ew httpsec.EventWriter) error {
					if err := writeAndFlush(ew); err != nil {
						return err
					}

					inner = rw.Stream(ctx, "", noBody)

					return nil
				}); err != nil {
					return err
				}

				return inner
			},
			assert: func(t *testing.T, _ *http.Response, body string, err error) {
				require.ErrorIs(t, err, httpsec.ErrStreamingStarted)
				assert.Equal(t, streamEvent, body)
			},
		},
		{
			name: "Write and WriteHeader around a stream reach nothing",
			serve: func(ctx context.Context, rw httpsec.ResponseWriter) error {
				var inside error

				err := rw.Stream(ctx, "", func(_ context.Context, ew httpsec.EventWriter) error {
					rw.WriteHeader(http.StatusTeapot)

					if n, err := io.WriteString(rw, "inside"); n != 0 || !errors.Is(err, httpsec.ErrStreamingStarted) {
						inside = errors.New("Write inside a stream's body did not refuse")
					}

					return writeAndFlush(ew)
				})
				if inside != nil {
					return inside
				}

				rw.WriteHeader(http.StatusTeapot)

				if n, werr := io.WriteString(rw, "after"); n != 0 || !errors.Is(werr, httpsec.ErrStreamingStarted) {
					return errors.New("Write after a stream did not refuse")
				}

				return err
			},
			assert: func(t *testing.T, res *http.Response, body string, err error) {
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, res.StatusCode)
				assert.Equal(t, streamEvent, body)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := make(chan error, 1)
			srv := startStreamServer(t, false, func(w http.ResponseWriter, r *http.Request) {
				got <- tc.serve(r.Context(), httpsec.NewHTTPResponseWriter(w))
			})

			resp := srv.get(t.Context(), t, 1)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			tc.assert(t, resp, string(body), <-got)
		})
	}
}

// recordingWriter records the order of what reaches it, and how far ahead each
// write deadline was set. It has the two methods http.ResponseController looks
// for, so the writer under test reaches them as it reaches a real connection's.
type recordingWriter struct {
	header  http.Header
	calls   []string
	windows []time.Duration
}

func (r *recordingWriter) Header() http.Header {
	if r.header == nil {
		r.header = http.Header{}
	}

	return r.header
}

func (r *recordingWriter) WriteHeader(int) { r.calls = append(r.calls, "header") }

func (r *recordingWriter) Write(b []byte) (int, error) {
	r.calls = append(r.calls, "write")

	return len(b), nil
}

func (r *recordingWriter) FlushError() error {
	r.calls = append(r.calls, "flush")

	return nil
}

func (r *recordingWriter) SetWriteDeadline(deadline time.Time) error {
	r.calls = append(r.calls, "deadline")
	r.windows = append(r.windows, time.Until(deadline))

	return nil
}

// flushOnly can flush but not move a deadline, as a recorder or a middleware's
// wrapper that does not unwrap can.
type flushOnly struct{ recordingWriter }

func (*flushOnly) SetWriteDeadline(time.Time) error { return http.ErrNotSupported }

// noFlush is a response writer that cannot flush at all.
type noFlush struct{ header http.Header }

func (n *noFlush) Header() http.Header { return n.header }

func (*noFlush) WriteHeader(int) {
	panic("a writer that cannot stream must have nothing written to it")
}

func (*noFlush) Write([]byte) (int, error) {
	panic("a writer that cannot stream must have nothing written to it")
}

// passesFlushOn has its own Flush and an Unwrap, as most middleware wrappers do. A
// flush from a stream stops at its Flush, which is what passes it on.
type passesFlushOn struct{ http.ResponseWriter }

func (p passesFlushOn) Flush() { _ = http.NewResponseController(p.ResponseWriter).Flush() }

func (p passesFlushOn) Unwrap() http.ResponseWriter { return p.ResponseWriter }

// TestHTTPResponseWriter_StreamDeadline pins what each step does to the write
// deadline, in the order it reaches the connection.
func TestHTTPResponseWriter_StreamDeadline(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		w      func() http.ResponseWriter
		serve  func(ctx context.Context, rw httpsec.ResponseWriter) error
		assert func(t *testing.T, w http.ResponseWriter, err error)
	}{
		{
			name: "the start, each write and each flush move the deadline before reaching the connection",
			w:    func() http.ResponseWriter { return &recordingWriter{} },
			serve: func(ctx context.Context, rw httpsec.ResponseWriter) error {
				return rw.Stream(ctx, "", func(_ context.Context, ew httpsec.EventWriter) error {
					return writeAndFlush(ew)
				})
			},
			assert: func(t *testing.T, w http.ResponseWriter, err error) {
				require.NoError(t, err)

				rec, ok := w.(*recordingWriter)
				require.True(t, ok)
				assert.Equal(t, []string{"deadline", "header", "deadline", "flush", "deadline", "write", "deadline", "flush"}, rec.calls)

				for _, window := range rec.windows {
					assert.InDelta(t, httpsec.StreamWriteWindow, window, float64(5*time.Second))
				}
			},
		},
		{
			name: "an ordinary response never moves the deadline",
			w:    func() http.ResponseWriter { return &recordingWriter{} },
			serve: func(_ context.Context, rw httpsec.ResponseWriter) error {
				rw.WriteHeader(http.StatusOK)

				_, err := io.WriteString(rw, "ordinary")

				return err
			},
			assert: func(t *testing.T, w http.ResponseWriter, err error) {
				require.NoError(t, err)

				rec, ok := w.(*recordingWriter)
				require.True(t, ok)
				assert.Equal(t, []string{"header", "write"}, rec.calls)
			},
		},
		{
			name: "a writer that cannot move the deadline still streams",
			w:    func() http.ResponseWriter { return &flushOnly{} },
			serve: func(ctx context.Context, rw httpsec.ResponseWriter) error {
				return rw.Stream(ctx, "", func(_ context.Context, ew httpsec.EventWriter) error {
					return writeAndFlush(ew)
				})
			},
			assert: func(t *testing.T, w http.ResponseWriter, err error) {
				require.NoError(t, err)

				rec, ok := w.(*flushOnly)
				require.True(t, ok)
				assert.Equal(t, []string{"header", "flush", "write", "flush"}, rec.calls)
			},
		},
		{
			name: "a Flush reaches the connection once, through a wrapper that has its own",
			w:    func() http.ResponseWriter { return passesFlushOn{&recordingWriter{}} },
			serve: func(ctx context.Context, rw httpsec.ResponseWriter) error {
				return rw.Stream(ctx, "", func(_ context.Context, ew httpsec.EventWriter) error {
					return writeAndFlush(ew)
				})
			},
			assert: func(t *testing.T, w http.ResponseWriter, err error) {
				require.NoError(t, err)

				wrapper, ok := w.(passesFlushOn)
				require.True(t, ok)

				rec, ok := wrapper.ResponseWriter.(*recordingWriter)
				require.True(t, ok)
				assert.Equal(t, []string{"deadline", "header", "deadline", "flush", "deadline", "write", "deadline", "flush"}, rec.calls)
			},
		},
		{
			name: "a writer that cannot flush reports that it cannot stream, and writes nothing",
			w:    func() http.ResponseWriter { return &noFlush{header: http.Header{}} },
			serve: func(ctx context.Context, rw httpsec.ResponseWriter) error {
				err := rw.Stream(ctx, "", func(context.Context, httpsec.EventWriter) error {
					return errors.New("this body must not run")
				})
				if !errors.Is(err, httpsec.ErrStreamingUnsupported) {
					return err
				}

				// The response has not begun, so an ordinary answer is still open:
				// it is what the signal stream's 501 is written through.
				if !httpsec.Committed(rw) {
					return err
				}

				return errors.New("the response was marked as begun")
			},
			assert: func(t *testing.T, _ http.ResponseWriter, err error) {
				require.ErrorIs(t, err, httpsec.ErrStreamingUnsupported)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := tc.w()
			tc.assert(t, w, tc.serve(t.Context(), httpsec.NewHTTPResponseWriter(w)))
		})
	}
}

// TestHTTPResponseWriter_StreamFlushFailureEndsContext pins that the body learns
// of a failed flush from its context as well as from the error, as it does on
// fiber, where the two reach different parts of the stream. The start's own flush
// succeeds and only the body's fails.
func TestHTTPResponseWriter_StreamFlushFailureEndsContext(t *testing.T) {
	t.Parallel()

	w := &failSecondFlush{}

	var live, ended bool

	var flushErr error

	err := httpsec.NewHTTPResponseWriter(w).Stream(t.Context(), "", func(ctx context.Context, ew httpsec.EventWriter) error {
		live = ctx.Err() == nil
		flushErr = ew.Flush()
		ended = ctx.Err() != nil

		return flushErr
	})

	require.NoError(t, err)
	require.EqualError(t, flushErr, "connection gone")
	assert.True(t, live, "the context was live while the stream was")
	assert.True(t, ended, "the context ended with the flush")
}

// failSecondFlush lets the flush that starts a stream through and fails the next.
type failSecondFlush struct {
	recordingWriter

	flushes int
}

func (f *failSecondFlush) FlushError() error {
	f.flushes++
	if f.flushes > 1 {
		return errors.New("connection gone")
	}

	return nil
}

// TestHTTPResponseWriter_StreamContract pins the promise every adapter keeps to a
// caller that holds something for its body to free: if Stream returns nil the body
// has run, exactly once, and if it returns an error the body never ran.
func TestHTTPResponseWriter_StreamContract(t *testing.T) {
	t.Parallel()

	type outcome struct {
		err     error
		runs    int
		live    error
		wrote   error
		flushed error
	}

	body := func(got *outcome) func(ctx context.Context, ew httpsec.EventWriter) error {
		return func(ctx context.Context, ew httpsec.EventWriter) error {
			got.runs++
			got.live = ctx.Err()
			_, got.wrote = io.WriteString(ew, streamEvent)
			got.flushed = ew.Flush()

			return errors.New("the body's own failure")
		}
	}

	cases := []struct {
		name   string
		w      http.ResponseWriter
		assert func(t *testing.T, w http.ResponseWriter, got outcome)
	}{
		{
			name: "a connection that has gone runs the body once, on an ended context, writing nowhere",
			w:    &failEveryFlush{err: errors.New("connection gone")},
			assert: func(t *testing.T, w http.ResponseWriter, got outcome) {
				require.NoError(t, got.err)
				assert.Equal(t, 1, got.runs)
				require.ErrorIs(t, got.live, context.Canceled)
				require.Error(t, got.wrote)
				require.Error(t, got.flushed)

				rec, ok := w.(*failEveryFlush)
				require.True(t, ok)
				assert.NotContains(t, rec.calls, "write", "what the body wrote reached the connection")
			},
		},
		{
			name: "a flush that turns out not to be supported is no stream, and the body never runs",
			w:    notSupportedAtRunTime{&recordingWriter{}},
			assert: func(t *testing.T, w http.ResponseWriter, got outcome) {
				require.ErrorIs(t, got.err, httpsec.ErrStreamingUnsupported)
				assert.Zero(t, got.runs)

				wrapper, ok := w.(notSupportedAtRunTime)
				require.True(t, ok)

				rec, ok := wrapper.ResponseWriter.(*recordingWriter)
				require.True(t, ok)
				assert.NotContains(t, rec.calls, "header", "a status was sent, so no ordinary answer can be")
			},
		},
		{
			// A limit ErrStreamingUnsupported states: a writer that moves a deadline is
			// taken for the connection, and gets its status first.
			name: "a writer that moves a deadline and then says it cannot flush still gets no body",
			w:    &failEveryFlush{err: http.ErrNotSupported},
			assert: func(t *testing.T, w http.ResponseWriter, got outcome) {
				require.ErrorIs(t, got.err, httpsec.ErrStreamingUnsupported)
				assert.Zero(t, got.runs)

				rec, ok := w.(*failEveryFlush)
				require.True(t, ok)
				assert.Contains(t, rec.calls, "header")
			},
		},
		{
			name: "the same below a wrapper",
			w:    unwrappingWriter{&failEveryFlush{err: http.ErrNotSupported}},
			assert: func(t *testing.T, w http.ResponseWriter, got outcome) {
				require.ErrorIs(t, got.err, httpsec.ErrStreamingUnsupported)
				assert.Zero(t, got.runs)

				wrapper, ok := w.(unwrappingWriter)
				require.True(t, ok)

				rec, ok := wrapper.ResponseWriter.(*failEveryFlush)
				require.True(t, ok)
				assert.Contains(t, rec.calls, "header")
			},
		},
		{
			name: "a live stream runs the body once, and Stream returns nil whatever it returned",
			w:    &recordingWriter{},
			assert: func(t *testing.T, _ http.ResponseWriter, got outcome) {
				require.NoError(t, got.err)
				assert.Equal(t, 1, got.runs)
				require.NoError(t, got.live)
				require.NoError(t, got.wrote)
				require.NoError(t, got.flushed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got outcome

			got.err = httpsec.NewHTTPResponseWriter(tc.w).Stream(t.Context(), "", body(&got))
			tc.assert(t, tc.w, got)
		})
	}
}

// failEveryFlush is a connection whose every flush fails.
type failEveryFlush struct {
	recordingWriter

	err error
}

func (f *failEveryFlush) FlushError() error { return f.err }

// TestHTTPResponseWriter_StreamThroughChain pins the same promise through the chain
// on a real server, where a body can panic and a chain can refuse. Neither is what a
// body's place depends on here, because the body runs inline: it has returned before
// either can happen.
func TestHTTPResponseWriter_StreamThroughChain(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string

		// outer runs around the stream, and body is the stream's.
		outer  func(ex *httpsec.Exchange, next httpsec.Next) error
		body   func(ctx context.Context, ew httpsec.EventWriter) error
		assert func(t *testing.T, events int, readErr error)
	}{
		{
			name: "a chain that refuses after Stream has run the body once, and the stream stands",
			outer: func(ex *httpsec.Exchange, next httpsec.Next) error {
				if err := next(ex); err != nil {
					return err
				}

				return httpsec.ErrRequestTooLarge
			},
			body: func(_ context.Context, ew httpsec.EventWriter) error { return writeAndFlush(ew) },
			assert: func(t *testing.T, events int, readErr error) {
				require.NoError(t, readErr)
				assert.Equal(t, 1, events)
			},
		},
		{
			name:  "a body that panics has run once, ends the response and leaves the server running",
			outer: func(ex *httpsec.Exchange, next httpsec.Next) error { return next(ex) },
			body: func(_ context.Context, ew httpsec.EventWriter) error {
				if err := writeAndFlush(ew); err != nil {
					return err
				}

				panic(http.ErrAbortHandler)
			},
			assert: func(t *testing.T, events int, readErr error) {
				require.Error(t, readErr, "the response did not end as if it were complete")
				assert.Equal(t, 1, events)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var runs atomic.Int64

			chain, err := httpsec.New(
				httpsec.RegisterInterceptor(httpsec.InterceptorFunc(tc.outer), httpsec.OrderJWKS),
				httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					if ex.Request.Path() != "/stream" {
						return next(ex)
					}

					return ex.Writer.Stream(ex.Context(), "", func(ctx context.Context, ew httpsec.EventWriter) error {
						runs.Add(1)

						return tc.body(ctx, ew)
					})
				}), httpsec.OrderBearerToken))
			require.NoError(t, err)

			srv := httptest.NewServer(chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})))
			t.Cleanup(srv.Close)

			ctx, cancel := context.WithTimeout(t.Context(), streamBound)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/stream", http.NoBody)
			require.NoError(t, err)

			resp, err := srv.Client().Do(req)
			require.NoError(t, err)

			defer func() { _ = resp.Body.Close() }()

			events, readErr := countEvents(resp.Body)
			tc.assert(t, events, readErr)
			assert.Equal(t, int64(1), runs.Load())
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

// flushHidingWriter says it can flush and has Unwrap, over a writer that cannot, as
// gin's writer does: its Flush does nothing, and returns no error to say so.
type flushHidingWriter struct{ http.ResponseWriter }

func (flushHidingWriter) Flush() {}

func (f flushHidingWriter) Unwrap() http.ResponseWriter { return f.ResponseWriter }

// TestHTTPResponseWriter_StreamCannotFlush pins that a writer that cannot flush is no
// stream at all, which is not the same as a client that left: the stream would close,
// and a browser would reconnect for ever. Nothing has been written, so an ordinary
// answer still goes out.
func TestHTTPResponseWriter_StreamCannotFlush(t *testing.T) {
	t.Parallel()

	const answer = "an ordinary answer"

	// serve is the handler under every wrapper: it streams, and answers ordinarily
	// when it cannot.
	serve := func(got chan<- error) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			rw := httpsec.NewHTTPResponseWriter(w)

			err := rw.Stream(r.Context(), "", func(_ context.Context, ew httpsec.EventWriter) error {
				return writeAndFlush(ew)
			})
			got <- err

			if err != nil {
				rw.WriteHeader(http.StatusNotImplemented)
				_, _ = io.WriteString(rw, answer)
			}
		}
	}

	wrap := func(wrapper func(http.ResponseWriter) http.ResponseWriter) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(wrapper(w), r)
			})
		}
	}

	unsupported := func(t *testing.T, resp *http.Response, body string, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrStreamingUnsupported)
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "nothing had been written")
		assert.Equal(t, answer, body)
	}

	cases := []struct {
		name   string
		mount  func(http.Handler) http.Handler
		assert func(t *testing.T, resp *http.Response, body string, err error)
	}{
		{
			name:   "a wrapper with neither Flush nor Unwrap",
			mount:  wrap(func(w http.ResponseWriter) http.ResponseWriter { return bareWriter{w} }),
			assert: unsupported,
		},
		{
			name: "http.TimeoutHandler, whose writer has neither",
			mount: func(next http.Handler) http.Handler {
				return http.TimeoutHandler(next, streamBound, "timed out")
			},
			assert: unsupported,
		},
		{
			name: "a wrapper with Unwrap over one that cannot flush",
			mount: wrap(func(w http.ResponseWriter) http.ResponseWriter {
				return unwrappingWriter{bareWriter{w}}
			}),
			assert: unsupported,
		},
		{
			name: "a wrapper whose Flush hides that what it wraps cannot flush",
			mount: wrap(func(w http.ResponseWriter) http.ResponseWriter {
				return flushHidingWriter{bareWriter{w}}
			}),
			assert: unsupported,
		},
		{
			name:   "a wrapper that says so only when asked to flush leaves an ordinary answer possible",
			mount:  wrap(func(w http.ResponseWriter) http.ResponseWriter { return notSupportedAtRunTime{w} }),
			assert: unsupported,
		},
		{
			name: "the same wrapper, beneath one that has only Unwrap",
			mount: wrap(func(w http.ResponseWriter) http.ResponseWriter {
				return unwrappingWriter{notSupportedAtRunTime{w}}
			}),
			assert: unsupported,
		},
		{
			name:  "a wrapper with Unwrap whose WriteHeader adds a header has its say",
			mount: wrap(func(w http.ResponseWriter) http.ResponseWriter { return headerOnWriteHeader{w} }),
			assert: func(t *testing.T, resp *http.Response, body string, err error) {
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "yes", resp.Header.Get("X-From-Wrapper"))
				assert.Equal(t, streamEvent, body)
			},
		},
		{
			name:  "a wrapper with a working Flush and no Unwrap is accepted",
			mount: wrap(func(w http.ResponseWriter) http.ResponseWriter { return flushMethodOnly{w} }),
			assert: func(t *testing.T, resp *http.Response, body string, err error) {
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, streamEvent, body)
			},
		},
		{
			name:  "a wrapper with Unwrap keeps working",
			mount: wrap(func(w http.ResponseWriter) http.ResponseWriter { return unwrappingWriter{w} }),
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
			srv := httptest.NewServer(tc.mount(serve(got)))
			t.Cleanup(srv.Close)

			ctx, cancel := context.WithTimeout(t.Context(), streamBound)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, http.NoBody)
			require.NoError(t, err)

			resp, err := srv.Client().Do(req)
			require.NoError(t, err)

			defer func() { _ = resp.Body.Close() }()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			tc.assert(t, resp, string(body), <-got)
		})
	}
}

// notSupportedAtRunTime has a FlushError that says it cannot flush only when asked,
// which nothing can see before calling it.
type notSupportedAtRunTime struct{ http.ResponseWriter }

func (notSupportedAtRunTime) FlushError() error { return http.ErrNotSupported }

// headerOnWriteHeader adds a header as the status goes out, as a session wrapper does
// with its cookie.
type headerOnWriteHeader struct{ http.ResponseWriter }

func (h headerOnWriteHeader) WriteHeader(status int) {
	h.Header().Set("X-From-Wrapper", "yes")
	h.ResponseWriter.WriteHeader(status)
}

func (h headerOnWriteHeader) Unwrap() http.ResponseWriter { return h.ResponseWriter }

// flushMethodOnly is a consumer's wrapper with a working Flush and no Unwrap.
type flushMethodOnly struct{ http.ResponseWriter }

func (f flushMethodOnly) Flush() {
	if flusher, ok := f.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// selfUnwrapping is a wrapper with a working Flush whose Unwrap returns itself.
type selfUnwrapping struct{ flushMethodOnly }

func (s selfUnwrapping) Unwrap() http.ResponseWriter { return s }

// pairedUnwrapping is half of a cycle of two wrappers.
type pairedUnwrapping struct {
	http.ResponseWriter

	next func() http.ResponseWriter
}

func (p pairedUnwrapping) Unwrap() http.ResponseWriter { return p.next() }

// heldHeadWriter chooses its encoding at the first write, and holds the status until
// then, so its Flush does nothing before it, as a compression middleware's does. A
// head sent from beneath it has no encoding on it, over a body that has one.
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

// hookedWriter has a WriteHeader hook and a FlushError, and no Unwrap: the status
// goes through the hook only if something names it.
type hookedWriter struct {
	http.ResponseWriter

	hooks *atomic.Int64
}

func (h hookedWriter) WriteHeader(status int) {
	h.hooks.Add(1)
	h.Header().Set("X-From-Hook", "yes")
	h.ResponseWriter.WriteHeader(status)
}

func (h hookedWriter) FlushError() error {
	return http.NewResponseController(h.ResponseWriter).Flush()
}

// hookedUnwrappingWriter is hookedWriter with an Unwrap, which is the shape of the
// wrappers a metrics or tracing middleware generates.
type hookedUnwrappingWriter struct{ hookedWriter }

func (h hookedUnwrappingWriter) Unwrap() http.ResponseWriter { return h.ResponseWriter }

// superfluousLines counts net/http's complaints about a second status.
type superfluousLines struct{ n atomic.Int64 }

func (s *superfluousLines) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "superfluous") {
		s.n.Add(1)
	}

	return len(p), nil
}

// TestHTTPResponseWriter_StreamBeneathWrappers pins that a stream leaves a middleware's
// wrapper in charge of what it wraps: a head the wrapper is holding stays held, and a
// status goes through its WriteHeader. The event is read while the body is still
// running, because a body that returned would flush it anyway.
func TestHTTPResponseWriter_StreamBeneathWrappers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		wrap   func(w http.ResponseWriter, hooks *atomic.Int64) http.ResponseWriter
		assert func(t *testing.T, resp *http.Response, hooks int64)
	}{
		{
			name: "a wrapper holding the head until its first write keeps it until then",
			wrap: func(w http.ResponseWriter, _ *atomic.Int64) http.ResponseWriter {
				return &heldHeadWriter{ResponseWriter: w}
			},
			assert: func(t *testing.T, resp *http.Response, _ int64) {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "chosen-at-first-write", resp.Header.Get("Content-Encoding"),
					"the head was sent from beneath the wrapper")
			},
		},
		{
			name: "a wrapper with FlushError, Unwrap and a WriteHeader hook has its hook run once",
			wrap: func(w http.ResponseWriter, hooks *atomic.Int64) http.ResponseWriter {
				return hookedUnwrappingWriter{hookedWriter{ResponseWriter: w, hooks: hooks}}
			},
			assert: func(t *testing.T, resp *http.Response, hooks int64) {
				assert.Equal(t, int64(1), hooks)
				assert.Equal(t, "yes", resp.Header.Get("X-From-Hook"))
			},
		},
		{
			// A limit ErrStreamingUnsupported states.
			name: "a wrapper with FlushError and no Unwrap streams, and its WriteHeader is skipped",
			wrap: func(w http.ResponseWriter, hooks *atomic.Int64) http.ResponseWriter {
				return hookedWriter{ResponseWriter: w, hooks: hooks}
			},
			assert: func(t *testing.T, resp *http.Response, hooks int64) {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Zero(t, hooks)
				assert.Empty(t, resp.Header.Get("X-From-Hook"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var hooks atomic.Int64

			lines := &superfluousLines{}
			release := make(chan struct{})

			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = httpsec.NewHTTPResponseWriter(tc.wrap(w, &hooks)).
					Stream(r.Context(), "", func(_ context.Context, ew httpsec.EventWriter) error {
						if err := writeAndFlush(ew); err != nil {
							return err
						}

						hold(t, release, "the row's release")

						return nil
					})
			}))
			srv.Config.ErrorLog = log.New(lines, "", 0)
			srv.Start()
			t.Cleanup(srv.Close)

			resp := streamServer{url: srv.URL, client: srv.Client()}.get(t.Context(), t, 1)
			r := bufio.NewReader(resp.Body)

			line, err := r.ReadString('\n')
			require.NoError(t, err)
			assert.Equal(t, streamLine, line)

			close(release)

			_, err = io.ReadAll(r)
			require.NoError(t, err)

			tc.assert(t, resp, hooks.Load())
			assert.Zero(t, lines.n.Load(), "net/http logged a second status")
		})
	}
}

// TestHTTPResponseWriter_StreamWrapperWalkEnds pins that a chain of wrappers that never
// ends is a writer that cannot flush, rather than a request that spins for ever. Each
// row is bounded by its own goroutine, because what fails here does not return.
func TestHTTPResponseWriter_StreamWrapperWalkEnds(t *testing.T) {
	t.Parallel()

	unsupported := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, httpsec.ErrStreamingUnsupported)
	}

	cases := []struct {
		name   string
		w      func() http.ResponseWriter
		assert func(t *testing.T, err error)
	}{
		{
			name: "a wrapper whose Unwrap returns itself",
			w: func() http.ResponseWriter {
				return selfUnwrapping{flushMethodOnly{httptest.NewRecorder()}}
			},
			assert: unsupported,
		},
		{
			name: "two wrappers that unwrap to each other",
			w: func() http.ResponseWriter {
				var first, second pairedUnwrapping

				first = pairedUnwrapping{ResponseWriter: httptest.NewRecorder(), next: func() http.ResponseWriter { return second }}
				second = pairedUnwrapping{ResponseWriter: httptest.NewRecorder(), next: func() http.ResponseWriter { return first }}

				return first
			},
			assert: unsupported,
		},
		{
			name: "wrappers too many to walk",
			w: func() http.ResponseWriter {
				var w http.ResponseWriter = httptest.NewRecorder()
				for range 1000 {
					w = unwrappingWriter{w}
				}

				return w
			},
			assert: unsupported,
		},
		{
			name: "a few wrappers are walked",
			w: func() http.ResponseWriter {
				var w http.ResponseWriter = httptest.NewRecorder()
				for range 8 {
					w = unwrappingWriter{w}
				}

				return w
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := tc.w()
			done := make(chan error, 1)
			ctx := t.Context()

			go func() {
				done <- httpsec.NewHTTPResponseWriter(w).Stream(ctx, "", func(context.Context, httpsec.EventWriter) error {
					return nil
				})
			}()

			select {
			case err := <-done:
				tc.assert(t, err)
			case <-time.After(streamBound):
				t.Fatal("Stream is still walking the wrappers")
			}
		})
	}
}

// TestHTTPResponseWriter_StreamBodyEndsEarly pins that a body that does not return
// cannot leave a response that looks complete, including when a recovery middleware
// catches its panic and the handler returns as usual, and that what the middleware or
// the server catches is what the body panicked with.
func TestHTTPResponseWriter_StreamBodyEndsEarly(t *testing.T) {
	t.Parallel()

	ownBug := errors.New("a body's own bug")

	cases := []struct {
		name      string
		overHTTP2 bool

		// recovers puts a recovering middleware around the handler.
		recovers bool
		end      func()
		assert   func(t *testing.T, recovered any)
	}{
		{
			name:     "over HTTP/1.1 a panic a middleware recovers leaves a cut response, and its value",
			recovers: true,
			end:      func() { panic(ownBug) },
			assert:   func(t *testing.T, recovered any) { t.Helper(); assert.Equal(t, ownBug, recovered) },
		},
		{
			name:      "over HTTP/2 a panic a middleware recovers leaves a cut response, and its value",
			overHTTP2: true,
			recovers:  true,
			end:       func() { panic(ownBug) },
			assert:    func(t *testing.T, recovered any) { t.Helper(); assert.Equal(t, ownBug, recovered) },
		},
		{
			name:     "over HTTP/1.1 http.ErrAbortHandler reaches the middleware as it was",
			recovers: true,
			end:      func() { panic(http.ErrAbortHandler) },
			assert:   func(t *testing.T, recovered any) { t.Helper(); assert.Equal(t, http.ErrAbortHandler, recovered) },
		},
		{
			name:      "over HTTP/2 http.ErrAbortHandler reaches the middleware as it was",
			overHTTP2: true,
			recovers:  true,
			end:       func() { panic(http.ErrAbortHandler) },
			assert:    func(t *testing.T, recovered any) { t.Helper(); assert.Equal(t, http.ErrAbortHandler, recovered) },
		},
		{
			name:      "over HTTP/2 a panic with no middleware reaches the server",
			overHTTP2: true,
			end:       func() { panic(http.ErrAbortHandler) },
			assert:    func(*testing.T, any) {},
		},
		{
			name:   "over HTTP/1.1 runtime.Goexit leaves a cut response",
			end:    runtime.Goexit,
			assert: func(*testing.T, any) {},
		},
		{
			name:      "over HTTP/2 runtime.Goexit leaves a cut response",
			overHTTP2: true,
			end:       runtime.Goexit,
			assert:    func(*testing.T, any) {},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			recovered := make(chan any, 1)
			srv := startStreamServer(t, tc.overHTTP2, func(w http.ResponseWriter, r *http.Request) {
				if tc.recovers {
					defer func() { recovered <- recover() }()
				} else {
					recovered <- nil
				}

				_ = httpsec.NewHTTPResponseWriter(w).Stream(r.Context(), "", func(_ context.Context, ew httpsec.EventWriter) error {
					if err := writeAndFlush(ew); err != nil {
						return err
					}

					tc.end()

					return nil
				})
			})

			ctx, cancel := context.WithTimeout(t.Context(), streamBound)
			defer cancel()

			resp := srv.get(ctx, t, protoMajor(tc.overHTTP2))

			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			events, err := countEvents(resp.Body)
			require.Error(t, err, "the response ended as if it were complete")
			assert.Equal(t, 1, events, "the event flushed before the end was lost")

			tc.assert(t, <-recovered)
		})
	}
}

// TestHTTPResponseWriter_StreamContentType is the type Stream is given, on a real server: it goes out
// with the stream's head and on nothing else. A refusal's answer is labelled by whatever labels any
// other answer, which here is the handler or net/http's detection.
func TestHTTPResponseWriter_StreamContentType(t *testing.T) {
	t.Parallel()

	const (
		eventStream  = "text/event-stream"
		consumerType = "text/x-consumer"
	)

	wrap := func(wrapper func(http.ResponseWriter) http.ResponseWriter) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(wrapper(w), r)
			})
		}
	}

	cannotFlush := wrap(func(w http.ResponseWriter) http.ResponseWriter { return bareWriter{w} })

	// consumersType is a consumer's interceptor that named a type first.
	consumersType := func(w httpsec.ResponseWriter) { w.SetHeader("Content-Type", consumerType) }

	refused := func(t *testing.T, resp *http.Response, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrStreamingUnsupported)
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	}

	carriesNone := func(t *testing.T, resp *http.Response, _ string, err error) {
		t.Helper()

		refused(t, resp, err)
		assert.NotContains(t, resp.Header, "Content-Type", "a refusal carries no type, not even a blank one")
	}

	keepsConsumers := func(t *testing.T, resp *http.Response, _ string, err error) {
		t.Helper()

		refused(t, resp, err)
		assert.Equal(t, []string{consumerType}, resp.Header["Content-Type"])
	}

	cases := []struct {
		name string

		// mount wraps the handler. Default: none.
		mount func(http.Handler) http.Handler

		// before runs ahead of Stream, as an earlier interceptor does.
		before func(w httpsec.ResponseWriter)

		contentType string

		// answer is written after a refusal. Default: nothing, only the status.
		answer string

		assert func(t *testing.T, resp *http.Response, body string, err error)
	}{
		{
			name:        "the type arrives with the stream",
			contentType: eventStream,
			assert: func(t *testing.T, resp *http.Response, body string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, []string{eventStream}, resp.Header["Content-Type"])
				assert.Equal(t, streamEvent, body)
			},
		},
		{
			name:        "the type arrives under a wrapper whose flush is what sends the head",
			mount:       wrap(func(w http.ResponseWriter) http.ResponseWriter { return hookedWriter{w, &atomic.Int64{}} }),
			contentType: eventStream,
			assert: func(t *testing.T, resp *http.Response, _ string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{eventStream}, resp.Header["Content-Type"])
			},
		},
		{
			name:        "the type replaces one a consumer named first",
			before:      consumersType,
			contentType: eventStream,
			assert: func(t *testing.T, resp *http.Response, _ string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{eventStream}, resp.Header["Content-Type"])
			},
		},
		{
			name: "an empty type sets none",
			assert: func(t *testing.T, resp *http.Response, body string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotContains(t, resp.Header, "Content-Type")
				assert.Equal(t, streamEvent, body)
			},
		},
		{
			name:   "an empty type leaves the one a consumer named",
			before: consumersType,
			assert: func(t *testing.T, resp *http.Response, _ string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{consumerType}, resp.Header["Content-Type"])
			},
		},
		{
			name:        "a wrapper that cannot flush refuses with no type",
			mount:       cannotFlush,
			contentType: eventStream,
			assert:      carriesNone,
		},
		{
			name: "http.TimeoutHandler refuses with no type",
			mount: func(next http.Handler) http.Handler {
				return http.TimeoutHandler(next, streamBound, "timed out")
			},
			contentType: eventStream,
			assert:      carriesNone,
		},
		{
			name:        "a refusal's answer gets net/http's detected type",
			mount:       cannotFlush,
			contentType: eventStream,
			answer:      "<html></html>",
			assert: func(t *testing.T, resp *http.Response, body string, err error) {
				t.Helper()

				refused(t, resp, err)
				assert.Equal(t, "<html></html>", body)
				assert.Equal(t, []string{"text/html; charset=utf-8"}, resp.Header["Content-Type"])
			},
		},
		{
			name:        "a refusal leaves the type a consumer named",
			mount:       cannotFlush,
			before:      consumersType,
			contentType: eventStream,
			assert:      keepsConsumers,
		},
		{
			name:        "a wrapper that refuses only when asked to flush leaves no type",
			mount:       wrap(func(w http.ResponseWriter) http.ResponseWriter { return notSupportedAtRunTime{w} }),
			contentType: eventStream,
			assert:      carriesNone,
		},
		{
			name: "the same wrapper, beneath one that has only Unwrap, leaves no type",
			mount: wrap(func(w http.ResponseWriter) http.ResponseWriter {
				return unwrappingWriter{notSupportedAtRunTime{w}}
			}),
			contentType: eventStream,
			assert:      carriesNone,
		},
		{
			name:        "a wrapper that refuses only when asked to flush restores the type a consumer named",
			mount:       wrap(func(w http.ResponseWriter) http.ResponseWriter { return notSupportedAtRunTime{w} }),
			before:      consumersType,
			contentType: eventStream,
			assert:      keepsConsumers,
		},
		{
			name: "ErrStreamingStarted leaves a consumer's headers alone",
			before: func(w httpsec.ResponseWriter) {
				consumersType(w)
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			contentType: eventStream,
			assert: func(t *testing.T, resp *http.Response, _ string, err error) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrStreamingStarted)
				assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
				assert.Equal(t, []string{consumerType}, resp.Header["Content-Type"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := make(chan error, 1)

			var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rw := httpsec.NewHTTPResponseWriter(w)

				if tc.before != nil {
					tc.before(rw)
				}

				err := rw.Stream(r.Context(), tc.contentType, func(_ context.Context, ew httpsec.EventWriter) error {
					return writeAndFlush(ew)
				})
				got <- err

				if err != nil {
					rw.WriteHeader(http.StatusNotImplemented)

					if tc.answer != "" {
						_, _ = io.WriteString(rw, tc.answer)
					}
				}
			})

			if tc.mount != nil {
				handler = tc.mount(handler)
			}

			srv := httptest.NewServer(handler)
			t.Cleanup(srv.Close)

			ctx, cancel := context.WithTimeout(t.Context(), streamBound)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, http.NoBody)
			require.NoError(t, err)

			resp, err := srv.Client().Do(req)
			require.NoError(t, err)

			defer func() { _ = resp.Body.Close() }()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			tc.assert(t, resp, string(body), <-got)
		})
	}
}

// lateRefusal says it cannot flush only after the status has been named, because the writer below it
// can flush and moves a deadline, so nothing asks it sooner. Its head is held by what it wraps, here a
// recorder, so what the header holds afterwards is still what a client would be sent.
type lateRefusal struct{ *recordingWriter }

func (l lateRefusal) Unwrap() http.ResponseWriter { return l.recordingWriter }

func (lateRefusal) FlushError() error { return http.ErrNotSupported }

// TestHTTPResponseWriter_StreamContentTypeLateRefusal is the one refusal that comes after the type had
// to be set: the writer puts back what was there.
func TestHTTPResponseWriter_StreamContentTypeLateRefusal(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		before []string
	}{
		{name: "no type was there, and none is left"},
		{name: "a consumer's type was there, and it is left", before: []string{"text/x-consumer"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			below := &recordingWriter{}

			if tc.before != nil {
				below.Header()["Content-Type"] = tc.before
			}

			err := httpsec.NewHTTPResponseWriter(lateRefusal{below}).Stream(t.Context(), "text/event-stream",
				func(context.Context, httpsec.EventWriter) error {
					t.Error("Stream refused, and its body ran")

					return nil
				})

			require.ErrorIs(t, err, httpsec.ErrStreamingUnsupported)
			assert.Equal(t, tc.before, below.Header()["Content-Type"])
		})
	}
}
