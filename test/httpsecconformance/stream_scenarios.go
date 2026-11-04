package httpsecconformance

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

const (
	// StreamWriteTimeout is the write timeout a StreamAdapter runs its server
	// under, the one the framework adapters specification names.
	StreamWriteTimeout = 3 * time.Second

	// SlowWritePath is the route a StreamAdapter mounts behind the chain that
	// writes one chunk, waits StreamWriteTimeout and a second more, and writes
	// another, in its framework's own way and with no stream of the library's.
	SlowWritePath = "/conformance/slow-write"

	// SlowWriteChunk is what that route writes each time.
	SlowWriteChunk = "chunk\n"

	// streamPath is the path the rows' chain streams on.
	streamPath = "/conformance/stream"

	// streamEvent is one event as a row writes it, and streamEventLine the line a
	// client reads first.
	streamEvent     = "data: e\n\n"
	streamEventLine = "data: e\n"

	// streamBound fails a row that would otherwise wait for ever. No row waits for
	// it to pass.
	streamBound = 10 * time.Second
)

// StreamServer is a framework stood up on a real listener. Shutdown is nil on a
// framework whose shutdown does not end an open stream by itself.
type StreamServer struct {
	URL      string
	Shutdown func(ctx context.Context) error

	// BodyRunsLater is set by a framework whose stream body runs after the chain has
	// returned, as fiber's does: a chain that refuses after Stream is then answered
	// with the refusal and the client gets no stream.
	BodyRunsLater bool

	// CompressesStream is set by an adapter whose ChainSpec.Compress wrapper really compresses
	// the event stream. net/http's and gin's gzhttp does. Fiber's compress middleware does not:
	// it skips any response marked Cache-Control: no-transform, which the stream always is.
	CompressesStream bool
}

// StreamAdapter is an Adapter that can also serve a chain on a real listener,
// which is what the streaming rows need and what Serve, reading one finished
// response, cannot offer.
//
// A row is skipped on an adapter that does not implement it. An integration on a
// fourth framework implements it to be held to those rows too.
type StreamAdapter interface {
	Adapter

	// Listen serves spec's chain on a real listener with the given write timeout,
	// with SlowWritePath mounted behind it. The server goes with the test.
	Listen(t *testing.T, spec ChainSpec, writeTimeout time.Duration) StreamServer
}

// WriteSlowly is the SlowWritePath route over net/http's own types, for an
// adapter that has them.
func WriteSlowly(w http.ResponseWriter) {
	rc := http.NewResponseController(w)

	_, _ = io.WriteString(w, SlowWriteChunk)
	_ = rc.Flush()

	// The sleep is the behaviour under test: time passing with no stream of the
	// library's to move the deadline.
	time.Sleep(StreamWriteTimeout + time.Second)

	_, _ = io.WriteString(w, SlowWriteChunk)
	_ = rc.Flush()
}

// streamScenarios is every streaming behaviour that must be identical on every
// adapter that can stream.
func streamScenarios() []Scenario {
	return []Scenario{
		{Name: "stream: a flushed event arrives while the response is open", Stream: flushedEventArrivesWhileOpen},
		{Name: "stream: headers set before streaming are sent", Stream: headersSetBeforeStreamingAreSent},
		{Name: "stream: a stream after the response began fails", Stream: streamAfterResponseBeganFails},
		{Name: "stream: a stream outlives a 3-second write timeout", Stream: streamOutlivesWriteTimeout},
		{Name: "stream: an ordinary response keeps the deadline", Stream: ordinaryResponseKeepsDeadline},
		{Name: "stream: a client that leaves stops the stream within a heartbeat", Stream: clientThatLeavesStopsStreamWithinHeartbeat},
		{Name: "stream: a client that leaves ends the body's context with nothing written", Stream: clientThatLeavesEndsContext},
		{Name: "stream: a client that half-closes counts as having left", Stream: clientThatHalfClosesHasLeft},
		{Name: "stream: server shutdown ends an open stream", Stream: serverShutdownEndsStream},
		{Name: "stream: a body that returns an error has run, and Stream returned nil", Stream: bodyErrorIsNotStreamError},
		{Name: "stream: a chain that refuses after Stream still runs the body exactly once", Stream: refusedStreamRunsBodyOnce},
		{Name: "stream: a body that panics has run once and leaves the server running", Stream: panickingBodyLeavesServerRunning},
		{Name: "stream: a body that exits its goroutine leaves a cut response", Stream: bodyThatExitsItsGoroutineLeavesCutResponse},
	}
}

// streamingChain is a chain that runs serve on streamPath and lets every other
// request through.
func streamingChain(serve func(ex *httpsec.Exchange) error) ChainSpec {
	return ChainSpec{Options: []httpsec.Option{httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
			if ex.Request.Path() != streamPath {
				return next(ex)
			}

			return serve(ex)
		}), httpsec.OrderBearerToken)}}
}

// openStream sends one request on ctx, on a connection of its own, leaving the
// body for the row to read. The whole exchange is bounded by streamBound, so a
// response that never comes or never ends fails the row instead of hanging it.
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

func writeStreamEvent(w httpsec.EventWriter) error {
	if _, err := io.WriteString(w, streamEvent); err != nil {
		return err
	}

	return w.Flush()
}

func waitForStream(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(streamBound):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// holdStream is how a body waits for ch. A server may not close while its handler
// runs, so a body that waited for ever would hang the row's cleanup: it reports and
// returns instead.
func holdStream(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(streamBound):
		t.Errorf("a body timed out waiting for %s", what)
	}
}

func flushedEventArrivesWhileOpen(t *testing.T, listen func(ChainSpec) StreamServer) {
	release, returned := make(chan struct{}), make(chan struct{})
	srv := listen(streamingChain(func(ex *httpsec.Exchange) error {
		return ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
			defer close(returned)

			if err := writeStreamEvent(w); err != nil {
				return err
			}

			holdStream(t, release, "the row's release")

			return nil
		})
	}))

	r := bufio.NewReader(openStream(t.Context(), t, srv.URL+streamPath).Body)

	line, err := r.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, streamEventLine, line)

	select {
	case <-returned:
		t.Error("the event arrived only once the body had returned")
	default:
	}

	close(release)

	_, err = io.ReadAll(r)
	require.NoError(t, err)
}

func headersSetBeforeStreamingAreSent(t *testing.T, listen func(ChainSpec) StreamServer) {
	release := make(chan struct{})
	srv := listen(streamingChain(func(ex *httpsec.Exchange) error {
		ex.Writer.SetHeader("Cache-Control", "no-store")
		ex.Writer.SetHeader("Access-Control-Allow-Origin", "https://app.example")

		err := ex.Writer.Stream(ex.Context(), func(context.Context, httpsec.EventWriter) error {
			holdStream(t, release, "the row's release")

			return nil
		})

		ex.Writer.SetHeader("X-Too-Late", "yes")

		return err
	}))

	// Bounded, so a head that waits for a body waiting on release fails on this
	// request's deadline instead of hanging.
	ctx, cancel := context.WithTimeout(t.Context(), streamBound)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+streamPath, http.NoBody)
	require.NoError(t, err)

	resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)

	close(release)
	require.NoError(t, err, "the head did not arrive before anything was written")

	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	assert.Equal(t, "https://app.example", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Empty(t, resp.Header.Get("X-Too-Late"))
}

func streamAfterResponseBeganFails(t *testing.T, listen func(ChainSpec) StreamServer) {
	got := make(chan error, 1)
	srv := listen(streamingChain(func(ex *httpsec.Exchange) error {
		_, _ = io.WriteString(ex.Writer, "written")

		got <- ex.Writer.Stream(ex.Context(), func(context.Context, httpsec.EventWriter) error {
			return errors.New("this body must not run")
		})

		return nil
	}))

	body, err := io.ReadAll(openStream(t.Context(), t, srv.URL+streamPath).Body)
	require.NoError(t, err)
	assert.Equal(t, "written", string(body), "nothing more was written")
	require.ErrorIs(t, <-got, httpsec.ErrStreamingStarted)
}

// streamOutlivesWriteTimeout is the scenario as the specification states it. The
// real window is two minutes and no adapter lets a consumer shorten it, so this row
// shows the server's write timeout does not end a stream, and cannot show that each
// step moves the window: each adapter's own suite does that, under a test-only
// window.
func streamOutlivesWriteTimeout(t *testing.T, listen func(ChainSpec) StreamServer) {
	const (
		heartbeat = 5 * time.Second
		lasting   = 30 * time.Second
		beats     = int(lasting/heartbeat) + 1 // the first at once
	)

	srv := listen(streamingChain(func(ex *httpsec.Exchange) error {
		return ex.Writer.Stream(ex.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
			for i := range beats {
				if i > 0 {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(heartbeat):
					}
				}

				if err := writeStreamEvent(w); err != nil {
					return err
				}
			}

			return nil
		})
	}))

	start := time.Now()
	r := bufio.NewReader(openStreamWithin(t.Context(), t, srv.URL+streamPath, lasting+streamBound).Body)
	events := 0

	for {
		line, err := r.ReadString('\n')
		if errors.Is(err, io.EOF) {
			break
		}

		require.NoError(t, err, "the stream was cut after %v and %d events", time.Since(start), events)

		if line == streamEventLine {
			events++
		}
	}

	assert.Equal(t, beats, events)
	assert.GreaterOrEqual(t, time.Since(start), lasting)
}

func ordinaryResponseKeepsDeadline(t *testing.T, listen func(ChainSpec) StreamServer) {
	srv := listen(streamingChain(func(*httpsec.Exchange) error { return nil }))

	body, err := io.ReadAll(openStream(t.Context(), t, srv.URL+SlowWritePath).Body)

	require.Error(t, err, "the second chunk came after the deadline")
	assert.Equal(t, SlowWriteChunk, string(body), "the first chunk came before it")
}

// leavingHeartbeat is the heartbeat the rows about a client leaving run under, and so
// how long they allow: the specification's bound is one heartbeat.
const leavingHeartbeat = time.Second

// clientThatLeavesStopsStreamWithinHeartbeat is the framework-adapters scenario with
// its time, on a body that goes on writing as the signal stream does.
func clientThatLeavesStopsStreamWithinHeartbeat(t *testing.T, listen func(ChainSpec) StreamServer) {
	first, ended := make(chan struct{}), make(chan time.Time, 1)

	var once sync.Once

	srv := listen(streamingChain(func(ex *httpsec.Exchange) error {
		return ex.Writer.Stream(ex.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
			defer func() { ended <- time.Now() }()

			for {
				if err := writeStreamEvent(w); err != nil {
					return err
				}

				once.Do(func() { close(first) })

				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(leavingHeartbeat):
				}
			}
		})
	}))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	resp := openStream(ctx, t, srv.URL+streamPath)
	waitForStream(t, first, "the first flush")

	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, streamEventLine, line)

	at := time.Now()

	cancel()
	assertEndsWithinHeartbeat(t, ended, at)
}

// clientThatLeavesEndsContext has a body that writes nothing after its first event,
// so no failed write can tell it: only its context can.
func clientThatLeavesEndsContext(t *testing.T, listen func(ChainSpec) StreamServer) {
	ended := make(chan time.Time, 1)
	srv := listen(streamingChain(func(ex *httpsec.Exchange) error {
		return ex.Writer.Stream(ex.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
			if err := writeStreamEvent(w); err != nil {
				return err
			}

			holdStream(t, ctx.Done(), "the client to leave")
			ended <- time.Now()

			return ctx.Err()
		})
	}))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	line, err := bufio.NewReader(openStream(ctx, t, srv.URL+streamPath).Body).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, streamEventLine, line)

	at := time.Now()

	cancel()
	assertEndsWithinHeartbeat(t, ended, at)
}

// clientThatHalfClosesHasLeft closes only the client's sending side: the connection
// can still carry what the server writes, and the stream ends anyway.
func clientThatHalfClosesHasLeft(t *testing.T, listen func(ChainSpec) StreamServer) {
	ended := make(chan time.Time, 1)
	srv := listen(streamingChain(func(ex *httpsec.Exchange) error {
		return ex.Writer.Stream(ex.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
			if err := writeStreamEvent(w); err != nil {
				return err
			}

			holdStream(t, ctx.Done(), "the client to half-close")
			ended <- time.Now()

			return ctx.Err()
		})
	}))

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", strings.TrimPrefix(srv.URL, "http://"))
	require.NoError(t, err)

	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(streamBound)))

	_, err = io.WriteString(conn, "GET "+streamPath+" HTTP/1.1\r\nHost: conformance\r\n\r\n")
	require.NoError(t, err)

	r := bufio.NewReader(conn)

	resp, err := http.ReadResponse(r, nil)
	require.NoError(t, err)

	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, streamEventLine, line)

	tcp, ok := conn.(*net.TCPConn)
	require.True(t, ok)

	at := time.Now()

	require.NoError(t, tcp.CloseWrite())
	assertEndsWithinHeartbeat(t, ended, at)
}

// assertEndsWithinHeartbeat reads when a body ended, and holds it to the bound.
func assertEndsWithinHeartbeat(t *testing.T, ended <-chan time.Time, at time.Time) {
	t.Helper()

	select {
	case end := <-ended:
		took := end.Sub(at)
		t.Logf("client leaving to body ending: %v", took)
		assert.LessOrEqual(t, took, leavingHeartbeat, "the specification's bound is one heartbeat")
	case <-time.After(streamBound):
		t.Fatal("the stream did not stop after the client left")
	}
}

func serverShutdownEndsStream(t *testing.T, listen func(ChainSpec) StreamServer) {
	opened, ended := make(chan struct{}), make(chan struct{})
	srv := listen(streamingChain(func(ex *httpsec.Exchange) error {
		return ex.Writer.Stream(ex.Context(), func(ctx context.Context, w httpsec.EventWriter) error {
			defer close(ended)

			if err := writeStreamEvent(w); err != nil {
				return err
			}

			close(opened)
			holdStream(t, ctx.Done(), "shutdown to end its context")

			return ctx.Err()
		})
	}))

	if srv.Shutdown == nil {
		t.Skip("on this framework a server's shutdown does not end an open stream by itself")
	}

	resp := openStream(t.Context(), t, srv.URL+streamPath)
	waitForStream(t, opened, "the stream to open")

	ctx, cancel := context.WithTimeout(t.Context(), streamBound)
	defer cancel()

	require.NoError(t, srv.Shutdown(ctx), "the stream did not hold shutdown open")
	waitForStream(t, ended, "the stream to end")

	_, _ = io.ReadAll(resp.Body)
}

// bodyErrorIsNotStreamError holds every adapter to the same reading of Stream's
// error, which is what a caller frees its place on: an error means the body never
// ran, so one that ran and failed is not reported as one.
func bodyErrorIsNotStreamError(t *testing.T, listen func(ChainSpec) StreamServer) {
	got, ran := make(chan error, 1), make(chan struct{})
	srv := listen(streamingChain(func(ex *httpsec.Exchange) error {
		err := ex.Writer.Stream(ex.Context(), func(context.Context, httpsec.EventWriter) error {
			close(ran)

			return errors.New("the body's own failure")
		})
		got <- err

		return err
	}))

	_, err := io.ReadAll(openStream(t.Context(), t, srv.URL+streamPath).Body)
	require.NoError(t, err)
	waitForStream(t, ran, "the body to run")
	require.NoError(t, <-got)
}

// refusedStreamRunsBodyOnce is the place a stream endpoint holds under its caps, which
// its body frees. What the client gets differs by adapter: on net/http and gin the
// body has returned before the chain can refuse and the stream stands, and on fiber
// the response is the refusal. That the body ran exactly once does not differ.
func refusedStreamRunsBodyOnce(t *testing.T, listen func(ChainSpec) StreamServer) {
	var runs atomic.Int64

	ended := make(chan struct{})
	spec := streamingChain(func(ex *httpsec.Exchange) error {
		return ex.Writer.Stream(ex.Context(), func(context.Context, httpsec.EventWriter) error {
			defer close(ended)

			runs.Add(1)

			return nil
		})
	})
	spec.Options = append(spec.Options, httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
			if err := next(ex); err != nil {
				return err
			}

			return httpsec.ErrRequestTooLarge
		}), httpsec.OrderJWKS))

	srv := listen(spec)

	_, err := io.ReadAll(openStream(t.Context(), t, srv.URL+streamPath).Body)
	require.NoError(t, err)

	waitForStream(t, ended, "the body of a refused stream to run")
	assert.Equal(t, int64(1), runs.Load())
}

func bodyThatExitsItsGoroutineLeavesCutResponse(t *testing.T, listen func(ChainSpec) StreamServer) {
	var calls, runs atomic.Int64

	srv := listen(streamingChain(func(ex *httpsec.Exchange) error {
		if calls.Add(1) > 1 {
			ex.Writer.WriteHeader(http.StatusNoContent)

			return nil
		}

		return ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
			runs.Add(1)

			if err := writeStreamEvent(w); err != nil {
				return err
			}

			runtime.Goexit()

			return nil
		})
	}))

	resp := openStream(t.Context(), t, srv.URL+streamPath)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the head goes out on every adapter")

	body, err := io.ReadAll(resp.Body)
	require.Error(t, err, "the response ended as if it were complete")
	require.NotErrorIs(t, err, context.DeadlineExceeded, "the client was left hanging")
	assert.Equal(t, streamEvent, string(body), "the event flushed before the end arrived")
	assert.Equal(t, int64(1), runs.Load())

	assert.Equal(t, http.StatusNoContent, openStream(t.Context(), t, srv.URL+streamPath).StatusCode)
}

func panickingBodyLeavesServerRunning(t *testing.T, listen func(ChainSpec) StreamServer) {
	var calls, runs atomic.Int64

	srv := listen(streamingChain(func(ex *httpsec.Exchange) error {
		if calls.Add(1) > 1 {
			ex.Writer.WriteHeader(http.StatusNoContent)

			return nil
		}

		return ex.Writer.Stream(ex.Context(), func(_ context.Context, w httpsec.EventWriter) error {
			runs.Add(1)

			if err := writeStreamEvent(w); err != nil {
				return err
			}

			panic(http.ErrAbortHandler)
		})
	}))

	resp := openStream(t.Context(), t, srv.URL+streamPath)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the head goes out on every adapter")

	body, err := io.ReadAll(resp.Body)
	require.Error(t, err, "the response did not end as if it were complete")
	assert.Equal(t, streamEvent, string(body), "the event flushed before the panic arrived")
	assert.Equal(t, int64(1), runs.Load())

	assert.Equal(t, http.StatusNoContent, openStream(t.Context(), t, srv.URL+streamPath).StatusCode)
}
