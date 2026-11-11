package fibersec

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/diag"
)

// request implements httpsec.Request directly over fiber's own context.
//
// Nothing here builds a net/http request. Converting one would allocate and
// copy every header and the whole body on every secured request, which is the
// cost fiber exists to avoid, and the chain needs none of it: an interceptor
// reads through this abstraction and never reaches for a framework type.
type request struct{ c fiber.Ctx }

// Compile-time proof that the adapters satisfy the ports the chain runs on.
var (
	_ httpsec.Request        = request{}
	_ httpsec.ResponseWriter = (*responseWriter)(nil)
)

func (r request) Method() string            { return r.c.Method() }
func (r request) Header(name string) string { return r.c.Get(name) }
func (r request) Query(name string) string  { return r.c.Query(name) }

// Path returns the request path decoded exactly as net/http decodes URL.Path,
// so every adapter hands the chain the same path for the same request: "%2F"
// becomes "/", "%20" a space, and "+" stays "+".
//
// It reads fasthttp's original path rather than fiber's Path, which is the path
// still percent-encoded by default and form-decoded ("+" as a space) under
// fiber's UnescapePath. A rewrite through fiber's Path(override) is still seen,
// because fiber writes it back to the URI. A path with a malformed escape, which
// net/http would have refused before any handler ran, is returned as sent; it
// then names nothing the chain serves.
func (r request) Path() string {
	raw := string(r.c.Request().URI().PathOriginal())
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return raw
	}

	return decoded
}

// EscapedPath returns the path as the client sent it, percent-encoding intact:
// fasthttp's original path, read from the request line and never decoded.
func (r request) EscapedPath() string { return string(r.c.Request().URI().PathOriginal()) }

// RawQuery returns the query as sent: fasthttp's query string, never decoded
// and never split into arguments, so a pair it could not parse is still in it.
func (r request) RawQuery() string { return string(r.c.Request().URI().QueryString()) }

// QueryValues returns every value of the parameter, in the order sent, and nil
// when it is absent. Each value is copied, because fasthttp's are views into a
// buffer it reuses for the next request on the connection.
func (r request) QueryValues(name string) []string {
	raw := r.c.Request().URI().QueryArgs().PeekMulti(name)
	if len(raw) == 0 {
		return nil
	}

	values := make([]string, len(raw))
	for i, v := range raw {
		values[i] = string(v)
	}

	return values
}

// The caps a field read parses a posted form under, the same as the net/http
// adapter's: the standard library's own defaults for a URL-encoded body and
// for a multipart one. A body over its cap is not parsed at all, and the
// field is answered from the query.
const (
	formURLEncodedCap = 10 << 20 // 10 MiB
	formMultipartCap  = 32 << 20 // 32 MiB
)

// FormValue reads a submitted field with the precedence every adapter shares:
// the posted form first — URL-encoded or multipart — and the URL query only
// when the posted form does not carry the field at all. A field present in
// the posted form with an empty value still counts as present, and a field
// repeated in it answers its first value. It deliberately does not call
// fiber's own FormValue, which searches the query first.
//
// The posted form is read only for POST, PUT and PATCH, matching net/http:
// fasthttp's posted arguments and parsed multipart form read the body whatever
// the method, so without this check a GET or DELETE carrying a body would
// answer from it instead of from the query, unlike every other adapter.
//
// A body is a posted form only when its Content-Type parses, by
// mime.ParseMediaType, as "application/x-www-form-urlencoded" (in any case,
// with any parameters) or as "multipart/form-data" with a boundary. At most 10
// MiB of a URL-encoded body and 32 MiB of a multipart one is parsed, inside
// the app's own BodyLimit, which fiber applies before any handler runs; a
// larger body, a content type that does not parse, or a body that does not
// parse as a whole — url.ParseQuery rejecting any one pair, a ';' separator
// included, or a malformed multipart envelope — answers from the query, as if
// no form had been posted. The body is judged as sent, not decoded from a
// Content-Encoding, as the net/http adapter judges it.
//
// This is the net/http adapter's rule, and it is why the body is parsed here
// with the standard library rather than through fasthttp's posted arguments,
// which match the media type by case-sensitive prefix and accept malformed
// pairs. Reading a field changes nothing Body later answers: Body checks each
// caller's own limit.
//
// The posted form is parsed once per request, on the first field read, and
// kept in the request's locals under a key only this package can name, so
// every adapter over the same request answers from the same parse. A multipart
// parse holds up to its 32 MiB cap of parts in memory on top of the body
// fasthttp has already buffered, so up to about 64 MiB in all; an app that
// cannot afford that per request lowers fiber's BodyLimit.
func (r request) FormValue(name string) string {
	switch r.c.Method() {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		if vs, ok := r.postedForm()[name]; ok && len(vs) > 0 {
			return vs[0]
		}
	}

	return string(r.c.Request().URI().QueryArgs().Peek(name))
}

// postedFormKey is the locals key the parsed posted form is kept under. Its
// type is unexported, so no consumer's key can collide with it.
type postedFormKey struct{}

// parsedForm is a posted form already parsed, nil values included, so a body
// that is not a form is not parsed again either.
type parsedForm struct{ values url.Values }

// postedForm is the posted form, parsed on the request's first field read.
func (r request) postedForm() url.Values {
	if p, ok := r.c.Locals(postedFormKey{}).(*parsedForm); ok {
		return p.values
	}

	p := &parsedForm{values: r.parsePostedForm()}
	r.c.Locals(postedFormKey{}, p)

	return p.values
}

// parsePostedForm parses the body as the form its content type names, under
// that form's cap, and answers nil for anything FormValue does not read as a
// form. Every value is a copy, never a view into the buffer fasthttp reuses.
func (r request) parsePostedForm() url.Values {
	mediaType, params, err := mime.ParseMediaType(r.c.Get(fiber.HeaderContentType))
	if err != nil {
		return nil
	}

	body := r.c.Request().Body()

	switch mediaType {
	case "application/x-www-form-urlencoded":
		if len(body) > formURLEncodedCap {
			return nil
		}

		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil
		}

		return values

	case "multipart/form-data":
		boundary, ok := params["boundary"]
		if !ok || len(body) > formMultipartCap {
			return nil
		}

		form, err := multipart.NewReader(bytes.NewReader(body), boundary).ReadForm(formMultipartCap)
		if err != nil {
			return nil
		}
		defer func() { _ = form.RemoveAll() }()

		return form.Value

	default:
		return nil
	}
}

// Cookie cannot tell an empty cookie from an absent one: fiber answers "" for
// both, and nothing in fiber's request API distinguishes them. The package
// documentation states it, and no interceptor keys a decision on the
// difference — a cookie that must mean something carries a value.
func (r request) Cookie(name string) (string, bool) {
	v := r.c.Cookies(name)

	return v, v != ""
}

// Body returns the body fiber has already buffered, bounded by limit.
//
// Each call applies its own limit, whatever an earlier call read or refused:
// an earlier, larger read does not widen a later, smaller one, and a refused
// read leaves the body as it was, so a later, larger read can succeed. fasthttp
// has read the body from the network once, before any handler ran.
//
// It is a length check rather than a bounded read, because by the time a
// handler runs fasthttp has read the whole request: there is nothing left to
// bound. An app that must cap what it reads at all sets fiber's own BodyLimit,
// which is stated on the package.
//
// The result is copied. fiber's accessors are zero-copy views into the buffer
// fasthttp reuses for the next request on the connection, so a slice returned
// as it came would be rewritten under whoever kept it.
func (r request) Body(limit int64) ([]byte, error) {
	b := r.c.Body()
	if int64(len(b)) > limit {
		return nil, httpsec.ErrRequestTooLarge
	}

	return bytes.Clone(b), nil
}

// ClientIP is the connection's own peer address: the host part of a TCP
// peer, and "" for a peer that is not in host and port form.
//
// It never calls fiber's IP or IPs, which follow a forwarded header once
// fiber's proxy trust is enabled: which proxies may name a client is the
// chain's decision (httpsec.EnableTrustedProxies), made the same way on every
// adapter. fiber's in-memory test transport reports the unspecified address,
// which the chain refuses to attribute a request to.
func (r request) ClientIP() string {
	switch addr := r.c.RequestCtx().RemoteAddr().(type) {
	case *net.TCPAddr:
		return addr.IP.String()
	case nil:
		return ""
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return ""
		}

		return host
	}
}

// DelHeaders removes every header whose name match reports true from the
// request fiber hands to the handlers after the chain. The chain calls it to
// remove the forwarded headers it consumed (httpsec.EnableTrustedProxies).
// The names are collected before any is removed, because fasthttp's header
// iteration must not see the headers change under it.
func (r request) DelHeaders(match func(name string) bool) {
	h := &r.c.Request().Header

	var names []string

	for k := range h.All() {
		if name := string(k); match(name) {
			names = append(names, name)
		}
	}

	for _, name := range names {
		h.Del(name)
	}
}

// HeaderValues returns every line of the header, in the order received, so the
// chain's trusted-proxy resolution joins repeated forwarded headers rather
// than reading the first line alone. Each value is copied out of fasthttp's
// reused buffer.
func (r request) HeaderValues(name string) []string {
	raw := r.c.Request().Header.PeekAll(name)
	if len(raw) == 0 {
		return nil
	}

	out := make([]string, len(raw))
	for i, v := range raw {
		out[i] = string(v)
	}

	return out
}

// Host is the host the client asked for: the request's Host header, or the
// host of an absolute request target, as fasthttp parsed it.
//
// It never calls fiber's Host, Hostname or Scheme, which follow a forwarded
// header once fiber's proxy trust is enabled: which proxies may name a host is
// the chain's decision (httpsec.EnableTrustedProxies), made the same way on
// every adapter. The result is copied out of fasthttp's reused buffer.
func (r request) Host() string { return string(r.c.Request().Host()) }

// Secure reports whether the connection the request arrived on is TLS.
//
// It never calls fiber's Secure or Scheme, which believe a forwarded scheme
// once fiber's proxy trust is enabled.
func (r request) Secure() bool { return r.c.RequestCtx().IsTLS() }

// ClientCertificate is the leaf certificate the client sent on the TLS connection
// the request arrived on, read from fasthttp's connection state, and nil when the
// connection is not TLS or the client sent none. No header is read.
func (r request) ClientCertificate() *x509.Certificate {
	state := r.c.RequestCtx().TLSConnectionState()
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}

	return state.PeerCertificates[0]
}

// responseWriter implements httpsec.ResponseWriter over fiber's context.
//
// It is a pointer because it remembers whether a status has been chosen: the
// net/http writer keeps the first status an interceptor sets and ignores a
// second, and an adapter that let the second win would answer one request
// differently on two frameworks.
type responseWriter struct {
	c fiber.Ctx

	wrote bool

	// streaming is whether Stream has started, after which nothing the writer is
	// asked to do reaches the response: its body writes through its EventWriter.
	streaming bool

	// inChain is whether Middleware built this writer, and gate what it opens once
	// the chain has returned, set by a Stream that started.
	inChain bool
	gate    *streamGate

	// streamType is the type a Stream that started was given, held for chainReturned
	// to set when the chain did not refuse. A writer with no chain sets it at once.
	streamType string

	// chainDone is whether the chain that built this writer has returned, after which
	// its fiber context is not this request's to touch. It is atomic because a Stream
	// made once the chain has returned, which refuses, may be called from another goroutine. Every
	// other call is made on the chain's own goroutine (see httpsec.ResponseWriter.Stream).
	chainDone atomic.Bool

	// streamWindow replaces httpsec.StreamWriteWindow in a test, and is zero
	// otherwise.
	streamWindow time.Duration
}

// SetHeader has no effect once a response has begun, a stream included, as net/http's
// has none once its head has gone, even though fiber would still send this. AddHeader and
// SetCookie have none either, for the same reason: one chain answers one way on both frameworks.
func (w *responseWriter) SetHeader(name, value string) {
	if w.wrote {
		return
	}

	w.c.Set(name, value)
}

// AddHeader appends a header line, keeping the lines already set. It does not
// use fiber's Append, which folds the value into one comma-joined line and
// drops a value already listed, so a list header would read differently from
// net/http's. It has no effect once a response has begun, as SetHeader has none.
func (w *responseWriter) AddHeader(name, value string) {
	if w.wrote {
		return
	}

	w.c.Response().Header.Add(name, value)
}

func (w *responseWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}

	w.wrote = true
	w.c.Status(status)
}

// Write writes nothing once a stream has started: fasthttp would drop the stream
// for the bytes.
func (w *responseWriter) Write(b []byte) (int, error) {
	if w.streaming {
		return 0, httpsec.ErrStreamingStarted
	}

	w.wrote = true

	return w.c.Write(b)
}

// Stream registers body with fiber and returns at once: see
// httpsec.ResponseWriter.Stream for the contract, and for what running after the
// handlers means for a body. A nil return means body runs, exactly once, because
// fasthttp starts the goroutine that runs it before this returns, and every path
// through that goroutine reaches body.
//
// Eight things here differ from what SendStreamWriter alone gives.
//
// A chain can still refuse once this has returned, so contentType waits until it has
// (chainReturned), and a refusal never carries it. A writer built outside a chain has
// nothing to wait for. fiber's error handler then labels the refusal as it would any other.
// An empty contentType sets none, and fasthttp fills in its default type on the response, as
// it does on any response no one named a type for.
//
// fasthttp starts the writer on a goroutine as soon as it is registered, while the
// handlers are still running, so the body waits at a gate the chain opens on its
// way out (chainReturned). A writer built outside a chain has no gate.
//
// A writer kept past its chain refuses, with httpsec.ErrStreamingStarted and without
// touching its fiber context, which fiber has released and may have given to another
// request: reading it on a later goroutine is a nil dereference at best. There would
// be no chain left to open a gate, and no safe way to send a head.
//
// fiber releases its context when the handlers return, and fasthttp pools its
// RequestCtx once the connection ends, which a body that has not yet returned can
// outlive. So the closure holds neither. It holds the connection and the shutdown
// channel, copied here while the handler still owns them.
//
// fasthttp tells nothing that the client has gone, and a write cannot: it reaches
// an in-memory pipe, so a failure comes back heartbeats late. So a goroutine reads
// the connection while the body runs (watchClient), and the response says
// Connection: close, because that goroutine discards whatever a client pipelined.
//
// The read deadline is cleared here, while the handler still holds the connection.
// The one fasthttp set for reading this request is still on it, and the goroutine
// would take its passing for the client leaving.
//
// The first write deadline is set here too, through RequestCtx rather than the
// connection. That tells fasthttp a handler owns this response's deadline. Unmarked,
// it sets its own write timeout once the handlers have returned, over whatever the
// body has set by then, and a first event a slow client takes longer than that to
// read is cut (TestFiber_StreamFirstDeadline).
//
// The stream reaches fasthttp through streamReader, which is how a body that panics
// or calls runtime.Goexit cuts the response without touching the connection
// (endStreamBody).
func (w *responseWriter) Stream(ctx context.Context, contentType string, body func(ctx context.Context, w httpsec.EventWriter) error) error {
	if w.chainDone.Load() || w.wrote {
		return httpsec.ErrStreamingStarted
	}

	window := w.streamWindow
	if window == 0 {
		window = httpsec.StreamWriteWindow
	}

	rctx := w.c.RequestCtx()
	if err := rctx.SetWriteDeadline(time.Now().Add(window)); err != nil {
		return err
	}

	if err := rctx.SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	w.wrote, w.streaming = true, true

	var gate *streamGate
	if w.inChain {
		gate = &streamGate{returned: make(chan struct{})}
		w.gate = gate
		w.streamType = contentType
	} else {
		w.setStreamType(contentType)
	}

	w.c.Status(http.StatusOK)

	rctx.Response.SetConnectionClose()

	// fasthttp otherwise holds the head back until the body's first flush, and
	// every other adapter has sent it by the time body runs.
	rctx.Response.ImmediateHeaderFlush = true

	run := &streamRun{
		body:     body,
		ctx:      context.WithoutCancel(ctx),
		conn:     rctx.Conn(),
		shutdown: rctx.Done(),
		window:   window,
		gate:     gate,
		pipe:     make(chan io.Closer, 1),
	}

	stream := fasthttp.NewStreamReader(run.run)
	run.pipe <- stream

	rctx.Response.SetBodyStream(&streamReader{ReadCloser: stream, cut: &run.cut}, -1)

	return nil
}

// streamRun is one stream's body and what it runs with. It holds nothing that
// belongs to fiber's context, which has been released by the time the body runs.
type streamRun struct {
	body     func(ctx context.Context, w httpsec.EventWriter) error
	ctx      context.Context //nolint:containedctx // the values a goroutine fasthttp starts has no other way to get
	conn     net.Conn
	shutdown <-chan struct{}
	window   time.Duration
	gate     *streamGate

	// pipe hands the running goroutine the reader fasthttp is given, which exists only
	// after that goroutine has started. Closing it is the one way to end the response
	// from a goroutine that runtime.Goexit is ending (endStreamBody).
	pipe chan io.Closer

	// cut says the body panicked or exited, which streamReader tells fasthttp.
	cut atomic.Bool
}

// run is the goroutine fasthttp starts for the stream. It runs the body exactly once,
// on whichever path it finds: a live stream, or, when the chain refused or the
// connection has gone, a context already ended and a writer that goes nowhere.
func (r *streamRun) run(bw *bufio.Writer) {
	pipe := <-r.pipe
	refused := false

	if r.gate != nil {
		<-r.gate.returned
		refused = r.gate.refused
	}

	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()

	returned := false

	// Nothing here moves the deadline further or watches the connection on a refused
	// stream: the response on it is the refusal. Stream has already moved the deadline,
	// and that stands, so a refusal is written under the stream's window and not the
	// server's WriteTimeout, which fasthttp no longer sets once a handler has set one.
	if refused || r.conn.SetWriteDeadline(time.Now().Add(r.window)) != nil {
		cancel()

		defer endStreamBody(r.ctx, &returned, nil, bw, pipe)

		_ = r.body(ctx, diag.NewEndedWriter(ctx))
		returned = true

		return
	}

	defer endStreamBody(r.ctx, &returned, &r.cut, bw, pipe)

	// It exits when the body returns, at the latest, through the cancel above.
	go func() {
		select {
		case <-r.shutdown:
			cancel()
		case <-ctx.Done():
		}
	}()

	defer watchClient(r.conn, cancel)()

	// There is no caller left to give an error to.
	_ = r.body(ctx, &eventWriter{bw: bw, conn: r.conn, window: r.window, cancel: cancel})
	returned = true
}

// streamReader is what fasthttp reads a stream from. It is fasthttp's own reader,
// which ends cleanly when the body has returned, with one thing added: a body that
// panicked reads as a stream that broke, so fasthttp writes no end of the response
// and closes the connection, as it does for any stream that fails.
//
// The failure comes after everything the body wrote, so it arrives in order: head,
// events, end of connection. A pipe closed by endStreamBody still gives up what it holds
// before it reports its end, so a runtime.Goexit keeps that order too. Closing the connection from the
// body's goroutine instead could outrun fasthttp's write of the head, and a client would be left with
// nothing.
//
// io.ErrUnexpectedEOF says what happened, and is one fasthttp does not log as a
// server's failure: the panic has its own log line.
type streamReader struct {
	io.ReadCloser

	cut *atomic.Bool
}

func (s *streamReader) Read(p []byte) (int, error) {
	n, err := s.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) && s.cut.Load() {
		err = io.ErrUnexpectedEOF
	}

	return n, err
}

// watchClient reads conn until it ends, which is how a stream learns its client
// has gone, and then calls left. Whatever a client sends meanwhile is discarded.
// EOF counts, so a client that half-closes counts as having left, as it does on
// net/http.
//
// It runs beside fasthttp's writes on the same connection, as net.Conn and tls.Conn
// both allow. Nothing else reads the connection by now: fasthttp read the request
// before the handlers ran, and with Connection: close it reads no further one.
//
// The returned stop unblocks it with a read deadline already passed, because the
// connection can stay open after the body has returned, for as long as fasthttp is
// still writing what the body wrote. stop does not wait: a net.Conn of the
// consumer's that ignored the deadline must not hold the response open, and the
// connection's own close ends the read then. So does every path through a body that
// has ended.
func watchClient(conn net.Conn, left func()) (stop func()) {
	go func() {
		buf := make([]byte, watchClientBuffer)

		for {
			if _, err := conn.Read(buf); err != nil {
				left()

				return
			}
		}
	}()

	return func() { _ = conn.SetReadDeadline(time.Unix(1, 0)) }
}

// watchClientBuffer is what one read of a stream's connection takes. It only has
// to be large enough that a client sending bytes costs few system calls.
const watchClientBuffer = 256

// endStreamBody is what a body that did not return ends in, deferred where the body
// runs. It does nothing for one that did, which returned says.
//
// A panic would take the process with it. On net/http a handler's panic ends one
// response, because the server recovers it. A stream's body runs on fasthttp's
// goroutine, where nothing does, so this does what net/http does: it logs the panic,
// and marks the stream cut so that the client cannot take the cut response for a
// complete one (streamReader). A nil cut is a stream with no response of its own to cut,
// whose client has gone or is being given a refusal, which a panic must leave whole.
//
// runtime.Goexit, which is what require or t.FailNow does in a body, is not a panic and
// recover does not see it. It also takes fasthttp's goroutine past the flush and the
// close that follow the writer, so the response would never end and the client would
// hang. So it does both here: what the body wrote goes on, and the pipe closes.
//
// What it logs is that a body panicked, and what diag.PanicAttrs records: the panic
// value's type, and the function, file and line of up to 32 frames. It logs nothing of
// the value, which is the body's and can be a secret, and not debug.Stack's text either,
// which quotes the arguments of the frames it lists. It writes to slog's default logger, because a
// writer has no way to reach the logger its chain was given (httpsec.WithLogger). It logs under
// ctx, which is the request's context without its cancellation (context.WithoutCancel), so a
// handler that reads the request's values sees them, and a request already ended does not drop
// the record.
func endStreamBody(ctx context.Context, returned *bool, cut *atomic.Bool, bw *bufio.Writer, pipe io.Closer) {
	r := recover()

	switch {
	case r != nil:
		slog.LogAttrs(ctx, slog.LevelError, "fibersec: the body of a stream panicked", diag.PanicAttrs(r)...)
	case *returned:
		return
	default:
		slog.LogAttrs(ctx, slog.LevelError, "fibersec: the body of a stream ended its goroutine without returning")
	}

	if cut != nil {
		cut.Store(true)
	}

	if r == nil {
		_ = bw.Flush()
		_ = pipe.Close()
	}
}

// streamGate holds a stream's body back until the chain that started it has
// returned. refused is written before returned is closed, and read after.
type streamGate struct {
	returned chan struct{}
	refused  bool
}

// chainReturned opens the gate of a stream started on this writer, if any. A
// refused chain answers through fiber's error handler, so the response is the
// refusal: the body still runs, because Stream returned nil, but on a context
// already ended and a writer that reaches nothing. The stream's type goes on only when the chain
// did not refuse, because a refusal is no event stream. The status and the other headers stay for
// fiber's error handler to answer over, as the Middleware godoc says.
func (w *responseWriter) chainReturned(refused bool) {
	w.chainDone.Store(true)

	if w.gate != nil {
		if !refused {
			w.setStreamType(w.streamType)
		}

		w.gate.refused = refused
		close(w.gate.returned)
	}
}

// setStreamType puts a stream's type on the response. An empty type sets none.
func (w *responseWriter) setStreamType(contentType string) {
	if contentType != "" {
		w.c.Set(fiber.HeaderContentType, contentType)
	}
}

// eventWriter is what the body of a live fiber stream writes through. It holds the
// connection and fasthttp's stream writer, and nothing that belongs to fiber's
// context, which has been released by the time the body runs.
type eventWriter struct {
	bw     *bufio.Writer
	conn   net.Conn
	window time.Duration
	cancel context.CancelFunc
}

// extend moves the connection's write deadline, which fails only on a connection
// the server has already closed.
func (e *eventWriter) extend() error {
	err := e.conn.SetWriteDeadline(time.Now().Add(e.window))
	if err != nil {
		e.cancel()
	}

	return err
}

func (e *eventWriter) Write(b []byte) (int, error) {
	if err := e.extend(); err != nil {
		return 0, err
	}

	n, err := e.bw.Write(b)
	if err != nil {
		e.cancel()
	}

	return n, err
}

func (e *eventWriter) Flush() error {
	if err := e.extend(); err != nil {
		return err
	}

	err := e.bw.Flush()
	if err != nil {
		e.cancel()
	}

	return err
}

// SetCookie carries a cookie over to fiber field by field.
//
// Two of fiber's own conventions are not net/http's, and neither is worked
// around here, because fiber owns the response: fiber substitutes "/" for an
// empty path, and it drops a cookie net/http would consider invalid instead of
// writing it. Both are stated on the package.
//
// A cookie with neither a maximum age nor an expiry is marked session-only,
// which is what net/http writes for the same cookie: no expiry attribute at
// all.
//
// It has no effect once a response has begun, as SetHeader has none.
func (w *responseWriter) SetCookie(c *httpsec.Cookie) {
	if c == nil || w.wrote {
		return
	}

	w.c.Cookie(&fiber.Cookie{
		Name:        c.Name,
		Value:       c.Value,
		Path:        c.Path,
		Domain:      c.Domain,
		Expires:     c.Expires,
		MaxAge:      c.MaxAge,
		Secure:      c.Secure,
		HTTPOnly:    c.HttpOnly,
		Partitioned: c.Partitioned,
		SameSite:    sameSite(c.SameSite),
		SessionOnly: c.MaxAge == 0 && c.Expires.IsZero(),
	})
}

// sameSite names the policy fiber spells as a string.
//
// A cookie that named no policy gets none written, which is what net/http does
// for the same cookie. fiber's own default is Lax, so leaving it unnamed would
// quietly change a cookie's cross-site behaviour between the two adapters.
func sameSite(mode http.SameSite) string {
	switch mode {
	case http.SameSiteLaxMode:
		return fiber.CookieSameSiteLaxMode
	case http.SameSiteStrictMode:
		return fiber.CookieSameSiteStrictMode
	case http.SameSiteNoneMode:
		return fiber.CookieSameSiteNoneMode
	case http.SameSiteDefaultMode:
		return fiber.CookieSameSiteDisabled
	default:
		return fiber.CookieSameSiteDisabled
	}
}
