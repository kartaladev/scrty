package httpsec

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
)

// NewHTTPRequest adapts a net/http request.
//
// It is the implementation of Request a consumer gets without configuring
// anything, and an integration for a framework that still carries net/http's
// own request and response types reuses it rather than writing its own.
func NewHTTPRequest(r *http.Request) Request { return &httpRequest{r: r} }

type httpRequest struct {
	r *http.Request

	// body is the whole request body once a read has reached its end, and
	// complete says so. Until then nothing is kept here: a read that stopped
	// at its limit has put its bytes back in front of the rest of the body.
	body     []byte
	complete bool

	// err is the transport failure a read met, returned to every later read.
	// net/http reports an early end of body once and a clean end after it, so
	// reading again would take the partial body for the whole one.
	err error

	form       url.Values
	formParsed bool
}

func (h *httpRequest) Method() string         { return h.r.Method }
func (h *httpRequest) Path() string           { return h.r.URL.Path }
func (h *httpRequest) Header(n string) string { return h.r.Header.Get(n) }
func (h *httpRequest) Query(n string) string  { return h.r.URL.Query().Get(n) }

// EscapedPath is the path as the client sent it: net/http keeps the sent
// spelling in URL.RawPath whenever it differs from the default encoding.
func (h *httpRequest) EscapedPath() string { return h.r.URL.EscapedPath() }

// QueryValues returns every value of the parameter, in the order sent.
func (h *httpRequest) QueryValues(n string) []string { return h.r.URL.Query()[n] }

// HeaderValues returns every line of the header, in the order received, so the
// chain's trusted-proxy resolution joins repeated forwarded headers rather
// than reading the first line alone. The slice is the caller's own copy.
func (h *httpRequest) HeaderValues(n string) []string { return slices.Clone(h.r.Header.Values(n)) }

// DelHeaders removes every header whose name match reports true from the
// request itself, so the handler behind the chain does not read it either.
// The chain calls it to remove the forwarded headers it consumed
// (EnableTrustedProxies).
func (h *httpRequest) DelHeaders(match func(name string) bool) {
	for name := range h.r.Header {
		if match(name) {
			delete(h.r.Header, name)
		}
	}
}

// Cookie reports absence separately from an empty value, so an interceptor can
// tell a cookie that was never sent from one deliberately cleared.
func (h *httpRequest) Cookie(n string) (string, bool) {
	c, err := h.r.Cookie(n)
	if err != nil {
		return "", false
	}
	return c.Value, true
}

// The caps a field read parses a posted form under: the standard library's
// own defaults for a URL-encoded body and for a multipart one. A body over
// its cap is not parsed at all, and the field is answered from the query.
const (
	formURLEncodedCap int64 = 10 << 20 // 10 MiB
	formMultipartCap  int64 = 32 << 20 // 32 MiB
)

// FormValue reads a submitted field with the precedence every adapter shares:
// the posted form first — URL-encoded or multipart — and the URL query only
// when the posted form does not carry the field at all. A field present in
// the posted form with an empty value still counts as present, so it is
// returned even when the query carries a non-empty value for the same name,
// and a field repeated in the posted form answers its first value. Only POST,
// PUT and PATCH carry a posted form; every other method reads the query
// alone, matching (*http.Request).ParseForm's own restriction.
//
// A body is a posted form only when its Content-Type parses, by
// mime.ParseMediaType, as "application/x-www-form-urlencoded" (in any case,
// with any parameters) or as "multipart/form-data" with a boundary. At most 10
// MiB of a URL-encoded body and 32 MiB of a multipart one is read; a larger
// body, a content type that does not parse, or a body that does not parse as a
// whole — url.ParseQuery rejecting any one pair, a ';' separator included, or
// a malformed multipart envelope — answers from the query, as if no form had
// been posted. A consumer that needs a field from a larger upload parses the
// body itself.
//
// A multipart read holds up to about twice its cap in memory while it parses,
// 64 MiB: the body, read so it can be put back, and the parts parsed from it.
// An application that cannot afford that per request bounds the body before
// the chain runs, with http.MaxBytesReader or its server's own limit.
//
// Reading a field never changes what Body answers. The posted form is read
// through the same buffer Body reads through, so the network is read once,
// and whatever was read stays readable: a later Body call applies its own
// limit to the whole body, and a handler behind the chain still reads it in
// full. The posted form is parsed once per request.
//
// It does not call (*http.Request).FormValue, which combines the query and
// the posted form into one list per field and answers the first entry: for a
// URL-encoded body that entry is the posted form's, but for a multipart body
// it is the query's, because net/http appends multipart values after the
// query's rather than before it. Nor does it call ParseForm or
// ParseMultipartForm, which parse straight from r.Body and leave it drained.
func (h *httpRequest) FormValue(n string) string {
	switch h.r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		if vs, ok := h.postedForm()[n]; ok && len(vs) > 0 {
			return vs[0]
		}
	}

	return h.r.URL.Query().Get(n)
}

// postedForm is the posted form, parsed on first use, and nil when the body is
// not a form FormValue reads.
func (h *httpRequest) postedForm() url.Values {
	if !h.formParsed {
		h.formParsed = true
		h.form = h.parsePostedForm()
	}

	return h.form
}

// parsePostedForm parses the body as the form its content type names, under
// that form's cap, and answers nil for anything FormValue does not read as a
// form.
func (h *httpRequest) parsePostedForm() url.Values {
	mediaType, params, err := mime.ParseMediaType(h.r.Header.Get("Content-Type"))
	if err != nil {
		return nil
	}

	switch mediaType {
	case "application/x-www-form-urlencoded":
		body, ok := h.formBody(formURLEncodedCap)
		if !ok {
			return nil
		}

		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil
		}

		return values

	case "multipart/form-data":
		boundary, ok := params["boundary"]
		if !ok {
			return nil
		}

		body, ok := h.formBody(formMultipartCap)
		if !ok {
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

// formBody is the whole body when it is no longer than limit, for FormValue
// to parse. It reads through the same buffer Body does, so whatever reads the
// body next — Body under its own limit, or the handler — sees all of it.
func (h *httpRequest) formBody(limit int64) ([]byte, bool) {
	b, err := h.buffer(limit)
	if err != nil || int64(len(b)) > limit {
		return nil, false
	}

	return b, true
}

// buffer answers the whole body when it is at most limit bytes long, and
// otherwise the limit+1 bytes that prove it is longer, with every byte read
// put back for the next reader.
//
// The network is read once: a body already read to its end is answered from
// memory, and a read that stopped at its limit is resumed by the next,
// larger one from the bytes it put back. Only a read that reaches the end is
// kept; the request body is then those bytes, still closing the original.
func (h *httpRequest) buffer(limit int64) ([]byte, error) {
	if h.complete {
		return h.body, nil
	}

	if h.err != nil {
		return nil, h.err
	}

	if h.r.Body == nil {
		h.complete = true
		return nil, nil
	}

	rest := h.r.Body

	b, err := h.readRestoring(limit)
	if err != nil {
		h.err = err
		h.r.Body = restoredBody{Reader: io.MultiReader(bytes.NewReader(b), failedReader{err: err}), Closer: rest}

		return nil, err
	}

	if int64(len(b)) > limit {
		return b, nil
	}

	h.body, h.complete = b, true
	h.r.Body = restoredBody{Reader: bytes.NewReader(b), Closer: rest}

	return b, nil
}

// readRestoring reads at most limit+1 bytes of the body and puts what it read
// back in front of the rest, so the read consumes nothing. limit+1 so a body
// exactly at the limit is told from one a byte over it without reading the
// rest; a limit at the largest integer, where limit+1 would overflow, reads
// the body to its end.
func (h *httpRequest) readRestoring(limit int64) ([]byte, error) {
	rest := h.r.Body

	var src io.Reader = rest
	if limit < math.MaxInt64 {
		src = io.LimitReader(rest, limit+1)
	}

	b, err := io.ReadAll(src)
	h.r.Body = restoredBody{Reader: io.MultiReader(bytes.NewReader(b), rest), Closer: rest}

	return b, err
}

// failedReader answers every read with the transport failure the body met, so
// a handler reading the restored body sees the failure rather than a clean
// end after the partial bytes.
type failedReader struct{ err error }

func (f failedReader) Read([]byte) (int, error) { return 0, f.err }

// restoredBody is a request body with bytes already read put back in front of
// it. Closing it closes the original body.
type restoredBody struct {
	io.Reader
	io.Closer
}

// Body returns the whole body when it is at most limit bytes long, and
// ErrRequestTooLarge, with nothing to parse, when it is longer.
//
// Each call applies its own limit, whatever an earlier call read or refused:
// a consumer's larger read made first does not widen a library endpoint's
// smaller one, and a refused read does not stop a later, larger one. The body
// is read from the network once. A read that reaches the end keeps the bytes,
// and later calls are judged against them; a refused read puts back what it
// read, so a later, larger read resumes from it, and the handler, or
// FormValue, still sees the whole body. Closing the request body afterwards
// closes the original.
//
// A transport failure, such as a body that ended before its declared length,
// is returned as it came, and is remembered: every later Body call, and
// FormValue, meets the same failure rather than reading again, and the
// handler reading the request body gets the bytes that arrived followed by
// the same failure. A refusal as too large is not remembered.
//
// A limit at the largest integer reads the whole body.
//
// The returned slice is a copy: changing it changes neither what a later call
// answers nor what the handler reads.
func (h *httpRequest) Body(limit int64) ([]byte, error) {
	b, err := h.buffer(limit)
	if err != nil {
		return nil, err
	}

	if int64(len(b)) > limit {
		return nil, ErrRequestTooLarge
	}

	return bytes.Clone(b), nil
}

// ClientIP is the host part of the transport peer, and "" when the peer
// address is not in host and port form.
//
// No forwarding header is read here: the request holds no trusted-proxy
// configuration to decide from, so honouring one would let a client choose the
// bucket its own failures are counted under. Forwarded-header resolution is the
// chain's: with EnableTrustedProxies it resolves the client address from the
// proxies the consumer names, and the chain reads the result from
// ClientFromContext.
func (h *httpRequest) ClientIP() string {
	host, _, err := net.SplitHostPort(h.r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

// Host is r.Host: the Host header, or the host of an absolute request target,
// as net/http resolved it. No forwarded header is read.
func (h *httpRequest) Host() string { return h.r.Host }

// Secure reports whether the request arrived over TLS, which net/http records
// as a non-nil r.TLS. No forwarded header is read.
func (h *httpRequest) Secure() bool { return h.r.TLS != nil }

// ClientCertificate is the leaf of r.TLS.PeerCertificates, the first
// certificate the client sent, and nil when the request did not arrive over
// TLS or the client sent none. No header is read.
func (h *httpRequest) ClientCertificate() *x509.Certificate {
	if h.r.TLS == nil || len(h.r.TLS.PeerCertificates) == 0 {
		return nil
	}

	return h.r.TLS.PeerCertificates[0]
}

// NewHTTPResponseWriter adapts a net/http response writer.
//
// It is the implementation of ResponseWriter a consumer gets without
// configuring anything.
func NewHTTPResponseWriter(w http.ResponseWriter) ResponseWriter {
	return &httpResponseWriter{w: w}
}

type httpResponseWriter struct {
	w     http.ResponseWriter
	wrote bool

	// streaming is whether Stream has started, after which Write writes nothing.
	streaming bool

	// streamWindow replaces StreamWriteWindow in a test, and is zero otherwise.
	streamWindow time.Duration
}

func (h *httpResponseWriter) SetHeader(n, v string) { h.w.Header().Set(n, v) }
func (h *httpResponseWriter) AddHeader(n, v string) { h.w.Header().Add(n, v) }
func (h *httpResponseWriter) SetCookie(c *Cookie)   { http.SetCookie(h.w, c) }

// WriteHeader sends the status, and ignores a second call. An interceptor that
// answered the request itself keeps the status it chose: a later stage that
// also wants to write one would otherwise turn a deliberate 401 into whatever
// it happened to decide.
func (h *httpResponseWriter) WriteHeader(status int) {
	if h.wrote {
		return
	}
	h.wrote = true
	h.w.WriteHeader(status)
}

// Write writes nothing once a stream has started, so that only what its body
// writes reaches the client.
func (h *httpResponseWriter) Write(b []byte) (int, error) {
	if h.streaming {
		return 0, ErrStreamingStarted
	}

	h.wrote = true
	return h.w.Write(b)
}

// Stream runs body inline, once the head has been flushed, and returns nil when it
// has. ctx is what body's context derives from, and the chain's own is derived from
// the request's, so body's ends when the client leaves. See ResponseWriter.Stream for
// the contract.
//
// What body returned is dropped, as it is on fiber, where it has nowhere to go: an
// error from Stream means the body never ran, so a caller holding something for its
// body to free would free it twice.
//
// http.ResponseController reaches the connection through any wrapper that has an
// Unwrap method, which is how gin's writer is reached. A wrapper that can flush
// but neither moves a deadline nor unwraps still streams, under whatever deadline
// its server set: nothing can tell that from a server that set none.
func (h *httpResponseWriter) Stream(ctx context.Context, body func(ctx context.Context, w EventWriter) error) error {
	if h.wrote {
		return ErrStreamingStarted
	}

	if !canFlush(h.w) {
		return ErrStreamingUnsupported
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ew := &httpEventWriter{
		w:      h.w,
		rc:     http.NewResponseController(h.w),
		window: h.streamWindow,
		cancel: cancel,
	}
	if ew.window == 0 {
		ew.window = StreamWriteWindow
	}

	if err := h.sendHead(ew); err != nil {
		if errors.Is(err, http.ErrNotSupported) {
			return ErrStreamingUnsupported
		}

		// The connection has gone. The failure has ended ctx.
		ew.runBody(ctx, endedWriter{ctx: ctx}, body)

		return nil
	}

	ew.runBody(ctx, ew, body)

	return nil
}

// sendHead moves the deadline and sends the status and headers, or returns an error
// that says http.ErrNotSupported. The deadline comes first, because a chain may have
// taken longer than the server's write timeout to get here.
//
// The status is named before the flush, because wrappers have their say on the way (a
// session or metrics wrapper's WriteHeader, say), and because gin's writer holds 404 for
// a path no route matches, which is what a chain's own endpoint is. What the flush then
// does is up to the first wrapper with a Flush or a FlushError: one that compresses
// holds the head until its first write.
//
// A FlushError is asked first in one place: at the bottom of the Unwrap chain, on a
// writer with no SetWriteDeadline, which is a consumer's wrapper and not the connection.
// canFlush has already looked below anything with an Unwrap, so only there can "not
// supported" be real, and asking before a status is named leaves an ordinary answer
// possible. It costs what ErrStreamingUnsupported says. Below other wrappers the status
// is still named after it says yes, so that gin's writer does not hold 404, which is one
// line of net/http's superfluous WriteHeader log per stream.
func (h *httpResponseWriter) sendHead(ew *httpEventWriter) error {
	if err := ew.extend(); err != nil {
		h.wrote, h.streaming = true, true

		return err
	}

	bottom, depth := bottomWriter(h.w)
	_, moves := bottom.(interface{ SetWriteDeadline(time.Time) error })

	if reporter, ok := bottom.(flushErrorer); ok && !moves {
		err := reporter.FlushError()
		if errors.Is(err, http.ErrNotSupported) {
			return err
		}

		if err != nil {
			ew.cancel()
		}

		if err != nil || depth == 0 {
			h.wrote, h.streaming = true, true

			return err
		}
	}

	h.wrote, h.streaming = true, true

	h.w.WriteHeader(http.StatusOK)

	err := ew.Flush()
	if errors.Is(err, http.ErrNotSupported) {
		h.streaming = false
	}

	return err
}

// maxResponseWrappers is how many layers of a writer are looked at. A chain longer than
// this is taken for one that never ends, because a wrapper whose Unwrap returns itself
// would otherwise hold its request for ever, and it counts as unable to flush.
const maxResponseWrappers = 32

// responseUnwrapper is what http.ResponseController follows through a wrapper.
type responseUnwrapper interface {
	Unwrap() http.ResponseWriter
}

// flushErrorer is the flush that can say it failed.
type flushErrorer interface {
	FlushError() error
}

// bottomWriter follows Unwrap to the layer that has none, and says how many it crossed.
// It is nil for a chain longer than maxResponseWrappers.
func bottomWriter(w http.ResponseWriter) (bottom http.ResponseWriter, depth int) {
	for depth = range maxResponseWrappers {
		u, ok := w.(responseUnwrapper)
		if !ok {
			return w, depth
		}

		w = u.Unwrap()
	}

	return nil, 0
}

// canFlush reports whether flushing w reaches a connection, without doing it, which
// would send the head. It looks past a wrapper that has Unwrap before believing the
// wrapper's own Flush: gin's writer always has one, which does nothing and returns no
// error over a writer that cannot flush, so a stream over it would seem to work and
// deliver nothing. Below the last Unwrap, a Flush or a FlushError is believed.
func canFlush(w http.ResponseWriter) bool {
	bottom, _ := bottomWriter(w)

	switch bottom.(type) {
	case flushErrorer, http.Flusher:
		return true
	default:
		return false
	}
}

// endedWriter is what a body gets when there is nothing to stream to. Whatever it
// writes goes nowhere, and each call returns why, so a body that checks stops.
type endedWriter struct {
	ctx context.Context //nolint:containedctx // what its calls report, and it lives no longer than the body
}

func (e endedWriter) Write([]byte) (int, error) { return 0, e.ctx.Err() }

func (e endedWriter) Flush() error { return e.ctx.Err() }

// httpEventWriter is what the body of a net/http stream writes through.
type httpEventWriter struct {
	w      http.ResponseWriter
	rc     *http.ResponseController
	window time.Duration
	cancel context.CancelFunc
}

// extend moves the write deadline. A writer with no deadline to move is not a
// failure: see Stream.
func (e *httpEventWriter) extend() error {
	// The system clock and never the chain's: this is a real socket's deadline,
	// which a controlled clock would set in the wrong place.
	err := e.rc.SetWriteDeadline(clock.System().Now().Add(e.window))
	if err == nil || errors.Is(err, http.ErrNotSupported) {
		return nil
	}

	e.cancel()

	return err
}

func (e *httpEventWriter) Write(b []byte) (int, error) {
	if err := e.extend(); err != nil {
		return 0, err
	}

	n, err := e.w.Write(b)
	if err != nil {
		e.cancel()
	}

	return n, err
}

// Flush delivers what was written, and ends the body's context when it cannot.
func (e *httpEventWriter) Flush() error {
	if err := e.extend(); err != nil {
		return err
	}

	err := e.rc.Flush()
	if err != nil {
		e.cancel()
	}

	return err
}

// runBody runs body, cutting the connection if it does not return. A recovery
// middleware outside the adapter, such as gin.Recovery, would otherwise let the handler
// return as usual, and net/http would write the end of the response, so a panic would
// look like a complete stream. A deadline already passed is what cuts it: net/http's
// write of that end fails and it closes the connection, and over HTTP/2 the stream is
// reset at once.
//
// It recovers nothing. A panic goes on as it came, http.ErrAbortHandler and its stack
// included, and so does runtime.Goexit, which a recover would not see. The deadline is
// not one a wrapper that hides the connection lets through, so behind such a wrapper a
// panic a middleware recovers can still look complete: see ErrStreamingUnsupported.
func (e *httpEventWriter) runBody(
	ctx context.Context,
	w EventWriter,
	body func(ctx context.Context, w EventWriter) error,
) {
	returned := false

	defer func() {
		if !returned {
			_ = e.rc.SetWriteDeadline(time.Unix(1, 0))
		}
	}()

	// There is no one to tell: see Stream.
	_ = body(ctx, w)

	returned = true
}

// committed reports whether a status or body has already gone out, so the
// default error handling does not write a second status over an interceptor's.
func (h *httpResponseWriter) committed() bool { return h.wrote }

// Middleware runs the chain in front of an ordinary net/http handler.
//
// It is the entrypoint a consumer who wires nothing of their own gets: the
// request and the response writer are adapted with NewHTTPRequest and
// NewHTTPResponseWriter, every interceptor runs in slot order, and the handler
// is reached only when none of them refused.
//
// The handler reads everything the chain resolved — the caller, the session,
// the authorizer — through r.Context() as usual, because the chain's context is
// written back onto the request at the innermost point, immediately before the
// handler runs. It is derived from the incoming request's context and never
// replaces it, so a value an outer middleware set and the client's own
// cancellation both survive.
//
// A refusal is answered by the error handler: the mapped status and no body by
// default, and whatever WithErrorHandler was given instead.
func (c *Chain) Middleware() func(http.Handler) http.Handler {
	return func(downstream http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Seeded from the incoming context, never replaced, so values and
			// cancellation set before the chain survive it.
			ex := NewExchange(r.Context(), NewHTTPRequest(r), NewHTTPResponseWriter(w))

			// The chain is folded around this request's handler rather than once
			// per mount, because the terminal is the only place that still holds
			// the framework's own writer and request, and smuggling them through
			// the exchange would make every interceptor able to reach past the
			// abstraction the chain exists to present.
			//nolint:contextcheck // ex.Context() is derived from r.Context(), which is what is written back here
			run := c.Assemble(func(ex *Exchange) error {
				downstream.ServeHTTP(w, r.WithContext(ex.Context()))

				return nil
			})

			if err := run(ex); err != nil {
				c.handleError(ex, w, r, err)
			}
		})
	}
}

// handleError answers a refusal.
//
// The default is the mapped status and nothing else: a body would either leak
// what the refusal knew — a driver's error text, whether an account exists — or
// invent a format the consumer must then work around. Rendering is the
// consumer's, through WithErrorHandler; this library's job is to fail closed.
//
// The default writes through the exchange's own writer, which ignores a second
// status, so an interceptor that already answered the request keeps the status
// it chose. A consumer's handler is handed the framework's writer and owns the
// whole response, including that decision.
func (c *Chain) handleError(ex *Exchange, w http.ResponseWriter, r *http.Request, err error) {
	if c.errorHandler != nil {
		c.errorHandler(w, r, err)

		return
	}

	ex.Writer.WriteHeader(StatusForError(err))
}
