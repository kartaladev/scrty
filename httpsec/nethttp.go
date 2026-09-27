package httpsec

import (
	"bytes"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
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

// QueryValues returns every value of the parameter, in the order sent.
func (h *httpRequest) QueryValues(n string) []string { return h.r.URL.Query()[n] }

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
// No forwarding header is read: net/http holds no trusted-proxy configuration
// to decide from, so honouring one here would let a client choose the bucket
// its own failures are counted under. Forwarded-header resolution belongs to
// an integration whose framework knows which proxies it trusts.
func (h *httpRequest) ClientIP() string {
	host, _, err := net.SplitHostPort(h.r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
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
}

func (h *httpResponseWriter) SetHeader(n, v string) { h.w.Header().Set(n, v) }
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

func (h *httpResponseWriter) Write(b []byte) (int, error) {
	h.wrote = true
	return h.w.Write(b)
}

// committed reports whether a status or body has already gone out, so the
// default error handling does not write a second status over an interceptor's.
func (h *httpResponseWriter) committed() bool { return h.wrote }
