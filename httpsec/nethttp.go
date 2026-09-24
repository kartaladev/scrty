package httpsec

import (
	"bytes"
	"io"
	"net"
	"net/http"
)

// NewHTTPRequest adapts a net/http request.
//
// It is the implementation of Request a consumer gets without configuring
// anything, and an integration for a framework that still carries net/http's
// own request and response types reuses it rather than writing its own.
func NewHTTPRequest(r *http.Request) Request { return &httpRequest{r: r} }

type httpRequest struct {
	r *http.Request

	body    []byte
	bodyErr error
	read    bool
}

func (h *httpRequest) Method() string         { return h.r.Method }
func (h *httpRequest) Path() string           { return h.r.URL.Path }
func (h *httpRequest) Header(n string) string { return h.r.Header.Get(n) }
func (h *httpRequest) Query(n string) string  { return h.r.URL.Query().Get(n) }

// Cookie reports absence separately from an empty value, so an interceptor can
// tell a cookie that was never sent from one deliberately cleared.
func (h *httpRequest) Cookie(n string) (string, bool) {
	c, err := h.r.Cookie(n)
	if err != nil {
		return "", false
	}
	return c.Value, true
}

// FormValue reads a submitted field, parsing the form if it has not been
// parsed yet.
func (h *httpRequest) FormValue(n string) string { return h.r.FormValue(n) }

// Body reads the body once, bounded by limit, and restores it so the
// downstream handler still reads it in full. A body longer than limit returns
// ErrRequestTooLarge, and nothing is returned to be parsed.
//
// The first call decides: a later call with a larger limit is answered from
// what was already read, so an interceptor cannot be talked past a bound that
// has already refused the body.
func (h *httpRequest) Body(limit int64) ([]byte, error) {
	if h.read {
		return h.body, h.bodyErr
	}
	h.read = true

	if h.r.Body == nil {
		return nil, nil
	}

	// limit+1 so a body exactly at the limit is accepted and the first byte
	// over it is seen without reading the rest.
	b, err := io.ReadAll(io.LimitReader(h.r.Body, limit+1))
	if err != nil {
		h.bodyErr = err
		return nil, err
	}
	if int64(len(b)) > limit {
		h.bodyErr = ErrRequestTooLarge
		return nil, ErrRequestTooLarge
	}

	h.body = b
	h.r.Body = io.NopCloser(bytes.NewReader(b))
	return b, nil
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
