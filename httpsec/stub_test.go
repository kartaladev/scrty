package httpsec_test

import (
	"net/http"

	"github.com/kartaladev/scrty/httpsec"
)

// stubRequest and stubWriter stand in for a framework's request and response
// wherever a test needs an exchange but not a real transport. They are the
// smallest thing that satisfies the ports, so a test that cares about one
// accessor leaves the rest zero.
type stubRequest struct {
	method, path string
	headers      map[string]string
	query        map[string]string
	cookies      map[string]string
	form         map[string]string
	body         []byte
	clientIP     string
}

func (r stubRequest) Method() string            { return r.method }
func (r stubRequest) Path() string              { return r.path }
func (r stubRequest) Header(n string) string    { return r.headers[n] }
func (r stubRequest) Query(n string) string     { return r.query[n] }
func (r stubRequest) FormValue(n string) string { return r.form[n] }
func (r stubRequest) ClientIP() string          { return r.clientIP }

func (r stubRequest) Cookie(n string) (string, bool) {
	v, ok := r.cookies[n]
	return v, ok
}

func (r stubRequest) Body(limit int64) ([]byte, error) {
	if int64(len(r.body)) > limit {
		return nil, httpsec.ErrRequestTooLarge
	}
	return r.body, nil
}

type stubWriter struct {
	header http.Header
	status int
	body   []byte
	cookie []*httpsec.Cookie
}

func (w *stubWriter) SetHeader(n, v string) {
	if w.header == nil {
		w.header = http.Header{}
	}
	w.header.Set(n, v)
}

func (w *stubWriter) SetCookie(c *httpsec.Cookie) { w.cookie = append(w.cookie, c) }
func (w *stubWriter) WriteHeader(s int)           { w.status = s }

func (w *stubWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}
