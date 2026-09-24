package fibersec

import (
	"bytes"
	"net/http"

	"github.com/gofiber/fiber/v3"

	"github.com/kartaladev/scrty/httpsec"
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
func (r request) Path() string              { return r.c.Path() }
func (r request) Header(name string) string { return r.c.Get(name) }
func (r request) Query(name string) string  { return r.c.Query(name) }

// FormValue reads a submitted field. fiber searches the query string, the
// posted form and any multipart form, in that order, and parses the multipart
// form under the app's own BodyLimit.
func (r request) FormValue(name string) string { return r.c.FormValue(name) }

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

// ClientIP is fiber's own client address.
//
// That is the transport peer unless the consumer enabled fiber's proxy trust,
// which is the only configuration that knows which proxies may name an address
// for a client. The package documentation gives the configuration in full, and
// the chain's own refusal of an empty, malformed or unspecified address applies
// to whatever this returns.
func (r request) ClientIP() string { return r.c.IP() }

// responseWriter implements httpsec.ResponseWriter over fiber's context.
//
// It is a pointer because it remembers whether a status has been chosen: the
// net/http writer keeps the first status an interceptor sets and ignores a
// second, and an adapter that let the second win would answer one request
// differently on two frameworks.
type responseWriter struct {
	c fiber.Ctx

	wrote bool
}

func (w *responseWriter) SetHeader(name, value string) { w.c.Set(name, value) }

func (w *responseWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}

	w.wrote = true
	w.c.Status(status)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	w.wrote = true

	return w.c.Write(b)
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
func (w *responseWriter) SetCookie(c *httpsec.Cookie) {
	if c == nil {
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
