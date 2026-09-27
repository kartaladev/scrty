package fibersec

import (
	"bytes"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"

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
