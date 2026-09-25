package httpsec

import (
	"context"
	"net/http"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/session"
)

// Request is everything an interceptor may read from the request it is
// judging. Each integration implements it over its own framework's request,
// which is what lets one chain run unchanged behind net/http, gin and fiber.
//
// The library supplies an implementation over net/http through NewHTTPRequest,
// which is what a consumer gets when they wire nothing of their own.
type Request interface {
	Method() string
	Path() string
	Header(name string) string
	Query(name string) string

	// QueryValues returns every value of the query parameter name, in the
	// order the client sent them, and nil when the parameter is absent. It is
	// what lets an interceptor refuse a parameter sent more than once rather
	// than silently judge whichever value Query happens to return.
	QueryValues(name string) []string

	Cookie(name string) (value string, ok bool)
	FormValue(name string) string

	// Body returns at most limit bytes of the request body, buffered so a
	// later reader still sees it, and ErrRequestTooLarge when the body is
	// longer. It never returns a body it did not fully read.
	Body(limit int64) ([]byte, error)

	// ClientIP is the address the request is attributed to, or "" when the
	// integration cannot tell. It is never read from a forwarding header
	// unless that integration's own trusted-proxy configuration says so.
	ClientIP() string
}

// Cookie is a cookie an interceptor sets. It mirrors http.Cookie so the
// net/http integration passes it through unchanged.
type Cookie = http.Cookie

// ResponseWriter is everything an interceptor may write.
//
// The library supplies an implementation over net/http through
// NewHTTPResponseWriter, which is what a consumer gets when they wire nothing
// of their own.
type ResponseWriter interface {
	SetHeader(name, value string)
	SetCookie(c *Cookie)
	WriteHeader(status int)
	Write(b []byte) (int, error)
}

// Exchange is one request passing through the chain.
//
// The context lives here rather than on the Request because a framework built
// on fasthttp carries no context on its request. It is seeded from the
// integration's own incoming context, so values and cancellation set before the
// chain survive, and it is written back into the framework's carrier
// immediately before the handler.
type Exchange struct {
	// Request is what the interceptors read. It is never replaced once the
	// exchange has started.
	Request Request

	// Writer is what the interceptors write.
	Writer ResponseWriter

	// Authentication is the result the authenticating interceptor resolved,
	// and nil on a request that authenticated nothing.
	Authentication *authenticate.Authentication

	// Session is the session this request carries, and nil for a stateless
	// request and for one that established none.
	Session *session.Session

	ctx context.Context
}

// NewExchange starts an exchange seeded from ctx.
//
// A nil ctx is taken as context.Background rather than refused, because an
// exchange with no context at all would panic at the first call into a core
// and an integration has nothing better to substitute.
func NewExchange(ctx context.Context, r Request, w ResponseWriter) *Exchange { //nolint:contextcheck // the fallback is only reached when the caller supplied no context to inherit from
	if ctx == nil {
		ctx = context.Background()
	}
	return &Exchange{Request: r, Writer: w, ctx: ctx}
}

// Context returns the context every call into scrty's cores is made with. It
// is derived from the incoming request's context and never replaces it, so an
// upstream value and an upstream cancellation both survive the chain.
func (e *Exchange) Context() context.Context { return e.ctx }

// SetContext replaces the context. An interceptor that resolves security state
// calls it so every later interceptor, and the handler, read that state.
//
// A nil context is ignored: dropping the context the exchange already holds
// would silently detach the rest of the chain from the client's cancellation.
func (e *Exchange) SetContext(ctx context.Context) {
	if ctx != nil {
		e.ctx = ctx
	}
}

// Next runs the rest of the chain, ending in the downstream handler.
type Next func(*Exchange) error

// Interceptor is one stage of the chain. It continues by calling next and
// stops the request by not calling it; anything after next runs once the
// handler and every inner interceptor have returned.
//
// A consumer supplies none by default: a chain runs the built-ins its Enable
// options asked for and nothing else, and RegisterInterceptor is how one of a
// consumer's own joins them. An interceptor that authenticates publishes what
// it resolved with WithCaller, which is what the built-in first factors do.
type Interceptor interface {
	Intercept(ex *Exchange, next Next) error
}

// InterceptorFunc adapts a function to Interceptor, so a consumer registers a
// closure without declaring a type.
type InterceptorFunc func(ex *Exchange, next Next) error

// Intercept implements Interceptor.
func (f InterceptorFunc) Intercept(ex *Exchange, next Next) error { return f(ex, next) }
