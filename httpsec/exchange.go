package httpsec

import (
	"context"
	"net/http"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
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

	// FormValue reads a submitted field. Every adapter the library provides
	// looks in the posted form first and falls back to the URL query. The
	// library's own credential reads never use FormValue; they read the body
	// — apart from the OIDC authorization response, whose code and state the
	// protocol delivers in the query (see oidc_callback.go).
	//
	// Only POST, PUT and PATCH carry a posted form, and only a body whose
	// Content-Type parses as "application/x-www-form-urlencoded" or as
	// "multipart/form-data" with a boundary. At most 10 MiB of a URL-encoded
	// body and 32 MiB of a multipart one is read; a larger body, a content type
	// that does not parse, or a body that does not parse as a whole answers
	// from the query. A consumer that needs a field from a larger upload parses
	// the body itself. A multipart read holds up to about twice its cap in
	// memory while it parses, 64 MiB: the buffered body and the parts parsed
	// from it. The posted form is parsed once per request.
	//
	// Reading a field never changes what Body answers: a later Body call
	// applies its own limit to the whole body, and the handler still reads it.
	FormValue(name string) string

	// Body returns the whole request body when it is at most limit bytes long,
	// buffered so a later reader still sees it, and ErrRequestTooLarge when the
	// body is longer. It never returns a body it did not fully read.
	//
	// Each call applies its own limit, whatever an earlier call read or
	// refused: an earlier, larger read does not widen a later, smaller one,
	// and a refused read leaves the body readable, so a later, larger read can
	// succeed. The body is read from the network once.
	//
	// The returned bytes are the caller's own copy: changing them changes
	// neither what a later call answers nor what the handler reads.
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

	// raised is the consumer challenge kind the per-request phase raised on
	// this request, and ChallengeNone when it raised none.
	raised policy.ChallengeKind

	// perRequest is the chain's per-request phase, set by the chain this
	// exchange runs through, and nil on one run through none.
	perRequest *perRequestPhase

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

// RaisedChallenge returns the challenge kind of the consumer's own that the
// bearer's per-request policy phase raised on this request, and
// policy.ChallengeNone when it raised none.
//
// It is how a gate declared with WithChallengeEnforcer learns the challenge it
// enforces. The library cannot mark a kind it does not know on the session,
// so it records it here and lets the request continue; the declared gate,
// registered after the bearer, reads it and refuses or resolves the request.
// Declaring a kind with WithChallengeEnforcer is the consumer's statement that
// such a gate exists and reads this; the chain cannot check it.
//
// A built-in kind is never recorded here. It is marked on the session, where
// its built-in gate reads it.
func (e *Exchange) RaisedChallenge() policy.ChallengeKind { return e.raised }

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

// PublishSession publishes a, the result of authenticating this request, and
// s, the session it was authenticated on, together: on the exchange, as
// Authentication and Session, and on its context, where WithCaller puts the
// result and its principal and SessionFromContext reads s. Every later
// interceptor and the handler read the caller and the session from there.
//
// It is how a consumer interceptor that authenticates on a session of its own
// resolving publishes it, and it is what the built-in session-bound
// authenticators call. A session published here is treated as theirs is: the
// session-touch step records its activity after the handler, through the
// session manager the chain was wired with, and EvaluatePerRequest judges it.
// Publishing a only, with no session, is WithCaller and SetContext; publishing
// s only, with no result, publishes a session no caller owns, which no
// built-in does.
//
// The default is unused: the built-ins call it, and a consumer calls it from
// an interceptor registered with RegisterInterceptor, normally at
// OrderBearerToken, after verifying the credential that names s. It is itself
// the consumer's extension point, so it has no override.
func (e *Exchange) PublishSession(a *authenticate.Authentication, s *session.Session) {
	e.Authentication = a
	e.Session = s
	e.SetContext(withSession(WithCaller(e.ctx, a), s))
}

// EvaluatePerRequest runs the chain's per-request policy phase for s, the
// session this request is authenticated on, and p, its caller, with the
// challenge handling the built-in authenticators apply, and returns their
// refusal or nil.
//
// A denial is returned as the policy's reason. A challenge of a kind nothing
// on the chain enforces is refused with a configuration error. Any other
// challenge is marked where the gate enforcing it reads it, and nil is
// returned so the request goes on to that gate: a built-in kind is marked on
// s, and a session entering the enrolment-only state is stored before this
// returns, its deadlines lowered to the chain's enrolment lifetime, so a
// failed store write is returned rather than served; a consumer kind is
// recorded for RaisedChallenge. A recovery-pending session is not marked, and
// goes on to the recovery gate. An allow returns nil.
//
// The phase is judged at the chain's clock, with the password-change time of
// the result PublishSession published, so call PublishSession first. The
// mark is stored through the session manager the chain was wired with, the
// one a built-in given to New brought; on a chain no built-in gave one, an
// enrolment mark is refused with a configuration error rather than held only
// in memory. The phase fails closed: a nil s or p, a call before
// PublishSession, or an s or p that is not the pair PublishSession published
// (the same pointers) is refused with ErrAuthenticationRequired, running no
// policy, because the phase judges an authenticated caller on a session, never
// an anonymous request or one authenticated as someone else.
// On an exchange not run through a chain there are no policies, and it
// returns nil.
//
// The default is unused: the built-in session-bound authenticators run the
// same phase, and a consumer interceptor calls it after PublishSession to be
// judged as they are. It is itself the consumer's extension point; the
// policies it runs are the ones given to WithPolicyEngine.
func (e *Exchange) EvaluatePerRequest(s *session.Session, p *identity.Principal) error {
	if s == nil || p == nil {
		return ErrAuthenticationRequired
	}

	// It fails closed: the phase judges the pair PublishSession published, and
	// a call for any other pair, or before anything was published, would judge
	// a caller this request was never authenticated as. Sessions are compared
	// by identity, as the exchange holds the one it published.
	if e.Authentication == nil || e.Authentication.Principal != p || e.Session != s {
		return ErrAuthenticationRequired
	}

	ph := e.perRequest
	if ph == nil {
		return nil
	}

	return e.evaluatePerRequest(ph, s, p, e.Authentication.PasswordChangedAt, ph.now())
}
