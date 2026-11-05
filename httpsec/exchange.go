package httpsec

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// Request is everything an interceptor may read from the request it is
// judging. Each integration implements it over its own framework's request,
// which is what lets one chain run unchanged behind net/http, gin and fiber.
//
// The library supplies an implementation over net/http through NewHTTPRequest,
// which is what a consumer gets when they wire nothing of their own.
//
// An integration whose request also has a method
// DelHeaders(match func(name string) bool), removing every header match
// reports true for from the request its framework hands on, lets the chain
// remove the forwarded headers EnableTrustedProxies consumed from that request
// too. Every integration the library provides has it. Without it the removed
// headers are still hidden from every interceptor, but not from the
// framework's own handlers.
type Request interface {
	Method() string
	Path() string

	// EscapedPath is the request path as the client sent it, percent-encoding
	// intact: "/api/ord%65rs" stays "/api/ord%65rs", where Path decodes it to
	// "/api/orders". An integration reads it from the request line itself,
	// never decoded and re-encoded.
	//
	// DPoP (EnableDPoP) compares a proof's htu against it, so a proof made for
	// one spelling of a path is not accepted for another that decodes to the
	// same path.
	EscapedPath() string

	// Header returns the value of the header name: its first line when the
	// request carries it more than once.
	Header(name string) string

	// HeaderValues returns every line of the header name, in the order
	// received, and nil when the request carries none.
	//
	// The chain's trusted-proxy resolution (EnableTrustedProxies) reads
	// forwarded headers through it, because the line a trusted proxy appended
	// is the last one: reading the first line alone would read a line the
	// client sent in place of the proxy's.
	HeaderValues(name string) []string

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
	// protocol delivers in the query (see oidc_login.go).
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
	// integration cannot tell. The chain's trusted-proxy resolution reads it
	// as the transport peer. Inside the chain it is the resolved address: a
	// trusted proxy's forwarded client when EnableTrustedProxies trusts that
	// field.
	ClientIP() string

	// Host is the host the client asked for: the request's Host header, or
	// the host of an absolute request target, port included when one was
	// sent. An integration reads it from the request itself, never from a
	// framework helper that consults a forwarded header. Inside the chain it
	// is the resolved host: a trusted proxy's forwarded host when
	// EnableTrustedProxies trusts that field.
	Host() string

	// Secure reports whether the request reached the application over TLS. An
	// integration reads it from the connection, never from a framework helper
	// that consults a forwarded header. Inside the chain it is the resolved
	// answer: true for every request under WithHTTPSDeployment, or a trusted
	// proxy's forwarded scheme when EnableTrustedProxies trusts that field.
	Secure() bool

	// ClientCertificate is the certificate the client presented on the TLS
	// connection the request arrived on: the leaf, the first certificate the
	// client sent, or nil when the connection is not TLS or the client sent
	// none. An integration reads it from the connection itself, never from a
	// header.
	//
	// Inside the chain it is the resolved answer, given to every interceptor
	// whether or not certificate binding (EnableCertificateBinding) is
	// enabled, and the one that binding judges: from a peer that is not a
	// trusted proxy, the connection's certificate; from a trusted proxy, the
	// certificate it forwarded in the WithClientCertificateHeader header,
	// decoded once, or nil when no header is named or its value does not
	// decode. A trusted proxy's own connection certificate is never taken for
	// the client's.
	//
	// The certificate is reported, not judged: whether its chain and dates are
	// valid is for the TLS server or the proxy that accepted it to decide.
	ClientCertificate() *x509.Certificate
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
	// SetHeader replaces every value of the response header name with value. Once
	// the response has begun, by WriteHeader, Write or Stream, it has no effect on the
	// writers the library provides, whether or not the framework has yet sent the head. The
	// library sets no stream's type through it: Stream is given that.
	SetHeader(name, value string)

	// AddHeader adds value to the response header name, keeping the values
	// already set, as net/http's Header.Add does. It is how a list header
	// such as Vary is extended without dropping what an outer layer or an
	// earlier interceptor put there. It has no effect once the response has begun,
	// as SetHeader has none.
	AddHeader(name, value string)

	// SetCookie adds a Set-Cookie header. It has no effect once the response has
	// begun, as SetHeader has none.
	SetCookie(c *Cookie)
	WriteHeader(status int)
	Write(b []byte) (int, error)

	// Stream sends the status, every header set so far and contentType as the
	// Content-Type, then has body write the rest of the response, each
	// EventWriter.Flush reaching the client while the response stays open. The status
	// is 200: a response that wants another answers with WriteHeader and does not
	// stream. Headers and cookies set after Stream have no effect.
	//
	// The type is set only when the adapter commits the head, so a refusal carries none
	// of it and has nothing to take back: an error from Stream, and a chain that refuses
	// on fiber after Stream returned, leave Content-Type as they found it, for what answers
	// the refusal to name, or for a framework or net/http to fill in. A response that had
	// already begun keeps the headers it chose. contentType replaces a Content-Type set
	// earlier when the stream goes out. An empty contentType sets none, so what was set
	// earlier stands, and otherwise the response has whatever its framework gives one no
	// one named a type for: nothing on net/http and gin, and fasthttp's default on fiber.
	//
	// It returns ErrStreamingStarted, writing nothing and not running body, when
	// the response has begun: after WriteHeader, after Write, or on a second call.
	// Once a stream has started, WriteHeader has no effect, and Write writes
	// nothing and returns ErrStreamingStarted, so nothing reaches the client but
	// what body writes.
	//
	// A writer that cannot stream returns ErrStreamingUnsupported, having written
	// nothing and without running body, and the signal stream answers such a
	// request with 501. That is what a consumer's own writer over a framework
	// with no way to deliver an open response returns, and what the net/http and
	// gin writers return over an http.ResponseWriter that cannot flush.
	//
	// If Stream returns nil, body runs exactly once. If it returns an error, body
	// never runs. So a caller may hold something for its body to free, and has only
	// that error to free it on. What body returns goes nowhere on any adapter, so a body
	// keeps its own record of how it ended.
	//
	// When Stream returns depends on the framework, so nothing after the call may
	// rely on the body having run or on it not having run:
	//   - net/http and gin run body inline. Stream returns once it has, with the
	//     response already sent, so a chain that refuses afterwards changes nothing the
	//     client received: its refusal has nowhere left to go. A connection already gone
	//     runs body on an ended context, with a writer whose every call fails and whose
	//     writes reach nothing. The chain's own context is what ctx normally is, so body's
	//     context ends when the client leaves.
	//   - fiber writes a response after its handlers have returned. Stream registers
	//     body and returns nil at once, and body runs once the chain has returned, on a
	//     context detached from ctx's cancellation. A goroutine reads the connection
	//     while body runs, which is how a client leaving ends body's context, so the
	//     response says Connection: close and the connection serves nothing after it. Its
	//     context also ends at server shutdown and when it returns. If the chain refused,
	//     or the connection has gone, body still runs: on an already-ended context, with
	//     a writer whose every call fails and whose writes reach nothing, and the response
	//     is the refusal and not a stream. Stream on a writer whose chain has returned
	//     returns ErrStreamingStarted and body never runs, because the fiber context the
	//     writer held is no longer this request's.
	//
	// On every adapter body's context carries ctx's values, and nothing else: read what
	// the chain resolved through it, not through the exchange.
	//
	// A body that does not return, through a panic or runtime.Goexit, has run, and must
	// not leave a response a client can take for a complete one:
	//   - net/http and gin cut the connection and let the panic go on unchanged, to a
	//     recovery middleware such as gin.Recovery or to the server, so a consumer sees
	//     the value it would have seen without a stream, http.ErrAbortHandler included.
	//     The cut needs a deadline to move, so behind a wrapper with no Unwrap that also
	//     hides the deadline, a panic that a middleware recovers still looks complete.
	//   - fiber runs the body on a goroutine no framework recovers, so it recovers and
	//     logs a panic itself, logging nothing of its value, and the response ends as cut.
	//     A refused stream, or a connection already gone, has no response of its own to
	//     cut.
	//
	// On net/http and gin a client on HTTP/1.0 cannot tell, because a response there has
	// no end to withhold. fiber answers such a client with HTTP/1.1 and chunks.
	//
	// On the adapters the library provides, body's context ends within a moment of the
	// client leaving, with nothing written to notice it, and a client that half-closes
	// its connection counts as having left. It also ends once a Write or a Flush has
	// failed. body should return when it ends. The deadline it writes under, what a nil
	// Flush promises, and how long a client that stops reading can hold a stream, are
	// described on EventWriter and StreamWriteWindow.
	//
	// # A consumer's own adapter
	//
	// All of this is the contract, and a consumer's adapter keeps it or returns
	// ErrStreamingUnsupported. In particular, it must:
	//   - set contentType only once nothing can refuse the stream any more, and set none for
	//     an empty one. If it runs body after its chain has returned, that is when the chain
	//     did not refuse;
	//   - keep the server's write deadline from ending the stream, moving it by
	//     StreamWriteWindow where a deadline exists, and end body's context when the client
	//     leaves, including with nothing written. The signal stream counts on both: a
	//     stream that never hears its client go keeps its place under the caps;
	//   - if it runs body after its chain has returned, hold body back until then, as
	//     fiber's writer does with a gate its middleware opens, and run it on an ended
	//     context if the chain refused. A body started while the chain still runs can
	//     send what the chain then refuses. Its body must not hold anything the framework
	//     reuses, and Stream must refuse once nothing is left to open the gate;
	//   - give body a context carrying ctx's values, and no cancellation from the end of
	//     the handlers if it runs after them;
	//   - keep a body that does not return from looking like a complete response, and
	//     from hanging the client.
	//
	// The signal stream's own code recovers its panics, so these guards serve a consumer
	// calling Stream directly.
	//
	// body must not read the exchange or anything it got from the exchange, on any
	// adapter. Copy what it needs before calling Stream, strings included (with
	// strings.Clone). On fiber the chain has returned by the time body runs, so the
	// request and the strings it answered are views into buffers that are reused for
	// other requests, and body could read another user's request. net/http and gin do
	// not reuse them that way, and the rule is the same so that a stream written on one
	// adapter is safe on the others.
	Stream(ctx context.Context, contentType string, body func(ctx context.Context, w EventWriter) error) error
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

	// csrfOptOut is whether the chain this exchange runs through was built
	// with WithoutCSRFProtection, which CheckCSRFToken reads when no CSRF
	// layer judged the request.
	csrfOptOut bool

	// refusalReported is whether a chain this exchange ran through has
	// already reported the refusal it was answered with (emitRefusal), so a
	// chain assembled inside another's does not have it reported twice.
	refusalReported bool

	// renewal is the identifier of a session the resolution core let through
	// to the renewal endpoint without publishing it: one presented after its
	// grace window under unused-successor recovery, on a request that is the
	// renewal endpoint's. Only the core sets it and only that endpoint reads
	// it; it authenticates nothing.
	renewal string

	// chargeRenewal records a failure against the source the bearer resolved
	// for a late renewal, and is set with renewal by the session-reference
	// bearer alone. The signed-token bearer has no source guard, so it leaves
	// it nil and nothing is charged.
	chargeRenewal func(ctx context.Context)

	// admitRenewal judges the session a late renewal loads, as the bearer
	// that let it through would have judged a session it loaded: its key
	// binding against the credential and the proof presented, a signed token's
	// subject against its user, the proof then recorded. It is set with renewal
	// by the resolution core, and nil when the bearer has nothing to judge. The
	// record it returns is the user it loaded, which the endpoint uses rather
	// than loading again; nil means the endpoint loads the user by the reference
	// the session records.
	admitRenewal func(ex *Exchange, s *session.Session) (*identity.Details, error)

	// certificateThumb is the thumbprint of the client certificate the
	// request presents, "" for none, once certificateRead says it has been
	// read (presentedThumbprint). Certificate binding reads it once, at
	// OrderMTLS, so every interceptor inside judges one answer.
	certificateThumb string
	certificateRead  bool

	// bearerCredential is the credential the chain's bearer authenticated on
	// this request, as it was presented: a signed token or a session
	// reference, under whatever scheme the bearer reads. It is set only once
	// the bearer has resolved it, and "" on a request no bearer
	// authenticated. A DPoP proof beside it carries ath over it.
	bearerCredential string

	ctx context.Context
}

// NewExchange starts an exchange seeded from ctx.
//
// It panics when ctx is nil: an exchange with no context would panic at the
// first call into a core, so the mistake is refused where it is made.
func NewExchange(ctx context.Context, r Request, w ResponseWriter) *Exchange {
	if ctx == nil {
		panic("httpsec: NewExchange needs a non-nil context")
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
// It panics when ctx is nil: dropping the context the exchange already holds
// would silently detach the rest of the chain from the client's cancellation.
func (e *Exchange) SetContext(ctx context.Context) {
	if ctx == nil {
		panic("httpsec: Exchange.SetContext needs a non-nil context")
	}
	e.ctx = ctx
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
// It refuses a non-nil s that belongs to no family (FamilyID is id.Nil) and
// publishes nothing, neither a nor s. Every stored session belongs to a
// family, which is what reuse detection, family revocation and logout act on;
// a session without one would escape all three, so one can only come from an
// interceptor that built it by hand. The error has fixed text and matches no
// sentinel, ErrAuthenticationRequired and the session errors included, so an
// interceptor that returns it gets the 500 any unclassified error maps to. A
// nil s is not refused: it is WithCaller and SetContext, and returns nil.
//
// The default is unused: the built-ins call it, and a consumer calls it from
// an interceptor registered with RegisterInterceptor, normally at
// OrderBearerToken, after verifying the credential that names s. Such an
// interceptor also calls RecordPresentedToken with that credential, so a DPoP
// proof beside it is judged for its ath. PublishSession is itself the
// consumer's extension point, so it has no override.
func (e *Exchange) PublishSession(a *authenticate.Authentication, s *session.Session) error {
	if s != nil && s.FamilyID == id.Nil {
		return errors.New("httpsec: a session with no family cannot be published; every stored session belongs to one")
	}

	e.Authentication = a
	e.Session = s
	e.SetContext(withSession(WithCaller(e.ctx, a), s))

	return nil
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

// RecordPresentedToken records tok as the access token the request presented,
// as the caller verified it, under whatever scheme the caller reads. A DPoP
// proof the request carries beside it must then carry ath over tok (RFC 9449
// section 4.2), at the endpoints that issue or continue a sign-in.
//
// A consumer's own bearer interceptor, registered with RegisterInterceptor at
// OrderBearerToken, calls it after verifying the credential and before next.
// The built-in bearers (EnableBearerToken, EnableSessionBearer) call it for
// the credential they authenticate. Call it only for a credential that was
// verified: the proof is judged against it as given.
//
// The default is that nothing is recorded: the request is judged as presenting
// no access token, so a proof with ath is refused and one without is accepted.
// It has no override, being the consumer's own extension point.
func (e *Exchange) RecordPresentedToken(tok string) {
	e.bearerCredential = tok
}
