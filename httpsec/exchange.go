package httpsec

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
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

	// Path is the request path as sent, decoded. The chain refuses a path
	// with a "." or ".." segment before any interceptor runs, so an
	// interceptor never sees one. Path is otherwise as sent, and may differ
	// from the path a router serves in letter case and trailing slashes: a
	// matcher that reads it must cover the spellings its framework routes to
	// one handler.
	Path() string

	// EscapedPath is the request path as the client sent it, percent-encoding
	// intact: "/api/ord%65rs" stays "/api/ord%65rs", where Path decodes it to
	// "/api/orders". An integration returns it exactly as sent, never
	// normalised: the chain's dot-segment refusal reads this value, so a
	// cleaned path would let a "." or ".." segment through. net/http's
	// URL.EscapedPath may re-encode from the decoded path when the raw path is
	// not a valid encoding. Dots stay visible either way, while an encoded
	// slash may come back as a plain "/", which the refusal reads as a
	// separator.
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

	// RawQuery is the query string exactly as the client sent it: no leading
	// "?", nothing decoded, and nothing dropped, so a pair the framework could
	// not parse is still in it. An empty query is "".
	//
	// It exists for a check that must not depend on how a framework parses:
	// the token endpoints refuse a client credential sent in the query by
	// scanning it, where Query and QueryValues would not show a pair the
	// framework silently discarded.
	RawQuery() string

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
	SetCookie(cookie *Cookie)
	WriteHeader(status int)
	Write(body []byte) (int, error)

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
	// earlier stands, and a consumer who names the type themselves and passes "" has it on
	// a refusal too: a Content-Type set before a refused Stream stays on the refusal.
	// Otherwise the response has whatever its framework gives one no one named a type for:
	// nothing on net/http and gin, and fasthttp's default on fiber.
	//
	// One refusal carries the type to the client, and that is a stated limit. A wrapper above
	// the bottom of the Unwrap chain can be asked whether it flushes only once the status is
	// named, and asking sooner can itself send the head. If such a wrapper then says
	// http.ErrNotSupported, Stream returns ErrStreamingUnsupported and puts the header back,
	// but a real server has copied the headers at WriteHeader(200): the client receives
	// status 200 with the stream's type, and whatever answers the refusal writes after it
	// (under gin, a render) goes out under that status and that type.
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
	// Stream is called on the chain's own goroutine, before the chain returns. That is a stated
	// limit: a writer handed to another goroutine while the chain unwinds is not safe to call on
	// fiber, where the writer reaches a fiber context the framework releases and reuses, and no lock
	// in the writer could make that safe. The one call promised from elsewhere is the refusal a
	// Stream makes once its chain has returned (ErrStreamingStarted).
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
	//   - set contentType only once nothing can refuse the stream any more, or put back what
	//     was there when it is refused, for a writer whose flush is both the question and the
	//     head, and set none for an empty one. If it runs body after its chain has returned, that
	//     is when the chain did not refuse;
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
	Stream(ctx context.Context, contentType string, body func(ctx context.Context, events EventWriter) error) error
}

// Exchange is one request passing through the chain.
//
// The context lives here rather than on the Request because a framework built
// on fasthttp carries no context on its request. It is seeded from the
// integration's own incoming context, so values and cancellation set before the
// chain survive, and it is written back into the framework's carrier
// immediately before the handler.
//
// An Exchange belongs to one goroutine: an interceptor that hands next or the
// exchange to another goroutine and returns before it finishes is unsupported.
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
	// the bearer has resolved it, or once resolution has ended in a per-request
	// throttle of the stream, where the credential has verified
	// (recordThrottledBearer), and "" on a request no bearer authenticated. A
	// DPoP proof beside it carries ath over it.
	bearerCredential string

	// terminals and extra are the stack of runs in progress on this exchange,
	// one entry per Assemble step entered and not yet returned: the chain and
	// the terminal that run was given. The prebuilt fold is shared by every
	// request, so its innermost step finds the terminal here (topTerminal)
	// rather than holding one. Two entries cover one chain, and one chain
	// nested in another, without allocating; deeper nesting spills to extra.
	// The occupied entries are always terminals[0], then terminals[1], then
	// extra in order.
	terminals [2]runTerminal
	extra     []runTerminal

	ctx context.Context
}

// runTerminal is one run in progress on an exchange: the chain running and the
// terminal its Assemble was given. running is set while the innermost step is
// inside next, so a lookup made from within that terminal, where the same
// chain is entered again, finds the run outside it rather than this one.
//
// gatesBegun is the run's gate mark on this exchange: it is set while the
// run is inside its chain's first enabled gate (recovery, enrolment, second
// factor or password change), whatever that gate then decides, and
// everything the gate passes the request to. While it is set PublishSession
// refuses a session the run itself publishes, since one published past its
// gates would reach the handler unjudged by them, and a session another run
// publishes unless that run's chain enables every gate this run's chain
// enables. The mark belongs to the run whose gate frame set it, so a
// different chain nested on the same exchange that covers every gate
// publishes, and its own gates judge what it published. The gate's frame
// puts back the value it found as it returns, a panic included, so a
// retried pass or a later run of the exchange publishes before the gates as
// normal (buildFold).
type runTerminal struct {
	chain      *Chain
	next       Next
	running    bool
	gatesBegun bool
}

// terminalCount is how many runs are in progress on e.
func (e *Exchange) terminalCount() int {
	switch {
	case e.terminals[0].chain == nil:
		return 0
	case e.terminals[1].chain == nil:
		return 1
	default:
		return len(e.terminals) + len(e.extra)
	}
}

// terminalAt returns the entry at position i of the stack, the bottom being 0.
func (e *Exchange) terminalAt(i int) *runTerminal {
	if i < len(e.terminals) {
		return &e.terminals[i]
	}

	return &e.extra[i-len(e.terminals)]
}

// pushTerminal records that c has begun a run on e with terminal t.
func (e *Exchange) pushTerminal(c *Chain, t Next) {
	entry := runTerminal{chain: c, next: t}

	switch n := e.terminalCount(); {
	case n < len(e.terminals):
		e.terminals[n] = entry
	default:
		e.extra = append(e.extra, entry)
	}
}

// popTerminal removes the topmost entry of c, the run that is returning.
//
// Runs return in the reverse order they began, a panic unwinding included,
// so that entry is the top of the stack; the entries above it, if any, are
// shifted down regardless, so a stack left out of order still never holds a
// terminal of a run that has ended. Nothing is removed when c has no entry.
func (e *Exchange) popTerminal(c *Chain) {
	n := e.terminalCount()

	i := n - 1
	for i >= 0 && e.terminalAt(i).chain != c {
		i--
	}

	if i < 0 {
		return
	}

	for j := i; j < n-1; j++ {
		*e.terminalAt(j) = *e.terminalAt(j + 1)
	}

	// The vacated top is cleared so the stack does not keep the terminal, and
	// what its closure holds, reachable.
	*e.terminalAt(n - 1) = runTerminal{}

	if n > len(e.terminals) {
		e.extra = e.extra[:n-1-len(e.terminals)]
	}
}

// topTerminal returns the position of c's topmost entry whose terminal is not
// already running, or -1 when there is none.
func (e *Exchange) topTerminal(c *Chain) int {
	for i := e.terminalCount() - 1; i >= 0; i-- {
		if t := e.terminalAt(i); t.chain == c && !t.running {
			return i
		}
	}

	return -1
}

// publishingChain returns the chain whose interceptors are running on e: the
// topmost run in progress whose terminal is not itself running. A run whose
// terminal is running has handed the request on, so what publishes there
// belongs to the run below it or to the handler. It is nil when no chain is
// running interceptors on e, such as from the handler, and a nil chain
// enables no gate, so the check it feeds fails closed.
func (e *Exchange) publishingChain() *Chain {
	if i := e.publishingRun(); i >= 0 {
		return e.terminalAt(i).chain
	}

	return nil
}

// publishingRun returns the position of the run publishingChain names, or -1
// when no chain is running interceptors on e.
func (e *Exchange) publishingRun() int {
	for i := e.terminalCount() - 1; i >= 0; i-- {
		if !e.terminalAt(i).running {
			return i
		}
	}

	return -1
}

// gateMarkRefusal returns why a session published now is refused by the gate
// marks of the runs on e, or nil when none refuses it. A mark of the
// publishing run itself makes the publication late: its own gates have begun
// (errLatePublication). A mark of any other run on e is judged by
// otherRunMarkRefusal. The marks are read from e itself, so the context an
// interceptor set does not change what they decide; runs on another exchange
// are judged by gatesRunning. The walk is as deep as the runs on e and
// allocates nothing.
func (e *Exchange) gateMarkRefusal() error {
	if p := e.publishingRun(); p >= 0 && e.terminalAt(p).gatesBegun {
		return errLatePublication
	}

	return e.otherRunMarkRefusal()
}

// otherRunMarkRefusal returns errPublishedInsideGates when a run on e other
// than the publishing one is marked and the publishing chain does not enable
// every gate that run's chain enables, or nil when none is. A publication from
// the handler, where no chain is running interceptors, enables no gate and is
// refused by any mark. The publishing run's own mark is not read: the
// resolution core runs before its own chain's gates, and PublishSession
// judges that mark itself (gateMarkRefusal). The marks are read from e, never
// from its context, so a context an interceptor replaced cannot hide them.
// The walk is as deep as the runs on e and allocates nothing.
func (e *Exchange) otherRunMarkRefusal() error {
	publisher := e.publishingRun()

	var have gateSet
	if publisher >= 0 {
		if c := e.terminalAt(publisher).chain; c != nil {
			have = c.gates
		}
	}

	for i := range e.terminalCount() {
		t := e.terminalAt(i)
		if i == publisher || !t.gatesBegun {
			continue
		}

		// A marked run always has a chain; one without is refused rather
		// than read as enabling no gate.
		if t.chain == nil || !have.covers(t.chain.gates) {
			return errPublishedInsideGates
		}
	}

	return nil
}

// NewExchange starts an exchange seeded from ctx.
//
// It panics when ctx is nil: an exchange with no context would panic at the
// first call into a core, so the mistake is refused where it is made.
func NewExchange(ctx context.Context, request Request, writer ResponseWriter) *Exchange {
	if ctx == nil {
		panic("httpsec: NewExchange needs a non-nil context")
	}
	return &Exchange{Request: request, Writer: writer, ctx: ctx}
}

// Context returns the context every call into scrty's cores is made with. It
// is derived from the incoming request's context and never replaces it, so an
// upstream value and an upstream cancellation both survive the chain.
func (e *Exchange) Context() context.Context { return e.ctx }

// SetContext replaces the context. An interceptor that resolves security state
// calls it so every later interceptor, and the handler, read that state.
//
// The new context must derive from the current one. The runs on this exchange
// are judged from the exchange's own marks, so replacing the context does not
// hide them. The enclosing runs on other exchanges are found through the
// context, so one that does not derive from it hides those: a chain run on it
// is judged as a chain on its own, and the check that refuses a session
// published inside another chain's gates then finds nothing to refuse.
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

// PublishSession publishes authentication, the result of authenticating this request, and
// sess, the session it was authenticated on, together: on the exchange, as
// Authentication and Session, and on its context, where WithCaller puts the
// result and its principal and SessionFromContext reads sess. Every later
// interceptor and the handler read the caller and the session from there.
//
// It is how a consumer interceptor that authenticates on a session of its own
// resolving publishes it, and it is what the built-in session-bound
// authenticators call. A session published here is treated as theirs is: the
// session-touch step records its activity after the handler, through the
// session manager the chain was wired with, and EvaluatePerRequest judges it.
// Publishing authentication only, with no session, is WithCaller and SetContext; publishing
// sess only, with no result, publishes a session no caller owns, which no
// built-in does.
//
// It refuses a non-nil sess that belongs to no family (FamilyID is id.Nil) and
// publishes nothing, neither authentication nor sess. Every stored session belongs to a
// family, which is what reuse detection, family revocation and logout act on;
// a session without one would escape all three, so one can only come from an
// interceptor that built it by hand. The error has fixed text and matches no
// sentinel, ErrAuthenticationRequired and the session errors included, so an
// interceptor that returns it gets the 500 any unclassified error maps to. A
// nil sess is not refused: it is WithCaller and SetContext, and returns nil.
//
// It also refuses a non-nil sess once the request has entered the chain's
// first enabled gate: the recovery gate (OrderAccountRecovery), the enrolment
// gate (OrderMFAEnrolment), the second-factor gate (OrderMFAChallenge) or the
// password-change gate (OrderPasswordChange). A session published past that
// point would reach the authorization stage and the handler without the gates
// having judged it, so one owing a second factor, a password change or an
// enrolment would be served. The error wraps ErrConfig, so the request is
// answered with a 500, nothing is published, and the chain writes one sampled
// record naming neither the session nor its user. The refusal is a wiring
// mistake, not a runtime condition: register the authenticating interceptor
// at OrderBearerToken, no later. Interceptors after OrderBearerToken, such as
// the recovery cool-down, judge a request by the session it carries when they
// run, so a session published behind them is never judged by them. A chain
// with none of the gates enabled refuses nothing, and a nil sess, signing the
// caller out, is never refused. The gate mark that makes a publication late
// belongs to the run whose first gate set it: only the publishing chain's own
// gates having begun do.
//
// A publication inside another chain's gates is judged by gate set instead:
// on the same exchange or on one an adapter's mount built further in,
// whether a consumer interceptor or a built-in authenticator publishes, it is
// refused when the publishing chain does not enable every gate the other
// chain enables, and the error, which also wraps ErrConfig, says to mount
// that chain outside the other chain's gates or to authenticate in the outer
// chain. A chain that enables every one of those gates, the same chain
// included, is not refused, whether it is assembled inside the other on one
// exchange or a handler forwards the request in-process through it: its own
// gates judge the session it publishes, and a late authenticator of its own
// is refused by its own gates' mark. A session published from the handler,
// where no chain is running interceptors, is refused once any chain's gates
// have begun. The mark holds only while the gates run, so an interceptor
// before OrderBearerToken that runs the rest of the chain twice publishes
// before the gates on both passes.
//
// The runs on the same exchange are judged from the exchange itself. The
// enclosing runs on other exchanges are found through the exchange's context,
// so the context an interceptor sets must derive from the current one
// (SetContext): a chain run on a fresh exchange whose context does not is
// judged as a chain on its own.
//
// The default is unused: the built-ins call it, and a consumer calls it from
// an interceptor registered with RegisterInterceptor at OrderBearerToken,
// after verifying the credential that names sess. Such an
// interceptor also calls RecordPresentedToken with that credential, so a DPoP
// proof beside it is judged for its ath. PublishSession is itself the
// consumer's extension point, so it has no override.
func (e *Exchange) PublishSession(authentication *authenticate.Authentication, sess *session.Session) error {
	// A session published once the publishing chain's gates have begun, or
	// inside the gates of another run on this exchange that the publishing
	// chain does not cover, reaches the handler and the authorization stage
	// without the gates having judged it: one owing a second factor, a
	// password change or an enrolment would be served. It is refused, never
	// published, and the chain is told once per window.
	if sess != nil {
		if err := e.gateMarkRefusal(); err != nil {
			e.logLatePublication()

			return err
		}
	}

	return e.publishSession(authentication, sess)
}

// errLatePublication is what PublishSession returns for a session published
// once the publishing chain's own gates have begun.
var errLatePublication = fmt.Errorf("%w: a session was published after the chain's gates had begun; "+
	"register the authenticator at OrderBearerToken", ErrConfig)

// errPublishedInsideGates is what publishing a session returns when the chain
// publishing it runs inside another chain's gates, on this exchange or on one
// an adapter built further in.
var errPublishedInsideGates = fmt.Errorf("%w: a session was published by a chain run inside another chain's gates; "+
	"mount this chain outside the other chain's gates or authenticate in the outer chain", ErrConfig)

// msgLatePublication is the record a refused late publication leaves.
const msgLatePublication = "httpsec: session published after the gates refused"

// latePublicationKey is the sampling key of that record.
const latePublicationKey = "late-session-publication"

// logLatePublication writes the record of a refused late publication through
// the chain running innermost on e, sampled per chain. It names neither the
// session nor its user: the refusal is a wiring mistake, and what an operator
// needs is that it happened, not whose request met it. An exchange no chain
// is running, or a chain that did not come from New, has no logger, and
// nothing is written.
func (e *Exchange) logLatePublication() {
	n := e.terminalCount()
	if n == 0 {
		return
	}

	c := e.terminalAt(n - 1).chain
	if c == nil || c.logger == nil || c.perRequest == nil {
		return
	}

	logSampled(e.ctx, c.sampler, c.logger, slog.LevelError, c.perRequest.now(), latePublicationKey, msgLatePublication)
}

// publishSession is PublishSession without the check of the publishing run's
// own gate mark: the path the resolution core and every built-in that
// publishes a session take, wherever in their own chain they run, since the
// core runs at OrderBearerToken, before its own chain's gates. It still
// refuses a non-nil sess while another chain's run is inside gates the
// publishing chain does not all enable, since a session published there
// reaches the handler unjudged by the gate it lacks, whoever publishes it.
// Such a run is found two ways, and either refuses: on this exchange, from
// the marks the exchange itself holds (otherRunMarkRefusal), so a consumer
// interceptor that replaced the context with one not derived from the run's
// does not hide it; and on an exchange further out, through the run marker's
// parent links on the context (gatesRunning).
func (e *Exchange) publishSession(authentication *authenticate.Authentication, sess *session.Session) error {
	if sess != nil {
		err := e.otherRunMarkRefusal()
		if err == nil && gatesRunning(e.ctx, e.publishingChain()) {
			err = errPublishedInsideGates
		}

		if err != nil {
			e.logLatePublication()

			return err
		}
	}

	if sess != nil && sess.FamilyID == id.Nil {
		return errors.New("httpsec: a session with no family cannot be published; every stored session belongs to one")
	}

	e.Authentication = authentication
	e.Session = sess
	e.SetContext(withSession(WithCaller(e.ctx, authentication), sess))

	return nil
}

// EvaluatePerRequest runs the chain's per-request policy phase for sess, the
// session this request is authenticated on, and principal, its caller, with the
// challenge handling the built-in authenticators apply, and returns their
// refusal or nil.
//
// A denial is returned as the policy's reason. On the signal stream's own path, a throttle
// matches it through errors.Is, and is not that very value. A challenge of a kind nothing
// on the chain enforces is refused with a configuration error. Any other
// challenge is marked where the gate enforcing it reads it, and nil is
// returned so the request goes on to that gate: a built-in kind is marked on
// sess, and a session entering the enrolment-only state is stored before this
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
// in memory. The phase fails closed: a nil sess or principal, a call before
// PublishSession, or a sess or principal that is not the pair PublishSession published
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
func (e *Exchange) EvaluatePerRequest(sess *session.Session, principal *identity.Principal) error {
	if sess == nil || principal == nil {
		return ErrAuthenticationRequired
	}

	// It fails closed: the phase judges the pair PublishSession published, and
	// a call for any other pair, or before anything was published, would judge
	// a caller this request was never authenticated as. Sessions are compared
	// by identity, as the exchange holds the one it published.
	if e.Authentication == nil || e.Authentication.Principal != principal || e.Session != sess {
		return ErrAuthenticationRequired
	}

	ph := e.perRequest
	if ph == nil {
		return nil
	}

	return e.evaluatePerRequest(ph, sess, principal, e.Authentication.PasswordChangedAt, ph.now())
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
