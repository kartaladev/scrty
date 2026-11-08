package httpsec

import (
	"context"
	"net/http"
	"strings"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// The signal stream's response headers. no-store keeps the stream out of every cache,
// no-transform asks an intermediary not to compress it, and X-Accel-Buffering asks a
// proxy that honours it not to hold it back.
const (
	signalsContentType    = "text/event-stream"
	signalsCacheControl   = "no-store, no-transform"
	signalsAccelBuffering = "X-Accel-Buffering"
)

// startStream answers with the stream's three headers and has body write the rest. Stream sets the
// type, and only when it commits the head. It returns what Stream returned.
func startStream(ex *Exchange, body func(ctx context.Context, w EventWriter) error) error {
	ex.Writer.SetHeader("Cache-Control", signalsCacheControl)
	ex.Writer.SetHeader(signalsAccelBuffering, "no")

	return ex.Writer.Stream(cancelOnly{ex.Context()}, signalsContentType, body)
}

// Intercept answers the stream's path and passes everything else through. The
// endpoint is terminal: nothing behind it runs for that path, whatever the answer.
//
// A cap, a close and a dependency failure are returned, and answered by sessionSignalsRetry,
// which is what also sees the same failure from the authenticators outside this slot.
func (e *sessionSignals) Intercept(ex *Exchange, next Next) error {
	if ex.Request.Path() != e.path {
		return next(ex)
	}

	// Set first, so every answer, a refusal included, is never cached.
	ex.Writer.SetHeader("Cache-Control", signalsCacheControl)

	if ex.Request.Method() != http.MethodGet {
		ex.Writer.SetHeader("Allow", http.MethodGet)

		return errSignalsMethod
	}

	s, err := streamSession(ex)
	if err != nil {
		return err
	}

	if err := e.crossSiteAllowed(ex, streamByCookie(ex)); err != nil {
		return err
	}

	wanted, err := e.narrowed(ex.Request.QueryValues("signals"))
	if err != nil {
		return err
	}

	reload, err := e.reloadContext(ex.Context(), s.FamilyID)
	if err != nil {
		return err
	}

	state, err := e.readSignIn(reload, s.UserID, s.FamilyID)
	if err != nil {
		return err
	}

	start := newStreamStart(reload, ex, s, wanted, state)
	start.stream.window = e.reasonWindow()

	// Registered before Stream, because on fiber Stream returns before its body runs, and
	// the place has to be held from here. If Stream returns nil its body runs exactly
	// once, whatever the chain then does, so the body frees it. If it returns an error its
	// body never runs, so that frees it.
	release, err := e.registry.admit(start.stream)
	if err != nil {
		return err
	}

	e.hub.start()

	err = startStream(ex, func(ctx context.Context, w EventWriter) error {
		defer release()

		e.runStream(ctx, w, start)

		return nil
	})
	if err != nil {
		release()

		return err
	}

	return nil
}

// cancelOnly is a context that ends when its parent does and holds no values. It is what a
// stream's body runs on, because adapters derive the body's context from the one they are
// handed, and the request's holds the session and its raw identifier.
type cancelOnly struct{ context.Context }

// Value holds nothing.
func (cancelOnly) Value(any) any { return nil }

// AfterFunc is what context asks a parent for before it starts a goroutine to watch one whose
// cancellation it cannot see, as Value hides this one's. So a stream's WithCancel costs no goroutine.
func (c cancelOnly) AfterFunc(f func()) func() bool { return context.AfterFunc(c.Context, f) }

// streamSession is the sign-in a stream may open on. A session reference, a signed bearer
// bound to a stored session and a consumer's cookie session all reach here the same way,
// published on the exchange. No credential is read from the query string anywhere on the
// way, so one named only there reaches here as no credential.
//
// With no caller the request is 401. A caller with no session is 403: it authenticated,
// by Basic, an API key or a token bound to no session, and a stream has no sign-in to
// report on. That caller may be on the context alone, because publishing a caller with no
// session is WithCaller and SetContext (Exchange.PublishSession). A session needs the result
// PublishSession published with it, so one no result owns is 401. The gates below this slot
// have refused a sign-in owing anything on a chain that enables them, and this holds the
// line on one that does not.
func streamSession(ex *Exchange) (*session.Session, error) {
	published := ex.Authentication != nil && ex.Authentication.Principal != nil

	s := ex.Session
	if s == nil {
		if _, onContext := identity.PrincipalFromContext(ex.Context()); published || onContext {
			return nil, errStreamNeedsSignIn
		}

		return nil, ErrAuthenticationRequired
	}

	if !published {
		return nil, ErrAuthenticationRequired
	}

	if err := fullSessionOnly(s); err != nil {
		return nil, err
	}

	if err := raisedChallengeRefusal(ex, s); err != nil {
		return nil, err
	}

	if err := requireSessionUser(ex, s); err != nil {
		return nil, err
	}

	return s, nil
}

// reloadContext makes the context a stream's reads run on, once, from the opening
// request's. By default it holds none of that request's values, because a consumer's
// transaction attached to it would stay open for the stream's life on net/http, and on
// fiber be committed when the chain returns, so that every reload failed. A consumer's
// hook carries what it needs over, and the request's cancellation is removed from what it
// returns, because the stream outlives the handlers on fiber. What else it keeps is the
// hook's: its godoc says never to return its argument.
func (e *sessionSignals) reloadContext(ctx context.Context, family id.ID) (_ context.Context, err error) {
	if e.cfg.ReloadContext == nil {
		return context.Background(), nil
	}

	// A panic in the consumer's hook is recovered as one in a store is, and logged without its
	// value. The request is then a dependency failure, which a retry could fix.
	defer func() {
		if v := recover(); v != nil {
			e.logStreamPanic(ctx, panicPhaseReload, family, v)

			err = errStreamReadPanicked
		}
	}()

	reload := e.cfg.ReloadContext(ctx)
	if reload == nil {
		return nil, errReloadContextMissing
	}

	return context.WithoutCancel(reload), nil
}

// streamStart is what a stream's body starts from. Everything in it was copied from the
// exchange before Stream was called, because a body must not read the exchange (see
// ResponseWriter.Stream).
type streamStart struct {
	// stream is the registered stream. The caller of runStream frees its place when the body
	// returns, so that CloseSessionSignals cannot return before the body has.
	stream *signalStream

	// reload is the context every read of the sign-in and its user runs on, from
	// SessionSignals.ReloadContext. It carries none of the opening request's
	// cancellation.
	reload context.Context //nolint:containedctx // a stream outlives the request that built it, and this is what its reads run on

	// state is the first read of the sign-in, for the first session event, with its upstream
	// fields cleared: what a stream holds of the upstream session is its digest.
	state session.SignInState

	// source and origin are the client's address and Origin header, for the stream's
	// open and close logs. They never reach the stream. The origin is cut to
	// crossSiteOriginLogLimit: Sec-Fetch-Site: none passes with any Origin, so its size is the
	// client's to choose, and a stream holds this for its whole life. There is no override, as only
	// a log reads it: a longer one is named in part.
	source, origin string
}

// newStreamStart copies what a body needs from the exchange, strings cloned, on every
// adapter. A body must not read the exchange (ResponseWriter.Stream): on fiber it runs after
// the chain has returned, when the request and the strings it answered are views into
// buffers reused for other requests, so it could read another user's request. A test on the
// fiber adapter would live in another module, so the conformance suite covers it.
func newStreamStart(
	reload context.Context, ex *Exchange, s *session.Session, wanted signalFilter, state session.SignInState,
) streamStart {
	source := strings.Clone(ex.Request.ClientIP())
	origin := ex.Request.Header("Origin")
	upstream := upstreamDigest(state.ExternalIssuer, state.ExternalSessionID)

	// The digest is all a stream holds of the upstream session, which identifies a session
	// at the provider, so the raw values go now.
	state.ExternalIssuer, state.ExternalSessionID = "", ""

	return streamStart{
		stream: newSignalStream(
			identity.UserID(strings.Clone(string(s.UserID))), s.FamilyID,
			upstream, source, wanted.owned(),
		),
		reload: reload,
		state:  state,
		source: source,
		origin: strings.Clone(origin[:min(len(origin), crossSiteOriginLogLimit)]),
	}
}

// owned is f with names of its own, since a parameter's values came from the request, and a
// consumer's adapter may answer with views into its buffers.
func (f signalFilter) owned() signalFilter {
	if f.names == nil {
		return f
	}

	names := make(map[string]bool, len(f.names))
	for name := range f.names {
		names[strings.Clone(name)] = true
	}

	f.names = names

	return f
}

// streamByCookie reports whether a stream's credential is one a browser sends on its own,
// which is what the cross-site rule decides by. A credential is a bearer's only when the
// chain recorded one and that is what the Authorization header carries, since a page has to
// hold it to send it. Recording alone does not say so, because a consumer's cookie
// authenticator is told to call RecordPresentedToken too. Anything else is taken for a
// cookie, the stricter of the two, which includes a consumer's bearer on a header of its own.
func streamByCookie(ex *Exchange) bool {
	_, token, _ := strings.Cut(ex.Request.Header("Authorization"), " ")

	return ex.bearerCredential == "" || strings.TrimSpace(token) != ex.bearerCredential
}
