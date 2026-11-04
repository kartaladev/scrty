package httpsec

import (
	"context"
	"errors"
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
	signalsContentType  = "text/event-stream"
	signalsCacheControl = "no-store, no-transform"
)

// Intercept answers the stream's path and passes everything else through. The
// endpoint is terminal: nothing behind it runs for that path, whatever the answer.
func (e *sessionSignals) Intercept(ex *Exchange, next Next) error {
	if ex.Request.Path() != e.cfg.Path {
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

	reload, err := e.reloadContext(ex.Context())
	if err != nil {
		return err
	}

	state, err := e.readSignIn(reload, s.UserID, s.FamilyID)
	if err != nil {
		return err
	}

	start := newStreamStart(reload, ex, s, wanted, state)

	// Registered before Stream, because on fiber Stream returns before its body runs, and
	// the place has to be held from here. If Stream returns nil its body runs exactly
	// once, whatever the chain then does, so the body frees it. If it returns an error its
	// body never runs, so that frees it.
	release, err := e.registry.admit(start.stream)
	if err != nil {
		return err
	}

	ex.Writer.SetHeader("Content-Type", signalsContentType)
	ex.Writer.SetHeader("X-Accel-Buffering", "no")

	err = ex.Writer.Stream(cancelOnly{ex.Context()}, func(ctx context.Context, w EventWriter) error {
		defer release()

		return e.runStream(ctx, w, start)
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
func (e *sessionSignals) reloadContext(ctx context.Context) (context.Context, error) {
	if e.cfg.ReloadContext == nil {
		return context.Background(), nil
	}

	reload := e.cfg.ReloadContext(ctx)
	if reload == nil {
		return nil, errReloadContextMissing
	}

	return context.WithoutCancel(reload), nil
}

// readSignIn is the first read of the sign-in. It runs as a reload does, on the reload
// context and within ReloadTimeout, so a tenant-scoped store with no hook fails here,
// where it can be seen, and not as an open stream that never hears of an end.
//
// A sign-in the store does not hold is 401. Any other failure is returned as it is,
// matching neither that nor anything a client is told by: a dependency failure.
//
// It takes the user and the family, not the session, so that a body can read through it
// holding neither the session nor its raw identifier.
func (e *sessionSignals) readSignIn(reload context.Context, user identity.UserID, family id.ID) (session.SignInState, error) {
	ctx, cancel := context.WithTimeout(reload, e.cfg.ReloadTimeout)
	defer cancel()

	state, err := e.sessions.SignInState(ctx, user, family)
	if errors.Is(err, session.ErrNotFound) {
		return session.SignInState{}, ErrAuthenticationRequired
	}

	return state, err
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
	// open and close logs. They never reach the stream.
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
	upstream := upstreamDigest(state.ExternalIssuer, state.ExternalSessionID)

	// The digest is all a stream holds of the upstream session, which identifies a session
	// at the provider, so the raw values go now.
	state.ExternalIssuer, state.ExternalSessionID = "", ""

	return streamStart{
		stream: newSignalStream(
			identity.UserID(strings.Clone(string(s.UserID))), s.FamilyID,
			upstream, source, wanted,
		),
		reload: reload,
		state:  state,
		source: source,
		origin: strings.Clone(ex.Request.Header("Origin")),
	}
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

// runStream is one stream's life. Dispatch C3 replaces it with the stream loop. For now
// it sends the head and waits for the stream's context to end. It writes no retry and no
// event.
func (e *sessionSignals) runStream(ctx context.Context, w EventWriter, _ streamStart) error {
	if err := w.Flush(); err != nil {
		return err
	}

	<-ctx.Done()

	return nil
}
