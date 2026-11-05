package httpsec

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// oidcEndSessionFlow names the end-session endpoint's rate-limit buckets and sampler keys.
const oidcEndSessionFlow = "oidc-end-session"

// How many requests one source may park or have refused at the end-session endpoint before it is
// refused unread. They are proposed values, those of the authorization endpoint, for the same
// reason: everyone behind one address signing out at once must fit, while anyone may otherwise
// fill the pending-request store.
const (
	defaultOIDCEndSessionLimit  = 300
	defaultOIDCEndSessionWindow = time.Minute
)

// oidcEndSessionGroup serves the end-session endpoint.
type oidcEndSessionGroup struct {
	oidcGroupBase

	throttle  oidcClientThrottle
	bodyLimit int64
}

// bind takes the provider's state, and the default the options replace.
func (g *oidcEndSessionGroup) bind(op *oidcEndpoints) {
	g.oidcGroupBase.bind(op)
	g.bodyLimit = DefaultLoginBodyLimit
}

func (g *oidcEndSessionGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCEndSession], handle: g.serve},
	}
}

func (g *oidcEndSessionGroup) settle(c *config) error {
	return g.throttle.settleAt(c, oidcEndSessionFlow, defaultOIDCEndSessionLimit, defaultOIDCEndSessionWindow)
}

func (g *oidcEndSessionGroup) wire(ch *Chain) {
	g.throttle.wire(ch)
}

func (g *oidcEndSessionGroup) flushRefusalLogs() error {
	g.throttle.flush()

	return nil
}

// WithOIDCEndSessionLimiter counts, per source, the requests the end-session endpoint parks and
// those it refuses. A source past its limit is refused with ErrOIDCThrottled, which wraps
// ratelimit.ErrThrottled and answers 429, before the request is read. A limiter that cannot
// answer, and a source that cannot be attributed, are refused the same way: the limit fails closed.
// A request ending a sign-in without asking is not counted, as it parks nothing and needs a live
// browser session to spend.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under namespace
// "oidc-end-session", or else an in-memory limiter of 300 per source a minute. A deployment of more
// than one replica supplies a factory or a limiter its replicas share, or the limit is per process.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it would read as no
// limit while the consumer believed they had replaced one.
func WithOIDCEndSessionLimiter(l ratelimit.Limiter) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if err := requireDep("WithOIDCEndSessionLimiter", "limiter", l); err != nil {
			return err
		}

		op.endSession.throttle.limiter = l

		return nil
	}
}

// WithOIDCEndSessionBodyLimit reads at most n bytes of a form POST to the end-session endpoint.
//
// Default: DefaultLoginBodyLimit. A body over it answers ErrRequestTooLarge. A limit of zero or
// less is refused, because it would refuse every form POST.
func WithOIDCEndSessionBodyLimit(n int64) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if n <= 0 {
			return newConfigError("WithOIDCEndSessionBodyLimit takes a positive bound, and %d would refuse "+
				"every form POST", n)
		}

		op.endSession.bodyLimit = n

		return nil
	}
}

// serve answers a request to the end-session endpoint. The order is the guarantee:
//
//  1. no answer may be cached, whatever follows, the chain's error handling included;
//  2. a method it does not serve, and a request not made over TLS, are refused with nothing read
//     from them;
//  3. the source is asked before anything else is read, so a throttled source costs no parsing, no
//     signature check and no store write;
//  4. the provider judges the request. A refusal goes to the chain's error handling, with no
//     Location, as RP-Initiated Logout section 4 forbids redirecting one; anything else is a 303.
//
// A form POST sent across sites carries no SameSite=Lax cookie, so it never matches the browser's
// session and always asks. The GET a relying party's redirect makes does carry it.
func (g *oidcEndSessionGroup) serve(ex *Exchange, _ Next) error {
	setOIDCNoStore(ex.Writer)

	method := ex.Request.Method()
	if method != http.MethodGet && method != http.MethodPost {
		ex.Writer.SetHeader("Allow", http.MethodGet+", "+http.MethodPost)
		ex.Writer.WriteHeader(http.StatusMethodNotAllowed)

		return nil
	}

	if !ex.Request.Secure() && !g.op.plainHTTPAllowed() {
		return ErrOIDCInvalidEndSession
	}

	src, ok := g.throttle.admit(ex, g.op)
	if !ok {
		return ErrOIDCThrottled
	}

	params, err := readOIDCAuthorizeParams(ex.Request, g.bodyLimit)
	if err != nil {
		if errors.Is(err, ErrOIDCInvalidAuthorization) {
			return ErrOIDCInvalidEndSession
		}

		return err
	}

	ctx := ex.Context()

	presented, _ := ex.Request.Cookie(oidcCookieName(g.op.provider, OIDCFlowCookie))
	browser, _ := ex.Request.Cookie(oidcCookieName(g.op.provider, OIDCBrowserSessionCookie))

	res, err := g.op.provider.EndSession(ctx, oidcprovider.EndSessionInput{
		Params:               params,
		FlowSecret:           presented,
		BrowserSessionSecret: browser,
	})
	if err != nil {
		if errors.Is(err, oidcprovider.ErrInvalidEndSession) {
			g.throttle.charge(ctx, src)

			return ErrOIDCInvalidEndSession
		}

		return err
	}

	if res.FlowSecret != "" {
		g.throttle.charge(ctx, src)

		if res.FlowSecret != presented {
			setOIDCCookie(ex.Writer, g.op.provider, OIDCFlowCookie, res.FlowSecret)
		}
	}

	if err := g.op.finishLogout(ex, res.Ended, res.User); err != nil {
		return err
	}

	ex.Writer.SetHeader("Location", res.Location)
	ex.Writer.WriteHeader(http.StatusSeeOther)

	return nil
}

// finishLogout does what the chain owes a sign-in whose grants the provider has ended: its first-party
// sessions go, then its browser session, and only then the cookie. The browser session is what lets
// the browser ask again, so it goes last, and a store failing anywhere here answers an error and leaves
// the browser that session and its cookie: asking again finishes the end, and RP-Initiated Logout
// section 2 is met by a success that means it.
//
// The end is reported as a logout's is, and only for a family this deleted: one already gone was
// ended by something else, which reported it. The report comes once the browser session has been tried,
// so that no sink holds that, and whatever became of it, so that a retry, finding the family gone, does
// not lose it.
func (op *oidcEndpoints) finishLogout(ex *Exchange, ended *oidcprovider.SignInSelector, user identity.UserID) error {
	if ended == nil {
		return nil
	}

	ctx := ex.Context()

	// Detached so a client hanging up cannot leave the family live; WithoutCancel keeps the
	// context's values, so a consumer's transaction is still joined.
	n, err := op.sessions.RevokeFamily(context.WithoutCancel(ctx), ended.Family)
	if err != nil && !errors.Is(err, session.ErrNotFound) {
		return err
	}

	deleted := err == nil && n > 0

	_, endErr := op.provider.EndSignIn(ctx, *ended)

	if deleted {
		for _, name := range []string{event.SessionLogout, event.AuthnTokenRevoked} {
			emitEvent(ctx, event.Event{Name: name, Outcome: event.OutcomeSuccess, User: user})
		}
	}

	if endErr != nil {
		return endErr
	}

	if op.provider.BrowserSessionsEnabled() {
		clearOIDCCookie(ex.Writer, op.provider, OIDCBrowserSessionCookie)
	}

	return nil
}

// clearOIDCCookie deletes one of p's cookies, with the attributes setOIDCCookie gave it, so that
// every browser matches it.
func clearOIDCCookie(w ResponseWriter, p *oidcprovider.Provider, name string) {
	named := oidcCookieName(p, name)

	w.SetCookie(&Cookie{
		Name:     named,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   named == name,
		SameSite: http.SameSiteLaxMode,
	})
}
