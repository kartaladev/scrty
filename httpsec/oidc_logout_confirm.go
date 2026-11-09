package httpsec

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
)

// oidcLogoutConfirmFlow names the confirmation's rate-limit buckets and sampler keys.
const oidcLogoutConfirmFlow = "oidc-logout-confirm"

// How many unknown handles one source may present before it is refused unread. They are proposed
// values, those of the resume endpoint, for the same reason: a handle cannot be guessed, so a
// source past them is scanning, and a page's retries and a browser's back button have room.
const (
	defaultOIDCLogoutConfirmLimit  = 30
	defaultOIDCLogoutConfirmWindow = time.Minute
)

// oidcLogoutConfirmGroup serves the logout confirmation. It reads no credential but the
// browser's cookies, so it answers at the provider's outer slot. It stays under CSRF protection,
// unlike end-session, because its answer is what ends a sign-in with nothing else to show for it.
type oidcLogoutConfirmGroup struct {
	oidcGroupBase

	throttle  oidcClientThrottle
	bodyLimit int64
}

// bind takes the provider's state, and the default the options replace.
func (g *oidcLogoutConfirmGroup) bind(op *oidcEndpoints) {
	g.oidcGroupBase.bind(op)
	g.bodyLimit = DefaultLoginBodyLimit
}

func (g *oidcLogoutConfirmGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCLogoutConfirm], handle: g.serve},
	}
}

func (g *oidcLogoutConfirmGroup) settle(c *config) error {
	return g.throttle.settleAt(c, oidcLogoutConfirmFlow, defaultOIDCLogoutConfirmLimit, defaultOIDCLogoutConfirmWindow)
}

func (g *oidcLogoutConfirmGroup) wire(ch *Chain) {
	g.throttle.wire(ch)
}

func (g *oidcLogoutConfirmGroup) flushRefusalLogs() error {
	g.throttle.flush()

	return nil
}

// WithOIDCLogoutConfirmLimiter counts the unknown handles presented at the logout confirmation,
// per source. A source past its limit is refused with ErrOIDCThrottled, which wraps
// ratelimit.ErrThrottled and answers 429, before its handle is looked up. A limiter that cannot
// answer, and a source that cannot be attributed, are refused the same way: the limit fails closed.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under namespace
// "oidc-logout-confirm", or else an in-memory limiter of 30 per source a minute. A deployment of
// more than one replica supplies a factory or a limiter its replicas share, or the limit is per
// process.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it would read as no
// limit while the consumer believed they had replaced one.
func WithOIDCLogoutConfirmLimiter(limiter ratelimit.Limiter) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if err := requireDep("WithOIDCLogoutConfirmLimiter", "limiter", limiter); err != nil {
			return err
		}

		op.logoutConfirm.throttle.limiter = limiter

		return nil
	}
}

// WithOIDCLogoutConfirmBodyLimit reads at most limit bytes of a logout confirmation's body.
//
// Default: DefaultLoginBodyLimit. A body over it answers ErrRequestTooLarge. A limit of zero or
// less is refused, because it would refuse every confirmation.
func WithOIDCLogoutConfirmBodyLimit(limit int64) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if limit <= 0 {
			return newConfigError("WithOIDCLogoutConfirmBodyLimit takes a positive bound, and %d would refuse "+
				"every confirmation", limit)
		}

		op.logoutConfirm.bodyLimit = limit

		return nil
	}
}

// oidcLogoutConfirmRequest is the document a logout page posts: the handle, and whether the user
// said yes. Anything but an explicit yes is a decline, so a page's mistake ends nothing.
type oidcLogoutConfirmRequest struct {
	Handle    string `json:"req"`
	Confirmed bool   `json:"confirmed"`
}

// oidcLogoutConfirmDocument is a successful answer: where the page sends the browser.
type oidcLogoutConfirmDocument struct {
	RedirectTo string `json:"redirect_to"`
}

// serve answers a logout page. The order is the guarantee:
//
//  1. no answer may be cached, whatever follows, the chain's error handling included;
//  2. anything but POST is refused, and so is a request not made over TLS, each with nothing read
//     from it;
//  3. the source is asked before anything else is read, so a throttled source costs no parsing and
//     no handle lookup;
//  4. a body not declared as JSON is refused, which a cross-site form could not send, on top of what
//     CSRF protection judges;
//  5. the provider judges the handle and ends the grants the answer may end, the chain finishes that
//     end, and the handle is spent last of all, so a failure anywhere leaves the page able to answer again.
//
// Only an unknown handle is charged to the source: a failure is no verdict on anyone.
func (g *oidcLogoutConfirmGroup) serve(ex *Exchange, _ Next) error {
	setOIDCNoStore(ex.Writer)

	if ex.Request.Method() != http.MethodPost {
		ex.Writer.SetHeader("Allow", http.MethodPost)
		ex.Writer.WriteHeader(http.StatusMethodNotAllowed)

		return nil
	}

	if !ex.Request.Secure() && !g.op.plainHTTPAllowed() {
		return ErrOIDCUnknownHandle
	}

	src, ok := g.throttle.admit(ex, g.op)
	if !ok {
		return ErrOIDCThrottled
	}

	doc, err := readOIDCLogoutConfirm(ex.Request, g.bodyLimit)
	if err != nil {
		return err
	}

	flow, _ := ex.Request.Cookie(oidcCookieName(g.op.provider, OIDCFlowCookie))
	browser, _ := ex.Request.Cookie(oidcCookieName(g.op.provider, OIDCBrowserSessionCookie))

	ctx := ex.Context()

	res, err := g.op.provider.ConfirmLogout(ctx, doc.Handle, flow, browser, doc.Confirmed)
	if err != nil {
		if errors.Is(err, oidcprovider.ErrUnknownHandle) {
			g.throttle.charge(ctx, src)

			return ErrOIDCUnknownHandle
		}

		return err
	}

	if err := g.op.finishLogout(ex, res.Ended, res.User); err != nil {
		return err
	}

	if res.Ended != nil {
		g.op.provider.SpendLogout(ctx, doc.Handle, flow)
	}

	return writeSuccessDocument(ex, oidcLogoutConfirmDocument{RedirectTo: res.RedirectTo})
}

// readOIDCLogoutConfirm reads the document a page posts. A body that is neither declared as JSON
// nor readable as it names no handle the provider could judge, so it is answered as an unknown one.
func readOIDCLogoutConfirm(r Request, limit int64) (oidcLogoutConfirmRequest, error) {
	body, err := r.Body(limit)
	if err != nil {
		return oidcLogoutConfirmRequest{}, err
	}

	if !declaresJSON(r.Header("Content-Type")) {
		return oidcLogoutConfirmRequest{}, ErrOIDCUnknownHandle
	}

	var doc oidcLogoutConfirmRequest
	if err := json.Unmarshal(body, &doc); err != nil {
		return oidcLogoutConfirmRequest{}, ErrOIDCUnknownHandle
	}

	return doc, nil
}
