package httpsec

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/internal/origin"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// The conventions the magic-link endpoints follow when the consumer names
// none. They are constants rather than bare literals so a client, a test or a
// proxy rule naming the same endpoint names the same thing this package does.
const (
	// DefaultMagicLinkRequestPath is where a link is asked for.
	DefaultMagicLinkRequestPath = "/login/magic"

	// DefaultMagicLinkConsumePath is where a link is redeemed.
	DefaultMagicLinkConsumePath = "/login/magic/consume"

	// DefaultBindingCookieName is the cookie the same-device binding travels
	// in.
	DefaultBindingCookieName = "magic_link_binding"

	// DefaultMagicLinkAddressParam is the form field, and JSON member, the
	// submitted address is read from.
	DefaultMagicLinkAddressParam = "email"

	// DefaultMagicLinkNextParam is the form field, and JSON member, the
	// redirect target is read from.
	DefaultMagicLinkNextParam = "next"

	// DefaultMagicLinkTokenParam is the form field the presented token is read
	// from at the consume endpoint.
	DefaultMagicLinkTokenParam = "token"
)

// magicLinkFlow names this flow's rate-limit buckets and sampler keys, so a
// source that exhausts its redemption allowance still has its own allowance at
// every other endpoint.
const magicLinkFlow = "magic-link-redeem"

// The allowance a source gets before redemptions are refused.
const (
	defaultMagicLinkFailureLimit  = 10
	defaultMagicLinkFailureWindow = 15 * time.Minute
)

// MagicLinkResult is what a successful redemption produced, handed to whatever
// writes the response.
type MagicLinkResult struct {
	// Token is the access token issued for the new session.
	Token string

	// Session is the session the redemption opened.
	Session *session.Session

	// Next is the resolved redirect target: an allowlisted entry, or "/". It
	// is never the target the caller submitted, so a responder that redirects
	// to it cannot send a caller somewhere the allowlist refused.
	Next string
}

// MagicLinkResponder writes the response to a successful redemption.
//
// It is called instead of the downstream handler, because the consume endpoint
// is the library's own and the application has no route behind it. An error it
// returns leaves the chain as the request's refusal.
type MagicLinkResponder func(ex *Exchange, result MagicLinkResult) error

// Redeemer is the redemption step, replaceable by a consumer.
type Redeemer interface {
	Redeem(
		ctx context.Context,
		token, bindingNonce string,
		checks ...magiclink.Check,
	) (magiclink.Redemption, error)
}

// magicLinkInterceptor answers both magic-link endpoints.
type magicLinkInterceptor struct {
	manager  *magiclink.Manager
	redeemer Redeemer
	respond  MagicLinkResponder
	sessions *session.Manager
	tokens   token.Generator
	checks   []magiclink.Check

	engine  *policy.Engine
	log     *slog.Logger
	sampler *logsample.Sampler
	guard   sourceGuard

	limiter   ratelimit.Limiter
	redirects *origin.Allowlist

	allowedRedirects []string
	allowedOrigins   []string

	now func() time.Time

	requestPath   string
	consumePath   string
	cookieName    string
	bodyLimit     int64
	countRefusals bool
}

// check reports the wiring faults only the assembled configuration can see:
// two endpoints on one path, and the collaborators a redemption cannot do
// without.
//
// It runs once every option has been applied, so a session manager wired by
// another built-in after EnableMagicLink still counts.
func (i *magicLinkInterceptor) check(c *config, option string) error {
	if i.requestPath == i.consumePath {
		return newConfigError("%s was given one path, %q, for both asking for a link and "+
			"redeeming one, so whichever endpoint matched first would swallow the other",
			option, i.requestPath)
	}

	if i.tokens == nil {
		return newConfigError("%s needs a token generator: a redeemed link opens a session, "+
			"and a caller with no credential for it could not use it (WithMagicLinkTokens)",
			option)
	}

	if i.sessions == nil && c.sessions == nil {
		return newConfigError("%s needs a session manager, and neither WithMagicLinkSessions "+
			"nor any other built-in on this chain supplied one", option)
	}

	return nil
}

// wire takes the settings the chain resolved, once every option has been
// applied, so a logger or an engine wired after EnableMagicLink is still the
// one these endpoints use.
func (i *magicLinkInterceptor) wire(c *Chain) {
	i.engine = c.engine
	i.log = c.logger
	i.sampler = c.sampler
}

// wireMagicLink builds what the magic-link endpoints cannot build until every
// option has been applied: the redirect allowlist, whose entries and declared
// origins arrive through two accumulating options, and the source guard, whose
// limiter and logger are the chain's.
func (c *config) wireMagicLink() error {
	return eachInterceptor(c, func(i *magicLinkInterceptor) error {
		return i.resolve(c)
	})
}

// resolve settles the interceptor's remaining collaborators against the
// assembled configuration.
func (i *magicLinkInterceptor) resolve(c *config) error {
	if i.sessions == nil {
		i.sessions = c.sessions
	}

	if i.redeemer == nil {
		i.redeemer = i.manager
	}

	// internal/origin owns these rules, so the redirect allowlist here and the
	// one a federated login will want cannot drift apart. The option names
	// travel with the lists, because the consumer has to know which of their
	// own settings to change.
	allow, err := origin.NewAllowlist(i.allowedRedirects, i.allowedOrigins,
		"WithAllowedRedirects", "WithAllowedOrigins")
	if err != nil {
		return newConfigError("EnableMagicLink was given a redirect target it cannot use: %s", err)
	}

	i.redirects = allow

	guard, err := c.resolveSourceGuard("EnableMagicLink", magicLinkFlow, i.limiter,
		defaultMagicLinkFailureLimit, defaultMagicLinkFailureWindow)
	if err != nil {
		return err
	}

	i.guard = guard

	return nil
}

// Intercept answers the two magic-link endpoints and passes everything else
// through.
//
// Both are POST-only. A link request changes state — it sends mail — and a
// redemption spends a credential, so neither is something a link, an image tag
// or a mail scanner's prefetch may trigger.
func (i *magicLinkInterceptor) Intercept(ex *Exchange, next Next) error {
	if ex.Request.Method() != http.MethodPost {
		return next(ex)
	}

	switch ex.Request.Path() {
	case i.requestPath:
		return i.request(ex)
	case i.consumePath:
		return i.consume(ex)
	default:
		return next(ex)
	}
}

// request answers a POST to the request path.
//
// It answers identically whatever happened, and never passes the request on: a
// later handler that could see the outcome would be a way to leak it. Every
// branch inside the manager — an unknown address, a disabled user, a store
// outage, a reached issuance limit, a failed send, a link that went out —
// produces this same response, and each cause is logged there rather than
// answered here.
func (i *magicLinkInterceptor) request(ex *Exchange) error {
	address, next := i.readRequest(ex.Request)

	result := i.manager.Request(ex.Context(), address, i.redirects.Resolve(next))

	// Binding is read from the manager, never configured on this interceptor.
	// If the two could be told different things, a deployment could emit
	// cookies for links that carry no binding, or issue bound links nothing
	// ever answers.
	if i.manager.BindingEnabled() {
		// Whatever Request returned, unchanged. With binding on it is always
		// the same length on every branch — the value a link was bound to, or
		// a decoy that binds nothing — so the cookie says nothing about the
		// address. It is empty only when the random source itself failed,
		// which is an outage in which nothing was issued for anybody. There is
		// deliberately no decoy made here: a second generator of binding
		// values could disagree with the one the manager uses, and dead
		// security code is worse than none.
		ex.Writer.SetCookie(&Cookie{
			Name:     i.cookieName,
			Value:    result.BindingNonce,
			Path:     i.consumePath,
			MaxAge:   int(i.manager.TTL().Seconds()),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	// Accepted, with no body. Whether a caller is shown "check your email", and
	// in what shape, is the consumer's decision, and a document invented here
	// would be one they cannot take back. The status and the body are the same
	// for every branch, which is the requirement.
	ex.Writer.WriteHeader(http.StatusAccepted)

	return nil
}

// readRequest reads the submitted address and redirect target out of the body.
//
// Every failure degrades to empty values rather than an error: a different
// answer for a malformed request is still a different answer, and a scanner
// would use it. That includes a body over the bound, which is read under it
// for the same reason an unauthenticated login is.
func (i *magicLinkInterceptor) readRequest(r Request) (address, next string) {
	body, err := r.Body(i.bodyLimit)
	if err != nil {
		return "", ""
	}

	declared := r.Header("Content-Type")

	if declaresForm(declared) {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return "", ""
		}

		return values.Get(DefaultMagicLinkAddressParam), values.Get(DefaultMagicLinkNextParam)
	}

	if len(body) == 0 || !declaresJSON(declared) {
		return "", ""
	}

	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		return "", ""
	}

	address, _ = fields[DefaultMagicLinkAddressParam].(string)
	next, _ = fields[DefaultMagicLinkNextParam].(string)

	return address, next
}

// consume answers a POST to the consume path.
//
// The source is checked before the token is read, so a throttled scanner costs
// one bucket read rather than a store round trip, and a refusal there is the
// same uniform error every other refusal gives: a client must not be able to
// tell a throttled source from a wrong token.
func (i *magicLinkInterceptor) consume(ex *Exchange) error {
	ctx := ex.Context()

	src, err := sourceThrottled(
		ctx, i.guard, ex.Request.ClientIP(), magicLinkFlow, i.sampler, i.log, i.now())
	if err != nil {
		return magiclink.ErrInvalidLink
	}

	token, next := i.readConsume(ex.Request)

	// Read only when the manager binds links. Presenting a cookie to a
	// redemption that ignores it would be harmless, but reading one the
	// manager never set would read as a binding the deployment does not have.
	var nonce string
	if i.manager.BindingEnabled() {
		nonce, _ = ex.Request.Cookie(i.cookieName)
	}

	check, out := redemptionPolicyCheck(i.engine, factor.MagicLink, i.now)

	// The policy check runs first and the consumer's own follow, in the order
	// they were registered: magiclink stops at the first refusal, so a login
	// the policy denies never reaches a consumer's check.
	checks := make([]magiclink.Check, 0, 1+len(i.checks))
	checks = append(checks, check)
	checks = append(checks, wrapChecks(i.checks, out)...)

	redemption, err := i.redeemer.Redeem(ctx, token, nonce, checks...)
	if err != nil {
		if countsAgainstSource(i.countRefusals, err, out) {
			recordSourceFailure(ctx, i.guard, src)
		}

		// The redeemer's error, unchanged: magiclink already answers every
		// cause with one uniform refusal, and a policy or consumer check
		// refusal is the consumer's own to read.
		return err
	}

	// Checked before anything is created. A Redeemer is an interface, and an
	// implementation that skipped or discarded the check has not shown this
	// login is permitted.
	if err := guardRedemption(out); err != nil {
		return err
	}

	// Set before the tail runs, so a challenge response carries it too: the URL
	// the browser came from holds the token either way.
	ex.Writer.SetHeader("Referrer-Policy", "no-referrer")

	tok, err := completeLogin(ex, loginTailDeps{
		engine:   i.engine,
		sessions: i.sessions,
		tokens:   i.tokens,
	}, postAuthenticationInput(
		&redemption.Principal, factor.MagicLink, "", redemption.PasswordChangedAt, i.now()))
	if err != nil {
		return err
	}

	// next is the target the allowlist resolved, never the one the caller
	// submitted: a responder that redirects to it cannot send a caller
	// somewhere the allowlist refused, which is the whole reason the allowlist
	// exists.
	return i.respond(ex, MagicLinkResult{Token: tok, Session: ex.Session, Next: next})
}

// writeMagicLinkResult is the response a redemption succeeds with when the
// consumer supplies no responder: the same three members a form login answers
// with, so a client that already reads one reads the other, plus the redirect
// target the allowlist settled on.
//
// The target is in the document rather than a Location header because the
// endpoint answers 200 to a POST the confirmation page made: where to send the
// browser next is that page's decision, and this is the library telling it
// which target survived the allowlist.
func writeMagicLinkResult(ex *Exchange, result MagicLinkResult) error {
	body := magicLinkDocument{
		loginDocument: loginDocument{AccessToken: result.Token},
		Next:          result.Next,
	}
	if result.Session != nil {
		body.ValidUntil = result.Session.IdleExpiresAt
	}

	return writeSuccessDocument(ex, body)
}

// magicLinkDocument is the default success body. Its member names are the
// documented contract of that default, and it embeds a login's document rather
// than restating it, so the two cannot drift apart.
type magicLinkDocument struct {
	loginDocument

	Next string `json:"next"`
}

// readConsume reads the presented token and the redirect target out of the
// body, and only out of it.
//
// A token is a credential, and a credential accepted from a query string is one
// already written into every access log, proxy log and browser history that saw
// the URL. That is the rule form login applies to a password, and a sign-in
// link is no different.
func (i *magicLinkInterceptor) readConsume(r Request) (token, next string) {
	body, err := r.Body(i.bodyLimit)
	if err != nil || !declaresForm(r.Header("Content-Type")) {
		return "", ""
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", ""
	}

	return values.Get(DefaultMagicLinkTokenParam),
		i.redirects.Resolve(values.Get(DefaultMagicLinkNextParam))
}
