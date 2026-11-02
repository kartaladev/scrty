package httpsec

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/origin"
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
	// Token is the access token issued for the new session. With
	// EnableSessionBearer on it is the session's identifier, the session
	// reference, rather than a signed token.
	Token string

	// Session is the session the redemption opened.
	Session *session.Session

	// TokenType is how Token is presented: TokenTypeDPoP when the
	// redemption carried a DPoP proof and Token is bound to its key,
	// TokenTypeBearer otherwise.
	TokenType TokenType

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
//
// The default is the *magiclink.Links given to EnableMagicLink, which runs
// every check before it consumes the link. A replacement takes on that
// contract: it must run the checks it is handed, against the user it will
// return and that user's password-change time, return the first check's error
// unchanged, and consume the link only after every check passed.
//
// The login completion step reuses the post-authentication decision the
// endpoint's own check made before the link was spent; it does not evaluate
// the post-authentication policies a second time after the link is spent, so
// a policy lookup failure never spends it. That decision is only reused for
// the login it was made about. After a replacement reports success, the
// endpoint refuses the request with policy.ErrDenied, and establishes
// no session, when that check never ran, or when the replacement returns a
// user with a different reference (identity.Principal.ID) or a
// password-change time that is not the same instant as the one the check was
// handed. The comparison is not deep equality: the same user loaded again, with
// the same instant in another location, is the same login. A check that ran
// and denied refuses with the policy's own reason.
//
// The last check the endpoint hands over builds the session and issues its
// credential, storing nothing, so a credential that cannot be issued is a
// dependency failure that leaves the link redeemable and is not counted
// against the source. The session is stored only after the replacement
// returns, so a redemption that loses the consume to a racing one stores
// nothing for the credential it issued. A replacement that runs the checks
// more than once issues once.
//
// The last check the endpoint hands over is the one that issues, and the
// endpoint holds a replacement to that order as a limit of this port, not a
// convention. A replacement that skips the issuing check, runs the checks out
// of order, or runs a check again for another login after the credential was
// issued is refused with policy.ErrDenied and stores no session: the issuing
// check refuses a second login itself, and the endpoint refuses a redemption
// whose decision no longer names the login that was issued for. The refusal
// comes after the replacement has consumed the link, so it spends the link
// and stores nothing. Running the checks again for the same login is fine.
//
// What the endpoint cannot do is un-spend a link a replacement consumed before
// it was refused.
type Redeemer interface {
	Redeem(
		ctx context.Context,
		token, bindingNonce string,
		checks ...magiclink.Check,
	) (magiclink.Redemption, error)
}

// magicLinkInterceptor answers both magic-link endpoints.
type magicLinkInterceptor struct {
	manager  *magiclink.Links
	redeemer Redeemer
	respond  MagicLinkResponder
	sessions *session.Sessions
	tokens   token.Generator
	checks   []magiclink.Check

	// issue issues the redeemed link's credential as the chain's bearer mode
	// decides, settled once every option has been applied.
	issue credentialIssuer

	engine  *policy.Engine
	log     *slog.Logger
	sampler *logsample.Sampler
	guard   sourceGuard

	// enrolmentLifetime is how long a session the login tail marks for an
	// enrolment challenge may live, handed over by wire.
	enrolmentLifetime time.Duration

	// enforced holds the challenge kinds something on the chain enforces,
	// handed over by wire; a raised kind outside it refuses the request.
	enforced map[policy.ChallengeKind]bool

	// challengeMethods looks up the methods a raised challenge offers
	// (Chain.challengeMethods), before the login's session is created.
	challengeMethods challengeMethodsFunc

	// cancelHeld cancels the user's held account recoveries at login, set at
	// assembly when the chain's recovery may hold one, and nil otherwise.
	cancelHeld heldRecoveryCanceller

	// csrfToken is whether the sign-ins this first factor makes carry a CSRF
	// token, decided when the chain is built (config.wireCSRF).
	csrfToken bool

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

	// automation is the automation-challenge gate when it was selected for the
	// link request, settled at assembly, and nil otherwise.
	automation *challengeGate
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

	if c.sessionBearer {
		if err := checkTokenGenerator(c, option, "WithMagicLinkTokens", i.tokens); err != nil {
			return err
		}
	} else {
		if i.tokens == nil {
			return newConfigError("%s needs a token generator: a redeemed link opens a session, "+
				"and a caller with no credential for it could not use it (WithMagicLinkTokens)",
				option)
		}

		if err := checkBindingGenerator(c, option, "WithMagicLinkTokens", i.tokens); err != nil {
			return err
		}
	}

	i.issue = c.credentialIssuer(i.tokens)

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
	i.enrolmentLifetime = c.enrolmentLifetime
	i.enforced = c.enforced
	i.challengeMethods = c.challengeMethods
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
		"WithMagicLinkAllowedRedirects", "WithMagicLinkAllowedOrigins")
	if err != nil {
		return newConfigError("EnableMagicLink was given a redirect target it cannot use: %s", err)
	}

	i.redirects = allow

	if err := checkCookieTTL("EnableMagicLink", "the magic link's lifetime", i.manager.TTL(),
		i.manager.BindingEnabled()); err != nil {
		return err
	}

	guard, err := c.resolveSourceGuard("EnableMagicLink", magicLinkFlow, i.limiter,
		defaultMagicLinkFailureLimit, defaultMagicLinkFailureWindow, c.refusalInterval)
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
// answered here. The one exception is an automation challenge
// (EnableAutomationChallenge) that refuses or fails: it is answered before the
// manager looks the address up, so it says nothing about one.
func (i *magicLinkInterceptor) request(ex *Exchange) error {
	address, next := i.readRequest(ex.Request)

	// Before the manager looks the address up or sends anything. The request
	// endpoint has no source limit, so a refusal is charged to nothing; the
	// source signal reads the redemption guard, the only one the magic link
	// counts failures in. No lockout counts failures by address, so no
	// identifier is read.
	if err := i.automation.ask(ex.Context(), ex.Request, challengeQuery{
		flow:     ChallengeFlowMagicLinkRequest,
		source:   i.guard,
		clientIP: ex.Request.ClientIP(),
	}); err != nil {
		return err
	}

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

// flushRefusalLogs reports what the redemption source guard is holding back.
func (i *magicLinkInterceptor) flushRefusalLogs() error {
	if i.guard != nil {
		i.guard.Flush()
	}

	return nil
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

	// The proof is judged before the link is redeemed, so a bad one leaves
	// the link unspent. An invalid proof is charged against the source as a
	// redemption carrying no usable token is; the nonce round trip and a
	// failure of the replay store or nonce cipher are not.
	binding, err := issuingBinding(ctx, ex.dpop(), ex.certBinding(), ex.Request)
	if err != nil {
		if chargesProofRefusal(err) {
			recordSourceFailure(ctx, i.guard, src)
		}

		return err
	}

	token, next := i.readConsume(ex.Request)

	// Read only when the manager binds links. Presenting a cookie to a
	// redemption that ignores it would be harmless, but reading one the
	// manager never set would read as a binding the deployment does not have.
	var nonce string
	if i.manager.BindingEnabled() {
		nonce, _ = ex.Request.Cookie(i.cookieName)
	}

	check, out := redemptionPolicyCheck(i.engine, i.enforced, i.challengeMethods, factor.MagicLink, i.now)

	// Built and issued inside the checks, after every refusal check has
	// passed and before the redeemer consumes the link, so a credential that
	// cannot be issued leaves the link redeemable. The session is stored only
	// once the link is spent, below.
	login := newRedemptionLogin(loginTailDeps{
		engine:            i.engine,
		sessions:          i.sessions,
		tokens:            i.tokens,
		issue:             i.issue,
		enrolmentLifetime: i.enrolmentLifetime,
		enforced:          i.enforced,
		challengeMethods:  i.challengeMethods,
		cancelHeld:        i.cancelHeld,
		csrfToken:         i.csrfToken,
		binding:           binding,
	}, out)

	// The policy check runs first and the consumer's own follow, in the order
	// they were registered, and the issuing step last: magiclink stops at the
	// first refusal, so a login the policy denies never reaches a consumer's
	// check, and a login any check refused is never issued for.
	checks := make([]magiclink.Check, 0, 2+len(i.checks))
	checks = append(checks, check)
	checks = append(checks, wrapChecks(i.checks, out)...)
	checks = append(checks, func(ctx context.Context, p identity.Principal, passwordChangedAt time.Time) error {
		return login.issue(ctx, postAuthenticationInput(&p, factor.MagicLink, "", passwordChangedAt, i.now()))
	})

	redemption, err := i.redeemer.Redeem(ctx, token, nonce, checks...)
	if err != nil {
		if countsAgainstSource(i.countRefusals, err, out) {
			recordSourceFailure(ctx, i.guard, src)
		}

		// The redeemer's error, unchanged: magiclink already answers every
		// cause with one uniform refusal, a policy or consumer check refusal
		// is the consumer's own to read, and a credential that could not be
		// issued is a dependency failure. Whatever the issuing step built is
		// dropped: it was never stored, so it names nothing.
		return err
	}

	// Checked before anything is stored. A Redeemer is an interface, and an
	// implementation that skipped or discarded the checks has not shown this
	// login is permitted, nor that the login issued for is the one returned.
	if err := guardRedemption(out, redemption.Principal, redemption.PasswordChangedAt); err != nil {
		return err
	}

	issued, err := login.redeemed()
	if err != nil {
		return err
	}

	// Set before the session is stored, so a challenge response carries it
	// too: the URL the browser came from holds the token either way.
	ex.Writer.SetHeader("Referrer-Policy", "no-referrer")

	// The link is spent, so the first factor is proved: the user's held
	// recoveries are cancelled before the session is stored, as completeLogin
	// cancels them for every login. A cancellation that cannot be recorded
	// refuses the login, with the link already spent.
	if err := login.deps.cancelHeldRecoveries(ctx, redemption.Principal.ID); err != nil {
		return err
	}

	tok, err := issued.commit(ex)
	if err != nil {
		return err
	}

	// next is the target the allowlist resolved, never the one the caller
	// submitted: a responder that redirects to it cannot send a caller
	// somewhere the allowlist refused, which is the whole reason the allowlist
	// exists.
	return i.respond(ex, MagicLinkResult{Token: tok, Session: ex.Session, Next: next, TokenType: tokenTypeOf(ex.Session)})
}

// writeMagicLinkResult is the response a redemption succeeds with when the
// consumer supplies no responder: the same members a form login answers
// with, so a client that already reads one reads the other, plus the redirect
// target the allowlist settled on.
//
// The target is in the document rather than a Location header because the
// endpoint answers 200 to a POST the confirmation page made: where to send the
// browser next is that page's decision, and this is the library telling it
// which target survived the allowlist.
func writeMagicLinkResult(ex *Exchange, result MagicLinkResult) error {
	body := magicLinkDocument{
		loginDocument: loginDocument{AccessToken: result.Token, TokenType: result.TokenType},
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
