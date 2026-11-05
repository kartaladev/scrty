package httpsec

import (
	"errors"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/signingkey"
)

const optionOIDCProvider = "EnableOIDCProvider"

// The provider's two slots.
const (
	// OrderOIDCProvider is the provider's endpoints that authenticate a request
	// their own way, or not at all: authorization, token, UserInfo, revocation,
	// introspection, metadata, end-session and its confirmation. It is inside
	// CSRF protection and outside Basic, API key and bearer authentication, which
	// would otherwise refuse a client's credentials and access tokens as their own.
	OrderOIDCProvider Order = 250

	// OrderOIDCProviderSession is the provider's endpoints that need a sign-in the
	// chain has judged: the resume and the user's consents. It is inside the
	// bearer and every gate, so a session owing a step is refused as anywhere on
	// the chain, and inside the session-touch step, which records the activity. It
	// is outside the authorization stage, so a consumer's rules do not reach them.
	OrderOIDCProviderSession Order = 850
)

// oidcEndpoints is the provider on the chain: what the options settled, and what
// the endpoints share.
type oidcEndpoints struct {
	provider *oidcprovider.Provider

	prefix    string
	overrides map[OIDCEndpoint]string

	// paths is where each endpoint answers, settled once the options have applied.
	paths [oidcEndpointCount]string

	pagesCarryFrameAncestors bool

	// groups is the endpoint groups, one per file, in the order they are asked.
	groups []oidcEndpointGroup
	// sessions is the manager the chain's bearer resolves sessions through,
	// settled by wireOIDCProvider.
	sessions *session.Sessions
	// log is the chain's logger, handed over when the chain is wired.
	log *slog.Logger
	// now reads the chain's clock.
	now func() time.Time

	// The endpoint groups, each declared in the file that serves it.
	authorize     oidcAuthorizeGroup
	resume        oidcResumeGroup
	token         oidcTokenGroup
	revoke        oidcRevokeGroup
	userinfo      oidcUserInfoGroup
	metadata      oidcMetadataGroup
	endSession    oidcEndSessionGroup
	logoutConfirm oidcLogoutConfirmGroup
	consents      oidcConsentsGroup
}

// newOIDCEndpoints returns the provider's state with its groups bound, and the
// defaults its options replace.
func newOIDCEndpoints(p *oidcprovider.Provider, now func() time.Time) *oidcEndpoints {
	op := &oidcEndpoints{
		provider:  p,
		now:       now,
		prefix:    DefaultOIDCProviderPrefix,
		overrides: map[OIDCEndpoint]string{},
	}

	op.groups = []oidcEndpointGroup{
		&op.authorize, &op.resume, &op.token, &op.revoke, &op.userinfo,
		&op.metadata, &op.endSession, &op.logoutConfirm, &op.consents,
	}

	for _, g := range op.groups {
		g.bind(op)
	}

	return op
}

// oidcHandler is one endpoint's handler. It has the shape of an interceptor, so
// it can pass on a request it does not answer, such as a method it does not serve.
//
// A refusal the protocol lets it answer itself is written to ex.Writer, with nil
// returned. Any other error it returns goes to the chain's error handling, which
// answers StatusForError and no body unless the consumer replaced it.
type oidcHandler func(ex *Exchange, next Next) error

// oidcRoute is a path an endpoint group answers.
type oidcRoute struct {
	path string

	// inner answers at OrderOIDCProviderSession rather than OrderOIDCProvider:
	// behind the bearer and the gates, so the handler reads the sign-in from
	// ex.Session, which the chain has already judged.
	inner bool

	handle oidcHandler
}

// oidcEndpointGroup is the endpoints one file serves. It keeps what those
// endpoints need in its own type, so a group gains a field, an option or a
// limiter without touching what the other groups share.
//
// Embed oidcGroupBase, which supplies everything but routes.
type oidcEndpointGroup interface {
	// bind hands the group the provider's shared state, before any option runs.
	bind(op *oidcEndpoints)

	// routes names the paths the group answers, once the options have settled
	// them. Two routes on one path refuse the chain.
	routes() []oidcRoute

	// settle runs during assembly, once every option has been applied and before
	// CSRF protection reads what it needs: build a source guard here with
	// c.resolveSourceGuard, or register with another feature. An error refuses
	// the chain. op.sessions is set by then.
	settle(c *config) error

	// wire takes what exists only once the chain does. op.log is set by then.
	wire(ch *Chain)

	// flushRefusalLogs reports what the group's samplers hold back, for
	// Chain.FlushRefusalLogs.
	flushRefusalLogs() error
}

// oidcGroupBase is what a group embeds: the provider's shared state, as op, and
// nothing to do at each step until the group declares its own.
type oidcGroupBase struct{ op *oidcEndpoints }

func (b *oidcGroupBase) bind(op *oidcEndpoints) { b.op = op }

func (*oidcGroupBase) settle(*config) error { return nil }

func (*oidcGroupBase) wire(*Chain) {}

func (*oidcGroupBase) flushRefusalLogs() error { return nil }

// oidcRouter answers the routes it holds, and passes on everything else.
type oidcRouter struct {
	routes map[string]oidcHandler
}

// Intercept matches the path exactly. A handler judges the method, because what a
// wrong method is answered with differs by endpoint.
func (r *oidcRouter) Intercept(ex *Exchange, next Next) error {
	if h, ok := r.routes[ex.Request.Path()]; ok {
		return h(ex, next)
	}

	return next(ex)
}

// oidcOuterRouter is the router at OrderOIDCProvider, which also stands for the
// provider's groups when the chain flushes, so each is flushed once.
type oidcOuterRouter struct {
	oidcRouter

	op *oidcEndpoints
}

func (r *oidcOuterRouter) flushRefusalLogs() error {
	var errs []error

	for _, g := range r.op.groups {
		if err := g.flushRefusalLogs(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// wireOIDCProvider settles the provider's groups against the assembled
// configuration, once every option has been applied.
func (c *config) wireOIDCProvider() error {
	op := c.oidcProvider
	if op == nil {
		return nil
	}

	op.sessions = bearerSessions(c)

	for _, g := range op.groups {
		if err := g.settle(c); err != nil {
			return err
		}
	}

	return nil
}

// wire hands the provider and its groups what exists only once the chain does.
func (op *oidcEndpoints) wire(ch *Chain) {
	op.log = ch.logger

	for _, g := range op.groups {
		g.wire(ch)
	}
}

// EnableOIDCProvider puts the OpenID Provider p on the chain. The provider answers
// the authorization code flow; the login and consent pages are the consumer's, and
// resume a parked request through the OIDCResume endpoint (see PendingOIDCRequest,
// and the README's "OpenID Provider").
//
// Defaults, each with what replaces it:
//
//   - Paths: its endpoints under DefaultOIDCProviderPrefix, at the paths the
//     OIDCEndpoint constants give (WithOIDCProviderPrefix, WithOIDCProviderPath).
//   - Cookies: OIDCFlowCookie and OIDCBrowserSessionCookie, HttpOnly, Secure,
//     SameSite=Lax and Path=/. Their names have no override, because the __Host-
//     prefix is what stops another host planting one; they lose it and Secure only
//     under oidcprovider.WithLoopbackHTTPIssuer, where a browser would refuse it.
//   - Browser session: on, which skips the login page for a browser signed in
//     already (oidcprovider.WithoutBrowserSessions turns it off, and fails the Basic
//     OP conformance plan).
//   - Authorization throttle: 300 parked or invalid-client requests per source a
//     minute (WithOIDCAuthorizeLimiter, or the chain's WithRateLimiterFactory).
//   - Resume throttle: 30 unknown handles per source a minute (WithOIDCResumeLimiter,
//     or the chain's WithRateLimiterFactory).
//   - Token throttle: 10 failed client authentications per source in 15 minutes
//     (WithOIDCTokenLimiter, or the chain's WithRateLimiterFactory).
//   - End-session throttle: 300 requests per source a minute that park a logout
//     or are refused; one that ends a sign-in without asking is not counted
//     (WithOIDCEndSessionLimiter, or the chain's WithRateLimiterFactory).
//   - Logout confirmation throttle: 30 unknown handles per source a minute
//     (WithOIDCLogoutConfirmLimiter, or the chain's WithRateLimiterFactory).
//   - Request bodies: DefaultLoginBodyLimit (WithOIDCAuthorizeBodyLimit,
//     WithOIDCResumeBodyLimit, WithOIDCTokenBodyLimit, WithOIDCEndSessionBodyLimit,
//     WithOIDCLogoutConfirmBodyLimit).
//   - Cross-site requests: POST to the authorization, token, revocation,
//     introspection and end-session endpoints skips CSRF protection, at the
//     paths the provider serves them (see "Cross-site requests", below). No
//     option removes it; WithCSRFExemption adds a route, UserInfo's among them.
//
// Every throttle fails closed: a source over its limit, a limiter that cannot answer
// and a source that cannot be attributed are refused alike. The authorization and
// resume endpoints answer ErrOIDCThrottled, 429 with an empty body, because a browser
// is in front of them and a 401 there reads as "sign the user in", which a page may
// answer by repeating the call. So do the end-session endpoint and the logout
// confirmation, which a browser is in front of too. The token endpoints answer invalid_client, which their
// clients are told to expect.
//
// # Cross-site requests
//
// A relying party reaches the authorization, token, revocation, introspection and
// end-session endpoints from its own origin, and a browser marks such a request
// cross-site. With EnableCSRFProtection, POST to each of them is therefore exempt
// from its Fetch Metadata and Origin check, and keeps every other protection the
// chain applies: the endpoint's throttle, its body limit and its client
// authentication. None of them takes a state-changing decision from a cookie alone.
//
// The resume, the logout confirmation and /consents are not exempt. The consent
// stage and the logout confirmation may rest on the provider's browser session, a
// cookie, so a cross-site POST to any of them is refused as ErrCrossSiteRequest
// (403) before its handler runs.
//
// The exemption follows the paths the provider serves (WithOIDCProviderPrefix,
// WithOIDCProviderPath) and compares each exactly, with the path as the client sent
// it: a trailing slash, another case, a dot segment or an escaped spelling such as
// "/oauth2/%74oken" names another route, which is judged as any route is.
//
// UserInfo is not exempt either, though a client may POST its access token there
// (RFC 6750 section 2.2): the token travels in the request and no cookie is
// involved, so a cross-site page cannot make a browser send one on a user's
// behalf, but the Origin check still judges a browser client of another origin.
// Trust that origin through the CORS layer or WithCSRFTrustedOrigins, or exempt the
// route with WithCSRFExemption(http.MethodPost, <the UserInfo path>).
//
// # Logout
//
// The end-session endpoint (OIDCEndSession, "/oauth2/logout" by default) is
// RP-Initiated Logout 1.0: GET or POST, with id_token_hint, post_logout_redirect_uri,
// state and client_id. A valid hint whose sid names the sign-in of the browser's
// own session ends that sign-in without asking, and the answer is a 303 to the
// registered post_logout_redirect_uri (with state), or else to the provider's
// LoggedOutURL. Any other request ends nothing: it is parked under a handle bound to
// the flow cookie, and the answer is a 303 to the provider's LogoutURL with the
// handle as the "req" query parameter. So does every request when the provider is
// built with oidcprovider.WithLogoutConfirmation or WithoutBrowserSessions. A
// request that cannot be judged, or whose hint fails its checks, is refused with
// ErrOIDCInvalidEndSession and never redirected.
//
// The logout page (LogoutURL, the consumer's own, on the issuer's origin) asks the
// user, naming no one, as PendingRequest refuses a logout's handle and RP-Initiated
// Logout section 2 requires the question and not a name. It posts the answer to the
// confirmation endpoint
// (OIDCLogoutConfirm, "/oauth2/logout/confirm") from the same browser, with its
// cookies, as Content-Type application/json:
//
//	{"req": "<the handle>", "confirmed": true}
//
// Anything but an explicit true is a decline, which ends nothing. The answer is
// 200 {"redirect_to": "..."} and the page navigates there: the client's
// post_logout_redirect_uri after a confirmed logout that asked for it, otherwise
// LoggedOutURL. A handle that is unknown, expired, spent, bound to another browser
// or no logout request answers 400 ErrOIDCUnknownHandle alike. The confirmation is
// not exempt from CSRF protection, so a page of another origin cannot post it.
//
// A confirmation ends the sign-in of the browser's own session, whichever sign-in
// the request's hint named. Ending a sign-in revokes the grants that do not outlive
// it (those without offline access) and tells each client that registered a
// back-channel logout URI, then deletes its first-party sessions, then its browser
// session, clearing the cookie.
//
// A retry behaves as follows. The handle is spent last of all, and the browser
// session goes after everything but the handle, because it is what lets the browser
// ask again. A failure anywhere (a store outage, answered as the chain's error
// handling does, a 500 by default) leaves the browser its session, its cookie and the
// handle, and posting the same answer again, or asking again at end-session, finishes
// the logout and tells no client twice. While a logout is failing that browser session
// stays usable, and nothing falls back on a hint or a first-party session to finish,
// which would let an ID token's holder end a sign-in from another browser. After a
// success the same post is an unknown handle, 400, and only unknown handles count
// against the confirmation's throttle.
//
// # Consents
//
// The user's allowed applications are listed at OIDCConsents ("/oauth2/consents"):
// GET answers a JSON list of {client_id, client_name, scopes, offline_access,
// last_given_at}, of the signed-in caller's own consents and no one else's. DELETE
// at the same path followed by "/" and a client's identifier forgets the consent
// and revokes the caller's grants and outstanding codes of that client, offline
// access included, so the next authorization asks again; a client the caller
// holds neither a consent nor a grant of answers ErrOIDCForeignConsent (404). Both
// need a full session, answer behind the bearer and the gates, are never cached,
// and refuse a cross-site state-changing request like the resume does. The group answers
// every path below the list's, so no endpoint of the chain's may lie there; New
// refuses one that does.
//
// # What revokes grants
//
// A grant outlives a sign-in only when it holds offline access. Each event below
// has a default and an option that keeps the grants instead, and an option
// naming a provider the chain supplies:
//
//   - A sign-in's end through any session manager on the chain (logout, end-session,
//     session management, a deletion) ends the grants that gave no offline access.
//     There is no option to keep these: it is what a sign-in's end means.
//   - Session management's "end every other sign-in" revokes every grant, offline
//     access included, when the request's body is {"revoke_application_access":true}.
//     Default: not revoked.
//   - An account recovery revokes all the user's grants. Default: revoked, through
//     the chain's provider. recovery.WithoutRecoveryGrantRevocation keeps them;
//     recovery.WithGrantRevoker names another revoker.
//   - An MFA enrolment reset (mfa.ResetEnrolment) revokes all the user's grants when
//     ResetDeps.Grants is given. Default: revoked then; mfa.WithoutResetGrantRevocation
//     keeps them.
//   - A suspected passkey clone revokes them when the manager is built with
//     passkey.WithGrantRevoker(provider). There is no default: a chain with a
//     provider and EnablePasskeys refuses a manager given neither that nor
//     passkey.WithoutCloneGrantRevocation, which keeps them.
//   - A password change keeps them. Default: kept. WithPasswordChangeGrantRevocation
//     revokes them all before the new password is written, and fails the change
//     when the revocation fails.
//
// A passkey manager takes a session manager, not a store: passkey.Deps.Sessions
// must report whether its ends reach the provider, which a bare session.Store
// cannot. The manager given to EnablePasskeys must be built over a *session.Sessions
// built with session.WithEndObserver(p), or New refuses the chain, unless the manager
// ends no session at all: passkey.WithoutSessionRevocationOnRemoval and
// passkey.WithoutSessionRevocationOnClone both given.
//
// A session manager's report of an end, which nothing retries, that the provider could
// not carry through to its grants is logged and reported as the event
// scrty_grant_end_failed, from outside the end's path. A logout the browser asked for
// reports no such thing: it answers an error, and asking again finishes it.
//
// # The provider's lifecycle
//
// The chain neither starts nor stops p. oidcprovider.Provider.Start is optional and
// launches nothing, because back-channel delivery starts itself at the first ended
// sign-in. Call oidcprovider.Provider.Shutdown when the application stops, which is
// what ends that delivery; a provider that has delivered nothing has nothing to end.
//
// # What refuses the chain
//
// A chain that could not serve the provider correctly does not build. Each of
// these is a configuration error naming this option:
//
//   - no bearer mode, because a resume needs a sign-in credential;
//   - no EnableJWKSEndpoint, or one given a *signingkey.Keys other than the
//     *signingkey.Keys the provider signs with. Only two of them can be told apart:
//     a wrapper on either side may hold the very keys the other publishes, and
//     builds;
//   - enabling it twice;
//   - two of its paths equal, or one equal to, or under a prefix claimed by, another
//     endpoint of the chain: the login, logout, key set, session renewal, session
//     management, password change, recovery, passkey, MFA, re-authentication,
//     magic-link and OIDC login endpoints;
//   - a session manager on the chain that does not report sign-in ends to p
//     (session.WithEndObserver), because grants would then outlive a logout. The
//     one a passkey manager was built over is among them;
//   - an endpoint of the chain's under the consents path, which answers every
//     path below it;
//   - oidcprovider.WithDPoP disagreeing with EnableDPoP;
//   - an oidcprovider.WithAssertionTokenEndpoint audience other than the public URL
//     of the token endpoint (see the issuer's path, below);
//   - a client requiring DPoP while EnableDPoP is off, or one requiring a certificate
//     binding while EnableCertificateBinding is off. A client of the consumer's own
//     registry cannot be listed here, and is judged as it is read;
//   - no EnableCSRFProtection while the provider keeps a browser session, which
//     oidcprovider.WithoutBrowserSessions turns off;
//   - no EnableSecurityHeaders, or security headers whose document profile does not
//     forbid framing: no Content-Security-Policy (removed, or only reported), no
//     frame-ancestors directive, or one naming any source but 'none', 'self'
//     (in any case) and named https origins such as https://ext.example.org:8000.
//     A wildcard source, a scheme-only source, a wildcard host and an http origin
//     are refused. A policy set with WithHeader is read from its text.
//     WithOIDCPagesCarryFrameAncestors states the consumer's pages protect
//     themselves instead. A route-matched profile (WithHeaderProfile) is chosen
//     per request and cannot be seen at construction, so only the document
//     profile is judged;
//   - a path or prefix that needs escaping in a URL path, such as one holding a
//     space, "?", "#" or "%", because it could not be published and compared
//     unescaped.
//
// # The issuer's path
//
// The issuer states the public URL, and the path the chain serves is planned
// apart from it, with no option of its own. An endpoint reached at the issuer's
// path plus its served path, behind a router that strips the issuer's path (such
// as http.StripPrefix("/auth", chain.Middleware()(next)) for the issuer
// https://id.example.com/auth), is published at that public URL. A served path
// already at or under the issuer's path is taken to be public as it stands.
//
// At construction a chain cannot tell whether a router strips the prefix, so a
// chain mounted without stripping must include the issuer's path in its prefix
// (WithOIDCProviderPrefix("/auth/oauth2")); otherwise the published URLs do not
// reach it.
//
// # What the resume endpoint reads
//
// The sign-in is read from the Authorization header, once, and nowhere else. A session
// that a consumer's interceptor publishes from the query, a cookie or a header of its
// own does not resume, even when the interceptor records the credential with
// Exchange.RecordPresentedToken: recording says which credential authenticated, not
// where it was presented. A consumer's own bearer reaches the endpoint by reading the
// Authorization header. A consent stage may stand on the browser session's cookie
// alone, as that session is the provider's own.
func EnableOIDCProvider(p *oidcprovider.Provider, opts ...OIDCProviderOption) Option {
	return func(c *config) error {
		if err := requireDep(optionOIDCProvider, "provider", p); err != nil {
			return err
		}

		if c.oidcProvider != nil {
			return newConfigError("%s was given twice; one chain has one provider", optionOIDCProvider)
		}

		op := newOIDCEndpoints(p, c.now)

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(op); err != nil {
				return err
			}
		}

		if err := op.settlePaths(); err != nil {
			return err
		}

		outer, inner, err := op.routers()
		if err != nil {
			return err
		}

		c.oidcProvider = op
		c.register(outer, OrderOIDCProvider)
		c.register(inner, OrderOIDCProviderSession)
		c.wire(op.wire)

		// The token endpoint and UserInfo verify bound credentials, so DPoP has
		// something to verify for on a chain with only the provider.
		c.bindingVerifiers = append(c.bindingVerifiers, optionOIDCProvider)

		c.enable(optionOIDCProvider, func() error { return op.check(c) })
		c.checkAfterWiring(func() error { return op.checkReporting(c) })

		return nil
	}
}

// settlePaths works out where each endpoint answers, and refuses two on one path.
func (op *oidcEndpoints) settlePaths() error {
	taken := make(map[string]OIDCEndpoint, oidcEndpointCount)

	for e := range oidcEndpointCount {
		path, ok := op.overrides[e]
		if !ok {
			path = op.prefix + oidcEndpointNames[e].suffix
		}

		if other, clash := taken[path]; clash {
			return newConfigError("%s serves both %s and %s on %q; give each its own path",
				optionOIDCProvider, other, e, path)
		}

		taken[path] = e
		op.paths[e] = path
	}

	return nil
}

// routers gathers each group's routes into the two slots, and refuses two routes
// on one path, a group's own included.
func (op *oidcEndpoints) routers() (*oidcOuterRouter, *oidcRouter, error) {
	outer := &oidcOuterRouter{oidcRouter: oidcRouter{routes: map[string]oidcHandler{}}, op: op}
	inner := &oidcRouter{routes: map[string]oidcHandler{}}

	for _, g := range op.groups {
		for _, route := range g.routes() {
			_, atOuter := outer.routes[route.path]
			_, atInner := inner.routes[route.path]
			if atOuter || atInner {
				return nil, nil, newConfigError("%s has two endpoints on %q; give each its own path",
					optionOIDCProvider, route.path)
			}

			if route.inner {
				inner.routes[route.path] = route.handle
			} else {
				outer.routes[route.path] = route.handle
			}
		}
	}

	return outer, inner, nil
}

// check is what can be judged once every option has been applied.
func (op *oidcEndpoints) check(c *config) error {
	for _, check := range []func(*config) error{
		op.checkBearer,
		op.checkJWKS,
		op.checkCollisions,
		op.checkDPoP,
		op.checkBindings,
		op.checkCSRF,
		op.checkAssertionEndpoint,
		op.checkFrameAncestors,
	} {
		if err := check(c); err != nil {
			return err
		}
	}

	return nil
}

// hasInterceptor reports whether an interceptor of type T is registered.
func hasInterceptor[T any](c *config) bool {
	return slices.ContainsFunc(c.registrations, func(r registration) bool {
		_, ok := r.interceptor.(T)

		return ok
	})
}

// findInterceptor returns the first registered interceptor of type T.
func findInterceptor[T any](c *config) (T, bool) {
	for _, r := range c.registrations {
		if v, ok := r.interceptor.(T); ok {
			return v, true
		}
	}

	var zero T

	return zero, false
}

// checkBearer requires a bearer mode, whichever one: the resume is how a sign-in
// reaches the provider, and it reads the credential only through one.
func (op *oidcEndpoints) checkBearer(c *config) error {
	if !hasInterceptor[*bearerToken](c) && !hasInterceptor[*sessionBearer](c) {
		return newConfigError("%s needs a bearer mode, because a resume needs a sign-in credential: "+
			"enable EnableSessionBearer or EnableBearerToken", optionOIDCProvider)
	}

	return nil
}

// checkJWKS requires the key set endpoint, and refuses one that publishes other
// keys than the provider signs with, wherever that can be known.
func (op *oidcEndpoints) checkJWKS(c *config) error {
	var endpoints int

	err := eachInterceptor(c, func(j *jwksEndpoint) error {
		endpoints++

		// Only two managers can be told apart: a wrapper on either side may hold
		// the very keys the other publishes.
		published, ok := j.keys.(*signingkey.Keys)
		if signs := op.provider.SigningManager(); ok && signs != nil && signs != published {
			return newConfigError("%s signs with other keys than EnableJWKSEndpoint publishes, so no "+
				"client could verify what the provider issues: give both the same manager",
				optionOIDCProvider)
		}

		return nil
	})
	if err != nil {
		return err
	}

	if endpoints == 0 {
		return newConfigError("%s needs EnableJWKSEndpoint, because clients verify what the provider "+
			"issues with the keys it publishes", optionOIDCProvider)
	}

	return nil
}

// checkCollisions refuses a provider path another endpoint of the chain answers:
// whichever matched first would swallow the other.
func (op *oidcEndpoints) checkCollisions(c *config) error {
	taken := c.oidcForeignPaths()
	prefixes := c.oidcForeignPrefixes()

	for _, g := range op.groups {
		for _, route := range g.routes() {
			if other, ok := taken[route.path]; ok {
				return newConfigError("%s answers on %q, which is already %s; whichever endpoint matched "+
					"first would swallow the other", optionOIDCProvider, route.path, other)
			}

			for _, prefix := range prefixes {
				if underPrefix(route.path, prefix) {
					return newConfigError("%s answers on %q, which falls under the prefix %q of another endpoint",
						optionOIDCProvider, route.path, prefix)
				}
			}
		}
	}

	return op.checkConsentSubtree(taken, prefixes)
}

// checkConsentSubtree refuses a chain endpoint under the consents path. The consents group answers
// every path below the list's, one client each, ahead of the application and of those endpoints,
// so an endpoint of the chain's there would never be reached.
func (op *oidcEndpoints) checkConsentSubtree(taken map[string]string, prefixes []string) error {
	below := strings.TrimSuffix(op.paths[OIDCConsents], "/") + "/"

	for _, path := range slices.Sorted(maps.Keys(taken)) {
		if strings.HasPrefix(path, below) {
			return newConfigError("%s serves %s on %q, under %q, where %s answers every path for a client's consent; "+
				"move it out of that subtree", optionOIDCProvider, taken[path], path, below, OIDCConsents)
		}
	}

	for _, prefix := range prefixes {
		if strings.HasPrefix(prefix, below) {
			return newConfigError("%s serves an endpoint of the chain's on %q, under %q, where %s answers "+
				"every path for a client's consent; move it out of that subtree", optionOIDCProvider, prefix, below, OIDCConsents)
		}
	}

	return nil
}

// oidcForeignPaths is the exact paths of the chain's other endpoints, and what
// each is.
func (c *config) oidcForeignPaths() map[string]string {
	taken := map[string]string{}

	if l := c.formLogin(); l != nil {
		taken[l.path] = "the login path"
	}

	if c.logoutPath != "" {
		taken[c.logoutPath] = "the logout path"
	}

	_ = eachInterceptor(c, func(j *jwksEndpoint) error {
		taken[j.path] = "the key set path"

		return nil
	})
	_ = eachInterceptor(c, func(r *sessionRenewal) error {
		taken[r.path] = "the session renewal path"

		return nil
	})
	_ = eachInterceptor(c, func(g *passwordChangeGate) error {
		if g.change != nil {
			taken[g.path] = "the password-change resolve path"
		}

		return nil
	})
	_ = eachInterceptor(c, func(i *recoveryInterceptor) error {
		for _, r := range i.endpointPaths() {
			taken[r.path] = "the recovery " + r.name + " path"
		}

		return nil
	})

	if p := c.passkeysOf(); p != nil {
		for _, e := range p.paths() {
			taken[e.path] = "the passkey " + e.name + " path"
		}
	}

	if m := c.mfaOf(); m != nil && m.listing != nil {
		taken[m.listing.path] = "the MFA method listing path"
	}

	_ = eachInterceptor(c, func(l *magicLinkInterceptor) error {
		taken[l.requestPath] = "the magic-link request path"
		taken[l.consumePath] = "the magic-link consume path"

		return nil
	})
	_ = eachInterceptor(c, func(o *oidcInterceptor) error {
		if o.handoffs != nil || o.handoffRedeemerSet {
			taken[o.handoffPath] = "the OIDC login handoff path"
		}

		return nil
	})
	_ = eachInterceptor(c, func(i *reauthInterceptor) error {
		p := i.paths()
		taken[p.methods] = "the re-authentication listing path"
		taken[p.password] = "the re-authentication password path"

		return nil
	})

	return taken
}

// oidcForeignPrefixes is the prefixes other endpoints answer every POST under.
func (c *config) oidcForeignPrefixes() []string {
	var prefixes []string

	if m := c.mfaOf(); m != nil {
		prefixes = append(prefixes, m.verifyPrefix, m.beginPrefix)
	}

	_ = eachInterceptor(c, func(i *enrolmentInterceptor) error {
		prefixes = append(prefixes, i.prefixes()...)

		return nil
	})
	_ = eachInterceptor(c, func(o *oidcInterceptor) error {
		// A prefix written with its trailing slash claims what the slash-free form does.
		for _, prefix := range []string{o.authorizePath, o.callbackPath, o.backchannelPath} {
			prefixes = append(prefixes, strings.TrimRight(prefix, "/"))
		}

		return nil
	})
	_ = eachInterceptor(c, func(i *reauthInterceptor) error {
		p := i.paths()
		prefixes = append(prefixes, p.begin, p.verify)

		return nil
	})
	_ = eachInterceptor(c, func(m *sessionManagement) error {
		prefixes = append(prefixes, m.prefix)

		return nil
	})

	return prefixes
}

// checkDPoP refuses a provider and a chain that disagree about DPoP. The provider
// cannot be changed once built, so the consumer states it there too.
func (op *oidcEndpoints) checkDPoP(c *config) error {
	switch stated := op.provider.DPoPEnabled(); {
	case stated && !c.dpopEnabled:
		return newConfigError("%s was given a provider built with oidcprovider.WithDPoP on a chain "+
			"without EnableDPoP, so no proof would be verified: add EnableDPoP, or remove WithDPoP",
			optionOIDCProvider)
	case !stated && c.dpopEnabled:
		return newConfigError("%s was given a provider built without oidcprovider.WithDPoP on a chain "+
			"with EnableDPoP, so it would refuse every dpop_jkt: add WithDPoP, or remove EnableDPoP",
			optionOIDCProvider)
	}

	return nil
}

// checkBindings refuses a client the chain could not verify. A client requiring
// DPoP needs EnableDPoP to verify the proofs, and one requiring a certificate
// binding needs EnableCertificateBinding, or every token it was issued would be
// refused wherever it was presented. The provider answers only for the clients it
// can list; a client of the consumer's own registry is judged as it is read.
func (op *oidcEndpoints) checkBindings(c *config) error {
	if op.provider.RequiresBinding(oidcprovider.BindingDPoP) && !c.dpopEnabled {
		return newConfigError("%s was given a provider with a client requiring DPoP on a chain without "+
			"EnableDPoP, so no proof would be verified: add EnableDPoP, with oidcprovider.WithDPoP on the "+
			"provider, or drop the client's RequireBinding", optionOIDCProvider)
	}

	if op.provider.RequiresBinding(oidcprovider.BindingMTLS) && c.certBinding == nil {
		return newConfigError("%s was given a provider with a client requiring a certificate binding on a "+
			"chain without EnableCertificateBinding, so no certificate would be verified: add "+
			"EnableCertificateBinding, or drop the client's RequireBinding", optionOIDCProvider)
	}

	return nil
}

// checkCSRF requires CSRF protection while the provider keeps a browser session,
// because the consent stage may then answer from a cookie.
func (op *oidcEndpoints) checkCSRF(c *config) error {
	if !op.provider.BrowserSessionsEnabled() || hasInterceptor[*csrfLayer](c) {
		return nil
	}

	return newConfigError("%s keeps a browser session, whose cookie can answer a consent, so it needs "+
		"EnableCSRFProtection; a provider built with oidcprovider.WithoutBrowserSessions needs none",
		optionOIDCProvider)
}

// checkAssertionEndpoint refuses an assertion audience the token endpoint is not
// served on. The provider has already held it to the issuer's origin, so only its
// path is left to compare, and a client naming it would otherwise be refused at
// every request.
func (op *oidcEndpoints) checkAssertionEndpoint(*config) error {
	endpoint := op.provider.AssertionTokenEndpoint()
	if endpoint == "" {
		return nil
	}

	u, err := url.Parse(endpoint)
	if err != nil || u.EscapedPath() != op.publicPath(op.paths[OIDCToken]) {
		return newConfigError("%s serves the token endpoint at %q, but the provider accepts assertions "+
			"naming %q: state the served URL with oidcprovider.WithAssertionTokenEndpoint",
			optionOIDCProvider, op.publicURL(op.paths[OIDCToken]), endpoint)
	}

	return nil
}

// publicURL is the URL a request is answered at when the chain serves it on
// path served: the issuer's origin, then served when it is at or under the
// issuer's own path, and the issuer's path before it otherwise.
//
// A chain cannot tell at construction whether a router strips the issuer's path
// before it, so this is the rule a consumer follows: the issuer states the public
// URL, and a chain mounted without stripping includes the path in its prefix.
func (op *oidcEndpoints) publicURL(served string) string {
	u, err := url.Parse(op.provider.Issuer())
	if err != nil {
		return served
	}

	return u.Scheme + "://" + u.Host + op.publicPath(served)
}

// publicPath is the path of publicURL, escaped. A served path needs no escaping
// (the options refuse one that does), so it is compared with the issuer's path
// decoded, and either is escaped where it is published.
func (op *oidcEndpoints) publicPath(served string) string {
	u, err := url.Parse(op.provider.Issuer())
	if err != nil {
		return served
	}

	base := strings.TrimRight(u.Path, "/")
	if underPrefix(served, base) {
		return (&url.URL{Path: served}).EscapedPath()
	}

	return (&url.URL{Path: base}).EscapedPath() + served
}

// plainHTTPAllowed reports whether the provider's issuer uses the http scheme,
// which construction permits only for oidcprovider.WithLoopbackHTTPIssuer on a
// loopback host. The endpoints that would otherwise insist on https answer
// plain http then.
func (op *oidcEndpoints) plainHTTPAllowed() bool {
	return issuerIsPlainHTTP(op.provider)
}

// issuerIsPlainHTTP reports whether p's issuer has the http scheme, compared as parsed,
// so that a scheme spelled in capitals is the same one.
func issuerIsPlainHTTP(p *oidcprovider.Provider) bool {
	u, err := url.Parse(p.Issuer())

	return err == nil && u.Scheme == "http"
}

// checkFrameAncestors requires the protection against framing the consumer's
// pages rest on, unless the consumer states those pages carry it themselves.
func (op *oidcEndpoints) checkFrameAncestors(c *config) error {
	if op.pagesCarryFrameAncestors {
		return nil
	}

	if l, ok := findInterceptor[*securityHeaders](c); ok && l.forbidsFraming() {
		return nil
	}

	return newConfigError("%s found that the chain's security headers do not forbid framing, and the "+
		"login and consent pages must not be framed: enable EnableSecurityHeaders with a "+
		"Content-Security-Policy whose frame-ancestors holds only 'none', 'self' or https origins; "+
		"if those pages carry frame-ancestors themselves, say so with "+
		"WithOIDCPagesCarryFrameAncestors", optionOIDCProvider)
}

// checkReporting refuses a session manager that does not report sign-in ends to
// the provider, because grants would then outlive a logout. It asks the manager,
// after the chain's wiring has run, because a manager can gain an observer then.
func (op *oidcEndpoints) checkReporting(c *config) error {
	if slices.ContainsFunc(c.sessionManagers, func(m *session.Sessions) bool {
		return !m.ReportsEndsTo(op.provider)
	}) {
		return newConfigError("%s found a session manager on the chain that does not report sign-in "+
			"ends to the provider, so grants would outlive a logout: build every manager with "+
			"session.WithEndObserver(provider)", optionOIDCProvider)
	}

	// A passkey manager ends sessions through its own manager, which can be a
	// different one from the chain's.
	if p := c.passkeysOf(); p != nil && !p.deps.Passkeys.ReportsEndsTo(op.provider) {
		return newConfigError("%s found the manager given to EnablePasskeys over a session manager that "+
			"does not report sign-in ends to the provider, so grants would outlive a passkey removal: "+
			"build the passkey manager's Deps.Sessions with session.WithEndObserver(provider)", optionOIDCProvider)
	}

	return nil
}
