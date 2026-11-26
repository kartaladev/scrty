package httpsec

import (
	"errors"
	"net/http"
	"strings"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// DefaultSessionCookieName is the name the cookie session sets and reads its
// cookie under, unless WithSessionCookieName replaces it.
//
// The __Host- prefix makes a browser accept the cookie only when it is set
// Secure, from a secure origin, with Path=/ and no Domain, so a sibling or
// parent domain, or a page served over plain HTTP, cannot plant or overwrite
// it.
const DefaultSessionCookieName = "__Host-scrty-session"

// sessionCookieFlow names the cookie transport's rate-limit namespace and its
// sampler and log keys, so an operator can tell refused cookies from refused
// session references presented in the Authorization header
// (sessionReferenceFlow).
const sessionCookieFlow = "session-cookie"

// The cookie name prefixes a browser enforces (RFC 6265bis section 4.1.3),
// matched without regard to case as browsers match them.
const (
	cookiePrefixHost   = "__Host-"
	cookiePrefixSecure = "__Secure-"
)

// SessionCookieOption configures the cookie session.
type SessionCookieOption func(*sessionCookie) error

// sessionCookie authenticates a session reference a browser presents in an
// HttpOnly cookie, through the same session-reference pipeline the session
// bearer judges the Authorization header by.
type sessionCookie struct {
	sessions *session.Sessions
	users    identity.UserLoader

	// ref is the session-reference pipeline the presented cookie is judged
	// by, its resolution core built by wire.
	ref sessionReference

	name     string
	sameSite http.SameSite
	domain   string

	// delivery is the consumer's SessionDelivery, nil for the default, which
	// sets the cookie itself (credentialDelivery).
	delivery SessionDelivery

	// nextParam is the field a sign-in names its destination in, and
	// redirects the absolute targets the consumer allowed it to be sent to
	// (WithSessionCookieNextParam, WithSessionCookieRedirects).
	nextParam string
	redirects map[string]struct{}

	// persist decides, at each new sign-in, whether its cookie persists
	// (WithSessionCookiePersistence), nil for never.
	persist func(*Exchange) bool

	// unrotated holds a bit, 1<<p, for each RotationPoint p whose rotation
	// WithoutSessionRotation turned off; zero rotates at every one.
	unrotated uint8

	// exempt is what the both-credentials guard lets through, settled at
	// construction (exemptFromCookieGuard); empty on a chain without the
	// OpenID Provider.
	exempt guardExemption
}

// AuthenticatesByCookie marks the cookie session as a CookieAuthenticator, so
// New requires CSRF protection, or its explicit opt-out, beside it.
func (*sessionCookie) AuthenticatesByCookie() {}

// cookie is the session cookie with value, under every attribute the chain
// sets it with. maxAge is read as http.Cookie reads MaxAge: zero sets no
// Max-Age, so the browser keeps the cookie for its session; a negative one
// expires it (Max-Age=0); a positive one keeps it that many seconds. Every
// cookie the chain writes under the session's name, set or expired, comes from
// here, so an expired cookie names the same name, path and domain the browser
// stored it under and does replace it.
func (s *sessionCookie) cookie(value string, maxAge int) *Cookie {
	return &Cookie{
		Name:     s.name,
		Value:    value,
		Path:     "/",
		Domain:   s.domain,
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: s.sameSite,
	}
}

// wireSessionCookie settles the limiter and the source guard against the
// assembled configuration, once every option has been applied.
func (c *config) wireSessionCookie() error {
	return eachInterceptor(c, func(s *sessionCookie) error {
		guard, err := c.resolveSourceGuard("EnableSessionCookie", sessionCookieFlow, s.ref.limiter,
			defaultSessionReferenceFailureLimit, defaultSessionReferenceFailureWindow, c.refusalInterval)
		if err != nil {
			return err
		}

		s.ref.guard = guard

		// Every path is resolved by now, the base path and the provider's
		// overrides included, so the guard's exemption is settled once, here.
		c.exemptFromCookieGuard(s)

		return nil
	})
}

// flushRefusalLogs reports what the source guard is holding back.
func (s *sessionCookie) flushRefusalLogs() error {
	if s.ref.guard != nil {
		s.ref.guard.Flush()
	}

	return nil
}

// wire takes the settings the chain resolved, once every option has been
// applied.
func (s *sessionCookie) wire(c *Chain) {
	s.ref.sampler = c.sampler
	s.ref.log = c.logger
	s.ref.resolver = sessionResolver{
		sessions: s.sessions,
		users:    s.users,
		log:      c.logger,
		cookie:   s,
		phase: perRequestPhase{
			engine:            c.engine,
			sessions:          s.sessions,
			enrolmentLifetime: c.enrolmentLifetime,
			enforced:          c.enforced,
			now:               s.ref.now,
		},
	}
}

// Intercept authenticates the session cookie against a live session and a
// live user. See EnableSessionCookie for what it refuses, and how.
func (s *sessionCookie) Intercept(ex *Exchange, next Next) error {
	presented, claimed := presentedCookie(ex.Request, s.name)
	if !claimed {
		return next(ex)
	}

	// Another authenticator has already accepted a credential the guard
	// (sessionCookieGuard) could not see. The cookie is not read, so that
	// neither credential silently wins and a bad cookie is never passed over:
	// the request is refused, judging neither, so the source is not charged
	// and the cookie is kept.
	if besideAnotherCaller(ex, presented) {
		return errors.Join(ErrAuthenticationRequired, errCookieBesideCaller)
	}

	rejected, err := s.ref.resolve(ex, presented, transportCookie, admitCookieSession)
	if err != nil {
		// Only a cookie the pipeline judged bad is expired. One refused
		// without being judged (its source throttled, the limiter down) or
		// one whose session could not be read for an outage may name a live
		// session, and expiring it would sign out every browser behind a
		// shared address or a failing store. It is set here, before the
		// error is answered, so the answer carries it whoever writes it.
		if rejected {
			ex.Writer.SetCookie(s.cookie("", -1))
		}

		return err
	}

	// Nothing is recorded as presented (Exchange.RecordPresentedToken): what
	// is recorded is what a DPoP proof's ath is judged against at the
	// issuing and continuing endpoints, and the cookie is no access token. A
	// rotation that needs the sign-in reads it from the published session.
	return next(ex)
}

// admitCookieSession is the cookie transport's own check (referenceCheck): it
// adds nothing before the load, and judges the loaded session before its user
// is reloaded or anything is published. The same admit runs at the renewal
// endpoint for a late session let through to it.
func admitCookieSession(*Exchange) (func(*Exchange, *session.Session) (*identity.Details, error), error) {
	return func(ex *Exchange, sess *session.Session) (*identity.Details, error) {
		// A browser cannot hold a DPoP key's proof or present a certificate
		// binding through a cookie, so a session bound to a sender is one
		// whose reference was taken from its sender: it is refused, and
		// charged, as a bound credential presented without its proof is.
		if sess.KeyBinding != (session.KeyBinding{}) {
			return nil, refusedReference(errBoundSessionInCookie)
		}

		if err := CheckCSRFToken(ex, sess); err != nil {
			return nil, csrfAnswer(err)
		}

		return nil, nil //nolint:nilnil // no user was loaded; the core reloads it by the session's reference
	}, nil
}

// errBoundSessionInCookie is the cause a session bound to a sender key is
// refused with when presented in the cookie.
var errBoundSessionInCookie = errors.New("httpsec: a sender-bound session was presented in the session cookie")

// csrfAnswer is the answer to a cookie request CheckCSRFToken failed with err.
// The pipeline reads an error matching ErrAuthenticationRequired as a refusal
// of the reference, charges the source for it and expires the cookie, but
// nobody judged the reference here, so that meaning is taken off err.
//
// A pure refusal, a token source breaking its contract (CSRFTokens.Verify
// refuses with ErrCrossSiteRequest) by returning ErrAuthenticationRequired
// alone, is answered as the cross-site refusal it stands for. An err that
// carries any other cause besides it is that cause's failure: it is returned
// as the other causes alone, so it is answered as a dependency failure, and
// the outage is neither lost nor charged to the source. An err whose causes
// cannot be listed within a bound is answered as a cross-site refusal, the
// safe reading that keeps the cookie and charges nobody.
func csrfAnswer(err error) error {
	if !errors.Is(err, ErrAuthenticationRequired) {
		return err
	}

	budget := csrfCauseBudget
	causes, ok := otherCauses(err, &budget)

	if !ok || len(causes) == 0 {
		return ErrCrossSiteRequest
	}

	rest := errors.Join(causes...)
	if errors.Is(rest, ErrAuthenticationRequired) {
		// A cause that still matches by its own Is method: nothing to keep
		// that the pipeline would not read as a verdict on the reference.
		return ErrCrossSiteRequest
	}

	return rest
}

// csrfCauseBudget bounds how many errors csrfAnswer walks in an error's tree.
const csrfCauseBudget = 64

// otherCauses lists the leaves of err's tree, in order, that are not
// ErrAuthenticationRequired itself. ok is false when the tree is larger than
// budget allows.
func otherCauses(err error, budget *int) (causes []error, ok bool) {
	if *budget--; *budget < 0 {
		return nil, false
	}

	switch u := err.(type) { //nolint:errorlint // the tree is walked on purpose, node by node
	case interface{ Unwrap() []error }:
		for _, child := range u.Unwrap() {
			sub, ok := otherCauses(child, budget)
			if !ok {
				return nil, false
			}

			causes = append(causes, sub...)
		}

		return causes, true
	case interface{ Unwrap() error }:
		if child := u.Unwrap(); child != nil {
			return otherCauses(child, budget)
		}
	}

	if err == ErrAuthenticationRequired { //nolint:errorlint // the sentinel itself, not an error wrapping it
		return nil, true
	}

	return []error{err}, true
}

// presentedCookie reports the value of the one cookie named name the request
// carries, and whether it carries any. Every Cookie header line is read, and
// a request carrying the name more than once claims the cookie with no value
// at all, which the pipeline refuses as malformed: two values are not one
// identifier, and taking either would let whoever planted the other choose
// which session the request runs as.
//
// The header is read here rather than through Request.Cookie, which answers
// the first value only, and drops one it cannot parse: a value no identifier
// has is a claim refused as malformed, not a request carrying no cookie.
func presentedCookie(r Request, name string) (value string, claimed bool) {
	var found int

	for _, line := range r.HeaderValues("Cookie") {
		for pair := range strings.SplitSeq(line, ";") {
			n, v, _ := strings.Cut(strings.TrimSpace(pair), "=")
			if strings.TrimSpace(n) != name {
				continue
			}

			found++
			if found > 1 {
				return "", true
			}

			value = strings.TrimSpace(v)
		}
	}

	return value, found == 1
}

// EnableSessionCookie authenticates browsers by a session cookie: the
// session's own identifier, in an HttpOnly cookie no script can read, judged
// by exactly the rules EnableSessionBearer judges a session reference in the
// Authorization header by.
//
// Default: off; the chain neither reads nor sets the cookie. When enabled, the
// cookie is DefaultSessionCookieName, set with Path=/, Secure, HttpOnly and
// SameSite=Lax, with no Domain and no Max-Age (WithSessionCookieName,
// WithSessionCookieSameSite and WithSessionCookieDomain replace what may be
// replaced, and WithSessionCookiePersistence lets a sign-in's cookie carry a
// Max-Age; Secure, HttpOnly and the path cannot be). It runs at
// OrderBearerToken.
//
// A chain delivers either cookies or tokens: New refuses it together with
// EnableSessionBearer or EnableBearerToken, naming both. A deployment serving
// browsers and native clients builds two chains, the token one under its own
// WithBasePath. It is a CookieAuthenticator, so New also refuses it without
// EnableCSRFProtection or the explicit WithoutCSRFProtection.
//
// Every issuing endpoint on the chain (form login, magic link redemption,
// the federated callback, passwordless passkey login, second-factor
// verification, re-authentication, recovery completion, session renewal)
// takes no token generator: once it has stored the session, it sets the
// cookie to the session's identifier and writes no credential to the body
// or any other header, and a challenge it raises carries the pending session
// and an empty Token. WithSessionDelivery replaces how the cookie is
// written, within that line. The federated login completes in its callback
// (EnableOIDCLogin), so the chain takes no handoff manager.
//
// Unless the endpoint's own responder option replaces it, each answers a
// sign-in by what the request prefers. A form post (a Content-Type of
// application/x-www-form-urlencoded or multipart/form-data), or a request
// whose Accept ranks text/html above application/json, is sent 303 See Other
// to its destination; any other request, a malformed Accept included, is
// answered 200 with {"idle_expires_at": "<RFC 3339>"} and no credential.
// Both are no-store. The destination is the endpoint's own where it has one
// (magic link redemption and the federated callback resolve theirs through
// their own allowlists); otherwise the body's DefaultSessionCookieNextParam
// field or JSON member (WithSessionCookieNextParam), kept only when it is a
// path on this origin or a target allowed by WithSessionCookieRedirects, and
// "/" otherwise. A recovery that reissued the user's saved codes is answered
// with a document carrying them whatever the request prefers, since a
// redirect would lose them.
//
// A request carrying the cookie and an Authorization header, of any scheme or
// value, is refused with ErrAuthenticationRequired at OrderSessionCookieGuard,
// before Basic authentication, the resource server, API keys or the cookie
// session read either. So is a cookie arriving at the cookie session after
// another authenticator has already published a caller for the request,
// through a credential of its own: neither credential silently wins. Neither
// refusal judges the cookie, so the source is not charged and the cookie is
// kept. There is no option to let one credential win.
//
// On a chain that also runs the OpenID Provider (EnableOIDCProvider), which
// then takes the cookie session as the sign-in its inner routes rest on, the
// provider's outer endpoints are exempt from that refusal: authorization,
// token, userinfo, revocation, introspection, end-session and device
// authorization, the OpenID configuration and the authorization-server
// metadata, whatever the method, and the key set (EnableJWKSEndpoint) for GET.
// They authenticate by a credential of their own and never read the session,
// so the cookie a browser sends with a first-party page's call to one of them
// is left unread. The exempt paths are settled at construction, under the base
// path and the provider's path overrides, and match a request's path exactly:
// a trailing slash, a doubled slash, another case or a path below one is not
// exempt. Every other route of the provider (the resume, the cancel, the
// consents, the logout confirmation, the device code entry) stays refused.
//
// A request carrying no cookie of the name passes through untouched. For one
// that carries it, in order:
//
//  1. the source is checked, and one over its allowance (by default 100
//     refused references per minute, WithSessionCookieLimiter), or one the
//     limiter cannot answer for, is refused with ErrAuthenticationRequired
//     before anything else (fail closed);
//  2. a value that is not a well-formed session identifier
//     (session.ValidIdentifier), an empty one, and a request carrying the
//     name more than once, are refused with ErrAuthenticationRequired before
//     any lookup: two values are never resolved to the first or the last;
//  3. the session is loaded by digest, refusing a missing, expired or
//     undecryptable one with ErrAuthenticationRequired, and a superseded one
//     presented after its window with ErrAuthenticationRequired joined to
//     session.ErrReused, by which time its family is revoked. A session
//     bound to a sender (a DPoP key or a certificate) is refused too, since a
//     cookie carries no proof of the key;
//  4. an unsafe request is checked with CheckCSRFToken against the loaded
//     session, before the user is reloaded and before anything is published:
//     one without the sign-in's token is refused with ErrCrossSiteRequest
//     (403), so a disabled user's cross-site request is answered 403, not
//     401;
//  5. the user is reloaded by the session's user reference, refusing a user
//     who is gone, is someone else, or is not active, with
//     ErrAuthenticationRequired;
//  6. the caller and the session are published, and the per-request policy
//     phase runs, as for the session bearer.
//
// The refusals of steps 2, 3 and 5 are charged to the source; a CSRF failure,
// a policy decision about a valid session, a dependency failure (a session,
// user or cipher store outage, answered 500 by default with the cause
// reachable through errors.Is) and a request whose own context ended are not.
// The cookie is never recorded as a presented access token
// (Exchange.RecordPresentedToken): a DPoP proof on a cookie request carries no
// ath.
//
// Refusals are logged and sampled under the flow "session-cookie", apart
// from the session bearer's "session-reference".
func EnableSessionCookie(deps SessionBearerDeps, opts ...SessionCookieOption) Option {
	const option = "EnableSessionCookie"

	return func(c *config) error {
		s := &sessionCookie{
			sessions:  deps.Sessions,
			users:     deps.Users,
			ref:       sessionReference{now: c.now, flow: sessionCookieFlow},
			name:      DefaultSessionCookieName,
			sameSite:  http.SameSiteLaxMode,
			nextParam: DefaultSessionCookieNextParam,
		}

		for _, opt := range opts {
			if opt == nil {
				return newConfigError("%s was given a nil option", option)
			}

			if err := opt(s); err != nil {
				return err
			}
		}

		if err := s.checkAttributes(); err != nil {
			return err
		}

		if hasInterceptor[*sessionCookie](c) {
			return newConfigError("%s was given twice; one chain has one cookie session", option)
		}

		c.sessionCookie = true

		c.enable(option, func() error {
			if hasInterceptor[*sessionBearer](c) {
				return newConfigError("%s and EnableSessionBearer are both enabled; a chain delivers "+
					"either cookies or tokens, so build a second chain under its own WithBasePath for "+
					"the clients that present tokens", option)
			}

			if hasInterceptor[*bearerToken](c) {
				return newConfigError("%s and EnableBearerToken are both enabled; a chain delivers "+
					"either cookies or tokens, so build a second chain under its own WithBasePath for "+
					"the clients that present tokens", option)
			}

			if err := requireDep(option, "session manager", deps.Sessions); err != nil {
				return err
			}

			return requireDep(option, "user loader", deps.Users)
		})

		c.useSessions(deps.Sessions)
		c.wire(s.wire)
		// The renewal endpoint may be enabled after this option, so it is
		// handed to the core once every option has been applied.
		c.wire(func(*Chain) { s.ref.resolver.renewal = c.renewal })
		c.register(s, OrderBearerToken)
		c.register(sessionCookieGuard{cookie: s}, OrderSessionCookieGuard)

		return nil
	}
}

// checkAttributes refuses a cookie a browser would not store as configured,
// or one whose name breaks its own prefix's rules, so a wiring mistake fails
// in New rather than as a sign-in that never sticks.
func (s *sessionCookie) checkAttributes() error {
	if s.domain != "" {
		switch {
		case hasPrefixFold(s.name, cookiePrefixHost):
			return newConfigError("WithSessionCookieDomain was given %q, but the cookie is named %q, and "+
				"a browser refuses a %s cookie that names a Domain; name it with the %s prefix to share it "+
				"across subdomains", s.domain, s.name, cookiePrefixHost, cookiePrefixSecure)
		case !hasPrefixFold(s.name, cookiePrefixSecure):
			return newConfigError("WithSessionCookieDomain was given %q, but the cookie is named %q; a "+
				"cookie shared across subdomains must carry the %s prefix, so that a subdomain serving "+
				"plain HTTP cannot overwrite it", s.domain, s.name, cookiePrefixSecure)
		}
	}

	// The probe is the cookie as it will be written, so a name or domain
	// net/http would refuse, or silently drop when writing it, is refused
	// here.
	if err := s.cookie("probe", 0).Valid(); err != nil {
		return newConfigError("the session cookie (name %q, domain %q) is not one a browser would "+
			"store: %s", s.name, s.domain, err)
	}

	return nil
}

// WithSessionCookieLimiter counts the refused session cookies each source
// presents in limiter.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under
// namespace "session-cookie", or else an in-memory limiter of 100 failures per
// source per minute, used by this flow alone. A deployment running more than
// one replica supplies a factory or a limiter its replicas share.
//
// A source over its limit is refused with ErrAuthenticationRequired before the
// cookie is parsed or looked up, and its cookie is left as it is: the
// browser's session was not judged. A limiter that cannot answer refuses the
// request as well (fail closed). It counts refused references only, as
// WithSessionBearerLimiter does; behind a shared address every client counts
// against one allowance, so configure the framework's trusted-proxy setting.
//
// A nil limiter, including an interface holding a nil pointer, is refused.
func WithSessionCookieLimiter(limiter ratelimit.Limiter) SessionCookieOption {
	return func(s *sessionCookie) error {
		if err := requireDep("WithSessionCookieLimiter", "limiter", limiter); err != nil {
			return err
		}

		s.ref.limiter = limiter

		return nil
	}
}

// WithSessionCookiePersistence asks decide, at every new sign-in on the chain,
// whether that sign-in's cookie persists across browser restarts ("remember
// me"). A chain-wide choice is func(*Exchange) bool { return true }.
//
// Default: no decision, so every session cookie is a browser-session cookie,
// set with no Max-Age and no Expires, which the browser drops when it closes.
//
// decide is asked once per sign-in, on the sign-in's own request, before its
// session is created: form login, magic link redemption, the federated
// callback, passwordless passkey login and recovery completion. It runs on
// the request's goroutine and must not write to the response; a panic in it
// is the consumer's, and nothing is stored. When it returns true the session
// is created with session.WithPersistentCookie in its one creating write, and
// every cookie of that sign-in, the ones re-set by second-factor
// verification, re-authentication, renewal, a role switch and a password
// change included, carries Max-Age: the seconds from the chain's clock to the
// session's absolute deadline, rounded up and at least 1. A rotation asks
// nothing, since the session records the choice.
//
// The line: Max-Age is never set past the absolute deadline the session has,
// or will have once the request's change is saved (a password change that
// ends a recovery gives the session its origin deadline back, and the cookie
// is set for that). A deadline lowered later without a new cookie, for example
// by a per-request policy, leaves the cookie longer-lived than the session,
// and so does a password change that ends a recovery but is refused or fails
// to save: the session keeps its lowered deadline.
// The server's idle and absolute deadlines stay authoritative: it refuses the
// session and expires the cookie, like any other that has ended. On a
// shared machine a persistent cookie keeps the user signed in after the
// browser closes, which is why it is opt-in. A nil decide is a configuration
// error from New.
func WithSessionCookiePersistence(decide func(*Exchange) bool) SessionCookieOption {
	return func(s *sessionCookie) error {
		if decide == nil {
			return newConfigError("WithSessionCookiePersistence was given no decision; leave it out for " +
				"browser-session cookies, or decide true for every sign-in")
		}

		s.persist = decide

		return nil
	}
}

// RotationPoint names a privilege change at which a cookie chain rotates the
// sign-in's session, for WithoutSessionRotation.
type RotationPoint uint8

// The rotation points WithoutSessionRotation can turn off.
const (
	// RotateOnRoleSwitch is the rotation at an active-role switch
	// (Chain.SwitchActiveRole).
	RotateOnRoleSwitch RotationPoint = iota + 1

	// RotateOnPasswordChange is the rotation at the password-change gate's
	// resolve endpoint (EnablePasswordChangeGate, WithPasswordChangeEndpoint).
	RotateOnPasswordChange
)

// lastRotationPoint is the highest RotationPoint WithoutSessionRotation knows.
const lastRotationPoint = RotateOnPasswordChange

// rotatesAt reports whether the cookie session rotates at p, which it does
// unless WithoutSessionRotation named p.
func (s *sessionCookie) rotatesAt(p RotationPoint) bool {
	return s.unrotated&(1<<p) == 0
}

// WithoutSessionRotation turns off the rotation of the cookie session at each
// privilege change points names, so the session keeps its identifier there and
// the cookie is not re-set.
//
// Default: a cookie chain rotates the sign-in into a new identifier, and re-sets
// the cookie to it, at every privilege change: second-factor verification,
// re-authentication, an active-role switch (RotateOnRoleSwitch) and the
// password change at the gate's resolve endpoint (RotateOnPasswordChange).
//
// Turning a rotation off reopens session fixation at that change: an
// identifier that existed before it, one an attacker planted in the browser or
// read before the change included, carries the role or the changed password's
// standing after it. Turn one off only where a rotation cannot be delivered,
// such as a deployment whose responses at that change cannot carry a cookie.
// With RotateOnRoleSwitch off, Chain.SwitchActiveRole records the role on the
// session the request is on, as for a bearer session, and so may be called on a
// context kept past its request. With RotateOnPasswordChange off, the change's
// resolution is saved on that session, and a persistent cookie keeps the
// Max-Age it was set with, even where the change restores a longer deadline
// than a recovery left: the browser then drops the cookie before the server
// would refuse the session.
//
// The line: only the two rotations named above can be turned off. Sign-in
// always creates a new session, and the rotations at second-factor
// verification and re-authentication have no off switch, since the sessions
// they guard rely on them in every mode. Naming no point, the zero
// RotationPoint, or one past RotateOnPasswordChange is a configuration error
// from New; naming one twice, or giving the option more than once, turns off
// every point named.
func WithoutSessionRotation(points ...RotationPoint) SessionCookieOption {
	return func(s *sessionCookie) error {
		if len(points) == 0 {
			return newConfigError("WithoutSessionRotation was given no rotation point; name " +
				"RotateOnRoleSwitch, RotateOnPasswordChange or both, or leave it out to rotate at every " +
				"privilege change")
		}

		for _, p := range points {
			if p == 0 || p > lastRotationPoint {
				return newConfigError("WithoutSessionRotation was given the rotation point %d, which is "+
					"neither RotateOnRoleSwitch nor RotateOnPasswordChange; the rotations at second-factor "+
					"verification and re-authentication cannot be turned off", p)
			}

			s.unrotated |= 1 << p
		}

		return nil
	}
}

// WithSessionCookieName sets and reads the session cookie under name instead.
//
// Default: DefaultSessionCookieName, whose __Host- prefix keeps the cookie on
// the one origin that set it. Another name is the consumer's choice, and the
// cookie is still set Secure, HttpOnly and with Path=/. The line: the name
// must be a valid cookie name (a non-empty token, with no space, ';', '=' or
// other separator), and a __Host- name takes no WithSessionCookieDomain; both
// are configuration errors from New.
func WithSessionCookieName(name string) SessionCookieOption {
	return func(s *sessionCookie) error {
		if name == "" {
			return newConfigError("WithSessionCookieName was given no name")
		}

		s.name = name

		return nil
	}
}

// WithSessionCookieSameSite sets the session cookie's SameSite attribute to
// mode.
//
// Default: http.SameSiteLaxMode, which keeps the cookie on a top-level
// navigation from another site, such as a link in an email or the return from
// an identity provider, and drops it on every other cross-site request; CSRF
// protection covers what Lax leaves. The line: only http.SameSiteLaxMode and
// http.SameSiteStrictMode are accepted. http.SameSiteNoneMode would send the
// cookie on every cross-site request, and http.SameSiteDefaultMode leaves the
// choice to the browser; both are configuration errors from New.
func WithSessionCookieSameSite(mode http.SameSite) SessionCookieOption {
	return func(s *sessionCookie) error {
		if mode != http.SameSiteLaxMode && mode != http.SameSiteStrictMode {
			return newConfigError("WithSessionCookieSameSite accepts http.SameSiteLaxMode or " +
				"http.SameSiteStrictMode; None would send the session cookie on every cross-site " +
				"request, and Default leaves the choice to the browser")
		}

		s.sameSite = mode

		return nil
	}
}

// WithSessionCookieDomain sets the session cookie's Domain attribute, so every
// subdomain of domain receives it.
//
// Default: no Domain, so only the origin that set the cookie receives it. The
// line: a cookie shared across subdomains must be named with the __Secure-
// prefix (WithSessionCookieName), and a __Host- name, the default included,
// takes no Domain; either mistake, an empty domain, and one net/http would
// not write, are configuration errors from New.
//
// A shared Domain trusts every subdomain of it: any HTTPS subdomain, a
// forgotten staging host or an application a third party runs there, can set
// or replace a __Secure- cookie for the domain, so it can plant its own
// session identifier in a victim's browser (cookie tossing, session
// fixation). The default host-only __Host- cookie avoids this, because a
// browser lets only the origin itself set it. Share a Domain only when every
// subdomain is as trusted as the application.
func WithSessionCookieDomain(domain string) SessionCookieOption {
	return func(s *sessionCookie) error {
		if domain == "" {
			return newConfigError("WithSessionCookieDomain was given no domain; leave it out for a " +
				"cookie only the origin that set it receives")
		}

		s.domain = domain

		return nil
	}
}
