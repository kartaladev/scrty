package httpsec

import (
	"net/http"
	"strings"
	"time"

	"github.com/kartaladev/scrty/internal/origin"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// OIDCOption configures the federated-login endpoints. Each replaces one of
// the defaults named on EnableOIDCLogin.
type OIDCOption func(*oidcInterceptor) error

// EnableOIDCLogin answers the federated-login endpoints at the OIDC slot:
// starting a login, the provider's callback, redeeming the handoff code the
// callback conveys the login with, and back-channel logout.
//
// The manager is required and holds everything about the providers: the
// registry, discovery, the broker and its role options all belong to the oidc
// constructors, and only transport lives here. The handoff manager is
// required unless WithCallbackSuccess conveys the login instead, because the
// default conveyance issues its code through it; with WithCallbackSuccess
// given, h must be nil, since the conveyance replaces it and issues no code
// for it, or any redemption-only option, to govern.
//
// Defaults: a login starts with a GET on DefaultOIDCAuthorizePath followed by
// the provider's name (WithOIDCAuthorizePath), and the provider calls back on
// DefaultOIDCCallbackPath followed by the provider's name
// (WithOIDCCallbackPath), matched to the browser by the
// DefaultOIDCFlowCookieName cookie (WithOIDCFlowCookieName). The callback
// creates no session: it redirects with a single-use handoff code
// (WithCallbackSuccess replaces that), redeemed by POST on
// DefaultOIDCHandoffPath (WithOIDCHandoffPath) through the handoff manager
// (WithHandoffRedeemer). No post-login destination is allowed, so every
// requested one becomes "/" (WithOIDCAllowedRedirects,
// WithOIDCAllowedOrigins). Every failed redemption counts against the
// source (WithHandoffCountRefusals), at 10 per 5 minutes through a limiter
// redemption alone uses (WithHandoffLimiter, WithHandoffRateLimit).
// Back-channel logout tokens are received by POST on
// DefaultOIDCBackchannelPath followed by the provider's name
// (WithBackchannelLogoutPath), and one naming no session ends only the
// sessions the token's issuer created (WithBackchannelLogoutScope). A token
// naming only a subject is resolved to a user through the broker's link
// store: the library's own broker has one, and a consumer IdentityBroker that
// also exposes Links() oidc.LinkStore gets subject-only logout resolved
// through it. A consumer broker without one ends nothing for such a token; the
// provider is still answered 200 and a WARN record says the subject could not
// be resolved.
// RP-initiated logout is on (WithOIDCRPInitiatedLogout).
//
// A back-channel logout token that fails verification is answered as one
// uniform refusal, and is recorded at WARN with the verifier's own text,
// naming which rule failed (never a claim value): kept on purpose, since it is
// the library's own protocol-failure text and not a dependency's. Every other
// dependency failure behind these endpoints — the flow store, the handoff
// store or its user loader, the link store, the session store — is recorded
// by a fixed reason and the error's Go type, and returned to the caller behind
// fixed library text with the dependency's error still reachable by
// errors.Is and errors.As. A consumer who wants a dependency's own text logs
// it inside their own implementation of the store or loader.
//
// The token generator is required (WithOIDCTokens) unless WithCallbackSuccess
// is given: the library ships no signing key, and a redeemed code opens a
// session its caller must be able to present, but WithCallbackSuccess issues
// no code, so nothing here mints a token for it. The session manager is taken
// from the chain when WithOIDCSessions is not given, and a chain with
// neither is refused.
//
// Construction also refuses two endpoints that one request could reach, an
// authorize, callback or back-channel prefix that is the root path "/" (it
// would claim every one-segment path of the application), a redirect
// allowlist entry or declared origin internal/origin does not accept, role
// sync on any provider while the default conveyance is kept (a handoff
// rebuilds the principal from the user's stored roles, so the synced ones
// would be silently lost between the callback and the session), and, with
// WithCallbackSuccess given, a non-nil handoff manager or any of
// WithHandoffRedeemer, WithHandoffLimiter, WithHandoffRateLimit,
// WithHandoffCountRefusals or WithOIDCHandoffPath, since none of them
// govern anything once no handoff code is issued.
func EnableOIDCLogin(m *oidc.Manager, h *oidc.HandoffManager, opts ...OIDCOption) Option {
	const option = "EnableOIDCLogin"

	return func(c *config) error {
		if m == nil {
			return newConfigError("%s needs an OIDC manager: it holds the providers every "+
				"endpoint serves", option)
		}

		i := &oidcInterceptor{
			manager:         m,
			handoffs:        h,
			now:             time.Now,
			authorizePath:   DefaultOIDCAuthorizePath,
			callbackPath:    DefaultOIDCCallbackPath,
			handoffPath:     DefaultOIDCHandoffPath,
			backchannelPath: DefaultOIDCBackchannelPath,
			cookieName:      DefaultOIDCFlowCookieName,
			bodyLimit:       DefaultLoginBodyLimit,
			limit:           defaultHandoffFailureLimit,
			window:          defaultHandoffFailureWindow,
			countRefusals:   true,
			scope:           IssuerSessions,
			rpLogout:        true,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(i); err != nil {
				return err
			}
		}

		c.enable(option, func() error { return i.check(c, option) })

		c.useSessions(i.sessions)
		c.register(i, OrderOIDC)
		c.wire(i.wire)

		return nil
	}
}

// check reports the wiring faults only the assembled configuration can see.
//
// It runs once every option has been applied, so a session manager wired by
// another built-in after EnableOIDCLogin still counts.
func (i *oidcInterceptor) check(c *config, option string) error {
	if i.callbackSuccess != nil {
		if err := i.checkConveyance(option); err != nil {
			return err
		}
	} else {
		if i.handoffs == nil {
			return newConfigError("%s needs a handoff manager to convey a login with, unless "+
				"WithCallbackSuccess conveys it instead", option)
		}

		if i.tokens == nil {
			return newConfigError("%s needs a token generator: a redeemed handoff opens a "+
				"session, and a caller with no credential for it could not use it "+
				"(WithOIDCTokens)", option)
		}
	}

	if i.sessions == nil && c.sessions == nil {
		return newConfigError("%s needs a session manager, and neither WithOIDCSessions "+
			"nor any other built-in on this chain supplied one", option)
	}

	if err := i.checkPaths(option); err != nil {
		return err
	}

	// A handoff reloads the user by reference and rebuilds the principal from
	// the stored roles, so the roles a sync derived at the callback would be
	// gone by the time the session exists.
	if syncing := i.manager.RoleSyncProviders(); len(syncing) > 0 && i.callbackSuccess == nil {
		return newConfigError("%s cannot keep role sync for %s with the handoff conveyance, "+
			"which rebuilds the principal from stored roles; convey the login with "+
			"WithCallbackSuccess, or turn role sync off", option, strings.Join(syncing, ", "))
	}

	return nil
}

// checkConveyance refuses the redemption-only wiring that a consumer's own
// WithCallbackSuccess makes meaningless: with it configured, no handoff code
// is ever issued, so a handoff manager and every redemption-only option are
// a contradiction the consumer should hear about at construction, not have
// silently ignored.
func (i *oidcInterceptor) checkConveyance(option string) error {
	if i.handoffs != nil {
		return newConfigError("%s was given both a handoff manager and WithCallbackSuccess, "+
			"which replaces the handoff conveyance and issues no code for it to redeem; "+
			"pass nil for the handoff manager", option)
	}

	redemptionOnly := []struct {
		name string
		set  bool
	}{
		{"WithHandoffRedeemer", i.handoffRedeemerSet},
		{"WithHandoffLimiter", i.handoffLimiterSet},
		{"WithHandoffRateLimit", i.handoffRateLimitSet},
		{"WithHandoffCountRefusals", i.handoffCountRefusalsSet},
		{"WithOIDCHandoffPath", i.handoffPathSet},
	}

	for _, opt := range redemptionOnly {
		if opt.set {
			return newConfigError("%s was given %s and WithCallbackSuccess, but the "+
				"conveyance issues no handoff code for %s to govern", option, opt.name, opt.name)
		}
	}

	return nil
}

// checkPaths refuses two endpoints that one request path could reach, since
// whichever matched first would silently swallow the other.
//
// A prefix endpoint answers the prefix followed by exactly one non-empty
// segment, so two different prefixes never answer the same path; the handoff
// endpoint answers one exact path. The handoff path is also refused when it
// names a prefix itself, with or without its trailing slash, because a reader
// cannot tell those endpoints apart either.
func (i *oidcInterceptor) checkPaths(option string) error {
	prefixes := []struct{ name, path string }{
		{"WithOIDCAuthorizePath", i.authorizePath},
		{"WithOIDCCallbackPath", i.callbackPath},
		{"WithBackchannelLogoutPath", i.backchannelPath},
	}

	for a := range prefixes {
		for b := a + 1; b < len(prefixes); b++ {
			if prefixes[a].path == prefixes[b].path {
				return newConfigError("%s was given one path prefix, %q, through both %s and %s, "+
					"so the two endpoints collide", option, prefixes[a].path,
					prefixes[a].name, prefixes[b].name)
			}
		}
	}

	for _, p := range prefixes {
		if i.handoffPath == p.path || i.handoffPath == strings.TrimSuffix(p.path, "/") ||
			providerSegment(i.handoffPath, p.path) != "" {
			return newConfigError("%s was given a handoff path, %q, that collides with the %q "+
				"prefix of %s", option, i.handoffPath, p.path, p.name)
		}
	}

	return nil
}

// providerSegment returns the provider name path carries after prefix, or ""
// when path is not prefix followed by exactly one non-empty segment.
func providerSegment(path, prefix string) string {
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok || rest == "" || strings.Contains(rest, "/") {
		return ""
	}

	return rest
}

// wireOIDCLogin builds what the federated-login endpoints cannot build until
// every option has been applied: the redirect allowlist, whose entries and
// declared origins arrive through two accumulating options, the redemption
// source guard, whose logger is the chain's, and logout's end-session step,
// which EnableLogout may have been given after EnableOIDCLogin.
func (c *config) wireOIDCLogin() error {
	return eachInterceptor(c, func(i *oidcInterceptor) error {
		return i.resolve(c)
	})
}

// resolve settles the interceptor's remaining collaborators against the
// assembled configuration.
func (i *oidcInterceptor) resolve(c *config) error {
	if i.sessions == nil {
		i.sessions = c.sessions
	}

	if i.redeemer == nil && i.handoffs != nil {
		i.redeemer = i.handoffs
	}

	// Settled here rather than in the option, so it holds whichever of
	// EnableLogout and EnableOIDCLogin was given first. A consumer's own
	// end-session step is never replaced.
	if c.logout != nil && c.logout.endSession == nil && i.rpLogout {
		c.logout.endSession = i.manager.EndSessionBuilder()
	}

	allow, err := origin.NewAllowlist(i.allowedRedirects, i.allowedOrigins,
		"WithOIDCAllowedRedirects", "WithOIDCAllowedOrigins")
	if err != nil {
		return newConfigError("EnableOIDCLogin was given a redirect target it cannot use: %s", err)
	}

	i.redirects = allow

	guard, err := c.resolveSourceGuard("EnableOIDCLogin", oidcHandoffFlow, i.limiter,
		i.limit, i.window)
	if err != nil {
		return err
	}

	i.guard = guard

	return nil
}

// WithOIDCTokens issues the access token of the session a redeemed handoff
// opens through g.
//
// There is no default, and it is required: the library ships no signing key,
// and a session a caller has no credential for is one they cannot use. The
// generator is the same one the other first factors issue through, so a token
// from a federated login and one from a password are indistinguishable to
// whatever verifies them. A nil generator, including an interface holding a
// nil pointer, is refused.
func WithOIDCTokens(g token.Generator) OIDCOption {
	return func(i *oidcInterceptor) error {
		if err := requireDep("WithOIDCTokens", "token generator", g); err != nil {
			return err
		}

		i.tokens = g

		return nil
	}
}

// WithOIDCSessions opens the session a redeemed handoff establishes in m,
// and ends back-channel-logged-out sessions there.
//
// Default: the session manager the chain's other built-ins were wired to, so a
// deployment with one session store declares it once. A chain that has none at
// all is refused. A nil manager is refused.
func WithOIDCSessions(m *session.Manager) OIDCOption {
	return func(i *oidcInterceptor) error {
		if err := requireDep("WithOIDCSessions", "session manager", m); err != nil {
			return err
		}

		i.sessions = m

		return nil
	}
}

// WithOIDCAuthorizePath starts logins under prefix instead: a GET on prefix
// followed by a provider's registered name starts a login with that provider.
//
// Default: DefaultOIDCAuthorizePath. A prefix without a trailing slash has
// one appended, since the provider's name is the one segment after it. An
// empty prefix, one that does not start with "/", or the root path "/"
// itself (which would claim every one-segment path of the application), is
// refused.
func WithOIDCAuthorizePath(prefix string) OIDCOption {
	return func(i *oidcInterceptor) error {
		p, err := oidcPrefix("WithOIDCAuthorizePath", prefix)
		if err != nil {
			return err
		}

		i.authorizePath = p

		return nil
	}
}

// WithOIDCCallbackPath answers provider callbacks under prefix instead: the
// provider redirects to prefix followed by its registered name, which each
// provider's registered redirect URL has to match.
//
// Default: DefaultOIDCCallbackPath. It is also what the flow cookie is
// scoped to, so moving the endpoint moves the cookie with it. A prefix without
// a trailing slash has one appended. An empty prefix, one that does not start
// with "/", or the root path "/" itself (which would claim every
// one-segment path of the application), is refused.
func WithOIDCCallbackPath(prefix string) OIDCOption {
	return func(i *oidcInterceptor) error {
		p, err := oidcPrefix("WithOIDCCallbackPath", prefix)
		if err != nil {
			return err
		}

		i.callbackPath = p

		return nil
	}
}

// WithOIDCHandoffPath redeems handoff codes by POST on path instead.
//
// Default: DefaultOIDCHandoffPath. The path is matched exactly. An empty
// path, or one that does not start with "/", is refused, and so is a path
// that collides with an authorize, callback or back-channel prefix, with or
// without that prefix's trailing slash. This option is redemption-only:
// given beside WithCallbackSuccess, which issues no handoff code for it to
// govern, it is refused.
func WithOIDCHandoffPath(path string) OIDCOption {
	return func(i *oidcInterceptor) error {
		if err := oidcPath("WithOIDCHandoffPath", path); err != nil {
			return err
		}

		i.handoffPath = path
		i.handoffPathSet = true

		return nil
	}
}

// WithBackchannelLogoutPath receives back-channel logout tokens by POST under
// prefix instead: a provider delivers to prefix followed by its registered
// name, which is the back-channel logout URI registered with the provider.
//
// Default: DefaultOIDCBackchannelPath. A prefix without a trailing slash has
// one appended. An empty prefix, one that does not start with "/", or the
// root path "/" itself (which would claim every one-segment path of the
// application), is refused.
func WithBackchannelLogoutPath(prefix string) OIDCOption {
	return func(i *oidcInterceptor) error {
		p, err := oidcPrefix("WithBackchannelLogoutPath", prefix)
		if err != nil {
			return err
		}

		i.backchannelPath = p

		return nil
	}
}

// oidcPath refuses a path no request could ever be matched against.
func oidcPath(option, path string) error {
	switch {
	case path == "":
		return newConfigError("%s was given no path, so the endpoint would answer nothing", option)
	case !strings.HasPrefix(path, "/"):
		return newConfigError("%s was given %q, which does not start with \"/\" and so "+
			"matches no request path", option, path)
	}

	return nil
}

// oidcPrefix validates a provider-prefixed path and returns it with the
// trailing slash the provider segment follows.
func oidcPrefix(option, prefix string) (string, error) {
	if err := oidcPath(option, prefix); err != nil {
		return "", err
	}

	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	if prefix == "/" {
		return "", newConfigError("%s was given the root path %q, which would claim every "+
			"one-segment path of the application", option, prefix)
	}

	return prefix, nil
}

// WithOIDCFlowCookieName carries the login flow in a cookie called name.
//
// Default: DefaultOIDCFlowCookieName. A name that is empty or not a valid
// cookie name is refused: the cookie would never be set, and no callback
// could ever be matched to the browser that started the login.
func WithOIDCFlowCookieName(name string) OIDCOption {
	return func(i *oidcInterceptor) error {
		// A probe of the name alone: this cookie is never sent.
		probe := &http.Cookie{Name: name} //nolint:gosec // G124: validity probe, never written
		if name == "" || probe.Valid() != nil {
			return newConfigError("WithOIDCFlowCookieName was given %q, which is not a "+
				"cookie name, so no callback could be matched to its browser", name)
		}

		i.cookieName = name

		return nil
	}
}

// WithOIDCAllowedRedirects allows entries as post-login destinations.
//
// Default: none, so every requested destination becomes "/". A destination is
// used only when it exactly equals an entry, with no prefix matching and no
// normalisation. An entry is a host-relative path, or an absolute http or
// https URL without userinfo whose origin was declared with
// WithOIDCAllowedOrigins; anything else fails construction, naming the entry
// and this option. The destination is resolved again wherever it is used, so
// a destination carrying a live handoff code never leaves for an undeclared
// site.
//
// Calls accumulate.
func WithOIDCAllowedRedirects(entries ...string) OIDCOption {
	return func(i *oidcInterceptor) error {
		i.allowedRedirects = append(i.allowedRedirects, entries...)

		return nil
	}
}

// WithOIDCAllowedOrigins declares the origins an absolute redirect entry may
// sit on.
//
// Default: none, under which only host-relative destinations can be accepted.
// An origin is a scheme, a host and an optional port, and must be https except
// on a loopback host, where http is accepted for development. Anything else
// fails construction, naming the origin and this option.
//
// Calls accumulate.
func WithOIDCAllowedOrigins(origins ...string) OIDCOption {
	return func(i *oidcInterceptor) error {
		i.allowedOrigins = append(i.allowedOrigins, origins...)

		return nil
	}
}

// WithCallbackSuccess replaces the handoff conveyance with fn, which then
// writes the whole response to a successful callback, for example for a
// backend-for-frontend that establishes its own session. No handoff code is
// issued, so the handoff manager given to EnableOIDCLogin must be nil, no
// token generator is required (WithOIDCTokens), and every redemption-only
// option (WithHandoffRedeemer, WithHandoffLimiter, WithHandoffRateLimit,
// WithHandoffCountRefusals, WithOIDCHandoffPath) is refused if given
// alongside it: none of them would govern anything.
//
// Default: redirect to the allowlisted destination with a single-use handoff
// code, redeemed through the required handoff manager by the required token
// generator. It is also the only way to keep role sync, which the default
// conveyance cannot carry. A nil function is refused.
func WithCallbackSuccess(fn CallbackSuccess) OIDCOption {
	return func(i *oidcInterceptor) error {
		if fn == nil {
			return newConfigError("WithCallbackSuccess was given no function; omit the " +
				"option to keep the handoff conveyance")
		}

		i.callbackSuccess = fn

		return nil
	}
}

// WithHandoffRedeemer redeems handoff codes through r instead.
//
// Default: the *oidc.HandoffManager given to EnableOIDCLogin, which runs
// every check before it consumes the code. A replacement takes on that
// contract (see HandoffRedeemer). The login completion reuses the decision the
// endpoint's check made before the code was spent, with no second evaluation
// after it; the endpoint still refuses a success whose policy check never ran
// or denied, or that returns a user with a different reference or
// password-change instant than the check was handed, but it cannot un-spend a
// code the replacement consumed. A nil
// redeemer, including an interface holding a nil pointer, is refused. This
// option is redemption-only: given beside WithCallbackSuccess, which issues
// no handoff code for it to redeem, it is refused.
func WithHandoffRedeemer(r HandoffRedeemer) OIDCOption {
	return func(i *oidcInterceptor) error {
		if err := requireDep("WithHandoffRedeemer", "redeemer", r); err != nil {
			return err
		}

		i.redeemer = r
		i.handoffRedeemerSet = true

		return nil
	}
}

// WithHandoffLimiter counts failed handoff redemptions through l.
//
// Default: an in-memory limiter of 10 failures per source per 5 minutes
// (WithHandoffRateLimit), used by redemption alone. A deployment running more
// than one replica supplies one its replicas share, or the limit is per
// process. A shared limiter shares its store, not the allowance: every key
// carries the flow it belongs to. A nil limiter, including an interface
// holding a nil pointer, is refused: it would read as "no limit". This
// option is redemption-only: given beside WithCallbackSuccess, which issues
// no code for anything to be limited on, it is refused.
func WithHandoffLimiter(l ratelimit.Limiter) OIDCOption {
	return func(i *oidcInterceptor) error {
		if err := requireDep("WithHandoffLimiter", "limiter", l); err != nil {
			return err
		}

		i.limiter = l
		i.handoffLimiterSet = true

		return nil
	}
}

// WithHandoffRateLimit sets the allowance of the default redemption limiter:
// limit failures per source per window.
//
// Default: 10 per 5 minutes. It does not apply to a limiter supplied with
// WithHandoffLimiter, which carries its own. A limit or window that is zero
// or negative is refused, since it would refuse every redemption or none.
// This option is redemption-only: given beside WithCallbackSuccess, which
// issues no code for it to rate limit, it is refused.
func WithHandoffRateLimit(limit int, window time.Duration) OIDCOption {
	return func(i *oidcInterceptor) error {
		if limit <= 0 || window <= 0 {
			return newConfigError("WithHandoffRateLimit was given %d per %s; both must be "+
				"positive", limit, window)
		}

		i.limit, i.window = limit, window
		i.handoffRateLimitSet = true

		return nil
	}
}

// WithHandoffCountRefusals decides whether a policy denial or a consumer
// check refusal of a valid handoff code counts against the source's
// allowance.
//
// Default: true, so a code the policy refuses cannot be replayed without limit
// for as long as it lives. Passing false exempts exactly those two refusals;
// every other failed redemption, outages included, is still recorded. That
// includes an enrolment-store outage while the check before the spend looks up
// the methods a raised second-factor challenge offers: a failure, not a
// refusal. A policy that reads the outage as a reason to deny is a denial like
// any other, and is exempted. This
// option is redemption-only: given beside WithCallbackSuccess, which issues
// no code for a refusal to count against, it is refused.
func WithHandoffCountRefusals(count bool) OIDCOption {
	return func(i *oidcInterceptor) error {
		i.countRefusals = count
		i.handoffCountRefusalsSet = true

		return nil
	}
}

// WithBackchannelLogoutScope sets which sessions a back-channel logout token
// that names a subject but no session ends.
//
// Default: IssuerSessions, only the sessions a login through the token's
// issuer created. AllSessions ends every session of the user, and so lets the
// provider end sessions it did not establish: the user's password sessions and
// sessions opened through other providers. A token naming a session (sid) is
// unaffected by the scope. Any other value is refused.
func WithBackchannelLogoutScope(s BackchannelLogoutScope) OIDCOption {
	return func(i *oidcInterceptor) error {
		if !s.valid() {
			return newConfigError("WithBackchannelLogoutScope was given %d, which is not "+
				"IssuerSessions or AllSessions", s)
		}

		i.scope = s

		return nil
	}
}

// WithOIDCRPInitiatedLogout decides whether logout offers the provider's
// end-session URL for a session a federated login created.
//
// Default: true: when EnableLogout is on the same chain, in either order, with
// no LogoutDeps.EndSession of its own, logout is given the manager's
// end-session step (oidc.Manager.EndSessionBuilder). An explicit
// LogoutDeps.EndSession always wins, whatever this option says. Passing false
// leaves logout without that step, answering every session as it answers a
// password session. A chain without EnableLogout is unaffected.
func WithOIDCRPInitiatedLogout(on bool) OIDCOption {
	return func(i *oidcInterceptor) error {
		i.rpLogout = on

		return nil
	}
}

// Compile-time proof that the default redeemer satisfies the port.
var _ HandoffRedeemer = (*oidc.HandoffManager)(nil)
