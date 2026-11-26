package httpsec

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/origin"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// OIDCOption configures the federated-login endpoints. Each replaces one of
// the defaults named on EnableOIDCLogin.
type OIDCOption func(*oidcInterceptor) error

// OIDCDeps are the dependencies EnableOIDCLogin cannot default.
type OIDCDeps struct {
	// RelyingParty holds the providers every endpoint serves: the registry,
	// discovery, the broker and its role options. It is required, and a nil
	// one is refused when the chain is built.
	RelyingParty *oidc.RelyingParty

	// Handoff issues and redeems the single-use code the callback conveys the
	// login with. It is required unless WithOIDCCallbackSuccess conveys the
	// login instead, or the chain has EnableSessionCookie on, whose callback
	// completes the sign-in itself; it must then be nil: neither conveyance
	// issues a code, so there is nothing for a handoff to govern.
	Handoff *oidc.Handoff

	// Users loads the user a federated sign-in completed on the server is for
	// (WithOIDCProviderCompletion). The session is built from the details it
	// returns, the stored roles and password-change time among them, never from
	// the broker's principal, as a handoff redemption builds it from its record.
	//
	// Default: nil, and nothing reads it. Completion requires it, and refuses a
	// nil one, or an interface holding a nil pointer, at construction. A loader
	// given without completion is refused too, since nothing would call it.
	Users identity.UserLoader
}

// EnableOIDCLogin answers the federated-login endpoints at the OIDC slot:
// starting a login, the provider's callback, redeeming the handoff code the
// callback conveys the login with, and back-channel logout.
//
// deps.RelyingParty is required and holds everything about the providers: the
// registry, discovery, the broker and its role options all belong to the oidc
// constructors, and only transport lives here. deps.Handoff is required unless
// WithOIDCCallbackSuccess conveys the login instead, because the default
// conveyance issues its code through it; with WithOIDCCallbackSuccess given,
// deps.Handoff must be nil, since the conveyance replaces it and issues no code
// for it, or any redemption-only option, to govern.
//
// Defaults: a login starts with a GET on DefaultOIDCAuthorizePath followed by
// the provider's name (WithOIDCAuthorizePath), and the provider calls back on
// DefaultOIDCCallbackPath followed by the provider's name
// (WithOIDCCallbackPath), matched to the browser by the
// DefaultOIDCFlowCookieName cookie (WithOIDCFlowCookieName). The callback
// creates no session: it redirects with a single-use handoff code
// (WithOIDCCallbackSuccess replaces that), redeemed by POST on
// DefaultOIDCHandoffPath (WithOIDCHandoffPath) through the handoff manager
// (WithOIDCHandoffRedeemer). No post-login destination is allowed, so every
// requested one becomes "/" (WithOIDCAllowedRedirects,
// WithOIDCAllowedOrigins). Every failed redemption counts against the
// source (WithOIDCHandoffCountRefusals), at 10 per 5 minutes through a limiter
// redemption alone uses (WithOIDCHandoffLimiter, WithOIDCHandoffRateLimit).
// Back-channel logout tokens are received by POST on
// DefaultOIDCBackchannelPath followed by the provider's name
// (WithOIDCBackchannelLogoutPath), and one naming no session ends only the
// sessions the token's issuer created (WithOIDCBackchannelLogoutScope). A token
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
// The token generator is required (WithOIDCTokens) unless WithOIDCCallbackSuccess
// is given: the library ships no signing key, and a redeemed code opens a
// session its caller must be able to present, but WithOIDCCallbackSuccess issues
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
// WithOIDCCallbackSuccess given, a non-nil handoff manager or any of
// WithOIDCHandoffRedeemer, WithOIDCHandoffLimiter, WithOIDCHandoffRateLimit,
// WithOIDCHandoffCountRefusals or WithOIDCHandoffPath, since none of them
// govern anything once no handoff code is issued.
//
// On a chain with EnableSessionCookie and no WithOIDCCallbackSuccess, the
// callback conveys the login itself, and issues no handoff code: it loads the
// user afresh through the cookie session's user loader by the reference the
// broker resolved (refusing an unknown, inactive or mismatched one with
// oidc.ErrInvalidHandoff, as a redemption does), runs the post-authentication
// policy on the assurance the ID token asserted, creates the session in one
// write with the oidc first factor, the provider's session and ID token and
// that assurance, sets the session cookie, and answers 303 See Other to the
// allowlist-resolved destination. A challenge the policy raises leaves the
// pending session's cookie and still redirects. A cookie that cannot be
// delivered ends the sign-in, and the failure is returned with no redirect.
// Such a chain takes no handoff manager, no token generator, none of the
// redemption-only options and no role sync (the user's stored roles are
// reloaded, as by a handoff); each is a configuration error from New.
func EnableOIDCLogin(deps OIDCDeps, opts ...OIDCOption) Option {
	const option = "EnableOIDCLogin"

	return func(c *config) error {
		if deps.RelyingParty == nil {
			return newConfigError("%s needs OIDCDeps.RelyingParty: it holds the providers every "+
				"endpoint serves", option)
		}

		i := &oidcInterceptor{
			manager:         deps.RelyingParty,
			handoffs:        deps.Handoff,
			users:           deps.Users,
			now:             c.now,
			authorizePath:   defaultPath(DefaultOIDCAuthorizePath),
			callbackPath:    defaultPath(DefaultOIDCCallbackPath),
			handoffPath:     defaultPath(DefaultOIDCHandoffPath),
			backchannelPath: defaultPath(DefaultOIDCBackchannelPath),
			cookieName:      DefaultOIDCFlowCookieName,
			bodyLimit:       DefaultLoginBodyLimit,
			limit:           defaultHandoffFailureLimit,
			window:          defaultHandoffFailureWindow,
			countRefusals:   true,
			scope:           BackchannelLogoutScopeIssuer,
			rpLogout:        true,
			parked:          parkedFailureConfig{param: DefaultOIDCLoginErrorParam},
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
	if i.parked.toClient && !i.completion {
		return newConfigError("%s WithOIDCFailToClient needs %s: only a login completion "+
			"recognises as a parked request's can end that request", option, optionProviderCompletion)
	}

	if i.parked.paramSet && !i.completion {
		return newConfigError("%s WithOIDCLoginErrorParam needs %s: only a login completion "+
			"recognises as a parked request's returns to the login page", option, optionProviderCompletion)
	}

	if i.completion {
		if err := i.checkCompletion(c, option); err != nil {
			return err
		}
	} else if !nilcheck.IsNil(i.users) {
		// The loader is read by completion alone: one given without it would
		// read as though federated logins loaded their user through it, while
		// nothing ever calls it (F28).
		return newConfigError("%s OIDCDeps.Users is read only by %s, which is not enabled: "+
			"enable it, or leave Users nil", option, optionProviderCompletion)
	}

	if i.callbackSuccess != nil {
		if err := i.checkConveyance(option); err != nil {
			return err
		}

		if c.issuesSessionReference() {
			if err := checkTokenGenerator(c, option, "WithOIDCTokens", i.tokens); err != nil {
				return err
			}
		} else if err := checkIssuingGenerator(c, option, "WithOIDCTokens", i.tokens); err != nil {
			return err
		}
	} else if c.sessionCookie {
		// The cookie chain's own conveyance (completeCookieSignIn): the
		// callback completes the sign-in, so no handoff code is issued.
		if err := i.checkCookieConveyance(option); err != nil {
			return err
		}

		if err := checkTokenGenerator(c, option, "WithOIDCTokens", i.tokens); err != nil {
			return err
		}
	} else {
		if i.handoffs == nil {
			return newConfigError("%s needs OIDCDeps.Handoff to convey a login with, unless "+
				"WithOIDCCallbackSuccess conveys it instead", option)
		}

		if c.issuesSessionReference() {
			if err := checkTokenGenerator(c, option, "WithOIDCTokens", i.tokens); err != nil {
				return err
			}
		} else if i.tokens == nil {
			return newConfigError("%s needs a token generator: a redeemed handoff opens a "+
				"session, and a caller with no credential for it could not use it "+
				"(WithOIDCTokens)", option)
		} else if err := checkIssuingGenerator(c, option, "WithOIDCTokens", i.tokens); err != nil {
			return err
		}
	}

	i.issue = c.credentialIssuer(i.tokens)
	i.deliver = c.delivery()

	if i.sessions == nil && c.sessions == nil {
		return newConfigError("%s needs a session manager, and neither WithOIDCSessions "+
			"nor any other built-in on this chain supplied one", option)
	}

	// A policy that decides federated logins on provider assurance with no
	// source would decide every one of them as unmet: required users whose
	// provider asserted exactly what the deployment accepts would be
	// challenged or refused. That holds under either conveyance, since a
	// session a consumer's handler creates is judged on every request too.
	if c.engine != nil {
		if unwired := c.engine.UnwiredFederatedAssurance(); len(unwired) > 0 {
			return newConfigError("%s cannot admit federated logins while %s decides them on "+
				"provider assurance with no source to match it against: give it "+
				"policy.WithFederatedAssuranceSource (the OIDC manager is one), choose "+
				"policy.FederatedAssuranceExempt, or exempt factor.OIDC with "+
				"policy.WithMFAExemption", option, strings.Join(unwired, ", "))
		}
	}

	// A handoff reloads the user by reference and rebuilds the principal from
	// the stored roles, so the roles a sync derived at the callback would be
	// gone by the time the session exists. A cookie chain's own conveyance
	// reloads the user in the callback the same way.
	if syncing := i.manager.RoleSyncProviders(); len(syncing) > 0 && i.callbackSuccess == nil {
		conveyance := "the handoff conveyance"
		if c.sessionCookie {
			conveyance = "the cookie chain's callback conveyance"
		}

		return newConfigError("%s cannot keep role sync for %s with %s, "+
			"which rebuilds the principal from stored roles; convey the login with "+
			"WithOIDCCallbackSuccess, or turn role sync off", option, strings.Join(syncing, ", "), conveyance)
	}

	if !i.redirectCheckWaived {
		return i.checkRedirectPaths(option)
	}

	return nil
}

// checkRedirectPaths refuses a provider whose registered redirect URL cannot
// reach the callback endpoint. The decoded path of the URL must end with the
// callback path as resolved (the base path included) followed by the provider's
// name; ending with it, rather than equalling it, lets a proxy that removes a
// public prefix through. A redirect URL that does not parse, or that the
// registry cannot name, is refused, since either would fail every login.
func (i *oidcInterceptor) checkRedirectPaths(option string) error {
	for _, name := range i.manager.Providers() {
		raw, ok := i.manager.RedirectURL(name)
		if !ok {
			return newConfigError("%s: provider %q has no redirect URL to check; "+
				"WithoutOIDCRedirectPathCheck waives the check", option, name)
		}

		u, err := url.Parse(raw)
		if err != nil {
			return newConfigError("%s: the redirect URL of provider %q does not parse, so it "+
				"cannot be checked against the callback path (WithoutOIDCRedirectPathCheck "+
				"waives the check)", option, name)
		}

		want := i.callbackPath.at() + name
		if !strings.HasSuffix(u.Path, want) {
			return newConfigError("%s: the redirect URL of provider %q has the path %q, which "+
				"cannot reach the callback this chain serves at %q; register a redirect URL "+
				"ending in that path, or waive the check with WithoutOIDCRedirectPathCheck",
				option, name, u.Path, want)
		}
	}

	return nil
}

// checkConveyance refuses the redemption-only wiring that a consumer's own
// WithOIDCCallbackSuccess makes meaningless: with it configured, no handoff code
// is ever issued, so a handoff manager and every redemption-only option are
// a contradiction the consumer should hear about at construction, not have
// silently ignored.
func (i *oidcInterceptor) checkConveyance(option string) error {
	if i.handoffs != nil {
		return newConfigError("%s was given both OIDCDeps.Handoff and WithOIDCCallbackSuccess, "+
			"which replaces the handoff conveyance and issues no code for it to redeem; "+
			"pass nil for OIDCDeps.Handoff", option)
	}

	if name, ok := i.redemptionOnlySet(); ok {
		return newConfigError("%s was given %s and WithOIDCCallbackSuccess, but the "+
			"conveyance issues no handoff code for %s to govern", option, name, name)
	}

	return nil
}

// checkCookieConveyance refuses the redemption-only wiring a cookie chain
// makes meaningless: its callback completes the sign-in and sets the session
// cookie (completeCookieSignIn), so no handoff code is ever issued for a
// handoff manager or any redemption-only option to govern.
func (i *oidcInterceptor) checkCookieConveyance(option string) error {
	if i.handoffs != nil {
		return newConfigError("%s was given OIDCDeps.Handoff, but EnableSessionCookie is on, so the "+
			"callback completes the sign-in and sets the session cookie, and no handoff code is "+
			"issued for it to redeem; pass nil for OIDCDeps.Handoff", option)
	}

	if name, ok := i.redemptionOnlySet(); ok {
		return newConfigError("%s was given %s, but EnableSessionCookie is on, so the callback "+
			"completes the sign-in and issues no handoff code for %s to govern", option, name, name)
	}

	return nil
}

// redemptionOnlySet names the first redemption-only option the consumer gave,
// if any.
func (i *oidcInterceptor) redemptionOnlySet() (string, bool) {
	redemptionOnly := []struct {
		name string
		set  bool
	}{
		{"WithOIDCHandoffRedeemer", i.handoffRedeemerSet},
		{"WithOIDCHandoffLimiter", i.handoffLimiterSet},
		{"WithOIDCHandoffRateLimit", i.handoffRateLimitSet},
		{"WithOIDCHandoffCountRefusals", i.handoffCountRefusalsSet},
		{"WithOIDCHandoffPath", i.handoffPathSet},
	}

	for _, opt := range redemptionOnly {
		if opt.set {
			return opt.name, true
		}
	}

	return "", false
}

// providerSegment returns the provider name path carries after prefix, or ""
// when path is not prefix followed by exactly one non-empty segment. prefix
// ends in the "/" oidcPrefix guarantees; one without it matches nothing.
func providerSegment(path, prefix string) string {
	base, ok := strings.CutSuffix(prefix, "/")
	if !ok {
		return ""
	}

	provider, _ := oneSegmentBelow(path, base)

	return provider
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
		"WithOIDCAllowedRedirects", "WithOIDCAllowedOrigins",
		origin.WithMaxEntryLen(origin.MaxEntryLen))
	if err != nil {
		return newConfigError("EnableOIDCLogin was given a redirect target it cannot use: %s", err)
	}

	i.redirects = allow

	guard, err := c.resolveSourceGuard("EnableOIDCLogin", oidcHandoffFlow, i.limiter,
		i.limit, i.window, c.refusalInterval)
	if err != nil {
		return err
	}

	i.guard = guard

	return nil
}

// WithOIDCTokens issues the access token of the session a redeemed handoff
// opens through tokens.
//
// There is no default, and it is required: the library ships no signing key,
// and a session a caller has no credential for is one they cannot use. The
// generator is the same one the other first factors issue through, so a token
// from a federated login and one from a password are indistinguishable to
// whatever verifies them. A nil generator, including an interface holding a
// nil pointer, is refused.
//
// With EnableSessionBearer on, it must not be given: the credential a
// redeemed handoff returns is the opened session's identifier, and a
// generator is a configuration error from New, since a token it minted would
// not be accepted by that chain.
func WithOIDCTokens(tokens token.Generator) OIDCOption {
	return func(i *oidcInterceptor) error {
		if err := requireDep("WithOIDCTokens", "token generator", tokens); err != nil {
			return err
		}

		i.tokens = tokens

		return nil
	}
}

// WithOIDCSessions opens the session a redeemed handoff establishes in sessions,
// and ends back-channel-logged-out sessions there.
//
// Default: the session manager the chain's other built-ins were wired to, so a
// deployment with one session store declares it once. A chain that has none at
// all is refused. A nil manager is refused.
func WithOIDCSessions(sessions *session.Sessions) OIDCOption {
	return func(i *oidcInterceptor) error {
		if err := requireDep("WithOIDCSessions", "session manager", sessions); err != nil {
			return err
		}

		i.sessions = sessions

		return nil
	}
}

// WithOIDCAuthorizePath starts logins under prefix instead: a GET on prefix
// followed by a provider's registered name starts a login with that provider.
//
// Default: DefaultOIDCAuthorizePath, "/sso/login/". The prefix is within the base
// path (WithBasePath). A prefix without a trailing slash has
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

		i.authorizePath.giveAs("WithOIDCAuthorizePath", prefix, p)

		return nil
	}
}

// WithOIDCCallbackPath answers provider callbacks under prefix instead: the
// provider redirects to prefix followed by its registered name, which each
// provider's registered redirect URL has to match.
//
// Default: DefaultOIDCCallbackPath, "/sso/callback/". The prefix is within the
// base path (WithBasePath), so the redirect URL registered with the provider
// must end with the resolved prefix and the provider's name (see
// WithoutOIDCRedirectPathCheck). It is also what the flow cookie is
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

		i.callbackPath.giveAs("WithOIDCCallbackPath", prefix, p)

		return nil
	}
}

// WithOIDCHandoffPath redeems handoff codes by POST on path instead.
//
// Default: DefaultOIDCHandoffPath, "/sso/handoff". The path is within the base
// path (WithBasePath), and is matched exactly. An empty
// path, or one that does not start with "/", is refused. New refuses a path
// that collides with another endpoint of the chain, as its collision check
// judges every built-in: equal to an authorize, callback or back-channel
// prefix, with or without that prefix's trailing slash, is one. This option
// is redemption-only:
// given beside WithOIDCCallbackSuccess, which issues no handoff code for it to
// govern, it is refused.
func WithOIDCHandoffPath(path string) OIDCOption {
	return func(i *oidcInterceptor) error {
		if err := checkEndpointPath("WithOIDCHandoffPath", path); err != nil {
			return err
		}

		i.handoffPath.give("WithOIDCHandoffPath", path)
		i.handoffPathSet = true

		return nil
	}
}

// WithOIDCBackchannelLogoutPath receives back-channel logout tokens by POST under
// prefix instead: a provider delivers to prefix followed by its registered
// name, which is the back-channel logout URI registered with the provider.
//
// Default: DefaultOIDCBackchannelPath, "/sso/backchannel-logout/". The prefix is
// within the base path (WithBasePath), so the URI registered with the provider
// includes the base path. A prefix without a trailing slash has
// one appended. An empty prefix, one that does not start with "/", or the
// root path "/" itself (which would claim every one-segment path of the
// application), is refused.
func WithOIDCBackchannelLogoutPath(prefix string) OIDCOption {
	return func(i *oidcInterceptor) error {
		p, err := oidcPrefix("WithOIDCBackchannelLogoutPath", prefix)
		if err != nil {
			return err
		}

		i.backchannelPath.giveAs("WithOIDCBackchannelLogoutPath", prefix, p)

		return nil
	}
}

// oidcPrefix validates a provider-prefixed path and returns it with the
// trailing slash the provider segment follows.
func oidcPrefix(option, prefix string) (string, error) {
	if err := checkEndpointPath(option, prefix); err != nil {
		return "", err
	}

	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
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

// WithOIDCCallbackSuccess replaces the handoff conveyance with fn, which then
// writes the whole response to a successful callback, for example for a
// backend-for-frontend that establishes its own session. No handoff code is
// issued, so the handoff manager given to EnableOIDCLogin must be nil, no
// token generator is required (WithOIDCTokens), and every redemption-only
// option (WithOIDCHandoffRedeemer, WithOIDCHandoffLimiter, WithOIDCHandoffRateLimit,
// WithOIDCHandoffCountRefusals, WithOIDCHandoffPath) is refused if given
// alongside it: none of them would govern anything.
//
// Default: redirect to the allowlisted destination with a single-use handoff
// code, redeemed through the required handoff manager by the required token
// generator; on a chain with EnableSessionCookie, complete the sign-in in the
// callback, set the session cookie and redirect to the allowlisted
// destination (EnableOIDCLogin). It is also the only way to keep role sync,
// which neither default conveyance can carry. On a cookie chain fn writes the
// whole response as on any other, and sets no session cookie unless it
// creates and delivers one itself. A nil function is refused.
func WithOIDCCallbackSuccess(fn CallbackSuccess) OIDCOption {
	return func(i *oidcInterceptor) error {
		if fn == nil {
			return newConfigError("WithOIDCCallbackSuccess was given no function; omit the " +
				"option to keep the handoff conveyance")
		}

		i.callbackSuccess = fn

		return nil
	}
}

// WithOIDCHandoffRedeemer redeems handoff codes through redeemer instead.
//
// Default: the *oidc.Handoff given to EnableOIDCLogin, which runs
// every check before it consumes the code. A replacement takes on that
// contract (see HandoffRedeemer). The login completion reuses the decision the
// endpoint's check made before the code was spent, with no second evaluation
// after it; the endpoint still refuses a success whose policy check never ran
// or denied, or that returns a user with a different reference or
// password-change instant than the check was handed, but it cannot un-spend a
// code the replacement consumed. A nil
// redeemer, including an interface holding a nil pointer, is refused. This
// option is redemption-only: given beside WithOIDCCallbackSuccess, which issues
// no handoff code for it to redeem, it is refused.
func WithOIDCHandoffRedeemer(redeemer HandoffRedeemer) OIDCOption {
	return func(i *oidcInterceptor) error {
		if err := requireDep("WithOIDCHandoffRedeemer", "redeemer", redeemer); err != nil {
			return err
		}

		i.redeemer = redeemer
		i.handoffRedeemerSet = true

		return nil
	}
}

// WithOIDCHandoffLimiter counts failed handoff redemptions through limiter.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under
// namespace "oidc.handoff", or else an in-memory limiter of 10 failures per
// source per 5 minutes; either way at the limit WithOIDCHandoffRateLimit sets, and
// used by redemption alone. A deployment running more than one replica supplies
// a factory or a limiter its replicas share, or the limit is per process. A
// shared limiter shares its store, not the allowance: every key carries the
// flow it belongs to.
// A limiter handed to several flows shares its key cap among them, so a flood
// on one refuses new sources on all.
//
// The flow's IPv6 aggregate (WithIPv6Aggregate) is sized from limiter: the
// aggregate's multiplier, 4 by default, times the limit limiter reports, over the
// window limiter reports, read through ratelimit.PolicyReporter, which the in-memory
// limiter and the shared limiters scrty ships implement. A limiter that does
// not implement it gets no default aggregate for this flow, and one warning
// when the chain is built; under an explicit WithIPv6Aggregate it is a
// configuration error.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it
// would read as "no limit". This option is redemption-only: given beside
// WithOIDCCallbackSuccess, which issues no code for anything to be limited on, it
// is refused.
func WithOIDCHandoffLimiter(limiter ratelimit.Limiter) OIDCOption {
	return func(i *oidcInterceptor) error {
		if err := requireDep("WithOIDCHandoffLimiter", "limiter", limiter); err != nil {
			return err
		}

		i.limiter = limiter
		i.handoffLimiterSet = true

		return nil
	}
}

// WithOIDCHandoffRateLimit sets the allowance of the default redemption limiter:
// limit failures per source per window.
//
// Default: 10 per 5 minutes. It does not apply to a limiter supplied with
// WithOIDCHandoffLimiter, which carries its own. A limit or window that is zero
// or negative is refused, since it would refuse every redemption or none.
// This option is redemption-only: given beside WithOIDCCallbackSuccess, which
// issues no code for it to rate limit, it is refused.
func WithOIDCHandoffRateLimit(limit int, window time.Duration) OIDCOption {
	return func(i *oidcInterceptor) error {
		if limit <= 0 || window <= 0 {
			return newConfigError("WithOIDCHandoffRateLimit was given %d per %s; both must be "+
				"positive", limit, window)
		}

		i.limit, i.window = limit, window
		i.handoffRateLimitSet = true

		return nil
	}
}

// WithOIDCHandoffCountRefusals decides whether a policy denial or a consumer
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
// option is redemption-only: given beside WithOIDCCallbackSuccess, which issues
// no code for a refusal to count against, it is refused.
func WithOIDCHandoffCountRefusals(count bool) OIDCOption {
	return func(i *oidcInterceptor) error {
		i.countRefusals = count
		i.handoffCountRefusalsSet = true

		return nil
	}
}

// WithOIDCBackchannelLogoutScope sets which sessions a back-channel logout token
// that names a subject but no session ends.
//
// Default: BackchannelLogoutScopeIssuer, only the sessions a login through the token's
// issuer created. BackchannelLogoutScopeAll ends every session of the user, and so lets the
// provider end sessions it did not establish: the user's password sessions and
// sessions opened through other providers. A token naming a session (sid) is
// unaffected by the scope. Any other value is refused.
func WithOIDCBackchannelLogoutScope(scope BackchannelLogoutScope) OIDCOption {
	return func(i *oidcInterceptor) error {
		if !scope.valid() {
			return newConfigError("WithOIDCBackchannelLogoutScope was given %d, which is not "+
				"BackchannelLogoutScopeIssuer or BackchannelLogoutScopeAll", scope)
		}

		i.scope = scope

		return nil
	}
}

// WithOIDCRPInitiatedLogout decides whether logout offers the provider's
// end-session URL for a session a federated login created.
//
// Default: true: when EnableLogout is on the same chain, in either order, with
// no LogoutDeps.EndSession of its own, logout is given the manager's
// end-session step (oidc.RelyingParty.EndSessionBuilder). An explicit
// LogoutDeps.EndSession always wins, whatever this option says. Passing false
// leaves logout without that step, answering every session as it answers a
// password session. A chain without EnableLogout is unaffected.
func WithOIDCRPInitiatedLogout(on bool) OIDCOption {
	return func(i *oidcInterceptor) error {
		i.rpLogout = on

		return nil
	}
}

// WithoutOIDCRedirectPathCheck waives the check that every provider's redirect
// URL can reach the callback endpoint.
//
// Default: the check is on. Assembling the chain fails with a configuration
// error unless the decoded path of each provider's redirect URL ends with the
// callback path the chain serves (the base path included) followed by the
// provider's name. A path that only ends with it is accepted, so a proxy that
// removes a public prefix needs no waiver. Waive the check for a proxy that
// rewrites paths beyond removing a prefix. Waiving it gives up the
// construction-time proof: a redirect URL that cannot arrive is found only when
// a provider redirects to it, and every login through that provider then fails
// after the user has authenticated.
func WithoutOIDCRedirectPathCheck() OIDCOption {
	return func(i *oidcInterceptor) error {
		i.redirectCheckWaived = true

		return nil
	}
}

// WithOIDCProviderCompletion completes, on the server, a federated sign-in
// started from the login page of the chain's own OpenID Provider: the callback
// runs what a handoff redemption followed by a resume would run, and answers the
// browser with a 303 to where the resume sends it, so the login page needs no
// script to finish the sign-in.
//
// Default: off. Every federated login is conveyed by a handoff code to the
// allowlisted destination, and a page the provider parked a request at redeems
// it and resumes the request itself.
//
// Which logins it completes. Only a login whose destination is exactly the
// provider's login URL (oidcprovider.Provider.LoginURL) carrying one parked
// request's handle and nothing else: the same scheme and host, the port as
// written, the raw path byte for byte (an empty one read as "/"), no user
// information, no fragment, and a query of exactly one non-empty req parameter.
// A trailing slash, another case, a percent-encoded path, an extra or repeated
// parameter, or a relative destination is not one, and is conveyed by the
// handoff as without this option. A recognised destination is never replaced by
// "/", whatever the allowlist (WithOIDCAllowedRedirects) holds.
//
// What it does, in order:
//   - checks the parked request before anything else, behind the resume
//     endpoint's source throttle: one that is unknown, expired past its grace
//     window or bound to another browser is refused with ErrOIDCUnknownHandle
//     and charged to the source; one past its login stage is refused the same,
//     uncharged; one expired within the window is answered access_denied at the
//     client, uncharged;
//   - loads the user through OIDCDeps.Users, refusing a missing, disabled or
//     mismatched one as a redemption does;
//   - runs the post-authentication policy on the stored details and the
//     assurance the verified ID token asserted;
//   - stores the session with the provider session and the asserted assurance,
//     after cancelling the user's held account recoveries, and keeps its
//     credential on the server;
//   - judges it under the chain's per-request policy and the resume endpoint's
//     checks, resumes the request with the sign-in the provider's assurance
//     mapping (WithOIDCSignInAssurance) states, and confirms the sign-in after
//     the resume;
//   - sets the provider's browser-session cookie and answers 303, with
//     Cache-Control: no-store and Referrer-Policy: no-referrer.
//
// A refused or disabled user, a policy's denial, and a user loader or session
// store that fails return the browser to the login page with the code
// (WithOIDCLoginErrorParam, WithOIDCFailToClient). A refusal after the session
// is stored ends that session first, and sends no code to the client. What the
// resume answered is read from its outcome (oidcprovider.ResumeResult.Outcome),
// never from the redirect's query, so a client whose registered redirect URI
// carries a parameter of its own, error included, completes. A resume that answers the
// client's error response, such as login_required for an id_token_hint naming
// another subject, ends the session too, and redirects to that response; one
// that answers the device code-entry page ends it and redirects there; one
// naming no outcome completion knows ends it and is refused with
// ErrOIDCReauthenticate, with no redirect. A session that cannot be ended is
// recorded at ERROR and the refusal returned unchanged; no credential for it
// was ever handed out. The end is detached from the request, so a client that
// hangs up does not leave the session live.
//
// The fallback. A login that still owes a step (a second factor, an enrolment,
// an account recovery or a password change) is not completed and stores no
// session: it is conveyed by a handoff code to the login URL carrying the
// handle, as without this option. The page redeems the code, whose answer names
// that same destination, finishes the step and resumes the request. A login the
// per-request policy challenges (a step it requires before this request, once
// the session is stored) falls back the same way: the stored session is ended
// first, then the login is handed off to the login URL carrying the handle, so
// the page answers the challenge and its redemption stores a session of its own.
//
// Exclusions. It needs EnableOIDCProvider on the same chain, OIDCDeps.Handoff,
// OIDCDeps.Users, OIDC login storing sessions in the provider's session manager,
// every provider's redirect URL on the issuer's origin (where the provider's
// host-only cookies are sent), and a login URL with no query of its own. It
// cannot be combined with WithOIDCCallbackSuccess, which replaces the conveyance
// it falls back to, or WithOIDCHandoffRedeemer, since it runs the library's own
// redemption checks. Each of these is refused at construction.
//
// One SSO login at a time per browser. The relying party's flow cookie has a
// single name, so an SSO login started before an earlier one in the same
// browser has called back makes the earlier callback an invalid state
// (oidc.ErrInvalidState), with nothing created; the user starts that one again.
// Requests parked in several tabs and signed in one after the other each
// complete.
func WithOIDCProviderCompletion() OIDCOption {
	return func(i *oidcInterceptor) error {
		i.completion = true

		return nil
	}
}

// DefaultOIDCLoginErrorParam is the query parameter that carries the error code
// when a failed login for a parked request returns to the provider's login page.
// WithOIDCLoginErrorParam replaces it.
const DefaultOIDCLoginErrorParam = "error"

// WithOIDCLoginErrorParam names the query parameter that carries the error code
// back to the login page.
//
// Default: DefaultOIDCLoginErrorParam. Construction refuses an empty name, a
// name the login page already reads (req, handoff), one that is not a plain
// query key of letters, digits, "-", ".", "_" and "~", and the option without
// WithOIDCProviderCompletion.
func WithOIDCLoginErrorParam(name string) OIDCOption {
	return func(i *oidcInterceptor) error {
		if !plainQueryKey(name) || name == oidcprovider.HandleParam || name == DefaultOIDCHandoffParam {
			return newConfigError("WithOIDCLoginErrorParam was given %q, which the login page could not "+
				"read apart from its own parameters", name)
		}

		i.parked.param = name
		i.parked.paramSet = true

		return nil
	}
}

// plainQueryKey reports whether name is non-empty and made only of RFC 3986's
// unreserved characters, so it is written and read back unescaped.
func plainQueryKey(name string) bool {
	if name == "" {
		return false
	}

	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '.', r == '_', r == '~':
		default:
			return false
		}
	}

	return true
}

// WithOIDCFailToClient ends a parked request whose brokered login failed, and
// answers the client's redirect URI with the error, state and iss. The codes
// are those the login page would get. A request that cannot be ended gets the
// login's own error, with one ERROR record.
//
// A device request has no client to answer: it returns to the login page.
//
// Default: off. The browser returns to the login page with the error code
// (WithOIDCLoginErrorParam), and the request stays parked. It needs
// WithOIDCProviderCompletion, or construction fails.
func WithOIDCFailToClient() OIDCOption {
	return func(i *oidcInterceptor) error {
		i.parked.toClient = true

		return nil
	}
}

// Compile-time proof that the default redeemer satisfies the port.
var _ HandoffRedeemer = (*oidc.Handoff)(nil)

// resolvePaths places the four endpoints under base. Each is computed from the
// path its option declared, never from the previous result, so resolving twice
// cannot prefix twice. The flow cookie and the callback's other derived values
// read callbackPath, so they follow the placed endpoint.
func (i *oidcInterceptor) resolvePaths(base string) {
	i.authorizePath.resolve(base)
	i.callbackPath.resolve(base)
	i.handoffPath.resolve(base)
	i.backchannelPath.resolve(base)
}

// declaredPaths reports the federated-login paths the consumer set whose
// endpoint is served, each as its option was given it: the handoff only while
// a redeemer is set, as endpoints declares it. The redeemer is settled by
// resolve, in build's wiring, so the handoff is reported as settled by wiring,
// for the repeat check's late pass alone; the other three are judged early.
func (i *oidcInterceptor) declaredPaths() []declaredPath {
	paths := declarations(i.authorizePath, i.callbackPath, i.backchannelPath)

	if i.redeemer != nil {
		paths = append(paths, wiringSettled(i.handoffPath)...)
	}

	return paths
}
