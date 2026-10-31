package httpsec

import (
	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// MagicLinkOption configures the magic-link endpoints. Each replaces one of
// the defaults named on EnableMagicLink.
type MagicLinkOption func(*magicLinkInterceptor) error

// EnableMagicLink answers the two magic-link endpoints at the magic-link slot.
//
// Defaults: a link is asked for by POST on DefaultMagicLinkRequestPath, which
// reads "email" and "next" from a form body or a JSON one and always answers
// 202 with an empty body (WithMagicLinkRequestPath); a link is redeemed by
// POST on DefaultMagicLinkConsumePath, which reads "token" from the form and
// the binding from DefaultBindingCookieName (WithMagicLinkConsumePath,
// WithMagicLinkBindingCookieName); no redirect target is allowed, so every submitted
// "next" becomes "/" (WithMagicLinkAllowedRedirects, WithMagicLinkAllowedOrigins); every failed
// redemption counts against the source (WithMagicLinkCountRefusals), at 10 per
// 15 minutes through a limiter this flow alone uses (WithMagicLinkLimiter);
// the built-in redeemer is the manager's own (WithMagicLinkRedeemer) and no
// consumer refusal checks run (WithMagicLinkChecks).
//
// Whether links are bound to the requesting device is read from the manager,
// never configured here: an interceptor that could be told one thing while the
// manager was told another would emit cookies for links that carry no binding,
// or issue bound links nothing ever answers. With binding on, the cookie lives
// as long as the link, so a manager whose link lifetime is not a whole number
// of seconds, at least one, is refused; that bound has no override.
//
// The token generator is required, because a redeemed link establishes a
// session the caller then has to be able to present. The session manager is
// taken from the chain when WithMagicLinkSessions is not given, and a chain
// with neither is refused.
func EnableMagicLink(m *magiclink.Links, opts ...MagicLinkOption) Option {
	const option = "EnableMagicLink"

	return func(c *config) error {
		if m == nil {
			return newConfigError("%s needs a magic-link manager", option)
		}

		i := &magicLinkInterceptor{
			manager:       m,
			respond:       writeMagicLinkResult,
			now:           c.now,
			requestPath:   DefaultMagicLinkRequestPath,
			consumePath:   DefaultMagicLinkConsumePath,
			cookieName:    DefaultBindingCookieName,
			bodyLimit:     DefaultLoginBodyLimit,
			countRefusals: true,
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
		c.register(i, OrderMagicLink)
		c.wire(i.wire)

		return nil
	}
}

// WithMagicLinkRequestPath answers link requests on path instead.
//
// Default: DefaultMagicLinkRequestPath. An empty path is refused, and so is
// one equal to the consume path: one path cannot both ask for a link and
// redeem one, and whichever branch matched first would silently swallow the
// other endpoint.
func WithMagicLinkRequestPath(path string) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if path == "" {
			return newConfigError("WithMagicLinkRequestPath was given no path, so no link " +
				"could be asked for")
		}

		i.requestPath = path

		return nil
	}
}

// WithMagicLinkConsumePath redeems links on path instead.
//
// Default: DefaultMagicLinkConsumePath. It is also what the binding cookie is
// scoped to, so moving the endpoint moves the cookie's scope with it. An empty
// path, or one equal to the request path, is refused.
func WithMagicLinkConsumePath(path string) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if path == "" {
			return newConfigError("WithMagicLinkConsumePath was given no path, so no link " +
				"could be redeemed")
		}

		i.consumePath = path

		return nil
	}
}

// WithMagicLinkBindingCookieName carries the same-device binding in a cookie called
// name.
//
// Default: DefaultBindingCookieName. An empty name is refused: a cookie
// without one is not set at all, and every bound link would then be
// unredeemable.
func WithMagicLinkBindingCookieName(name string) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if name == "" {
			return newConfigError("WithMagicLinkBindingCookieName was given no name, so the binding " +
				"cookie would never be set and no bound link could be redeemed")
		}

		i.cookieName = name

		return nil
	}
}

// WithMagicLinkAllowedRedirects allows targets as redirect destinations after a link is
// redeemed.
//
// Default: none, so every submitted target becomes "/". A target is used only
// when it exactly equals one of these entries — no prefix matching, no case
// folding, no normalisation — because every way of making two targets equal is
// a way of reaching an entry that was never configured.
//
// An entry is either a host-relative path, or an absolute http or https URL
// without userinfo whose origin was declared with WithMagicLinkAllowedOrigins. Anything
// else fails construction, naming the entry and this option.
//
// Calls accumulate, so a consumer whose configuration is split across several
// places builds one list from all of them.
func WithMagicLinkAllowedRedirects(targets ...string) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		i.allowedRedirects = append(i.allowedRedirects, targets...)

		return nil
	}
}

// WithMagicLinkAllowedOrigins declares the origins an absolute redirect entry may sit
// on.
//
// Default: none, under which only host-relative targets can ever be accepted,
// so nothing the consumer configures can send a browser to another site.
// Declaring an origin is deliberately a separate act from listing the entry:
// widening the set of reachable sites is not something a redirect entry should
// be able to do on its own.
//
// An origin is a scheme, a host and an optional port, and must be https except
// on a loopback host, where http is accepted so a consumer can develop against
// one. Anything else fails construction, naming the origin and this option.
func WithMagicLinkAllowedOrigins(origins ...string) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		i.allowedOrigins = append(i.allowedOrigins, origins...)

		return nil
	}
}

// WithMagicLinkCountRefusals decides whether a policy denial or a consumer
// check refusal of a valid link counts against the source's allowance.
//
// Default: true. An attacker holding one link the policy refuses could
// otherwise replay it without limit for as long as it lives, and each attempt
// would cost a store read and a policy evaluation.
//
// Passing false exempts exactly those two refusals. Every other redemption
// failure is still recorded, including one from a redeemer that discarded the
// denial and then failed for a reason of its own, and an enrolment-store
// outage while the check before the spend looks up the methods a raised
// second-factor challenge offers: that is a failure, not a refusal. A policy
// that reads the outage as a reason to deny is a denial like any other, and
// is exempted.
func WithMagicLinkCountRefusals(count bool) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		i.countRefusals = count

		return nil
	}
}

// WithMagicLinkLimiter counts failed redemptions through l.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under
// namespace "magic-link-redeem", or else an in-memory limiter of 10 failures
// per source per 15 minutes, used by this flow alone. A deployment running more
// than one replica supplies a factory or a limiter its replicas share, or the
// limit is per process and an attacker simply spreads their attempts.
//
// One limiter may be handed to several flows. That shares the store and the
// limit it was built with, not the allowance: every key carries the flow it
// belongs to, so a source that exhausts its redemptions still has its whole
// allowance at every other endpoint.
// A limiter handed to several flows shares its key cap among them, so a flood
// on one refuses new sources on all.
//
// The flow's IPv6 aggregate (WithIPv6Aggregate) is sized from l: the
// aggregate's multiplier, 4 by default, times the limit l reports, over the
// window l reports, read through ratelimit.PolicyReporter, which the in-memory
// limiter and the shared limiters scrty ships implement. A limiter that does
// not implement it gets no default aggregate for this flow, and one warning
// when the chain is built; under an explicit WithIPv6Aggregate it is a
// configuration error.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it
// would read as "no limit" while the consumer believed they had replaced one.
func WithMagicLinkLimiter(l ratelimit.Limiter) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if err := requireDep("WithMagicLinkLimiter", "limiter", l); err != nil {
			return err
		}

		i.limiter = l

		return nil
	}
}

// WithMagicLinkSessions opens the redeemed link's session in m.
//
// Default: the session manager the chain's other built-ins were wired to, so a
// deployment with one session store declares it once. A chain that has none at
// all is refused: a redemption that could not open a session would spend the
// link and authenticate nobody.
func WithMagicLinkSessions(m *session.Sessions) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if err := requireDep("WithMagicLinkSessions", "session manager", m); err != nil {
			return err
		}

		i.sessions = m

		return nil
	}
}

// WithMagicLinkTokens issues the redeemed link's access token through g.
//
// There is no default, and it is required: the library ships no signing key, and
// a session a caller has no credential for is one they cannot use. The
// generator is the same one the other first factors issue through, so a token
// from a link and a token from a password are indistinguishable to whatever
// verifies them.
//
// With EnableSessionBearer on, it must not be given: the credential is the
// opened session's identifier (MagicLinkResult.Token), and a generator is a
// configuration error from New, since a token it minted would not be accepted
// by that chain.
func WithMagicLinkTokens(g token.Generator) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if err := requireDep("WithMagicLinkTokens", "token generator", g); err != nil {
			return err
		}

		i.tokens = g

		return nil
	}
}

// WithMagicLinkRedeemer redeems links through r instead of the manager.
//
// Default: the magic-link manager's own Redeem, which checks everything before
// it consumes anything. A consumer who replaces it takes on that ordering
// contract — see Redeemer, which also says what the endpoint still enforces
// itself and what it cannot. In short: the login completion reuses the
// decision the endpoint's check made before the link was spent, with no second
// evaluation after it, and a success whose check never ran, or that returns a
// user with a different reference or password-change instant than the check
// was handed, is refused with policy.ErrDenied.
//
// A nil redeemer is refused: there would be nothing to redeem with.
func WithMagicLinkRedeemer(r Redeemer) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if err := requireDep("WithMagicLinkRedeemer", "redeemer", r); err != nil {
			return err
		}

		i.redeemer = r

		return nil
	}
}

// WithMagicLinkResponder replaces the response written when a link is
// successfully redeemed.
//
// With none supplied, the library writes a JSON document carrying the access
// token, an empty refresh token field, the session's validity and the resolved
// redirect target — the same document a successful login answers with, plus
// that target.
//
// It is called instead of the downstream handler, because the consume endpoint
// is the library's own and the application has no route behind it. An error it
// returns leaves the chain as the request's refusal.
//
// The result's Next is the target the allowlist resolved, never the one the
// caller submitted: a responder that redirects to it cannot send a caller
// somewhere the allowlist refused. Referrer-Policy is already set when the
// responder runs, so a response that forgets it still cannot leak the token
// through a referrer.
func WithMagicLinkResponder(fn MagicLinkResponder) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if fn == nil {
			return newConfigError("WithMagicLinkResponder was given no function; omit the " +
				"option to keep the default document")
		}

		i.respond = fn

		return nil
	}
}

// WithMagicLinkChecks runs the consumer's own refusal checks at redemption.
//
// Default: none. Each check receives the resolved principal and the user's
// password-change time, and the first that returns an error stops the
// redemption, leaving the link redeemable and returning that error unchanged.
//
// A check must have no side effects: several racing redemptions of one link may
// each run it, and only one of them will go on to spend the link.
//
// Calls accumulate, and the checks run in the order they were given, after the
// library's own policy check.
func WithMagicLinkChecks(checks ...magiclink.Check) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		for _, check := range checks {
			if check == nil {
				return newConfigError("WithMagicLinkChecks was given a nil check, which would " +
					"panic at the first redemption")
			}
		}

		i.checks = append(i.checks, checks...)

		return nil
	}
}
