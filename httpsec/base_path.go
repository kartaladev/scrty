package httpsec

import (
	"strings"
)

// WithBasePath answers every built-in endpoint under path.
//
// Default: none. A chain given no base path answers each endpoint at the path
// its own setting names, as before.
//
// The path has the shape every endpoint path has: it starts with "/", is not
// "/", is clean (no "." or ".." segment, no "//"), and holds only letters,
// digits, "-", ".", "_", "~" and "/". One trailing slash is dropped, so "/auth/"
// and "/auth" are the same base path. A path that breaks the shape fails New
// with a configuration error naming WithBasePath.
//
// New also refuses two settings that would make the base path meaningless. A
// chain that enables no built-in endpoint is refused, because the base path
// would move nothing. A path the consumer set for a single built-in endpoint
// that is the base path or lies under it, judged on whole segments, is refused,
// because it would answer with the base path repeated: "/auth" with
// WithLoginRequestPath("/auth/sign-in/password") would answer
// "/auth/auth/sign-in/password". "/api-keys" under "/api" is not a repeat. A
// consumer who wants "/auth/auth/..." writes a base path of "/auth/auth". Paths
// the consumer did not set are not judged.
//
// Given twice, the last call applies. The option takes effect wherever it stands
// among the chain's options, because New judges it once every option has run.
//
// Every built-in endpoint the chain answers moves under it: password sign-in,
// logout, the key set, session renewal, the password-change endpoint, the
// session signal stream, session management, the second factor, enrolment,
// passkeys, the magic link, recovery, re-authentication, federated (OIDC) login
// and the OpenID Provider's endpoints. Each answers at the base path followed
// by its own path, the default or the one the consumer set, which is therefore
// relative to the base: "/auth" with WithLoginRequestPath("/signin") answers
// "/auth/signin", and the path without the base passes through. The exemption
// the gates give logout follows it. The key set moves too, and so do the
// provider's resume, consents and token endpoints; Chain.Endpoints lists every
// endpoint at its resolved path.
//
// The provider's two discovery documents are not placed by the base path; the
// issuer decides where they answer. The OpenID configuration sits at the issuer
// followed by "/.well-known/openid-configuration" (OpenID Connect Discovery 1.0
// section 4). The authorization server metadata inserts its suffix before the
// issuer's path (RFC 8414 section 3): for the issuer "https://id.example.com/auth"
// it is at "/.well-known/oauth-authorization-server/auth", at the host root,
// whatever the base path. A proxy that forwards only "/auth/*" must route that
// path to the chain as well.
//
// What does not move:
//
//   - the pages the consumer serves: the provider's login, consent, logout and
//     logged-out pages, redirect destinations, and the magic-link confirm page
//     (authenticate/magiclink.WithConfirmPath), which the emailed link points at.
//     The magic-link redeem endpoint, which that page posts to, is a chain
//     endpoint and does move;
//   - authorization rules, which describe the consumer's own routes and keep
//     judging them;
//   - the routes the consumer gives the chain (recovery cool-down routes,
//     cross-site exemptions, header-profile matchers), which must name the
//     moved paths;
//   - interceptors the consumer registers, which answer where they were written to;
//   - a prefix a proxy already strips. The matching is on the request path the
//     chain sees, so a proxy that already strips "/auth" needs no base path, and
//     setting one as well would answer nothing. The chain never reads
//     X-Forwarded-Prefix.
//
// New refuses a base path that leaves one of these stale:
//
//   - with the OpenID Provider, an issuer whose path does not cover the base path
//     (WithoutOIDCIssuerBasePathCheck waives it);
//   - a recovery cool-down route or cross-site exemption naming a path a built-in
//     endpoint answered at before the base moved it (WithoutBasePathRouteCheck
//     waives it);
//   - a federated-login provider whose registered redirect URL cannot reach the
//     callback (WithoutOIDCRedirectPathCheck waives it).
//
// A base path that repeats the first segment of a default path, such as "/sso"
// with the SSO endpoints, answers "/sso/sso/login/{provider}": that is what was
// configured, and it is not refused.
func WithBasePath(p string) Option {
	return func(c *config) error {
		c.basePath = p
		c.basePathGiven = true

		return nil
	}
}

// declaredPath is one built-in endpoint path the consumer set, and the option
// that set it.
type declaredPath struct {
	setting string
	path    string
}

// pathDeclarations is what an interceptor embeds to remember the paths the
// consumer set for it, so the base path can judge them once every option has
// run. A path left at its default is never declared.
type pathDeclarations []declaredPath

// declare records that setting set path, replacing an earlier declaration by the
// same setting, since the last call to an option is the one that applies.
func (d *pathDeclarations) declare(setting, path string) {
	for i := range *d {
		if (*d)[i].setting == setting {
			(*d)[i].path = path

			return
		}
	}

	*d = append(*d, declaredPath{setting: setting, path: path})
}

// declaredPaths reports what the consumer set.
func (d pathDeclarations) declaredPaths() []declaredPath {
	return d
}

// pathDeclarer is an interceptor that can say which of its paths the consumer
// set.
type pathDeclarer interface {
	declaredPaths() []declaredPath
}

// endpointAnswering names the Enable options that answer a built-in endpoint. A
// built-in not listed here is taken as answering none: the base path is then
// refused on a chain holding only such built-ins.
var endpointAnswering = map[string]bool{
	"EnableFormLogin":          true,
	"EnableLogout":             true,
	"EnableJWKSEndpoint":       true,
	"EnableSessionRenewal":     true,
	"EnablePasswordChangeGate": true,
	"EnableSessionSignals":     true,
	"EnableSessionManagement":  true,
	"EnableMFA":                true,
	"EnableMFAEnrolment":       true,
	"EnablePasskeys":           true,
	"EnableMagicLink":          true,
	"EnableAccountRecovery":    true,
	"EnableReauthentication":   true,
	"EnableOIDCLogin":          true,
	optionOIDCProvider:         true,
}

// answersEndpoint reports whether the chain enables a built-in that answers a
// request path of its own.
//
// The password-change gate answers one only when the consumer gave it a
// resolve endpoint (WithPasswordChangeEndpoint); without one it guards
// requests and answers none, so it alone gives the base path nothing to move.
func (c *config) answersEndpoint() bool {
	for _, e := range c.enabled {
		if !endpointAnswering[e.option] {
			continue
		}

		if e.option == "EnablePasswordChangeGate" && !c.passwordChangeAnswers() {
			continue
		}

		return true
	}

	return false
}

// passwordChangeAnswers reports whether a password-change gate of the chain
// has a resolve endpoint.
func (c *config) passwordChangeAnswers() bool {
	answers := false

	_ = eachInterceptor(c, func(g *passwordChangeGate) error {
		if g.change != nil {
			answers = true
		}

		return nil
	})

	return answers
}

// settleBasePath judges the base path and settles it, with one trailing slash
// dropped. It runs once, after every option, so the order of WithBasePath among
// the others cannot change what it sees, and a base path given twice is judged
// only as its last value. It does nothing when none was given.
func (c *config) settleBasePath() error {
	const option = "WithBasePath"

	if !c.basePathGiven {
		return nil
	}

	if err := checkEndpointPath(option, c.basePath); err != nil {
		return err
	}

	base := strings.TrimSuffix(c.basePath, "/")

	if !c.answersEndpoint() {
		return newConfigError("%s was given %q, but the chain enables no built-in endpoint, so it would move nothing", option, c.basePath)
	}

	err := eachInterceptor(c, func(d pathDeclarer) error {
		for _, p := range d.declaredPaths() {
			trimmed := strings.TrimSuffix(p.path, "/")
			if trimmed == base || strings.HasPrefix(trimmed, base+"/") {
				return newConfigError("%s was given %q, which is at or under the base path %q set by %s, "+
					"so the endpoint would answer %q; give the path within the base path, without it",
					p.setting, p.path, base, option, base+p.path)
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	c.basePath = base

	return nil
}

// joinBase is where an endpoint declared at p answers under base. Both are
// settled before they are joined: base is "" or a clean absolute path without a
// trailing slash, and p is a clean absolute path, so concatenation can neither
// glue two segments together nor double a slash. An empty p is an endpoint the
// consumer did not place, which answers nowhere, base or not.
func joinBase(base, p string) string {
	if p == "" {
		return ""
	}

	return base + p
}

// pathResolver is a built-in that answers request paths of its own. It keeps
// the paths its options declared, and resolvePaths sets where it answers: each
// declared path under base. It is computed from the declared paths every time,
// never from the previous result, so resolving twice cannot prefix twice.
type pathResolver interface {
	resolvePaths(base string)
}

// resolvePaths settles where every built-in answers, once the base path is
// settled and before anything is checked or wired from a path. With no base
// path every built-in answers where its options placed it.
//
// The logout path is copied from its endpoint here, not when EnableLogout
// runs, so the gates that exempt it exempt the path logout answers.
func (c *config) resolvePaths() {
	_ = eachInterceptor(c, func(r pathResolver) error {
		r.resolvePaths(c.basePath)

		return nil
	})

	if c.logout != nil {
		c.logoutPath = c.logout.path
	}
}

func (l *formLogin) resolvePaths(base string) { l.path = joinBase(base, l.declaredPath) }

func (l *logout) resolvePaths(base string) { l.path = joinBase(base, l.declaredPath) }

func (j *jwksEndpoint) resolvePaths(base string) { j.path = joinBase(base, j.declaredPath) }

func (r *sessionRenewal) resolvePaths(base string) { r.path = joinBase(base, r.declaredPath) }

func (g *passwordChangeGate) resolvePaths(base string) { g.path = joinBase(base, g.declaredPath) }

func (m *sessionManagement) resolvePaths(base string) { m.prefix = joinBase(base, m.declaredPrefix) }

// resolvePaths places the stream. It reads the default itself rather than
// filling cfg.Path, because settle fills the defaults later and the base path's
// repeat check must see an unset path as unset.
func (e *sessionSignals) resolvePaths(base string) {
	p := e.cfg.Path
	if p == "" {
		p = DefaultSessionSignalsPath
	}

	e.path = joinBase(base, p)
}
