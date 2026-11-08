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
// the consumer did not set are not judged, and neither is a path set for an
// endpoint the configuration leaves off, such as the recovery start path
// without issued codes: it answers nowhere, so it repeats nothing. Where the
// feature refuses such a path itself, that refusal is the one New returns.
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
	// settledByWiring marks a path whose endpoint is served or not as its
	// feature's wiring in build decides, not as the options alone do. The
	// repeat check judges it in its late pass, once that is known, and every
	// other path in its early pass (see checkBaseRepeats).
	settledByWiring bool
}

// endpointPath is one path a built-in answers, held as a single record: the path
// its setting declared, the setting that declared it, and where it answers once
// the base path is resolved. A path option sets this record and nothing else, so
// no option can move an endpoint without the base path's repeat check seeing the
// path it set, and a default is written in one place, the defaultPath that
// starts the record.
type endpointPath struct {
	// setting is the option that set the path, and "" for a default, which the
	// repeat check does not judge.
	setting string
	// written is the path as the setting was given it, which the repeat check
	// judges and names; declared is where it answers without the base path,
	// which differs from written only where the option normalises it.
	written  string
	declared string
	// resolved is where the endpoint answers, settled by resolve.
	resolved string
}

// defaultPath is a path no consumer set: it answers at p, under the base path
// once resolved, and is not judged by the repeat check.
func defaultPath(p string) endpointPath {
	return endpointPath{written: p, declared: p}
}

// give records that setting set the path to p. A later call replaces an earlier
// one, since the last call to an option is the one that applies; the earlier
// value is neither judged nor answered at.
func (e *endpointPath) give(setting, p string) {
	e.giveAs(setting, p, p)
}

// giveAs is give for an option that normalises what the consumer wrote: the
// endpoint answers at p, and the repeat check judges and names written.
func (e *endpointPath) giveAs(setting, written, p string) {
	e.setting = setting
	e.written = written
	e.declared = p
}

// resolve settles where the endpoint answers under base. It is computed from
// the declared path every time, never from the previous result, so resolving
// twice cannot prefix twice.
func (e *endpointPath) resolve(base string) {
	e.resolved = joinBase(base, e.declared)
}

// at is where the endpoint answers, once resolved.
func (e endpointPath) at() string {
	return e.resolved
}

// declaration reports the path the consumer set and the setting that set it,
// and false for a default.
func (e endpointPath) declaration() (declaredPath, bool) {
	if e.setting == "" {
		return declaredPath{}, false
	}

	return declaredPath{setting: e.setting, path: e.written}, true
}

// declarations reports, of paths, the ones the consumer set, in the order given.
func declarations(paths ...endpointPath) []declaredPath {
	var out []declaredPath

	for _, p := range paths {
		if d, ok := p.declaration(); ok {
			out = append(out, d)
		}
	}

	return out
}

// wiringSettled is declarations for paths whose serving the feature's wiring
// in build settles: each is marked so that only the repeat check's late pass
// judges it.
func wiringSettled(paths ...endpointPath) []declaredPath {
	out := declarations(paths...)
	for i := range out {
		out[i].settledByWiring = true
	}

	return out
}

// pathDeclarer is an interceptor that can say which of its paths the consumer
// set. Each built-in reports the declaration of every endpointPath it holds
// whose endpoint it serves, so the repeat check sees every served path a
// setting placed and none that answers nowhere. A path whose serving only the
// built-in's wiring in build settles is reported through wiringSettled: before
// that wiring it may read as off, so only the repeat check's late pass, which
// runs after it, judges it.
type pathDeclarer interface {
	declaredPaths() []declaredPath
}

// pathOwner is a built-in that holds endpointPath records: it resolves them and
// reports the ones the consumer set. Every built-in that owns a path is listed
// here, so a listed built-in that resolves paths but has no declaredPaths fails
// to compile. The list itself, and whether declaredPaths reports every record,
// are held by the per-option repeat tests, not by the compiler. The
// passwordless endpoints resolve a copy of the passkey prefix and are not
// listed: the passkey built-in, which the option sets, reports it.
type pathOwner interface {
	pathResolver
	pathDeclarer
}

var (
	_ pathOwner = (*formLogin)(nil)
	_ pathOwner = (*logout)(nil)
	_ pathOwner = (*jwksEndpoint)(nil)
	_ pathOwner = (*sessionRenewal)(nil)
	_ pathOwner = (*passwordChangeGate)(nil)
	_ pathOwner = (*sessionManagement)(nil)
	_ pathOwner = (*sessionSignals)(nil)
	_ pathOwner = (*mfaInterceptor)(nil)
	_ pathOwner = (*enrolmentInterceptor)(nil)
	_ pathOwner = (*passkeyInterceptor)(nil)
	_ pathOwner = (*magicLinkInterceptor)(nil)
	_ pathOwner = (*recoveryInterceptor)(nil)
	_ pathOwner = (*reauthInterceptor)(nil)
	_ pathOwner = (*oidcInterceptor)(nil)
	_ pathOwner = (*oidcOuterRouter)(nil)
)

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
// dropped. It runs once, after every option and before any path is resolved,
// so the order of WithBasePath among the others cannot change what it sees,
// and a base path given twice is judged only as its last value. It does
// nothing when none was given. Whether a consumer's path repeats the base is
// judged after the paths are resolved, by checkBaseRepeatsEarly and
// checkBaseRepeats.
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

	c.basePath = base

	return nil
}

// checkBaseRepeatsEarly is the repeat check's early pass. It runs in New, once
// the paths are resolved and before validate, and judges every path the
// consumer set whose serving the options alone decide, which is every path
// not marked settledByWiring.
//
// It runs before validate because several of validate's checks read a
// resolved path and refuse one that does not fit (the OIDC login's redirect
// check, the provider's assertion endpoint check). Judged by them first, a
// doubled path would be refused with advice to register or state the doubled
// URL; judged here, the refusal names the option that set it.
//
// The paths whose serving wiring settles (recovery's start, finish, cancel and
// codes, the OIDC handoff) are left to the late pass: before wiring they may
// read as off, so a served, doubled path would slip through. The handoff is
// never judged here, even when the options already set a redeemer, so that
// the OIDC login's own refusal of a handoff path the consumer's conveyance
// leaves unused comes first.
func (c *config) checkBaseRepeatsEarly() error {
	return c.judgeBaseRepeats(false)
}

// checkBaseRepeats is the repeat check's late pass. It runs in build, once
// every built-in is wired, and judges only the paths marked settledByWiring:
// recovery's start, finish, cancel and codes, settled by wireAccountRecovery,
// and the OIDC handoff, settled by wireOIDCLogin. Each declaredPaths leaves out
// a path whose endpoint is off, so a path set for an endpoint the wiring turns
// off is not judged, and a feature's own refusal of it comes first. It runs
// before the inventory's collision check, so a doubled path is refused as one,
// not as whatever it collides with.
func (c *config) checkBaseRepeats() error {
	return c.judgeBaseRepeats(true)
}

// judgeBaseRepeats refuses a path the consumer set for a served built-in
// endpoint that is the base path or lies under it, judged on whole segments,
// among the paths whose settledByWiring is settled.
func (c *config) judgeBaseRepeats(settled bool) error {
	const option = "WithBasePath"

	if !c.basePathGiven {
		return nil
	}

	base := c.basePath

	return eachInterceptor(c, func(d pathDeclarer) error {
		for _, p := range d.declaredPaths() {
			if p.settledByWiring != settled {
				continue
			}

			trimmed := strings.TrimSuffix(p.path, "/")
			if trimmed == base || strings.HasPrefix(trimmed, base+"/") {
				return newConfigError("%s was given %q, which is at or under the base path %q set by %s, "+
					"so the endpoint would answer %q; give the path within the base path, without it",
					p.setting, p.path, base, option, base+p.path)
			}
		}

		return nil
	})
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
// each path as an endpointPath, and resolvePaths sets where it answers: each
// declared path under base (endpointPath.resolve). It is computed from the
// declared paths every time, never from the previous result, so resolving twice
// cannot prefix twice.
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
		c.logoutPath = c.logout.path.at()
	}
}

func (l *formLogin) resolvePaths(base string) { l.path.resolve(base) }

func (l *formLogin) declaredPaths() []declaredPath { return declarations(l.path) }

func (l *logout) resolvePaths(base string) { l.path.resolve(base) }

func (l *logout) declaredPaths() []declaredPath { return declarations(l.path) }

func (j *jwksEndpoint) resolvePaths(base string) { j.path.resolve(base) }

func (j *jwksEndpoint) declaredPaths() []declaredPath { return declarations(j.path) }

func (r *sessionRenewal) resolvePaths(base string) { r.path.resolve(base) }

func (r *sessionRenewal) declaredPaths() []declaredPath { return declarations(r.path) }

func (g *passwordChangeGate) resolvePaths(base string) { g.path.resolve(base) }

func (g *passwordChangeGate) declaredPaths() []declaredPath { return declarations(g.path) }

func (m *sessionManagement) resolvePaths(base string) { m.prefix.resolve(base) }

func (m *sessionManagement) declaredPaths() []declaredPath { return declarations(m.prefix) }

func (e *sessionSignals) resolvePaths(base string) { e.path.resolve(base) }

func (e *sessionSignals) declaredPaths() []declaredPath { return declarations(e.path) }
