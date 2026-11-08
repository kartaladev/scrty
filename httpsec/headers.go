package httpsec

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
)

// Header names the security-headers layer sets.
const (
	headerCSP            = "Content-Security-Policy"
	headerContentType    = "X-Content-Type-Options"
	headerReferrerPolicy = "Referrer-Policy"
	headerCOOP           = "Cross-Origin-Opener-Policy"
)

// nonceBytes is the nonce's size before encoding: 128 bits, the least the
// CSP guidance asks for.
const nonceBytes = 16

// nonceSentinel stands for the nonce in a policy's sources until a response
// has one. It holds a control character, which the source check refuses, so a
// consumer's own source can never be mistaken for it.
const nonceSentinel = "'nonce-\x00'"

// HeaderOption adjusts the security-headers layer. Each names, in its own
// documentation, the default it replaces.
type HeaderOption func(*securityHeaders) error

// profileHeader is one header of a profile: a fixed value, or a policy that is
// rendered per response because it carries the response's nonce.
type profileHeader struct {
	name   string
	value  string
	policy *CSPPolicy
}

// HeaderProfile is the set of headers a response gets.
type HeaderProfile struct {
	headers []profileHeader

	// err is the first fault of the editors the profile was built with,
	// reported when the profile reaches WithHeaderProfile, because APIHeaders
	// and NewHeaderProfile have no error to return.
	err error
}

// usesNonce reports whether serving the profile needs a nonce.
func (p HeaderProfile) usesNonce() bool {
	for _, h := range p.headers {
		if h.policy != nil && h.policy.usesNonce() {
			return true
		}
	}

	return false
}

// documentProfile is the profile a request no other profile selects gets.
func documentProfile() HeaderProfile {
	csp := StrictCSP()

	return HeaderProfile{headers: []profileHeader{
		{name: headerCSP, policy: &csp},
		{name: headerContentType, value: "nosniff"},
		{name: headerReferrerPolicy, value: "strict-origin-when-cross-origin"},
		{name: headerCOOP, value: "same-origin-allow-popups"},
	}}
}

// securityHeaders is the layer EnableSecurityHeaders registers. It is built
// once and read-only while serving.
type securityHeaders struct {
	document HeaderProfile

	// hsts is the Strict-Transport-Security header sent on secure requests, or
	// nil when the consumer removed it.
	hsts *hstsPolicy

	// profiles are the consumer's route profiles, in the order they were given.
	profiles []routedProfile

	// random is where nonces come from: crypto/rand, replaced only by tests.
	random io.Reader

	// failed is run on the exchange whose nonce could not be generated. That
	// request fails outside every other interceptor's slot, so the steps
	// features run on such a refusal (Chain.refusalSteps) are run for it too.
	// It is nil until the chain is built.
	failed func(*Exchange)

	// scoped is set while the editors build one profile (APIHeaders,
	// NewHeaderProfile), where an option that reaches beyond the profile is
	// refused rather than silently ignored.
	scoped bool

	// reportOnly, candidate and endpoint are the report-only options, applied
	// together by finish so their order does not matter.
	reportOnly bool
	candidate  *CSPPolicy
	endpoint   *reportingEndpoint
}

// layerWide refuses option when the editors are building a single profile,
// because option sets something the whole layer shares.
func (l *securityHeaders) layerWide(option string) error {
	if l.scoped {
		return newConfigError("%s sets something the whole security-headers layer shares, so it "+
			"cannot edit one header profile: give it to EnableSecurityHeaders", option)
	}

	return nil
}

// editProfile applies the profile editors in opts to p, and returns the result
// carrying the first fault.
func editProfile(p HeaderProfile, opts []HeaderOption) HeaderProfile {
	scratch := &securityHeaders{document: p, scoped: true}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		if err := opt(scratch); err != nil {
			scratch.document.err = err

			break
		}
	}

	return scratch.document
}

// NewHeaderProfile is a profile that sends no header, edited by opts with the
// same editors that edit the document profile: WithHeader, WithoutHeader and
// WithCSP. It is the base for a consumer's own profile.
//
// Default: no header. An option that sets something the whole layer shares,
// such as WithHSTS, or that is not a header editor fails construction when the
// profile reaches WithHeaderProfile.
func NewHeaderProfile(opts ...HeaderOption) HeaderProfile {
	return editProfile(HeaderProfile{}, opts)
}

// EnableSecurityHeaders sets security response headers on every response the
// chain produces.
//
// Default: off. Once enabled, with no options, a response carries a
// Content-Security-Policy with a fresh nonce, 'strict-dynamic', object-src
// 'none', base-uri 'none' and frame-ancestors 'none' (WithCSP, HashCSP);
// X-Content-Type-Options: nosniff; Referrer-Policy:
// strict-origin-when-cross-origin; and Cross-Origin-Opener-Policy:
// same-origin-allow-popups (WithHeader, WithoutHeader). X-XSS-Protection,
// X-Frame-Options, Cross-Origin-Embedder-Policy and Origin-Agent-Cluster are
// never sent unless a consumer adds them with WithHeader. A secure response
// also carries Strict-Transport-Security: max-age=31536000; includeSubDomains,
// and a plain-HTTP one never does (WithHSTS).
//
// The policy is enforced by default. WithCSPReportOnly sends it as
// Content-Security-Policy-Report-Only instead, WithCSPReportOnlyPolicy sends a
// candidate beside the enforced one with the same nonce, and
// WithReportingEndpoint names where reports go; by default none is named and
// the policy carries no report-to or report-uri. WithHeaderProfile gives the
// routes a matcher selects the API profile (APIHeaders) or one of the
// consumer's own (NewHeaderProfile), both edited with the same editors; by
// default every route gets the document set.
//
// The layer runs in OrderSecurityHeaders, outside every built-in interceptor,
// and sets its headers before calling the next one, without wrapping the
// response writer: a handler's own value for a header wins, and flushing and
// hijacking work as without the layer. A host refusal, which no interceptor
// sees, carries the headers too. A handler reads the response's nonce with
// CSPNonce.
//
// The limit: a consumer interceptor registered ahead of OrderSecurityHeaders,
// such as at Before(OrderSecurityHeaders), runs outside the layer, and a
// response it writes carries no security headers. Register a consumer
// interceptor at or after the layer's slot to have its responses marked.
//
// Enabling the layer twice fails construction.
func EnableSecurityHeaders(opts ...HeaderOption) Option {
	const option = "EnableSecurityHeaders"

	return func(c *config) error {
		dup := eachInterceptor(c, func(*securityHeaders) error {
			return newConfigError("%s was given twice; one chain has one security-headers layer", option)
		})
		if dup != nil {
			return dup
		}

		l := &securityHeaders{document: documentProfile(), hsts: &hstsPolicy{maxAge: 365 * 24 * time.Hour, subdomains: true}, random: rand.Reader}

		for _, opt := range opts {
			if opt == nil {
				continue
			}

			if err := opt(l); err != nil {
				return err
			}
		}

		if err := l.finish(); err != nil {
			return err
		}

		c.register(l, OrderSecurityHeaders)
		c.wire(func(ch *Chain) {
			ch.headers = l
			l.failed = func(ex *Exchange) {
				for _, step := range ch.refusalSteps {
					step(ex)
				}
			}
		})

		return nil
	}
}

// nonceContextKey is the context key the response's nonce is stored under.
type nonceContextKey struct{}

// CSPNonce returns the nonce the security-headers layer put in this request's
// Content-Security-Policy, for the handler to put on its script tags. It
// reports false when the layer did not serve the request with a nonce: it is
// not enabled, the route's profile carries none, or the context is not the
// chain's.
func CSPNonce(ctx context.Context) (string, bool) {
	n, ok := ctx.Value(nonceContextKey{}).(string)

	return n, ok
}

// Intercept sets the headers, and the nonce on the context, and calls next.
func (l *securityHeaders) Intercept(ex *Exchange, next Next) error {
	profile := l.profileFor(ex.Request)

	nonce := ""

	if profile.usesNonce() {
		var err error

		if nonce, err = l.newNonce(); err != nil {
			// The headers still go out, without a nonce: the policy then
			// admits no script at all, which is the safe reading of a failed
			// random source. The request itself fails.
			l.apply(ex.Writer, profile, "", ex.Request.Secure())

			if l.failed != nil {
				l.failed(ex)
			}

			return diag.Wrap(err, "httpsec: the CSP nonce could not be generated")
		}

		ex.SetContext(context.WithValue(ex.Context(), nonceContextKey{}, nonce))
	}

	l.apply(ex.Writer, profile, nonce, ex.Request.Secure())

	return next(ex)
}

// newNonce returns 16 random bytes, base64-encoded.
func (l *securityHeaders) newNonce() (string, error) {
	b := make([]byte, nonceBytes)

	if _, err := io.ReadFull(l.random, b); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

// apply sets profile's headers on w, and HSTS when secure. nonce is "" when
// none was generated.
func (l *securityHeaders) apply(w ResponseWriter, profile HeaderProfile, nonce string, secure bool) {
	for _, h := range profile.headers {
		value := h.value
		if h.policy != nil {
			value = h.policy.render(nonce)
		}

		w.SetHeader(h.name, value)
	}

	if secure && l.hsts != nil {
		w.SetHeader(headerHSTS, l.hsts.String())
	}
}

// applyHeaders is the step the chain runs on a response written outside the
// layer's slot: a host refusal, returned before any interceptor runs. It sets
// the headers the layer would set for req, with no nonce, because no handler
// will read one.
func (l *securityHeaders) applyHeaders(w ResponseWriter, req Request) {
	l.apply(w, l.profileFor(req), "", req.Secure())
}

// WithCSP replaces the Content-Security-Policy of the document profile, or of
// the profile being built by APIHeaders or NewHeaderProfile, with p.
//
// Default: StrictCSP() with no directives added. A policy that fails its own
// check (see CSPDirective), or that holds no directive at all (the zero
// CSPPolicy, or one built from it with nothing added), fails construction
// here. To send no policy, use WithoutHeader("Content-Security-Policy").
func WithCSP(p CSPPolicy) HeaderOption {
	return func(l *securityHeaders) error {
		if p.err != nil {
			return newConfigError("WithCSP was given a policy that cannot be sent: %s", p.err)
		}

		if len(p.directives) == 0 {
			return newConfigError("WithCSP was given a policy with no directive; remove the header with WithoutHeader to send none")
		}

		l.document.set(profileHeader{name: headerCSP, policy: &p})

		return nil
	}
}

// WithHeader sets the document profile's header name to value, replacing the
// default's value or adding a header the default does not send. Setting
// Content-Security-Policy this way replaces the whole policy with a fixed
// string and generates no nonce for it: use WithCSP to keep the nonce.
//
// Default: the headers named on EnableSecurityHeaders. A name that is not an
// HTTP token, or a value holding a control character, fails construction. So
// does an empty or blank value for Content-Security-Policy or
// Content-Security-Policy-Report-Only, as WithCSP does for a policy with no
// directive: to send no policy, use WithoutHeader("Content-Security-Policy").
func WithHeader(name, value string) HeaderOption {
	return func(l *securityHeaders) error {
		if !isHeaderToken(name) {
			return newConfigError("WithHeader was given %q, which is not an HTTP header name", name)
		}

		canonical := textproto.CanonicalMIMEHeaderKey(name)
		if (canonical == headerCSP || canonical == headerCSPReportOnly) && strings.TrimSpace(value) == "" {
			return newConfigError("WithHeader was given an empty %s; remove the header with WithoutHeader to send none", canonical)
		}

		if hasControl(value) {
			return newConfigError("WithHeader was given a value for %s holding a control character or line break", name)
		}

		if canonical == headerHSTS {
			return newConfigError("WithHeader was given %s: set it with WithHSTS, which keeps it "+
				"off plain-HTTP responses and refuses an unsafe preload", headerHSTS)
		}

		l.document.set(profileHeader{name: canonical, value: value})

		return nil
	}
}

// WithoutHeader stops the document profile sending the header name.
//
// Default: the headers named on EnableSecurityHeaders. Removing
// Content-Security-Policy also stops the nonce being generated.
func WithoutHeader(name string) HeaderOption {
	return func(l *securityHeaders) error {
		if !isHeaderToken(name) {
			return newConfigError("WithoutHeader was given %q, which is not an HTTP header name", name)
		}

		canonical := textproto.CanonicalMIMEHeaderKey(name)
		if canonical == headerHSTS {
			if err := l.layerWide("WithoutHeader(" + headerHSTS + ")"); err != nil {
				return err
			}

			l.hsts = nil
		}

		l.document.remove(canonical)

		return nil
	}
}

// forbidsFraming reports whether the document profile enforces a policy limiting
// who may frame it. It reads only the document profile: a route-matched profile
// is chosen per request, and cannot be seen at construction.
//
// Only a frame-ancestors made of 'none', 'self' (keywords in any case) and
// named https origins limits it: a wildcard source, a scheme-only source, a
// wildcard host or an http origin lets pages the consumer does not control
// frame it, and no directive leaves them open. A policy set with WithHeader is
// read from its text, the first frame-ancestors directive deciding as a browser
// does.
func (l *securityHeaders) forbidsFraming() bool {
	h, ok := l.document.find(headerCSP)
	if !ok {
		return false
	}

	if h.policy != nil {
		for _, d := range h.policy.directives {
			if strings.EqualFold(d.name, "frame-ancestors") {
				return limitsFraming(d.sources)
			}
		}

		return false
	}

	for _, directive := range strings.Split(h.value, ";") {
		fields := strings.Fields(directive)
		if len(fields) > 0 && strings.EqualFold(fields[0], "frame-ancestors") {
			return limitsFraming(fields[1:])
		}
	}

	return false
}

// limitsFraming reports whether every source of a frame-ancestors directive is
// 'none', 'self' or a named https origin, and there is at least one.
func limitsFraming(sources []string) bool {
	if len(sources) == 0 {
		return false
	}

	return !slices.ContainsFunc(sources, func(src string) bool {
		switch strings.ToLower(src) {
		case "'self'", "'none'":
			return false
		}

		rest, ok := strings.CutPrefix(strings.ToLower(src), "https://")

		return !ok || rest == "" || strings.ContainsAny(rest, "*'")
	})
}

// set replaces the header of h's name in place, or appends h.
func (p *HeaderProfile) set(h profileHeader) {
	for i := range p.headers {
		if p.headers[i].name == h.name {
			p.headers[i] = h

			return
		}
	}

	p.headers = append(p.headers, h)
}

// find returns the header named name.
func (p HeaderProfile) find(name string) (profileHeader, bool) {
	for _, h := range p.headers {
		if h.name == name {
			return h, true
		}
	}

	return profileHeader{}, false
}

// remove drops the header named name.
func (p *HeaderProfile) remove(name string) {
	p.headers = slices.DeleteFunc(p.headers, func(h profileHeader) bool { return h.name == name })
}

// hasControl reports whether s holds a control character, a line break
// included: the characters that would split a header or smuggle a second one.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// isHeaderToken reports whether name is a valid HTTP header field name.
func isHeaderToken(name string) bool {
	return name != "" && !strings.ContainsFunc(name, func(r rune) bool {
		return r <= 0x20 || r >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", r)
	})
}

// RouteMatcher selects the requests a header profile applies to. It reads the
// request only: the layer never chooses a profile by inspecting the response.
type RouteMatcher func(Request) bool

// PathPrefix selects the requests whose path is under prefix, matching whole
// path segments: "/api/" selects "/api" and "/api/orders" and not "/apix".
// Matching is exact and case-sensitive. A prefix that does not start with "/"
// is read as if it did.
func PathPrefix(prefix string) RouteMatcher {
	base := strings.TrimRight(prefix, "/")
	if !strings.HasPrefix(base, "/") && base != "" {
		base = "/" + base
	}

	return func(r Request) bool {
		path := r.Path()

		return base == "" || path == base || strings.HasPrefix(path, base+"/")
	}
}

// APIHeaders is the profile for routes that serve data, not pages:
// Content-Security-Policy: default-src 'none'; frame-ancestors 'none',
// X-Content-Type-Options: nosniff and Referrer-Policy: no-referrer, and no
// nonce.
//
// opts edit it with the editors that edit the document profile (WithHeader,
// WithoutHeader, WithCSP). Default: no edit. An option that sets something the
// whole layer shares, such as WithHSTS, fails construction when the profile
// reaches WithHeaderProfile.
func APIHeaders(opts ...HeaderOption) HeaderProfile {
	csp := CSPPolicy{directives: []CSPDirectiveValue{
		CSPDirective("default-src", "'none'"),
		CSPDirective("frame-ancestors", "'none'"),
	}}

	return editProfile(HeaderProfile{headers: []profileHeader{
		{name: headerCSP, policy: &csp},
		{name: headerContentType, value: "nosniff"},
		{name: headerReferrerPolicy, value: "no-referrer"},
	}}, opts)
}

// WithHeaderProfile gives the requests m selects the headers of p instead of
// the document set. Profiles are tried in the order given and the first whose
// matcher selects a request applies; a request none selects gets the document
// set.
//
// Default: no profile, so every request gets the document set. A nil matcher
// fails construction: it would select nothing, and the profile would never
// apply.
//
// The matcher is a function, so New cannot read the paths it compares and does
// not check it against WithBasePath: a matcher written for an endpoint's path
// without the base path silently stops selecting that endpoint once a base path
// moves it. Compare the resolved paths, which Chain.Endpoints lists
// (WithoutBasePathRouteCheck covers only the routes given as paths).
func WithHeaderProfile(p HeaderProfile, m RouteMatcher) HeaderOption {
	return func(l *securityHeaders) error {
		if err := l.layerWide("WithHeaderProfile"); err != nil {
			return err
		}

		if p.err != nil {
			return newConfigError("WithHeaderProfile was given a profile that cannot be sent: %s", p.err)
		}

		if m == nil {
			return newConfigError("WithHeaderProfile was given no route matcher, so its profile would never apply")
		}

		l.profiles = append(l.profiles, routedProfile{profile: p, matches: m})

		return nil
	}
}

// routedProfile is a profile and the matcher choosing it.
type routedProfile struct {
	profile HeaderProfile
	matches RouteMatcher
}

// profileFor is the first registered profile whose matcher selects r, or the
// document profile.
func (l *securityHeaders) profileFor(r Request) HeaderProfile {
	for _, rp := range l.profiles {
		if rp.matches(r) {
			return rp.profile
		}
	}

	return l.document
}

const (
	headerHSTS = "Strict-Transport-Security"

	// preloadMinAge is the least max-age hstspreload.org accepts.
	preloadMinAge = 365 * 24 * time.Hour
)

// hstsPolicy is the Strict-Transport-Security header's settings.
type hstsPolicy struct {
	maxAge     time.Duration
	subdomains bool
	preload    bool
}

// String is the header's value.
func (h hstsPolicy) String() string {
	v := "max-age=" + strconv.FormatInt(int64(h.maxAge/time.Second), 10)
	if h.subdomains {
		v += "; includeSubDomains"
	}

	if h.preload {
		v += "; preload"
	}

	return v
}

// HSTSOption adjusts the Strict-Transport-Security header WithHSTS sets.
type HSTSOption func(*hstsPolicy)

// HSTSIncludeSubdomains sends includeSubDomains. It is the default, and is
// named so a consumer's intent reads at the call.
func HSTSIncludeSubdomains() HSTSOption { return func(h *hstsPolicy) { h.subdomains = true } }

// WithoutHSTSSubdomains drops includeSubDomains, replacing the default that
// sends it.
func WithoutHSTSSubdomains() HSTSOption { return func(h *hstsPolicy) { h.subdomains = false } }

// HSTSPreload adds the preload token. It is never a default: hstspreload.org
// asks tooling not to enable it, and removal from the list takes months.
// WithHSTS refuses it with a max-age below one year or without
// includeSubDomains, which the list does not accept.
func HSTSPreload() HSTSOption { return func(h *hstsPolicy) { h.preload = true } }

// WithHSTS sets the Strict-Transport-Security header's maximum age and options.
//
// Default: max-age=31536000; includeSubDomains, sent only on a response to a
// request the chain judges secure (Request.Secure: TLS, WithHTTPSDeployment, or
// a trusted proxy's forwarded scheme), because RFC 6797 has a client ignore the
// header over plain HTTP. A zero age is allowed, to withdraw an earlier policy;
// a negative or sub-second age, preload below one year or without
// includeSubDomains fails construction. Use WithoutHeader to stop sending it.
func WithHSTS(maxAge time.Duration, opts ...HSTSOption) HeaderOption {
	return func(l *securityHeaders) error {
		if err := l.layerWide("WithHSTS"); err != nil {
			return err
		}

		h := hstsPolicy{maxAge: maxAge, subdomains: true}

		for _, opt := range opts {
			if opt != nil {
				opt(&h)
			}
		}

		switch {
		case maxAge < 0:
			return newConfigError("WithHSTS was given a negative maximum age, %s", maxAge)
		case maxAge%time.Second != 0:
			return newConfigError("WithHSTS was given %s, which is not a whole number of seconds: "+
				"the header would be truncated, and under a second it would withdraw the policy", maxAge)
		case h.preload && maxAge < preloadMinAge:
			return newConfigError("WithHSTS was given preload with a maximum age of %s: "+
				"preload needs at least one year", maxAge)
		case h.preload && !h.subdomains:
			return newConfigError("WithHSTS was given preload without includeSubDomains: " +
				"preload needs it")
		}

		l.hsts = &h

		return nil
	}
}
