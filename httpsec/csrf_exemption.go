package httpsec

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// csrfWildcard is the path pattern segment that matches any one segment.
const csrfWildcard = "*"

// csrfExemption is one route CSRF protection does not judge: an exact method
// and an exact path, or a path pattern whose wildcard segments match one path
// segment each, or a literal prefix followed by one segment.
type csrfExemption struct {
	method  string
	pattern string

	// segments are the pattern's segments after its leading "/", and nil when
	// it has no wildcard and is compared as a whole.
	segments []string

	// prefix, when set, makes the exemption the back-channel logout
	// endpoint's: prefix, compared as a literal, followed by exactly one
	// provider segment. pattern and segments are then unused.
	prefix string
}

// matches reports whether the request's method and its path as sent
// (Request.EscapedPath) name this exempt route. Nothing is cleaned, folded or
// decoded before the comparison, so a path a router would redirect, or
// another route's path written differently or encoded differently, never
// matches.
func (e csrfExemption) matches(method, path string) bool {
	if method != e.method {
		return false
	}

	if e.prefix != "" {
		rest, ok := strings.CutPrefix(path, e.prefix)

		// A provider segment holding an escape could decode to a "/", which
		// would make it another route; a provider's name needs none.
		return ok && !strings.Contains(rest, "%") && oneRealSegment(rest)
	}

	if e.segments == nil {
		return path == e.pattern
	}

	rest, ok := strings.CutPrefix(path, "/")
	if !ok {
		return false
	}

	parts := strings.Split(rest, "/")
	if len(parts) != len(e.segments) {
		return false
	}

	for i, seg := range e.segments {
		if seg != csrfWildcard {
			if parts[i] != seg {
				return false
			}

			continue
		}

		// A wildcard stands for one real segment, judged as it decodes: an
		// encoded "/" would make it two, and an encoded dot segment is a path
		// a router cleans into another route.
		decoded, err := url.PathUnescape(parts[i])
		if err != nil || !oneRealSegment(decoded) {
			return false
		}
	}

	return true
}

// oneRealSegment reports whether seg is one path segment a router keeps as
// it is: not empty, not "." or "..", and holding no "/".
func oneRealSegment(seg string) bool {
	return seg != "" && seg != "." && seg != ".." && !strings.Contains(seg, "/")
}

// WithCSRFExemption exempts one route from CSRF protection: requests whose
// method is exactly method and whose path is exactly pattern skip both the
// Fetch Metadata and Origin check and the token check. It is meant for routes
// another server calls, such as a payment provider's webhook, which carry no
// browser signals the check could trust and no sign-in's token.
//
// The path compared is the path as the client sent it (Request.EscapedPath:
// neither decoded nor cleaned), and the comparison is exact: a trailing
// slash, a change of case, dot segments, or any percent-encoding the pattern
// does not spell names another route, which is judged as an ordinary one, so
// "/webhooks%2Fpayments" is not "/webhooks/payments", whatever a router makes
// of it. Write a pattern as clients send it: a character a request always
// escapes is written escaped, "/webhooks/caf%C3%A9" and not "/webhooks/café".
// A pattern segment "*" matches exactly one path segment which, decoded, is
// not empty, "." or ".." and holds no "/", so "/webhooks/*/events" matches
// "/webhooks/stripe/events" and not "/webhooks/a/b/events" or
// "/webhooks/a%2Fb/events". Every other protection the chain applies still
// applies to an exempt route. Exemptions accumulate; give the option once per
// route.
//
// Default: no route is exempt, apart from the OIDC back-channel logout
// endpoint (see WithoutBackchannelLogoutExemption) and, with EnableOIDCProvider,
// POST to the provider's authorization, token, revocation, introspection and
// end-session endpoints. A route the consumer also exempts is exempt once, and
// builds. There is no option
// exempting every route: that is WithoutCSRFProtection.
//
// Construction fails with ErrConfig when:
//   - method is empty, not a single method name, or GET, HEAD or OPTIONS
//     (never judged, so exempting it is meaningless);
//   - pattern is empty, does not start with "/", is "/" alone, has an empty
//     interior segment, a "." or ".." segment, a "*" inside a segment, or no
//     segment other than "*";
//   - a fixed segment is a malformed percent-encoding ("%zz"), decodes to "."
//     or ".." ("%2e%2e") or to one holding "/" ("a%2Fb"), or holds a character
//     a request escapes (a space, "é"): it could never match, so it must be
//     written in its escaped form ("a%20b", "caf%C3%A9").
func WithCSRFExemption(method, pattern string) CSRFOption {
	const option = "WithCSRFExemption"

	return func(l *csrfLayer) error {
		switch {
		case method == "":
			return newConfigError("%s(%q, %q) names no method; an exemption is of one exact method", option, method, pattern)
		case !isCORSToken(method):
			return newConfigError("%s was given the method %q, which is not a single method name", option, method)
		case isSafeMethod(method):
			return newConfigError("%s was given %s, which CSRF protection never judges; exempting it changes nothing", option, method)
		}

		e, err := parseCSRFExemption(method, pattern)
		if err != nil {
			return newConfigError("%s(%q, %q): %s", option, method, pattern, err)
		}

		l.exemptions = append(l.exemptions, e)

		return nil
	}
}

// parseCSRFExemption validates pattern and builds the exemption of method on
// it.
func parseCSRFExemption(method, pattern string) (csrfExemption, error) {
	switch {
	case pattern == "":
		return csrfExemption{}, errors.New("the path is empty")
	case pattern[0] != '/':
		return csrfExemption{}, errors.New("the path must start with \"/\"")
	case pattern == "/":
		return csrfExemption{}, errors.New("the root path \"/\" alone is never exempt")
	}

	segments := strings.Split(pattern[1:], "/")
	wild, literal := false, false

	for i, seg := range segments {
		if err := checkExemptionSegment(seg); err != nil {
			return csrfExemption{}, err
		}

		switch {
		case seg == "" && i < len(segments)-1:
			return csrfExemption{}, errors.New("the path has an empty segment")
		case seg == "." || seg == "..":
			return csrfExemption{}, errors.New("the path has a dot segment")
		case seg == csrfWildcard:
			wild = true
		case strings.Contains(seg, csrfWildcard):
			return csrfExemption{}, errors.New("a wildcard \"*\" is a whole segment")
		case seg != "":
			literal = true
		}
	}

	if !literal {
		return csrfExemption{}, errors.New("the path has no segment other than a wildcard")
	}

	e := csrfExemption{method: method, pattern: pattern}
	if wild {
		e.segments = segments
	}

	return e, nil
}

// checkExemptionSegment refuses a fixed segment that is not a well-formed
// escape, that decodes to a dot segment or to one holding "/" (a router that
// decodes it would hand the handler a path other than the one written), or
// that holds a character a request always escapes: such a segment is compared
// with the path as sent, so it could never match.
func checkExemptionSegment(seg string) error {
	if seg == "" || seg == csrfWildcard {
		return nil
	}

	decoded, err := url.PathUnescape(seg)

	switch {
	case err != nil:
		return errors.New("a segment is not a well-formed percent-encoding")
	case decoded == "." || decoded == "..":
		return errors.New("the path has a dot segment")
	case strings.Contains(decoded, "/"):
		return errors.New("a segment decodes to one holding \"/\"")
	}

	// RawPath keeps the escapes and the characters a client may send as they
	// are; what a request escapes (non-ASCII, a space) is escaped, and so
	// differs from the segment.
	if (&url.URL{Path: "/" + decoded, RawPath: "/" + seg}).EscapedPath() != "/"+seg {
		escaped := (&url.URL{Path: "/" + decoded}).EscapedPath()[1:]

		return fmt.Errorf("a segment holds a character a request escapes; write it in its escaped form, %q", escaped)
	}

	return nil
}

// WithoutBackchannelLogoutExemption judges the OIDC back-channel logout
// endpoint as an ordinary route.
//
// Default: with EnableOIDCLogin, POST to the back-channel logout path followed
// by one provider segment (DefaultOIDCBackchannelPath, or the path
// WithOIDCBackchannelLogoutPath sets) is exempt, because the identity provider
// calls it server to server, and its signed logout token is its credential.
// The path is compared with the path as sent, as a literal: a "*" in it is
// that character, never a wildcard. A provider sends no Origin and no
// Sec-Fetch-Site, which the check passes in any case; remove the exemption to
// have a browser's request there judged as well.
func WithoutBackchannelLogoutExemption() CSRFOption {
	return func(l *csrfLayer) error {
		l.noBackchannel = true

		return nil
	}
}

// settleExemptions settles the exempt routes: those WithCSRFExemption names,
// the OpenID Provider's protocol endpoints when the chain has one (see
// providerExemptions) and, unless WithoutBackchannelLogoutExemption was given,
// the back-channel logout endpoint of every OIDC login on the chain. An
// exemption that cannot be built fails construction, rather than being
// dropped.
func (l *csrfLayer) settleExemptions(c *config) error {
	l.exempt = slices.Clone(l.exemptions)
	l.exempt = append(l.exempt, providerExemptions(c.oidcProvider)...)

	if l.noBackchannel {
		return nil
	}

	return eachInterceptor(c, func(i *oidcInterceptor) error {
		e, err := backchannelExemption(i.backchannelPath)
		if err != nil {
			return newConfigError("the CSRF exemption of the OIDC back-channel logout endpoint cannot be built "+
				"from WithOIDCBackchannelLogoutPath(%q): %s; give a path a router keeps as it is, or "+
				"judge the endpoint with WithoutBackchannelLogoutExemption", i.backchannelPath, err)
		}

		l.exempt = append(l.exempt, e)

		return nil
	})
}

// providerEndpointsExempt are the provider's endpoints a relying party reaches
// cross-site by design: none takes a state-changing decision from a cookie
// alone. The resume, the logout confirmation, the user's consents and UserInfo
// are not among them, and stay judged.
var providerEndpointsExempt = [...]OIDCEndpoint{
	OIDCAuthorize, OIDCToken, OIDCRevoke, OIDCIntrospect, OIDCEndSession,
}

// providerExemptions is the exemption of POST to each of providerEndpointsExempt,
// at the path the provider settled for it, so a moved path or prefix is followed.
// Each is the exact path, compared as a literal with the path as sent: a "*" in
// it is that character, and an escaped spelling of it is another route, which is
// judged. A chain with no provider has none.
func providerExemptions(op *oidcEndpoints) []csrfExemption {
	if op == nil {
		return nil
	}

	exemptions := make([]csrfExemption, 0, len(providerEndpointsExempt))

	for _, e := range providerEndpointsExempt {
		exemptions = append(exemptions, csrfExemption{method: http.MethodPost, pattern: op.paths[e]})
	}

	return exemptions
}

// backchannelExemption builds the exemption of POST to prefix followed by one
// provider segment. prefix is a literal, never a pattern; it always ends in
// "/" (oidcPrefix). One holding an escape, a character a request escapes
// (its escaped form differs from itself), an empty interior segment or a dot
// segment is refused: it would name a path other than the one the endpoint
// answers once decoded or cleaned.
func backchannelExemption(prefix string) (csrfExemption, error) {
	if strings.Contains(prefix, "%") {
		return csrfExemption{}, errors.New("the path holds a percent-encoding")
	}

	// RawPath keeps the characters a client may send as they are, such as "*";
	// what it cannot hold (non-ASCII, a space) is escaped, and so differs.
	if (&url.URL{Path: prefix, RawPath: prefix}).EscapedPath() != prefix {
		return csrfExemption{}, errors.New("the path holds a character a request escapes")
	}

	for _, seg := range strings.Split(strings.TrimSuffix(prefix[1:], "/"), "/") {
		switch seg {
		case "":
			return csrfExemption{}, errors.New("the path has an empty segment")
		case ".", "..":
			return csrfExemption{}, errors.New("the path has a dot segment")
		}
	}

	return csrfExemption{method: http.MethodPost, prefix: prefix}, nil
}

// exempts reports whether the request names an exempt route.
func (l *csrfLayer) exempts(req Request) bool {
	method, path := req.Method(), req.EscapedPath()

	return slices.ContainsFunc(l.exempt, func(e csrfExemption) bool { return e.matches(method, path) })
}
