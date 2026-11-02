package httpsec

import (
	"errors"
	"net/http"
	"slices"
	"strings"
)

// csrfWildcard is the path pattern segment that matches any one segment.
const csrfWildcard = "*"

// csrfExemption is one route CSRF protection does not judge: an exact method
// and an exact path, or a path pattern whose wildcard segments match one path
// segment each.
type csrfExemption struct {
	method  string
	pattern string

	// segments are the pattern's segments after its leading "/", and nil when
	// it has no wildcard and is compared as a whole.
	segments []string
}

// matches reports whether the request's method and its routed path, as
// Request.Path returns it, name this exempt route. Nothing is cleaned, folded
// or decoded further, so a path a router would redirect, or another route's
// path written differently, never matches.
func (e csrfExemption) matches(method, path string) bool {
	if method != e.method {
		return false
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

		// A wildcard stands for one real segment: an empty or dot segment is
		// a path a router cleans into another route.
		if parts[i] == "" || parts[i] == "." || parts[i] == ".." {
			return false
		}
	}

	return true
}

// WithCSRFExemption exempts one route from CSRF protection: requests whose
// method is exactly method and whose path is exactly pattern skip both the
// Fetch Metadata and Origin check and the token check. It is meant for routes
// another server calls, such as a payment provider's webhook, which carry no
// browser signals the check could trust and no sign-in's token.
//
// The path compared is the one the chain routes by (Request.Path: decoded,
// never cleaned), and the comparison is exact: a trailing slash, a change of
// case, dot segments, or an encoding that decodes to any of those names
// another route, which is judged as an ordinary one. A pattern segment "*"
// matches exactly one path segment that is not empty, "." or "..", so
// "/webhooks/*/events" matches "/webhooks/stripe/events" and not
// "/webhooks/a/b/events". Every other protection the chain applies still
// applies to an exempt route. Exemptions accumulate; give the option once per
// route.
//
// Default: no route is exempt, apart from the OIDC back-channel logout
// endpoint (see WithoutBackchannelLogoutExemption). There is no option
// exempting every route: that is WithoutCSRFProtection. Construction fails
// with ErrConfig when method is empty, not a single method name, or GET, HEAD
// or OPTIONS (never judged, so exempting it is meaningless), or when pattern
// is empty, does not start with "/", is "/" alone, has an empty interior
// segment, a "." or ".." segment, a "*" inside a segment, or no segment other
// than "*".
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

// WithoutBackchannelLogoutExemption judges the OIDC back-channel logout
// endpoint as an ordinary route.
//
// Default: with EnableOIDCLogin, POST to the back-channel logout path followed
// by one provider segment (DefaultOIDCBackchannelPath, or the path
// WithOIDCBackchannelLogoutPath sets) is exempt, because the identity provider
// calls it server to server, and its signed logout token is its credential. A
// provider sends no Origin and no Sec-Fetch-Site, which the check passes in
// any case; remove the exemption to have a browser's request there judged as
// well.
func WithoutBackchannelLogoutExemption() CSRFOption {
	return func(l *csrfLayer) error {
		l.noBackchannel = true

		return nil
	}
}

// settleExemptions settles the exempt routes: those WithCSRFExemption names
// and, unless WithoutBackchannelLogoutExemption was given, the back-channel
// logout endpoint of every OIDC login on the chain.
func (l *csrfLayer) settleExemptions(c *config) {
	l.exempt = slices.Clone(l.exemptions)

	if l.noBackchannel {
		return
	}

	_ = eachInterceptor(c, func(i *oidcInterceptor) error {
		// The back-channel prefix always ends in "/", and a provider is one
		// segment after it (providerSegment).
		e, err := parseCSRFExemption(http.MethodPost, i.backchannelPath+csrfWildcard)
		if err == nil {
			l.exempt = append(l.exempt, e)
		}

		return nil
	})
}

// exempts reports whether the request names an exempt route.
func (l *csrfLayer) exempts(req Request) bool {
	method, path := req.Method(), req.Path()

	return slices.ContainsFunc(l.exempt, func(e csrfExemption) bool { return e.matches(method, path) })
}
