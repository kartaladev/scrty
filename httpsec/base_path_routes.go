package httpsec

import (
	"slices"
	"strings"
)

// optionWithoutBasePathRouteCheck names the waiver of the stale-route check in
// the refusal that offers it.
const optionWithoutBasePathRouteCheck = "WithoutBasePathRouteCheck"

// WithoutBasePathRouteCheck lets a chain with a base path be built although a
// route the consumer gave it names the path a built-in endpoint answered at
// before the base path moved it.
//
// Default: with WithBasePath, New compares each recovery cool-down route
// (EnableRecoveryCooldown) and each cross-site exemption (WithCSRFExemption)
// with the paths the built-in endpoints would have had without the base path,
// and refuses a route that would match one of them, naming the route, the
// setting that gave it and the endpoint now answering under the base. Such a
// route no longer matches the endpoint, so a cool-down route left there lets a
// sensitive action through while the cool-down runs, and an exemption there
// leaves the endpoint judged by CSRF protection.
//
// Give this option when the consumer serves a route of their own at such a
// path, for instance a "/sign-in/password" that is exempt from CSRF protection
// because the application answers it. What it gives up: a route that was
// meant for a built-in endpoint and was not moved with it goes unnoticed, and
// stays in force on nothing, until a request shows it. Without a base path
// nothing is checked, and the option changes nothing.
//
// Routes given as functions, such as the matcher of WithHeaderProfile, are not
// checked either way: the library cannot read them. Chain.Endpoints lists the
// resolved paths to compare them with.
func WithoutBasePathRouteCheck() Option {
	return func(c *config) error {
		c.routeCheckWaived = true

		return nil
	}
}

// movedEndpoint is a built-in operation the base path moved, with the path it
// answered at before: its resolved path without the base, cut before the first
// segment it reads.
type movedEndpoint struct {
	endpoint Endpoint
	declared string // "/reauth/password"; for a segment endpoint, "/sso/login"; an exact path keeps its trailing slash
}

// matchedPrefix is an inventory path as the endpoint matches it: cut before the
// first segment it reads, and, for a segment or subtree endpoint, without the
// trailing slash that cut leaves. An exact path keeps its trailing slash, since
// the exact match compares it.
func matchedPrefix(path string, match PathMatch) string {
	if i := strings.IndexByte(path, '{'); i >= 0 {
		path = path[:i]
	}

	if match != MatchExact {
		path = strings.TrimSuffix(path, "/")
	}

	return path
}

// currentEndpoints are every inventory entry at the path it answers at now,
// base path included, in the form movedEndpoint compares in.
func currentEndpoints(endpoints []Endpoint) []movedEndpoint {
	current := make([]movedEndpoint, 0, len(endpoints))

	for _, e := range endpoints {
		current = append(current, movedEndpoint{endpoint: e, declared: matchedPrefix(e.Path, e.Match)})
	}

	return current
}

// movedEndpoints are the entries of the inventory that sit under the base path.
// The provider's discovery documents are left out: the issuer places them, so
// the base path did not move them, and an entry outside the base path was never
// moved by it.
func movedEndpoints(base string, endpoints []Endpoint) []movedEndpoint {
	moved := make([]movedEndpoint, 0, len(endpoints))

	for _, e := range endpoints {
		if e.PlacedBy == optionOIDCProvider {
			continue
		}

		rest, ok := strings.CutPrefix(e.Path, base+"/")
		if !ok || rest == "" {
			continue
		}

		declared := matchedPrefix("/"+rest, e.Match)
		if declared == "" {
			continue
		}

		moved = append(moved, movedEndpoint{endpoint: e, declared: declared})
	}

	return moved
}

// checkStaleRoutes refuses the consumer routes left at an endpoint's pre-base
// path. It does nothing without a base path, or when the consumer waived the
// check (WithoutBasePathRouteCheck).
//
// It reads the resolved inventory and takes the base off each path, rather
// than reading each built-in's declared path: the inventory lists every
// built-in with its match kind, so a new built-in is checked without a change
// here, and a route that names a path the base path left alone never
// qualifies.
func checkStaleRoutes(c *config, endpoints []Endpoint) error {
	if c.basePath == "" || c.routeCheckWaived {
		return nil
	}

	moved := movedEndpoints(c.basePath, endpoints)
	if len(moved) == 0 {
		return nil
	}

	current := currentEndpoints(endpoints)

	err := eachInterceptor(c, func(g *recoveryCooldown) error { return g.checkStale(moved, current) })
	if err != nil {
		return err
	}

	return eachInterceptor(c, func(l *csrfLayer) error { return l.checkStale(moved, current) })
}

// staleRouteError is the refusal naming the route, the setting that gave it
// and the endpoint it was meant for.
func staleRouteError(setting, route string, m movedEndpoint) error {
	return newConfigError("%s was given the route %s, which is where %s answered before the base path "+
		"moved it to %s; write the route with the base path, or give %s if the application serves that "+
		"path itself",
		setting, route, m.endpoint.OperationID, m.endpoint.Path, optionWithoutBasePathRouteCheck)
}

// coversNormalised reports whether a path in the cool-down's normal form (lower-case,
// no trailing slash) is one the endpoint matches at its declared path: the
// declared path itself for an exact endpoint; it or a path beneath it for a
// subtree; the declared path followed by one segment for a segment endpoint.
func (m movedEndpoint) coversNormalised(path string) bool {
	declared := strings.ToLower(strings.TrimSuffix(m.declared, "/"))

	switch m.endpoint.Match {
	case MatchSubtree:
		return path == declared || strings.HasPrefix(path, declared+"/")
	case MatchSegment:
		rest, ok := strings.CutPrefix(path, declared+"/")

		return ok && rest != "" && !strings.Contains(rest, "/")
	default:
		return path == declared
	}
}

// checkStale refuses a marked route that names a moved endpoint's old path, in
// the form the cool-down compares in. A route is checked against the
// operations whose method it names, since another method on that path is not
// the endpoint's request. A route that an endpoint answers at its resolved
// path is that endpoint's, so it is never stale.
func (g *recoveryCooldown) checkStale(moved, current []movedEndpoint) error {
	answers := func(m movedEndpoint, r Route) bool {
		return slices.ContainsFunc(m.endpoint.Methods, func(method string) bool {
			return normalizeRoute(method, "/").Method == r.Method
		}) && m.coversNormalised(r.Path)
	}

	for _, given := range g.given {
		r := normalizeRoute(given.Method, given.Path)

		if slices.ContainsFunc(current, func(c movedEndpoint) bool { return answers(c, r) }) {
			continue
		}

		for _, m := range moved {
			if answers(m, r) {
				return staleRouteError("EnableRecoveryCooldown", given.Method+" "+given.Path, m)
			}
		}
	}

	return nil
}

// overlaps reports whether some request path is both matched by the
// exemption's pattern, as the exemption matches (case-sensitive, a "*" for one
// segment), and by the endpoint at its declared path.
func (m movedEndpoint) overlaps(pattern string) bool {
	segs := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	declared := strings.Split(strings.TrimPrefix(m.declared, "/"), "/")

	// A wildcard stands for one real segment, so it never agrees with the
	// empty segment a trailing slash leaves.
	agree := func(seg string, fixed string) bool {
		return seg == fixed || (seg == csrfWildcard && fixed != "")
	}

	prefixAgrees := func(n int) bool {
		for i := 0; i < n; i++ {
			if !agree(segs[i], declared[i]) {
				return false
			}
		}

		return true
	}

	switch m.endpoint.Match {
	case MatchSubtree:
		return len(segs) >= len(declared) && prefixAgrees(len(declared))
	case MatchSegment:
		return len(segs) == len(declared)+1 && segs[len(declared)] != "" && prefixAgrees(len(declared))
	default:
		return len(segs) == len(declared) && prefixAgrees(len(declared))
	}
}

// checkStale refuses an exemption the consumer gave whose pattern can match a
// request to a moved endpoint's old path, in a method the endpoint answers. An
// exemption that also reaches an endpoint's resolved path, in a method that
// endpoint answers, is that endpoint's and is never stale.
func (l *csrfLayer) checkStale(moved, current []movedEndpoint) error {
	for _, e := range l.exemptions {
		if slices.ContainsFunc(current, func(c movedEndpoint) bool {
			return slices.Contains(c.endpoint.Methods, e.method) && c.overlaps(e.pattern)
		}) {
			continue
		}

		for _, m := range moved {
			if !slices.Contains(m.endpoint.Methods, e.method) {
				continue
			}

			if m.overlaps(e.pattern) {
				return staleRouteError("WithCSRFExemption", e.method+" "+e.pattern, m)
			}
		}
	}

	return nil
}
