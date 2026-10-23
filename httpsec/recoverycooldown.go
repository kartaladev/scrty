package httpsec

import (
	"net/http"
	"strings"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/recovery"
)

// textCooldownLookupFailed is the text a request the cool-down guard could not
// judge is refused behind: the record store's own text is not the library's.
const textCooldownLookupFailed = "httpsec: the recovery cool-down could not be checked"

// Route names one request by its method and path, as the cool-down guard
// matches it.
//
// The match is deliberately broad, because a match refuses: a request matches
// when its method is the route's, with HEAD counted as GET, and its path
// equals the route's ignoring ASCII letter case and any trailing slashes. Both
// sides are normalised, the route when the option is applied and the request
// when it arrives, so "POST" and "/account/email" also hold "post
// /Account/Email/", and "GET" and "/account/export" also hold "HEAD
// /account/export". Without that, a router that sends such variants to the
// marked handler, as fiber does by default (it is case-insensitive and
// ignores trailing slashes), would reach the handler by a path the guard did
// not match. A path beneath the route and another method still do not match, and a
// route marked on "/" matches "/" and a run of slashes, but no other path.
//
// The cost is an over-match on routers that tell those variants apart, such as
// net/http's ServeMux and gin: a genuinely different route like
// "/Account/Email" is also held during the window. It is fail-closed, lasts
// only the cool-down, and has no option to narrow it.
//
// Only the cool-down matches this broadly. Every path the chain exempts from
// a gate, or answers itself, is matched exactly, since a broadened exemption
// would let a request past a gate to a handler the library does not own.
// Authorization rules the consumer writes are the consumer's own predicates,
// which the library does not match: on fiber, write them knowing the router
// treats letter case and trailing slashes as the same route.
type Route struct{ Method, Path string }

// normalizeRoute is the form a route and a request are compared in by the
// cool-down guard: the method upper-cased in ASCII, with HEAD counted as GET,
// and the path lower-cased in ASCII with every trailing slash removed, a path
// left empty becoming "/".
func normalizeRoute(method, path string) Route {
	method = asciiUpper(method)
	if method == http.MethodHead {
		method = http.MethodGet
	}

	path = strings.TrimRight(asciiLower(path), "/")
	if path == "" {
		path = "/"
	}

	return Route{Method: method, Path: path}
}

// asciiUpper and asciiLower fold only the ASCII letters. A Unicode fold would
// equate letters a router keeps apart, such as the Kelvin sign and "k", and
// rewriting only ASCII bytes leaves every multi-byte UTF-8 sequence intact.
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}

	return string(b)
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}

	return string(b)
}

// EnableRecoveryCooldown refuses the routes the consumer marks as sensitive,
// for d after the user's latest completed account recovery, with
// recovery.ErrCooldown (403).
//
// The cool-down is off until this option is given; there is no default
// duration and no default route, since which actions are sensitive is the
// consumer's to say. It is independent of EnableAccountRecovery: it reads only
// records, which is the same record store the recovery writes to (a durable
// one, or the store handed to RecoveryDeps.Records), so a chain that serves
// recovery elsewhere can still enforce it.
//
// The guard runs just after bearer authentication, at After(OrderBearerToken),
// and acts only on a request that matches a route, as Route describes, and
// carries a session. For such a request it reads the user's latest completion
// (recovery.RecordStore.LatestCompletion) and refuses while now is before that
// instant plus d. The cool-down is per user, not per session: it is read from
// the recovery record, so logging out and in again does not end it. A request
// with no session is passed on, for later interceptors and authorization to
// decide. A lookup that fails refuses the request behind fixed text (500),
// never the store's own, rather than let a sensitive action through
// unchecked.
//
// New refuses, with an error wrapping ErrConfig, a d of zero or less, no
// routes, a route with an empty method or path, and a nil store (a typed nil
// included).
func EnableRecoveryCooldown(records recovery.RecordStore, d time.Duration, routes ...Route) Option {
	const option = "EnableRecoveryCooldown"

	return func(c *config) error {
		if err := requireDep(option, "recovery record store", records); err != nil {
			return err
		}

		if d <= 0 {
			return newConfigError("%s was given a cool-down of %s; it must be above zero, or "+
				"leave the option out to have none", option, d)
		}

		if len(routes) == 0 {
			return newConfigError("%s was given no routes; a cool-down that marks nothing "+
				"refuses nothing", option)
		}

		marked := make(map[Route]struct{}, len(routes))

		for _, r := range routes {
			if r.Method == "" || r.Path == "" {
				return newConfigError("%s was given the route %q %q; a route needs both a method "+
					"and a path, or it matches no request", option, r.Method, r.Path)
			}

			marked[normalizeRoute(r.Method, r.Path)] = struct{}{}
		}

		c.register(&recoveryCooldown{records: records, window: d, routes: marked, now: c.now},
			After(OrderBearerToken))

		return nil
	}
}

// recoveryCooldown refuses the marked routes during the cool-down after the
// user's latest completed recovery.
type recoveryCooldown struct {
	records recovery.RecordStore
	window  time.Duration
	routes  map[Route]struct{}
	now     func() time.Time
}

// Intercept refuses a marked request from a session whose user completed a
// recovery within the window, and passes everything else on.
func (g *recoveryCooldown) Intercept(ex *Exchange, next Next) error {
	if ex.Session == nil {
		return next(ex)
	}

	if _, ok := g.routes[normalizeRoute(ex.Request.Method(), ex.Request.Path())]; !ok {
		return next(ex)
	}

	completed, ok, err := g.records.LatestCompletion(ex.Context(), ex.Session.UserID)
	if err != nil {
		return diag.Wrap(err, textCooldownLookupFailed)
	}

	if ok && g.now().Before(completed.Add(g.window)) {
		return recovery.ErrCooldown
	}

	return next(ex)
}
