package httpsec

import (
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/recovery"
)

// textCooldownLookupFailed is the text a request the cool-down guard could not
// judge is refused behind: the record store's own text is not the library's.
const textCooldownLookupFailed = "httpsec: the recovery cool-down could not be checked"

// Route names one request by its method and exact path, as the cool-down
// guard matches it: "POST" and "/account/email" mark only a POST to exactly
// that path, never another method, a path beneath it, or one differing in
// case or a trailing slash.
type Route struct{ Method, Path string }

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
// and acts only on a request that matches a route's method and exact path and
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

			marked[r] = struct{}{}
		}

		c.register(&recoveryCooldown{records: records, window: d, routes: marked, now: time.Now},
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

	if _, ok := g.routes[Route{Method: ex.Request.Method(), Path: ex.Request.Path()}]; !ok {
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
