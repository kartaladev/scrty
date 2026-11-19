package httpsec

// This file exposes the library's quiet classification sites to the external
// tests, so each can be driven with a hostile error on a chain's own exchange
// without wiring the whole feature it belongs to. It is a test file, so nothing
// here reaches a production build.

// QuietSite runs one quiet classification site on ex with err, from inside an
// interceptor of the chain under test, and discards what it decides: the tests
// read only the records it writes.
type QuietSite func(ex *Exchange, err error)

var (
	// QuietSiteOIDCConsent is the OIDC sign-in challenge's classification of
	// a refusal (challengeOIDCSignIn).
	QuietSiteOIDCConsent QuietSite = func(ex *Exchange, err error) {
		_ = (&oidcEndpoints{}).challengeOIDCSignIn(ex, err)
	}

	// QuietSitePerRequestThrottle is the signal stream's marking of a
	// per-request throttle (markPerRequestThrottle). The exchange is put on
	// the stream's path for the call, and back as it returns; err must match
	// ratelimit.ErrThrottled through the standard library for the site to
	// classify it.
	QuietSitePerRequestThrottle QuietSite = func(ex *Exchange, err error) {
		saved := ex.perRequest
		defer func() { ex.perRequest = saved }()

		ex.perRequest = &perRequestPhase{signals: &sessionSignals{path: endpointPath{resolved: ex.Request.Path()}}}
		_ = ex.markPerRequestThrottle(err)
	}

	// QuietSiteThrottledSignIn is the signal stream's check for a throttled
	// sign-in (isThrottledSignIn). err is handed to it carrying the
	// per-request throttle's mark, which the check requires before it
	// classifies.
	QuietSiteThrottledSignIn QuietSite = func(ex *Exchange, err error) {
		_ = (&sessionSignals{}).isThrottledSignIn(ex.Context(), ex, &perRequestThrottle{err})
	}

	// QuietSiteDependencyFailure is the signal stream's check for a dependency
	// failure (isDependencyFailure).
	QuietSiteDependencyFailure QuietSite = func(ex *Exchange, err error) {
		_ = (&sessionSignals{}).isDependencyFailure(ex.Context(), ex, err)
	}
)
