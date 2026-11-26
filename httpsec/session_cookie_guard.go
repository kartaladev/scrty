package httpsec

import (
	"crypto/subtle"
	"errors"
)

// OrderSessionCookieGuard is where a cookie chain refuses a request carrying
// the session cookie beside an Authorization header: after CSRF protection
// (OrderCSRF), and before every built-in that reads a credential, Basic
// authentication (OrderBasicAuth), the resource server (OrderResourceServer),
// API keys (OrderAPIKey) and the cookie session itself (OrderBearerToken)
// among them.
const OrderSessionCookieGuard = OrderCSRF + 5

// errCookieBesideAuthorization is the cause a request carrying the session
// cookie and an Authorization header is refused with.
var errCookieBesideAuthorization = errors.New("httpsec: the request carries the session cookie and an " +
	"Authorization header")

// errCookieBesideCaller is the cause a request carrying the session cookie is
// refused with when another authenticator has already published a caller for
// it.
var errCookieBesideCaller = errors.New("httpsec: the request carries the session cookie and another " +
	"credential an authenticator has already accepted")

// sessionCookieGuard refuses a request that carries the session cookie and an
// Authorization header, whatever its scheme or value, before anything reads
// either: which credential named the caller would otherwise depend on which
// interceptor ran first, and a cross-site page that can make a browser send
// its cookie must not be able to pair it with a credential of its choosing.
// It is registered on a cookie chain alone (EnableSessionCookie).
//
// The refusal judges neither credential, so it charges no source and leaves
// the cookie as it is: expiring it would let any page that adds a header sign
// the browser out.
//
// The guard sees the Authorization header and nothing else. A credential
// another interceptor reads from elsewhere (a consumer's own key header) is
// caught at the cookie session itself (besideAnotherCaller), which refuses a
// request presenting the cookie once another caller has been published. That
// refusal is also what a consumer interceptor ordered before the cookie
// session (OrderBearerToken) runs into when it publishes a default or
// anonymous caller for every request: every request carrying the cookie is
// then refused, and nobody can use a cookie until that interceptor publishes
// nothing for a request that presents one.
type sessionCookieGuard struct {
	cookie *sessionCookie
}

// Intercept refuses a request carrying both credentials, and passes every
// other through untouched.
func (g sessionCookieGuard) Intercept(ex *Exchange, next Next) error {
	if _, claimed := presentedCookie(ex.Request, g.cookie.name); claimed &&
		len(ex.Request.HeaderValues("Authorization")) > 0 {
		return errors.Join(ErrAuthenticationRequired, errCookieBesideAuthorization)
	}

	return next(ex)
}

// besideAnotherCaller reports whether a request presenting the cookie
// presented arrives at the cookie session with a caller another
// authenticator already published, from a credential the guard cannot see
// (a consumer's own key header, say). Only the session this very cookie names,
// published by an enclosing run of a cookie chain over the same exchange, is
// not another caller.
//
// A caller published for a request that carries the cookie is another caller
// whatever it is: an interceptor that publishes a default or anonymous caller
// before the cookie session runs locks out every cookie request. The request
// is refused rather than guessed at, and the consumer fixes the interceptor,
// not the cookie session.
func besideAnotherCaller(ex *Exchange, presented string) bool {
	if ex.Authentication == nil && ex.Session == nil {
		return false
	}

	if ex.Session != nil && presented != "" &&
		subtle.ConstantTimeCompare([]byte(ex.Session.ID), []byte(presented)) == 1 {
		return false
	}

	return true
}
