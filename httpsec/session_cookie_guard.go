package httpsec

import (
	"crypto/subtle"
	"errors"
	"net/http"
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
//
// On a chain that also runs the OpenID Provider, the provider's outer
// endpoints are exempt (exemptFromCookieGuard): they authenticate by a
// credential of their own and never read the chain's session, and a
// first-party page on the origin calling one of them, with an access token or
// client credentials, sends the cookie whether it means to or not.
type sessionCookieGuard struct {
	cookie *sessionCookie
}

// Intercept refuses a request carrying both credentials, unless its path is
// one the guard exempts, and passes every other through untouched.
func (g sessionCookieGuard) Intercept(ex *Exchange, next Next) error {
	if _, claimed := presentedCookie(ex.Request, g.cookie.name); claimed &&
		len(ex.Request.HeaderValues("Authorization")) > 0 && !g.cookie.guardExempts(ex.Request) {
		return errors.Join(ErrAuthenticationRequired, errCookieBesideAuthorization)
	}

	return next(ex)
}

// guardExemption is what the both-credentials guard lets through on a chain
// running the OpenID Provider, settled once at construction from the paths the
// chain resolved, its base path and the consumer's path overrides included, and
// never changed after.
type guardExemption struct {
	// any is the paths answered by the provider's outer router itself, whatever
	// the method: its handlers answer every request on their path, a wrong
	// method included, and pass none on.
	any map[string]struct{}

	// get is the key set's path, exempt for GET alone: the key set answers GET
	// and passes every other method on down the chain, where an authenticator
	// would read the Authorization header beside the cookie.
	get map[string]struct{}
}

// guardExempts reports whether r is one the both-credentials guard lets
// through: its path exactly one the exemption holds, compared as the routers
// that answer it compare, so a variant (a trailing slash, a doubled slash,
// another case, a path below) is not exempt and stays guarded.
func (s *sessionCookie) guardExempts(r Request) bool {
	path := r.Path()

	if _, ok := s.exempt.any[path]; ok {
		return true
	}

	_, ok := s.exempt.get[path]

	return ok && r.Method() == http.MethodGet
}

// oidcGuardExempt are the provider's outer endpoints the both-credentials guard
// exempts: each authenticates by a credential of its own (a client's, an access
// token, an ID token hint, or none) and never reads the chain's session. The
// discovery documents are exempted beside them. Every other provider route
// rests on the sign-in the chain judges, or is a page a browser posts to, and
// stays guarded.
var oidcGuardExempt = []OIDCEndpoint{
	OIDCAuthorize, OIDCToken, OIDCUserInfo, OIDCRevoke, OIDCIntrospect, OIDCEndSession, OIDCDeviceAuthorization,
}

// exemptFromCookieGuard settles the paths the both-credentials guard exempts:
// none on a chain without the OpenID Provider; with it, the path each of
// oidcGuardExempt answers at, the discovery documents', and, for GET, the key
// set's. Only a path the provider's outer router routes is exempt, so an
// endpoint the provider does not serve (the device authorization without the
// device grant) adds nothing. It runs once the chain's paths are resolved.
func (c *config) exemptFromCookieGuard(s *sessionCookie) {
	op := c.oidcProvider
	if op == nil || op.outer == nil {
		return
	}

	exempt := guardExemption{any: map[string]struct{}{}, get: map[string]struct{}{}}

	paths := make([]string, 0, len(oidcGuardExempt)+2)
	for _, e := range oidcGuardExempt {
		if op.served(e) {
			paths = append(paths, op.paths[e])
		}
	}

	openid, oauth := op.metadata.servedPaths()
	paths = append(paths, openid, oauth)

	for _, p := range paths {
		if _, routed := op.outer.routes[p]; routed && p != "" {
			exempt.any[p] = struct{}{}
		}
	}

	if j, ok := findInterceptor[*jwksEndpoint](c); ok && j.path.at() != "" {
		exempt.get[j.path.at()] = struct{}{}
	}

	s.exempt = exempt
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
