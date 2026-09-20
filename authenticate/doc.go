// Package authenticate decides who a caller is.
//
// A Manager runs ordered providers and returns the first answer that is not a
// refusal to handle the credentials. Providers for a username and password, and
// for a bearer token, ship here; a consumer adds their own by implementing
// Authenticator.
//
// The manager is the one place that decides what a success may contain. A
// provider returning no result at all, or a result carrying no principal, is
// reported as a failed authentication rather than passed on, so every caller
// that reads the principal after a nil error reads one that is there. Leaving
// that check to each provider would let the next provider written reopen it.
//
// A successful authentication travels with the request through
// WithAuthentication and AuthenticationFromContext, which report an absent
// result as absent rather than as an empty one. A caller that ignores the
// second return value is then handed nothing it could mistake for an
// authenticated caller.
package authenticate
