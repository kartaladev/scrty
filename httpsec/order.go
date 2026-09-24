package httpsec

import "github.com/kartaladev/scrty/internal/nilcheck"

// Order is an interceptor's position in the chain. The lowest order is
// outermost, so an interceptor with a lower order wraps every one above it and
// the downstream handler is innermost.
//
// The named slots are spaced by at least twenty-five, and the slots either side
// of each are left free, so a consumer can register immediately before or
// after any built-in with Before and After without choosing a number that a
// later scrty release might want.
type Order int

// The slots the library's own interceptors occupy, and the ones reserved for
// the interceptors other capabilities add. They are ordered outermost first:
// a request is served the key set before anything tries to authenticate it, is
// authenticated before a gate or a challenge judges it, and is authorized last,
// when everything it is judged on has been resolved.
const (
	// OrderJWKS serves the public key set, which is answered for anyone.
	OrderJWKS Order = 100

	// OrderOIDC is reserved for federated login: the authorize redirect, the
	// callback and the handoff.
	OrderOIDC Order = 200

	// OrderFormLogin is the form and JSON login endpoint.
	OrderFormLogin Order = 300

	// OrderMagicLink is reserved for one-time link requests and redemptions.
	OrderMagicLink Order = 350

	// OrderBasicAuth is HTTP Basic authentication.
	OrderBasicAuth Order = 400

	// OrderAPIKey is reserved for API key authentication.
	OrderAPIKey Order = 450

	// OrderMTLS is reserved for client certificate authentication.
	OrderMTLS Order = 475

	// OrderBearerToken is bearer token authentication.
	OrderBearerToken Order = 500

	// OrderMFAChallenge is reserved for the second-factor verify endpoint and
	// the gate that holds a pending challenge.
	OrderMFAChallenge Order = 600

	// OrderPasswordChange is the gate a session owing a password change is
	// held at, and the endpoint that resolves it.
	OrderPasswordChange Order = 650

	// OrderLogout ends the session.
	OrderLogout Order = 700

	// OrderSessionTouch records activity, and runs after the handler has
	// returned so a refused request is recorded too.
	OrderSessionTouch Order = 800

	// OrderAuthorizer is the authorization stage, innermost of the built-ins
	// because it judges everything the earlier slots resolved.
	OrderAuthorizer Order = 900
)

// Before is the slot immediately outside o, which runs just before it.
func Before(o Order) Order { return o - 1 }

// After is the slot immediately inside o, which runs just after it and before
// the next named slot.
func After(o Order) Order { return o + 1 }

// RegisterInterceptor runs i at slot at.
//
// There is no default: a chain registers only the built-ins its Enable options
// asked for, and this is how a consumer adds one of their own. Use Before and
// After to sit immediately outside or inside a named slot. Registering two
// interceptors at one slot is allowed, and they run in the order they were
// registered.
//
// An interceptor that authenticates a request publishes what it resolved with
// WithCaller, which is what the built-in first factors use. Publishing with
// authenticate.WithAuthentication alone announces the event without the caller,
// and every guard behind the interceptor then refuses a caller it had just
// authenticated.
//
// A nil interceptor, including an interface holding a nil pointer, is refused
// when the chain is built: it can only ever panic on the first request.
func RegisterInterceptor(i Interceptor, at Order) Option {
	return func(c *config) error {
		if nilcheck.IsNil(i) {
			return newConfigError("RegisterInterceptor was given no interceptor for slot %d", at)
		}

		c.registrations = append(c.registrations, registration{interceptor: i, order: at, seq: c.seq})
		c.seq++
		return nil
	}
}
