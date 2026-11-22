package ginsec

// Option configures Middleware. A nil Option is skipped.
type Option func(*config)

// config is what Middleware's options decide. Its zero value is the default
// behaviour.
type config struct {
	// refusalsRendered is the consumer's declaration that an error middleware
	// registered before Middleware renders every refusal.
	refusalsRendered bool
}

// WithRefusalsRendered declares that the consumer's own gin error middleware
// renders every refusal, so Middleware leaves even an unrouted 404 for it.
//
// Default: a 404 refusal on a path gin has no route for — every 404 at the
// chain's own endpoints, such as a federated login naming an unregistered
// provider, since those are not gin routes — is committed at once with an
// empty body, so gin's no-route fallback cannot add its own text. That keeps
// the answer alike across adapters, but no error middleware can render it.
// This option replaces that default: the 404 is set and the request aborted
// as for every other refusal, and the status, headers and body are left to
// the error middleware. Nothing else changes; refusals on routes gin matched,
// and refusals of any other status, were already left open.
//
// The option is the consumer's promise, which the library cannot check. The
// error middleware must be registered before Middleware (engine.Use it
// first), read c.Errors after c.Next() returns, and write a response for
// every refusal. A middleware registered after Middleware never sees the
// refusal. When the promise is broken — no error middleware, one registered
// after Middleware, or one that skips some errors — gin's no-route fallback
// answers such a request with its own "404 page not found" text. That still
// fails closed and carries no refusal text, but it differs from the empty 404
// the net/http and fiber adapters send.
//
// Giving the option twice is the same as giving it once.
func WithRefusalsRendered() Option {
	return func(c *config) { c.refusalsRendered = true }
}

// newConfig applies opts over the default, skipping a nil option.
func newConfig(opts []Option) config {
	var cfg config

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		opt(&cfg)
	}

	return cfg
}
