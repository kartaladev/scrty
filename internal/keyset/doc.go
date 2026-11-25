// Package keyset fetches and caches a remote issuer's signing keys.
//
// Cache is the engine: TTL, failure backoff, an unknown-key-id refetch
// cooldown, singleflight per resource, an optional stale window, and panic
// recovery on the fetch goroutine. It is keyed by an opaque name chosen by
// its owner, never by issuer, so two consumers of one issuer with different
// settings never share an entry. The OpenID relying party and Source both
// run on it.
//
// Source locates a key set from an issuer's metadata (OpenID Connect
// Discovery, then RFC 8414 on a 404 only), refuses metadata naming another
// issuer or a key set on another origin, and accepts a pinned https URL on
// any origin. Every request goes through the confined outbound client it is
// given.
//
// The package is internal: consumers configure it through the components that
// use it.
package keyset
