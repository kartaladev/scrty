package ginsec

import "github.com/kartaladev/scrty/httpsec"

// forwardedClientIP replaces the address a request is attributed to, and
// nothing else: everything the chain reads from the request still comes from
// the request itself.
type forwardedClientIP struct {
	httpsec.Request

	addr string
}

// ClientIP is gin's own client address.
//
// It is returned exactly as gin reported it, including the empty string: what
// an address that names nobody costs a request is the chain's decision, made in
// one place for every framework, and an address invented here would be one the
// chain then trusts.
func (f forwardedClientIP) ClientIP() string { return f.addr }

// WithForwardedClientIP attributes a request to gin's own client address
// instead of the transport peer.
//
// Default: the transport peer, because it is the one address a client cannot
// choose for itself.
//
// gin trusts every proxy until the consumer calls engine.SetTrustedProxies:
// until then c.ClientIP() returns whatever a client put in the forwarding
// header, so with this option enabled a client chooses its own address — and
// therefore its own rate-limit bucket, and whatever else the deployment
// attributes to an address. The safe order is to set the trusted proxy list
// first, and only then enable this.
//
// It lives here rather than on the chain because net/http and fiber hold no gin
// proxy configuration: a core option would silently do nothing on them, and an
// option that does not take effect is exactly what this library refuses.
func WithForwardedClientIP() Option {
	return func(c *config) { c.forwardedClientIP = true }
}
