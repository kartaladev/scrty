// Package outbound sends the HTTP requests scrty itself makes, confined to
// where configuration said, for a bounded time and a bounded size.
//
// A key set fetch, a provider's discovery document and a token exchange all
// leave the process on scrty's behalf, carrying scrty's trust and sometimes a
// client secret. Each one is aimed by configuration, and the answer decides
// what scrty then believes: which keys verify a token, which endpoint a code is
// exchanged at. A request that can be steered somewhere else — by a redirect,
// by a scheme downgrade, by a target nobody declared — is therefore a way to
// choose scrty's answers for it.
//
// Every check is made before the request is sent. A check on the response has
// already let the request leave, and a client secret cannot be unsent.
//
//	c, err := outbound.New(outbound.WithAllowedOrigins("https://idp.example.com"))
//	if err != nil {
//		return err
//	}
//	res, err := c.Get(ctx, "https://idp.example.com/jwks", nil)
//
// With no options: https only, at most DefaultMaxRedirects redirects, each of
// which must stay on the origin the request started with, each call bounded by
// DefaultTimeout and each response body by DefaultMaxResponseBytes.
//
// # Limits, stated
//
// A consumer Transport that follows redirects by itself is never asked to
// consult a redirect policy, so it bypasses the pre-send check. Only the
// final-URL re-check remains, and it runs after the request has already gone
// out: the response is refused and none of its content is returned, but a body
// sent with the request has been sent. A Transport that does not follow
// redirects — which is every Transport net/http builds — keeps the full
// protection.
//
// Confinement here is by URL, never by resolved address. A declared origin is
// compared as text, so a host that resolves to a link-local or private address
// is not refused for that, and a name that resolves differently between the
// check and the connection is not detected. That check belongs where the
// address is known, and a consumer who needs it supplies a Transport whose
// dialer enforces it — the checks in this package still apply on top.
package outbound
