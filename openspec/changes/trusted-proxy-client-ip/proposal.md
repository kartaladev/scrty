## Why

Every per-source limit is only as good as the client address it is keyed on. On net/http, `httpsec` uses the TCP peer and never reads forwarding headers, which is safe. But behind a load balancer every client shares the balancer's address, so one attacker throttles every user, and the limit protects nothing.

The current answer is undocumented: a consumer rewrites `RemoteAddr` upstream. gin's `WithForwardedClientIP` uses gin's `ClientIP()`, which trusts every proxy until the consumer calls `SetTrustedProxies`. That is documented, but not detected at construction. fiber relies on its own trusted-proxy settings.

## What Changes

- **A client-address resolver seam** in `httpsec`. The default stays the TCP peer, so nothing is trusted that was not configured.
- **A built-in trusted-proxy resolver.** It takes a list of trusted proxy prefixes and reads `Forwarded` (RFC 7239) or `X-Forwarded-For`, right to left, stopping at the first untrusted hop. A spoofed left-most entry never becomes the key.
- **Construction-time refusal of a trust-everything configuration**, unless it is explicitly declared. This includes gin's forwarded mode with no trusted proxies set.
- **Documentation** of how each adapter obtains the address, and what a consumer behind a proxy must configure.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `http-security-chain` and `framework-adapters`: client-address resolution and its configuration errors.
- `rate-limiting`: the guard's client address comes from the resolver.

## Impact

- **Changed code:** `httpsec` (net/http adapter and options), `ginsec` and `fibersec`.
- **Depends on:** nothing unbuilt.
- **Consumers:** none yet. Nothing is tagged.

## References

**Researched (accessed 2026-10-03):**
- [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html): per-IP controls, and their limits.

**Primary documentation:**
- [RFC 7239, Forwarded HTTP Extension](https://www.rfc-editor.org/rfc/rfc7239): the standard forwarding header.
