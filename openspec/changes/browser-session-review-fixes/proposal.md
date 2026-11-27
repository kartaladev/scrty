## Why

A code review and a security review of PR #160 found six faults in the browser session that the
earlier changes on the branch did not cover. One of them lets a request through without a valid
CSRF token when the consumer's token source reports its refusal in an unusual error shape. They
are fixed here, on the PR branch, before it merges.

## What Changes

- **CSRF fails closed on any refusal shape.** A refusal from the consumer's `CSRFTokens` whose
  error tree holds a nil or typed-nil entry is refused as a cross-site request. Today such a
  refusal is turned into no error, and the request is admitted, or the walk panics.
- **`MFAAtFirstFactor` is write-once across rotations.** Strict and caller-built rotations take
  it from the stored record, as they already take `PersistentCookie` and `FirstFactor`. A copy
  can no longer set or clear it.
- **A delivery that quotes the cookie is refused.** `SessionDelivery`'s attribute check compares
  `Quoted` too. Such a cookie would never be read back, so every sign-in it delivers would be
  signed out at the next request.
- **BREAKING (configuration): cookie name prefixes are accepted only in their canonical
  spelling.** `__Host-` and `__Secure-` must be written exactly so. `__host-sid` or `__HOST-sid`
  becomes a configuration error that names the canonical spelling. This reverses the
  case-insensitive matching chosen in `browser-session-hardening` decision 5. A browser that
  matches prefixes case-sensitively gives a differently cased name no prefix protection.
- **A role switch and the end of its request exclude each other.** The run takes one lock per
  request. A switch made after the request ended is refused and stores nothing. A switch in
  progress finishes, cookie and all, before the request ends.
- **A key-bound session cannot be continued on a cookie chain.** Second-factor verification,
  re-authentication and renewal refuse a session bound to a sender key, as the cookie interceptor
  already refuses one at authentication. Today they skip the proof check for it.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `browser-session`:
  - an unsafe cookie request is refused whatever shape the token source's refusal takes;
  - a delivery that alters the cookie, quoting included, is refused;
  - cookie name prefixes must use their canonical spelling;
  - a role switch that rotates a cookie session is refused once its request's handler has returned.
- `sessions`: every rotation takes `MFAAtFirstFactor` from the stored record.
- `sender-constrained-tokens`: a key-bound session is refused at continuation on a cookie chain.

## Impact

- `httpsec`: `session_cookie.go` (`csrfAnswer`, `checkAttributes`),
  `session_delivery.go` (`sameCookie`), `chain.go` and `exchange.go` (the per-request switch guard), `role_switch.go`
  (`SwitchActiveRole`), `dpop.go` (`credentialDelivery.continuingProof`), and their tests.
- `session`: `sessions.go` (strict rotation) and `reuse.go` (`successorFromCaller`), the godoc of
  `Session.MFAAtFirstFactor` and of the store's rotation contract, and their tests.
- The `[Unreleased]` CHANGELOG entries for the cookie session.
- No dependency or migration change. The cookie session is unreleased, so the configuration break
  reaches no released consumer.

## References

**Researched (2026-11-28):**
- [draft-ietf-httpbis-rfc6265bis-12](https://www.ietf.org/archive/id/draft-ietf-httpbis-rfc6265bis-12.html): cookie name prefixes matched case-insensitively by user agents. Supports the canonical-spelling decision.
- [httpwg/http-extensions issue 2605](https://github.com/httpwg/http-extensions/issues/2605): discussion of the move from case-sensitive to case-insensitive prefix matching.
- [Mozilla bug 1891349 (CVE-2024-5699)](https://bugzilla.mozilla.org/show_bug.cgi?id=1891349): Firefox matched prefixes case-sensitively until 126, so a differently cased name got no protection there.
- [curl issue 4864](https://curl.haxx.se/bug/?i=4864): an earlier draft (rfc6265bis-04) specified a case-sensitive match, and a client implemented it. Safari's current behaviour is unverified.
