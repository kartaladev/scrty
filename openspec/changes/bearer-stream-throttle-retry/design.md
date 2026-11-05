# Design

## Context

`session-signals` (R1) answers a per-request policy's `ratelimit.ErrThrottled` on the stream's path with 200 and only `retry`, after the stream's cross-site check. That check takes `streamByCookie(ex)`, which is true while `ex.bearerCredential` is empty. Both bearers record the credential only after `resolver.resolve` returns nil, and the policy's denial comes back through that call, so a throttled bearer request looks like a cookie one. From a CORS wildcard's origin the cookie rule refuses it (REPRODUCED in `session-signals`' review; pinned by a row in `TestSessionSignals_Caps_ThrottledCookie`).

## Goals / Non-Goals

- **Goal:** a throttled bearer stream is judged as a bearer, so it retries where an unthrottled one opens.
- **Non-goal:** any change to what a cookie stream, a failed credential or any other refusal answers.

## Decisions

### D1. Record the credential only for a marked throttle

**Default:** when `resolver.resolve` returns an error carrying the `*perRequestThrottle` mark, the bearer records the presented credential before returning that error. The mark exists only on GET at the stream's path, for a throttle that maps to 401, and only after the credential verified and the caller was published.

**Override:** `SessionSignals.RetryableError` returning false sends the throttle through the chain's mapping, as before. The cross-site rule itself has no separate override, because it follows the consumer's CORS policy.

*Rejected:* recording whenever `ex.Authentication != nil`. A review tried it and it works, but other code reads `bearerCredential` (`issuingBinding`, `oidc_resume`, `mfa_verify`), and this would widen what every non-stream refusal leaves on the exchange for no benefit here. *Rejected:* teaching `streamByCookie` to read `Authorization` alone: admission judges a request as bearer only when the chain recorded a credential and `Authorization` carries it, so that a consumer's cookie authenticator calling `RecordPresentedToken` stays a cookie, and a header alone proves nothing.

**Why it is safe:** the credential has verified at that point, and it is a bearer's own header, which a cross-site page cannot attach as it can a cookie. The answer reveals only what the same request learns when unthrottled.

## Risks / Trade-offs

- **[A signed bearer has the same shape]** The review's trial covered the session bearer only. → Both bearers get rows, on the wildcard row and on a credentialless named origin.

## Migration Plan

None. Free before the first tag.

## Open Questions

None.

## References

Reasoned from scrty's own settled specs and the established design.
