# Proposal

## Why

A per-request policy's throttle on the session-signal stream answers a client with a retry, because any other status ends the client's stream for good. A bearer stream from an origin a CORS wildcard allows does not get that answer. The throttle runs before the bearer records its credential, so the endpoint judges the request by the stricter cookie rule and answers 403, where the same request opens when not throttled. A brief rate limit therefore ends a valid client's stream until its page reloads.

`session-signals` kept this as a stated limit and left the choice to the maintainer, who chose to change it (2026-11-05).

## What Changes

- A bearer records its credential when its resolution ends in a per-request policy's throttle, so the stream's cross-site check judges that request as a bearer, as it judges the same request unthrottled.
- Nothing else changes: no other refusal records a credential, and a cross-site cookie stream still answers 403.

## Capabilities

### New Capabilities
<!-- None. -->

### Modified Capabilities
- `session-signals`: a throttled bearer stream is judged by the same cross-site rule as an unthrottled one.

## Impact

`httpsec/bearer.go`, `httpsec/session_bearer.go`, `httpsec/signals_retry.go` and their tests, plus a conformance row in `test/httpsecconformance`. No API or migration changes.

## References

Reasoned from scrty's own settled specs and the established design; no outside source bears on it.
