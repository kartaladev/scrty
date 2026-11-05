## ADDED Requirements

### Requirement: A throttled bearer stream is judged as a bearer
When a per-request policy throttles a request for the stream that a bearer authenticated, the stream's cross-site check SHALL judge that request by the rule for a bearer, as it judges the same request unthrottled.

#### Scenario: A throttled bearer stream from a wildcard's origin
- **WHEN** CORS allows any origin, and a per-request policy throttles a cross-site stream request carrying a valid session bearer or signed bearer token
- **THEN** the response is 200 with only a longer reconnection delay, where the same request unthrottled opens a stream

#### Scenario: A throttled cookie stream stays refused
- **WHEN** CORS allows any origin, and a per-request policy throttles a cross-site stream request authenticated by a cookie
- **THEN** the response is 403, as the same request is unthrottled, and nothing is counted as throttled

#### Scenario: The consumer keeps the throttle final
- **WHEN** `RetryableError` returns false for such a bearer stream's throttle
- **THEN** the response is what the chain's mapping answers, and no stream opens
