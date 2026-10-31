## Purpose

Lets browser pages on origins the consumer names call the chain's endpoints and the consumer's API, answers their preflights before any authentication runs, and refuses configurations that would expose credentials to any origin.

## ADDED Requirements

### Requirement: CORS is off until enabled, and then needs an explicit allowlist
The chain SHALL send no CORS response header until the consumer enables CORS. Enabling it SHALL require at least one allowed origin, each an exact `scheme://host[:port]`. Construction SHALL fail with a configuration error, naming the setting, when:
- no origin is given;
- an origin is `null`, or has a path, query, fragment or userinfo;
- `*` is given together with credentials;
- an origin pattern is given without the explicit pattern option.

#### Scenario: Wildcard with credentials
- **WHEN** the consumer enables CORS with origins `*` and credentials allowed
- **THEN** building the chain fails with a configuration error naming the credentials setting

#### Scenario: Null origin
- **WHEN** the consumer lists `null` as an allowed origin
- **THEN** building the chain fails with a configuration error naming that origin

### Requirement: Origins are matched exactly and the answer varies by origin
A request's `Origin` SHALL be allowed only when it equals an allowed origin exactly, compared case-insensitively in scheme and host. An allowed request SHALL get `Access-Control-Allow-Origin` with that origin, never `*` when credentials are allowed. Every response whose CORS headers depend on the request's origin SHALL carry `Vary: Origin`. A request from an origin not on the list SHALL get no CORS headers and SHALL otherwise be handled as if CORS were off.

#### Scenario: Allowed origin
- **WHEN** `https://app.example.com` is allowed and a request carries `Origin: https://app.example.com`
- **THEN** the response carries `Access-Control-Allow-Origin: https://app.example.com` and `Vary: Origin`

#### Scenario: Look-alike origin
- **WHEN** `https://app.example.com` is allowed and a request carries `Origin: https://app.example.com.evil.example`
- **THEN** the response carries no `Access-Control-Allow-Origin` header

### Requirement: Preflights are answered before authentication
A preflight, an `OPTIONS` request carrying `Origin` and `Access-Control-Request-Method`, SHALL be answered by the CORS layer with 204 and SHALL NOT reach any authentication interceptor, the authorizer or the handler. An allowed preflight SHALL carry the allowed methods, the allowed request headers and `Access-Control-Max-Age`, which SHALL be 10 minutes by default and replaceable. A preflight from a disallowed origin, or asking for a method or header not allowed, SHALL get 204 with no CORS headers.

#### Scenario: Preflight for an authenticated API
- **WHEN** a preflight from an allowed origin asks for `GET` with the `authorization` header on a route that requires authentication
- **THEN** the response is 204 with the allow headers and `Access-Control-Max-Age: 600`, and no authentication runs

#### Scenario: Consumer max age
- **WHEN** the consumer sets the preflight cache to 1 hour
- **THEN** allowed preflights carry `Access-Control-Max-Age: 3600`

### Requirement: The CORS policy follows the chain's own features
When sender-constrained tokens are enabled, the CORS layer SHALL add `DPoP` to the allowed request headers and `DPoP-Nonce` and `WWW-Authenticate` to the exposed response headers, unless the consumer removes them explicitly. When CSRF protection uses a token header, its header name SHALL be added to the allowed request headers.

#### Scenario: DPoP across origins
- **WHEN** CORS and DPoP are both enabled and an allowed origin sends a preflight asking for the `dpop` header
- **THEN** the preflight allows it, and actual responses expose `DPoP-Nonce`
