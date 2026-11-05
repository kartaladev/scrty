# cors Specification

## Purpose
Lets browser pages on origins the consumer names call the chain's endpoints and the consumer's API, answers their preflights before any authentication runs, and refuses configurations that would expose credentials to any origin.

## Requirements

### Requirement: CORS is off until enabled, and then needs an explicit allowlist
The chain SHALL send no CORS response header until the consumer enables CORS. Enabling it SHALL require at least one allowed origin, each an exact `scheme://host[:port]` with an `http` or `https` scheme. Construction SHALL normalise each origin to a lower-case scheme and host and drop a default port (`:443` for `https`, `:80` for `http`), so it compares as browsers serialise origins. Construction SHALL fail with a configuration error, naming the setting, when:
- no origin is given;
- an origin is `null`, has another scheme, or has a path other than empty, a query, a fragment or userinfo;
- `*` is given together with credentials, or `*` is given beside other origins;
- an origin pattern is given without the explicit pattern option, or a pattern's wildcard is anywhere but a whole leftmost host label;
- CORS is enabled more than once.

#### Scenario: Wildcard with credentials
- **WHEN** the consumer enables CORS with origins `*` and credentials allowed
- **THEN** building the chain fails with a configuration error naming the credentials setting

#### Scenario: Null origin
- **WHEN** the consumer lists `null` as an allowed origin
- **THEN** building the chain fails with a configuration error naming that origin

#### Scenario: Origin with a path
- **WHEN** the consumer lists `https://app.example.com/app` as an allowed origin
- **THEN** building the chain fails with a configuration error naming that origin

#### Scenario: Normalised at construction
- **WHEN** the consumer lists `HTTPS://App.Example.com:443` and a request carries `Origin: https://app.example.com`
- **THEN** the origin is allowed

### Requirement: Origins are matched exactly and the answer varies by origin
A request's `Origin` SHALL be allowed only when it equals an allowed origin exactly after the same normalisation, or matches an explicit pattern, whose wildcard SHALL match exactly one non-empty host label. An allowed request SHALL get `Access-Control-Allow-Origin` with that origin, never `*` when credentials are allowed, and `Access-Control-Allow-Credentials: true` only when credentials are allowed. An allowed actual response SHALL carry the exposed headers. Every response on a CORS-enabled chain SHALL carry `Vary: Origin`, whether or not the request carried an `Origin` and whether or not it was allowed, so no cache serves one origin's answer to another. A request from an origin not on the list SHALL get no other CORS headers and SHALL otherwise be handled as if CORS were off. With `*` allowed and no credentials, every origin SHALL get `Access-Control-Allow-Origin: *`. A consumer interceptor registered ahead of the CORS layer runs outside it, and a response it writes carries no `Vary: Origin` unless it adds one; the documentation SHALL say so.

#### Scenario: Allowed origin
- **WHEN** `https://app.example.com` is allowed and a request carries `Origin: https://app.example.com`
- **THEN** the response carries `Access-Control-Allow-Origin: https://app.example.com` and `Vary: Origin`

#### Scenario: Look-alike origin
- **WHEN** `https://app.example.com` is allowed and a request carries `Origin: https://app.example.com.evil.example`
- **THEN** the response carries no `Access-Control-Allow-Origin` header

#### Scenario: Other scheme or port
- **WHEN** `https://app.example.com` is allowed and requests carry `Origin: http://app.example.com` and `Origin: https://app.example.com:8443`
- **THEN** neither response carries `Access-Control-Allow-Origin`

#### Scenario: Pattern matches one label
- **WHEN** the pattern `https://*.example.com` is allowed explicitly and requests carry `Origin: https://a.example.com`, `Origin: https://a.b.example.com` and `Origin: https://example.com`
- **THEN** only the first is allowed

#### Scenario: No origin still varies
- **WHEN** CORS is enabled and a request carries no `Origin`
- **THEN** the response carries `Vary: Origin` and no other CORS header

#### Scenario: A refusal is readable by an allowed origin
- **WHEN** `https://app.example.com` is allowed, `WWW-Authenticate` is exposed, and a request from it is refused with 401 by an authentication interceptor
- **THEN** the 401 response carries `Access-Control-Allow-Origin: https://app.example.com` and `Access-Control-Expose-Headers` naming `WWW-Authenticate`

### Requirement: Preflights are answered before authentication
A preflight, an `OPTIONS` request carrying `Origin` and `Access-Control-Request-Method`, SHALL be answered by the CORS layer with 204 and SHALL NOT reach any authentication interceptor, the authorizer or the handler. The allowed methods SHALL default to `GET`, `HEAD` and `POST`, and be replaceable. Requested methods SHALL be compared case-sensitively and requested headers case-insensitively, reading every `Access-Control-Request-Headers` line as one comma-separated list with spaces ignored. An allowed preflight SHALL carry the allowed origin, the allowed methods, the requested headers it allows and `Access-Control-Max-Age`, which SHALL be 10 minutes by default and replaceable, and SHALL vary by `Origin`, `Access-Control-Request-Method` and `Access-Control-Request-Headers`. A preflight from a disallowed origin, or asking for a method or a header not allowed, SHALL get 204 with no CORS headers other than `Vary`. An `OPTIONS` request without `Access-Control-Request-Method` is not a preflight and SHALL continue through the chain.

#### Scenario: Preflight for an authenticated API
- **WHEN** a preflight from an allowed origin asks for `GET` with the `authorization` header on a route that requires authentication
- **THEN** the response is 204 with the allow headers and `Access-Control-Max-Age: 600`, and no authentication runs

#### Scenario: Consumer max age
- **WHEN** the consumer sets the preflight cache to 1 hour
- **THEN** allowed preflights carry `Access-Control-Max-Age: 3600`

#### Scenario: Method not allowed
- **WHEN** a preflight from an allowed origin asks for `DELETE` with the default methods
- **THEN** the response is 204 with no `Access-Control-Allow-Origin` and no `Access-Control-Allow-Methods`

#### Scenario: Header not allowed
- **WHEN** a preflight from an allowed origin asks for `x-debug` and that header is not allowed
- **THEN** the response is 204 with no `Access-Control-Allow-Origin`

#### Scenario: Headers across lines and cases
- **WHEN** `Authorization` and `Content-Type` are allowed and a preflight sends `Access-Control-Request-Headers: content-type` and a second line `AUTHORIZATION`
- **THEN** the preflight is allowed

#### Scenario: Plain OPTIONS is not a preflight
- **WHEN** an `OPTIONS` request carries `Origin` but no `Access-Control-Request-Method`
- **THEN** it is not answered by the CORS layer, and continues through the chain's authentication and authorizer

### Requirement: The CORS policy follows the chain's own features
When DPoP is enabled, the CORS layer SHALL add `DPoP` to the allowed request headers and `DPoP-Nonce` and `WWW-Authenticate` to the exposed response headers. When CSRF protection uses a token header, its header name SHALL be added to the allowed request headers. The consumer SHALL be able to turn these additions off with one option whose name says so.

#### Scenario: DPoP across origins
- **WHEN** CORS and DPoP are both enabled and an allowed origin sends a preflight asking for the `dpop` header
- **THEN** the preflight allows it, and actual responses expose `DPoP-Nonce`

#### Scenario: Additions turned off
- **WHEN** CORS and DPoP are both enabled, the consumer turns the automatic additions off, and a preflight asks for the `dpop` header
- **THEN** the preflight gets no CORS headers, because `DPoP` is not on the consumer's own list

### Requirement: The provider's endpoints follow the CORS rules of the protocol
When CORS is enabled with the provider, the CORS layer SHALL answer for the provider's token, UserInfo, revocation and introspection endpoints, and for the metadata documents, as for any other route, under the consumer's allowlist. It SHALL never add CORS headers to the authorization endpoint, the resume endpoint, the end-session endpoint or its confirmation, whatever the allowlist says.

#### Scenario: Browser client calls the token endpoint
- **WHEN** an allowed origin sends a preflight for the token endpoint
- **THEN** the preflight is allowed

#### Scenario: Cross-origin call to the resume endpoint
- **WHEN** an allowed origin sends a cross-origin request to the resume endpoint
- **THEN** the response carries no CORS headers

#### Scenario: Cross-origin call to the authorization endpoint
- **WHEN** an allowed origin sends a cross-origin request to the authorization endpoint
- **THEN** the response carries no CORS headers

### Requirement: Browser clients can use DPoP at the provider's endpoints
On the endpoints the CORS layer answers for, it SHALL by default allow the `Authorization` and `DPoP` request headers, and SHALL expose `DPoP-Nonce` and `WWW-Authenticate`. A consumer who turns off the layer's automatic headers states these itself. It SHALL never allow credentials there, whatever the consumer's policy says. The provider's consent-management endpoint is an application route, and SHALL follow the consumer's policy unchanged.

#### Scenario: Browser client uses DPoP
- **WHEN** an allowed origin sends a preflight for the token endpoint asking for the `DPoP` header
- **THEN** the preflight allows it, and the response exposes `DPoP-Nonce`

#### Scenario: Consumer turns off the automatic headers
- **WHEN** a consumer turns off the layer's automatic headers, and its policy allows credentials
- **THEN** the token endpoint no longer gains the `DPoP` header, and credentials are still not allowed there
