# Spec Delta

## ADDED Requirements

### Requirement: The signal stream is answered after authentication
When the signal stream is enabled, the chain SHALL answer it only after every authentication interceptor has run, so a stream is opened on the identity the chain resolved, as for any protected route. Interceptors in earlier slots, such as security headers, trusted proxies, CORS and rate limits, SHALL apply to it as to any request.

#### Scenario: Rate limit before the stream
- **WHEN** a source is over its rate limit and requests the stream
- **THEN** it is refused by the rate limit, and no stream opens

#### Scenario: Pending-session gates before the stream
- **WHEN** a sign-in whose password change is pending requests the stream
- **THEN** it is refused by the password-change gate, and no stream opens

#### Scenario: Consumer authentication
- **WHEN** a consumer's own interceptor authenticates a cookie session and publishes its sign-in
- **THEN** the stream opens for that sign-in

### Requirement: Stream requests record no session activity
A request for the signal stream SHALL NOT record activity on its session, unlike other authenticated requests, so it does not move the idle deadline.

#### Scenario: Opening a stream
- **WHEN** a client opens a stream on a sign-in whose idle deadline is 10:30
- **THEN** the idle deadline is still 10:30

#### Scenario: Stream held open past the touch interval
- **WHEN** a stream stays open for longer than the session manager's touch interval, and the client sends no other request
- **THEN** the sign-in's last-activity time and idle deadline are unchanged

#### Scenario: Consumer interceptor asks before recording activity
- **WHEN** a consumer interceptor that records activity itself runs before the stream and asks whether the request records session activity
- **THEN** it is told the stream request does not

### Requirement: A cross-origin stream is governed by CORS
A cross-origin request for the signal stream SHALL be answered only for an origin the chain's CORS policy names: with credentials allowed for a stream authenticated by a cookie, where a wildcard SHALL NOT count; and with or without them, a wildcard included, for a stream authenticated by an `Authorization` header. `Origin: null` SHALL never pass.

#### Scenario: Allowed origin
- **WHEN** CORS allows `https://app.example.com` with credentials and a page there opens the stream
- **THEN** the stream opens with that origin's CORS headers

#### Scenario: Bearer page on an allowed origin, without credentials
- **WHEN** CORS names `https://app.example.com` without credentials, and a page there sends a `fetch()` of the stream with an `Authorization` header
- **THEN** the stream opens

#### Scenario: Wildcard CORS and a bearer token
- **WHEN** CORS allows `*`, and a page on another site sends a `fetch()` of the stream with an `Authorization` header
- **THEN** the stream opens

#### Scenario: An echoed origin varies
- **WHEN** the stream's response echoes an allowed origin
- **THEN** it carries `Vary: Origin`

#### Scenario: Preflight for a bearer client
- **WHEN** CORS allows `https://app.example.com` with the `Authorization` header, and a page there sends the preflight for a `fetch()` of the stream
- **THEN** the preflight is answered by CORS with that origin and header allowed, and no stream opens for the preflight

### Requirement: A stream from an untrusted origin is refused before it opens
A request from any other origin SHALL be refused with 403 before a stream opens, by its `Sec-Fetch-Site` and `Origin` headers as unsafe requests are judged, whether or not CSRF protection is enabled, and SHALL NOT be reported as a CSRF attack. A request carrying neither header SHALL pass. The stream changes no state, so CSRF protection SHALL NOT require a token for it.

#### Scenario: Other origin
- **WHEN** a page on `https://evil.example` opens the stream with the user's cookies
- **THEN** it is refused with 403, no stream opens, and the sign-in's stream count is unchanged

#### Scenario: Cross-site page with CSRF protection off
- **WHEN** CSRF protection is not enabled and a request for the stream carries `Sec-Fetch-Site: cross-site` from an origin CORS does not allow
- **THEN** it is refused with 403

#### Scenario: Wildcard CORS and a cookie
- **WHEN** CORS allows `*`, and a page on another site opens the stream with the user's cookies
- **THEN** it is refused with 403

#### Scenario: Client without fetch metadata
- **WHEN** a non-browser client requests the stream with a valid bearer token and neither `Sec-Fetch-Site` nor `Origin`
- **THEN** the stream opens

#### Scenario: Cookie stream without a CSRF token
- **WHEN** CSRF protection is enabled and a same-origin page opens the stream with its cookie session and no CSRF token
- **THEN** the stream opens
