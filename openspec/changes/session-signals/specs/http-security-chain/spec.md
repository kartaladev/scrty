# Spec Delta

## ADDED Requirements

### Requirement: The signal stream is answered after authentication
When the signal stream is enabled, the chain SHALL answer it only after every authentication interceptor has run, so a stream is opened on the identity the chain resolved, as for any protected route. Interceptors in earlier slots, such as security headers, trusted proxies, CORS and rate limits, SHALL apply to it as to any request.

#### Scenario: Rate limit before the stream
- **WHEN** a source is over its rate limit and requests the stream
- **THEN** it is refused by the rate limit, and no stream opens

#### Scenario: Consumer authentication
- **WHEN** a consumer's own interceptor authenticates a cookie session and publishes its sign-in
- **THEN** the stream opens for that sign-in

### Requirement: Stream requests record no session activity
A request for the signal stream SHALL NOT record activity on its session, unlike other authenticated requests, so it does not move the idle deadline.

#### Scenario: Opening a stream
- **WHEN** a client opens a stream on a sign-in whose idle deadline is 10:30
- **THEN** the idle deadline is still 10:30

### Requirement: A cross-origin stream is governed by CORS
A cross-origin request for the signal stream SHALL be answered only for an origin the chain's CORS policy allows with credentials. Any other origin SHALL be refused before a stream opens. The stream changes no state, so CSRF protection SHALL NOT require a token for it.

#### Scenario: Allowed origin
- **WHEN** CORS allows `https://app.example.com` with credentials and a page there opens the stream
- **THEN** the stream opens with that origin's CORS headers

#### Scenario: Other origin
- **WHEN** a page on `https://evil.example` opens the stream with the user's cookies
- **THEN** no stream opens for it
