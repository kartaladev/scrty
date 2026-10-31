## Purpose

Refuses state-changing requests that another site makes the user's browser send, first by the browser's own Fetch Metadata and Origin signals and then, for cookie-authenticated requests, by a token bound to the session.

## ADDED Requirements

### Requirement: Cross-site unsafe requests are refused by Fetch Metadata and Origin
With CSRF protection enabled, a request whose method is not `GET`, `HEAD` or `OPTIONS` SHALL be judged before any authentication interceptor runs:
1. `Sec-Fetch-Site` of `same-origin` or `none` SHALL pass.
2. `Sec-Fetch-Site` of `same-site` or `cross-site` SHALL be refused unless its `Origin` is a trusted origin.
3. With no `Sec-Fetch-Site`, an `Origin` whose scheme and host differ from the request's own scheme and host SHALL be refused unless it is a trusted origin.
4. With neither header, the request SHALL pass this check.

The request's own scheme and host SHALL be those the chain resolves, including through trusted proxies. The refusal SHALL be the cross-site-request error.

#### Scenario: Cross-site form post
- **WHEN** a page on `https://evil.example` submits a form to `POST https://app.example.com/settings` and the browser sends `Sec-Fetch-Site: cross-site`
- **THEN** the request is refused with the cross-site-request error and the handler does not run

#### Scenario: Older browser without Fetch Metadata
- **WHEN** a request arrives with `Origin: https://evil.example`, no `Sec-Fetch-Site`, and the request's own origin is `https://app.example.com`
- **THEN** it is refused with the cross-site-request error

#### Scenario: Non-browser client
- **WHEN** a server-to-server `POST` arrives with neither `Sec-Fetch-Site` nor `Origin`
- **THEN** it passes the Fetch Metadata check

### Requirement: Origins allowed by CORS are trusted for CSRF by default
Every origin the CORS policy allows SHALL be a trusted origin for the Fetch Metadata check, so a frontend on a sibling subdomain can call the API. The consumer SHALL be able to add trusted origins, and SHALL be able to stop CORS origins from being trusted.

#### Scenario: Sibling frontend
- **WHEN** CORS allows `https://app.example.com` and that page sends `POST https://api.example.com/orders` with `Sec-Fetch-Site: same-site`
- **THEN** the request passes the Fetch Metadata check

#### Scenario: Consumer opts out
- **WHEN** the consumer stops CORS origins from being trusted for CSRF, and the same request arrives
- **THEN** it is refused with the cross-site-request error

### Requirement: Cookie-authenticated unsafe requests need a session-bound token
An unsafe request authenticated by a cookie SHALL carry a CSRF token, in a header or form field whose names are replaceable. The token SHALL be issued for the request's session, and SHALL be refused when it is missing, malformed, or issued for another session. The token SHALL be readable by the consumer's page through a documented accessor or endpoint. A request authenticated only by an `Authorization` header SHALL NOT need a token.

#### Scenario: Missing token
- **WHEN** a cookie-authenticated `POST` passes the Fetch Metadata check but carries no CSRF token
- **THEN** it is refused with the cross-site-request error

#### Scenario: Token from another session
- **WHEN** a cookie-authenticated `POST` carries a token issued for a different session
- **THEN** it is refused with the cross-site-request error

#### Scenario: Bearer request
- **WHEN** a `POST` authenticated by `Authorization: Bearer` carries no CSRF token
- **THEN** the token check does not refuse it

### Requirement: Cookie authentication cannot be enabled without CSRF protection
Building a chain SHALL fail with a configuration error when it enables any interceptor that authenticates requests by a cookie and CSRF protection is not enabled, unless the consumer opts out explicitly with an option whose name states that CSRF protection is off.

#### Scenario: Cookie session without protection
- **WHEN** a chain enables cookie-authenticated sessions without CSRF protection and without the explicit opt-out
- **THEN** building the chain fails with a configuration error naming CSRF protection

### Requirement: Exemptions are explicit and narrow
The consumer SHALL be able to exempt specific routes, each named by method and path pattern, from CSRF protection. There SHALL be no option that exempts every route. An exempted route SHALL still carry every other protection the chain applies.

#### Scenario: Webhook route
- **WHEN** the consumer exempts `POST /webhooks/payments` and a provider posts to it cross-site with no token
- **THEN** the request is not refused by CSRF protection

### Requirement: The chain's own unsafe endpoints are covered
The chain's own state-changing endpoints SHALL be subject to CSRF protection like any other route when it is enabled: login, logout, magic-link, second-factor, enrolment, passkey, recovery, renewal, password-change, re-authentication and session-management endpoints. The OIDC back-channel logout endpoint SHALL be exempt by default, because the provider calls it server to server.

#### Scenario: Re-proof endpoint
- **WHEN** CSRF protection is enabled and a cross-site page posts to the password re-proof endpoint
- **THEN** the request is refused with the cross-site-request error
