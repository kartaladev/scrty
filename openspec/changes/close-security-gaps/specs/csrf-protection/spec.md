## Purpose

Refuses state-changing requests that another site makes the user's browser send, first by the browser's own Fetch Metadata and Origin signals and then, for cookie-authenticated requests, by a token bound to the sign-in.

## ADDED Requirements

### Requirement: Cross-site unsafe requests are refused by Fetch Metadata and Origin
With CSRF protection enabled, a request whose method is not exactly `GET`, `HEAD` or `OPTIONS`, compared case-sensitively, SHALL be judged before any authentication interceptor runs:
1. `Sec-Fetch-Site` of `same-origin` or `none` SHALL pass.
2. `Sec-Fetch-Site` of `same-site` or `cross-site`, or any other value, SHALL be refused unless its `Origin` is a trusted origin.
3. With no `Sec-Fetch-Site`, an `Origin` whose scheme, host and port differ from the request's own scheme and host SHALL be refused unless it is a trusted origin. `Origin: null` SHALL never match and SHALL never be trusted.
4. With neither header, the request SHALL pass this check.

The request's own scheme and host SHALL be those the chain resolves, including through trusted proxies. The refusal SHALL be the cross-site-request error, and the check SHALL read no session and no body.

#### Scenario: Cross-site form post
- **WHEN** a page on `https://evil.example` submits a form to `POST https://app.example.com/settings` and the browser sends `Sec-Fetch-Site: cross-site`
- **THEN** the request is refused with the cross-site-request error and the handler does not run

#### Scenario: Login CSRF
- **WHEN** a page on `https://evil.example` posts the attacker's credentials to `POST https://app.example.com/login` with `Sec-Fetch-Site: cross-site`
- **THEN** the request is refused with the cross-site-request error, no credential is checked and no session is created

#### Scenario: Older browser without Fetch Metadata
- **WHEN** a request arrives with `Origin: https://evil.example`, no `Sec-Fetch-Site`, and the request's own origin is `https://app.example.com`
- **THEN** it is refused with the cross-site-request error

#### Scenario: Sandboxed or privacy-redirected origin
- **WHEN** a `POST` arrives with `Origin: null` and no `Sec-Fetch-Site`
- **THEN** it is refused with the cross-site-request error

#### Scenario: Port differs
- **WHEN** a `POST` to `https://app.example.com` arrives with `Origin: https://app.example.com:8443` and no `Sec-Fetch-Site`
- **THEN** it is refused with the cross-site-request error

#### Scenario: Unusual method
- **WHEN** a request with method `get` (lower case) or `PROPFIND` arrives with `Sec-Fetch-Site: cross-site`
- **THEN** it is judged as unsafe and refused

#### Scenario: Behind a trusted proxy
- **WHEN** a trusted proxy forwards scheme `https` and host `app.example.com`, the app receives the request over plain HTTP for host `10.20.1.5:8080`, and the browser sends `Origin: https://app.example.com` with no `Sec-Fetch-Site`
- **THEN** the request passes the check

#### Scenario: Non-browser client
- **WHEN** a server-to-server `POST` arrives with neither `Sec-Fetch-Site` nor `Origin`
- **THEN** it passes the Fetch Metadata check

#### Scenario: Safe method
- **WHEN** a cross-site `GET` arrives with `Sec-Fetch-Site: cross-site`
- **THEN** it is not refused by CSRF protection

### Requirement: Origins allowed by CORS are trusted for CSRF by default
Every origin the CORS policy lists exactly, or matches by an explicit pattern, SHALL be a trusted origin for the Fetch Metadata check, so a frontend on a sibling subdomain can call the API. A CORS `*` SHALL NOT make any origin trusted. The consumer SHALL be able to add trusted origins, validated and normalised as CORS origins are, and SHALL be able to stop CORS origins from being trusted.

#### Scenario: Sibling frontend
- **WHEN** CORS allows `https://app.example.com` and that page sends `POST https://api.example.com/orders` with `Sec-Fetch-Site: same-site`
- **THEN** the request passes the Fetch Metadata check

#### Scenario: Consumer opts out
- **WHEN** the consumer stops CORS origins from being trusted for CSRF, and the same request arrives
- **THEN** it is refused with the cross-site-request error

#### Scenario: Wildcard CORS trusts nothing
- **WHEN** CORS allows `*` without credentials and a page on `https://evil.example` sends a `POST` with `Sec-Fetch-Site: cross-site`
- **THEN** it is refused with the cross-site-request error

#### Scenario: Same-site sibling not listed
- **WHEN** CORS allows only `https://app.example.com` and a page on `https://blog.example.com` sends `POST https://api.example.com/orders` with `Sec-Fetch-Site: same-site`
- **THEN** it is refused with the cross-site-request error

### Requirement: Cookie-authenticated unsafe requests need a token bound to the sign-in
An unsafe request authenticated by a cookie SHALL carry a CSRF token, in a header or form field whose names are replaceable, `X-CSRF-Token` and `csrf_token` by default. The token SHALL be issued for the request's sign-in, and SHALL be refused when it is missing, malformed, or issued for another sign-in. It SHALL stay valid across the renewals and rotations of that sign-in, and SHALL NOT be accepted for a new sign-in after logout or a fresh login. It SHALL be compared in constant time. The token SHALL be readable by the consumer's page through a documented accessor. A request authenticated only by an `Authorization` header SHALL NOT need a token. By default the token SHALL be at least 32 random bytes made when the sign-in's session is built and stored on the sign-in, and a sign-in that holds no token SHALL be refused on unsafe cookie-authenticated requests. The consumer SHALL be able to replace the token source, and the accessor and the check SHALL then use the consumer's source.

#### Scenario: Missing token
- **WHEN** a cookie-authenticated `POST` passes the Fetch Metadata check but carries no CSRF token
- **THEN** it is refused with the cross-site-request error

#### Scenario: Token from another sign-in
- **WHEN** a cookie-authenticated `POST` carries a token issued for a different sign-in
- **THEN** it is refused with the cross-site-request error

#### Scenario: Token survives renewal
- **WHEN** a sign-in's session is renewed and the page posts with the token it read before the renewal
- **THEN** the token check passes

#### Scenario: Token does not survive a new sign-in
- **WHEN** a user logs out, logs in again, and the page posts with the token it read before logging out
- **THEN** it is refused with the cross-site-request error

#### Scenario: Bearer request
- **WHEN** a `POST` authenticated by `Authorization: Bearer` carries no CSRF token
- **THEN** the token check does not refuse it

#### Scenario: Sign-in without a token
- **WHEN** a cookie-authenticated `POST` arrives for a sign-in made before CSRF protection was enabled, so it holds no token
- **THEN** it is refused with the cross-site-request error

#### Scenario: Consumer's token source
- **WHEN** the consumer replaces the token source with one that derives the token from the sign-in's handle under their own key
- **THEN** the accessor returns that source's token, a cookie-authenticated `POST` carrying it passes, and one carrying the default source's token is refused

### Requirement: Cookie authentication cannot be enabled without CSRF protection
Building a chain SHALL fail with a configuration error when it enables any interceptor that authenticates requests by a cookie and CSRF protection is not enabled, unless the consumer opts out explicitly with an option whose name states that CSRF protection is off.

#### Scenario: Cookie session without protection
- **WHEN** a chain enables cookie-authenticated sessions without CSRF protection and without the explicit opt-out
- **THEN** building the chain fails with a configuration error naming CSRF protection

#### Scenario: Explicit opt-out
- **WHEN** a chain enables cookie-authenticated sessions with the explicit opt-out
- **THEN** the chain builds

#### Scenario: Cookie authenticator ahead of the CSRF check
- **WHEN** a chain with CSRF protection registers a cookie-authenticating interceptor in a slot at or before the one where CSRF protection judges requests
- **THEN** building the chain fails with a configuration error naming CSRF protection

#### Scenario: Token check where CSRF protection never ran
- **WHEN** a cookie authenticator asks for the token check on a request CSRF protection never judged, on a chain that did not opt out
- **THEN** the check fails with a configuration error, answered 500, and no session is published

### Requirement: Exemptions are explicit and narrow
The consumer SHALL be able to exempt specific routes, each named by an exact method and an exact path or a path pattern whose wildcard matches one path segment, from CSRF protection. Matching SHALL use the path the chain routes by, and SHALL NOT match another path that a redirect, a trailing slash, a case change or a different encoding would lead to. There SHALL be no option that exempts every route, and an exemption naming no method or the path `/` alone SHALL fail construction. An exempted route SHALL still carry every other protection the chain applies.

#### Scenario: Webhook route
- **WHEN** the consumer exempts `POST /webhooks/payments` and a provider posts to it cross-site with no token
- **THEN** the request is not refused by CSRF protection

#### Scenario: Neighbouring paths stay protected
- **WHEN** the consumer exempts `POST /webhooks/payments` and cross-site posts arrive for `/webhooks/payments/`, `/Webhooks/payments` and `/webhooks/payments/../../settings`
- **THEN** each is judged by CSRF protection as an ordinary route

#### Scenario: Other method stays protected
- **WHEN** the consumer exempts `POST /webhooks/payments` and a cross-site `DELETE /webhooks/payments` arrives
- **THEN** it is refused with the cross-site-request error

### Requirement: The chain's own unsafe endpoints are covered
The chain's own state-changing endpoints SHALL be subject to CSRF protection like any other route when it is enabled: login, logout, magic-link request and redemption, OIDC handoff redemption, second-factor, enrolment, passkey, recovery, renewal, password-change, re-authentication and session-management endpoints. The OIDC back-channel logout endpoint SHALL be exempt by default, because the provider calls it server to server; the consumer SHALL be able to remove that exemption.

#### Scenario: Re-proof endpoint
- **WHEN** CSRF protection is enabled and a cross-site page posts to the password re-proof endpoint
- **THEN** the request is refused with the cross-site-request error

#### Scenario: Session management
- **WHEN** CSRF protection is enabled and a cross-site page sends `DELETE /sessions`
- **THEN** the request is refused and no sign-in is ended

#### Scenario: Back-channel logout
- **WHEN** CSRF protection is enabled and an identity provider posts a logout token to the back-channel logout endpoint with no `Origin` and no `Sec-Fetch-Site`
- **THEN** CSRF protection does not refuse it
