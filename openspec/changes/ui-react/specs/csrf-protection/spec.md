# Spec Delta

## ADDED Requirements

### Requirement: Same-origin scripts can read the sign-in's CSRF token
On a chain whose sign-ins are cookie sessions, the consumer SHALL be able to enable an endpoint that answers a `GET` from a same-origin script with the request's sign-in's CSRF token as JSON, with `Cache-Control: no-store`. It SHALL refuse a request without a sign-in, and a request whose Fetch Metadata or `Origin` marks it cross-site. It SHALL be off by default.

#### Scenario: Same-origin script
- **WHEN** the endpoint is enabled and a same-origin script with a valid session cookie requests it
- **THEN** it answers `200` with the sign-in's token

#### Scenario: Cross-site request
- **WHEN** a request with `Sec-Fetch-Site: cross-site` and a valid session cookie reaches it
- **THEN** it is refused as cross-site, and no token is answered

#### Scenario: No sign-in
- **WHEN** a request without a session cookie reaches it
- **THEN** it is refused with the authentication-required error

#### Scenario: Off by default
- **WHEN** the endpoint is not enabled and its path is requested
- **THEN** the request passes through to the consumer's handler
