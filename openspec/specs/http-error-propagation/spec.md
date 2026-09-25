# http-error-propagation Specification

## Purpose

Defines how scrty's HTTP layer reports a refusal: as a typed error handed to the consumer's own error handling, mapped to a status by one public table, and answered by default with nothing but a status code, so no internal detail reaches a client unless the consumer chooses to render it.

## Requirements

### Requirement: Refusals propagate as errors, unrendered
Interceptors and guards SHALL report every refusal by returning an error. The library SHALL NOT write a response body for a refusal. The error reaching the consumer's error handling SHALL be the refusal error itself, or an error wrapping it, so the consumer can identify the refusal by error identity or type. The library SHALL NOT include a problem-details or other body renderer.

#### Scenario: Consumer identifies the refusal
- **WHEN** a request is refused because the account is locked
- **THEN** the error reaching the consumer's error handler is identifiable as the account-locked refusal

#### Scenario: No body from the library
- **WHEN** any refusal occurs and the consumer's error handler writes nothing
- **THEN** no bytes written by the library appear in the response body

### Requirement: Refusal errors are a stable public contract
The library SHALL expose distinguishable public refusal errors for at least these cases:
- authentication required;
- malformed login;
- request too large.

A refusal a core already names SHALL be reported as that core's own error rather than restated under a second name. In particular, a policy that denies without giving a reason SHALL be reported as the security-policy capability's reasonless-deny error, because the policy engine already substitutes it: a second sentinel for the same condition would be unreachable, and a consumer matching one identity would miss the other. Where this capability's own refusal and a core's name the same condition, the chain SHALL wrap the core's with its own so that either identity matches.

It SHALL also expose one challenge error type, and SHALL map the refusal errors that the authentication, authorization, session, security-policy and second-factor cores define. A challenge error SHALL carry its challenge kind, the pending session when one exists, and the access token issued with it when one was issued. No refusal error's text SHALL contain an access token, a session handle or a submitted credential.

#### Scenario: Challenge error contents
- **WHEN** form login is challenged for a second factor
- **THEN** the challenge error carries the second-factor kind, the pending session and the token

#### Scenario: Challenge text carries no secret
- **WHEN** a challenge error carrying a token is converted to text
- **THEN** the text names the challenge kind and contains neither the token nor the session handle

#### Scenario: Challenge raised on a later request
- **WHEN** the password-change gate refuses a session
- **THEN** the challenge error carries the session and no token

### Requirement: One public table maps refusals to a status
The library SHALL provide a public status-only mapping from an error to an HTTP status code. Every library default response and helper SHALL use it, and it SHALL recognise wrapped and joined errors:

| Refusal | Status |
|---|---|
| authentication required (this capability's, and the authorization capability's own), authentication failed, session idle, throttled source | 401 |
| challenge of kind password change | 403 |
| challenge of any other kind | 401 |
| access denied, refused by policy without a reason (the security-policy capability's own error), second factor required or unsatisfiable, second-factor enrolment required, second factor on the same channel as the first | 403 |
| malformed login, invalid federated logout token | 400 |
| unknown identity provider named in a federated login or logout path | 404 |
| request too large | 413 |
| account locked | 423 |
| too many sessions | 429 |
| any other error | 500 |

Federated login refusals that are authentication failures (an invalid flow, an invalid ID token, an unlinked identity, a refused provisioning, an invalid handoff code) SHALL be identifiable as the authentication-failed refusal and SHALL therefore map to 401 without rows of their own.

#### Scenario: Wrapped sentinel
- **WHEN** an error wraps the access-denied refusal with extra context
- **THEN** the mapping returns 403

#### Scenario: Joined verification failure
- **WHEN** an error joins the authentication failure refusal with a token-parsing cause
- **THEN** the mapping returns 401

#### Scenario: Second-factor challenge
- **WHEN** the error is a challenge of kind second factor
- **THEN** the mapping returns 401

#### Scenario: Password-change challenge
- **WHEN** the error is a challenge of kind password change
- **THEN** the mapping returns 403

#### Scenario: Unrecognised error
- **WHEN** the error is a database connection failure that wraps no refusal
- **THEN** the mapping returns 500

#### Scenario: Either identity matches a wrapped core refusal
- **WHEN** an unauthenticated request matches a rule requiring authentication
- **THEN** the refusal matches both this capability's authentication-required error and the authorization capability's own, and maps to 401

#### Scenario: Unknown identity provider
- **WHEN** the error is the unknown-provider refusal of a federated login path
- **THEN** the mapping returns 404

#### Scenario: Invalid logout token
- **WHEN** the error is the invalid-logout-token refusal
- **THEN** the mapping returns 400

#### Scenario: Federated authentication failure
- **WHEN** the error is the invalid-handoff refusal
- **THEN** the mapping returns 401

#### Scenario: Consumer refines the mapping
- **WHEN** the consumer's error handler maps its own error type to 409 and falls back to the library mapping for everything else
- **THEN** the consumer's error returns 409 and a library refusal keeps its library status

### Requirement: A challenge takes precedence over a sentinel
When an error is, or wraps, a challenge error, the mapping SHALL use the challenge's status even if the error also wraps a refusal sentinel.

#### Scenario: Challenge wrapping a sentinel
- **WHEN** a challenge of kind second factor wraps the access-denied refusal
- **THEN** the mapping returns 401

### Requirement: A policy deny without a reason never passes as success
When a policy denies a request in any phase without giving a reason, the chain SHALL refuse the request with the refused-by-policy error. It SHALL map to 403, never to an authentication failure and never to a successful response. The refusal SHALL NOT be counted as a failed credential.

#### Scenario: Reasonless deny at login
- **WHEN** a consumer's post-authentication policy denies with no reason during form login
- **THEN** the request is refused with 403, no session is created and no failed attempt is recorded

#### Scenario: Reasonless deny per request
- **WHEN** a consumer's per-request policy denies with no reason for a bearer token request
- **THEN** the request is refused with 403 and the handler does not run

### Requirement: The default response is a bare status and fails closed
With no error handler configured, a refused request on the net/http chain SHALL receive the mapped status code with an empty body. It SHALL carry no error text and SHALL NOT reach the downstream handler. Headers set by an interceptor before refusing, such as a `WWW-Authenticate` challenge, SHALL be kept.

#### Scenario: Default refusal
- **WHEN** an unauthenticated request is refused and no error handler is configured
- **THEN** the response is 401 with an empty body and the handler did not run

#### Scenario: Internal error text withheld
- **WHEN** a lookup fails with the message `connection refused to db-primary:5432` and no error handler is configured
- **THEN** the response is 500 with an empty body

#### Scenario: Challenge header kept
- **WHEN** Basic authentication fails with no error handler configured
- **THEN** the response is 401 with a `WWW-Authenticate` header and an empty body

### Requirement: A consumer error handler replaces the default
The consumer SHALL be able to supply an error handler for the net/http chain. The handler SHALL receive the response writer, the request and the propagated error for every refusal, and the default response SHALL NOT be written. The net/http per-endpoint guards SHALL accept the same kind of handler. With none given, guards SHALL answer with the status from the public mapping and an empty body.

#### Scenario: Consumer renders a body
- **WHEN** the consumer supplies an error handler that writes a JSON body using the library status mapping, and a request is refused as access denied
- **THEN** the response is 403 with the consumer's JSON body

#### Scenario: Consumer handler for guards
- **WHEN** a net/http guard refuses and the consumer supplied an error handler for guards
- **THEN** the consumer's handler receives the guard's refusal error

#### Scenario: Guard default agrees with the table
- **WHEN** a net/http guard with no error handler refuses because its authorization attributes are invalid
- **THEN** the response carries the same status the public mapping gives that error, with an empty body
