## MODIFIED Requirements

### Requirement: One public table maps refusals to a status
The library SHALL provide a public status-only mapping from an error to an HTTP status code. Every library default response and helper SHALL use it, and it SHALL recognise wrapped and joined errors:

| Refusal | Status |
|---|---|
| authentication required (this capability's, and the authorization capability's own), authentication failed, session idle, throttled source | 401 |
| challenge of kind password change, challenge of kind second-factor enrolment | 403 |
| challenge of any other kind | 401 |
| invalid second-factor code, throttled second-factor verification or enrolment | 401 |
| access denied, refused by policy without a reason (the security-policy capability's own error), second factor required or unsatisfiable, second-factor enrolment required, second factor on the same channel as the first, already enrolled | 403 |
| malformed login, invalid federated logout token | 400 |
| unknown identity provider named in a federated login or logout path | 404 |
| request too large | 413 |
| new password matches a recent password (the password-encoding capability's password-reused error) | 422 |
| account locked | 423 |
| too many sessions | 429 |
| any other error | 500 |

A failure to read or record password history is a dependency failure, not a refusal of the caller's input, and SHALL map to 500 like any other unrecognised error.

Federated login refusals that are authentication failures (an invalid flow, an invalid ID token, an unlinked identity, a refused provisioning, an invalid handoff code) SHALL be identifiable as the authentication-failed refusal and SHALL therefore map to 401 without rows of their own. An invalid, expired or voided emailed enrolment code SHALL be identifiable as the invalid second-factor code refusal.

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

#### Scenario: Enrolment challenge
- **WHEN** the error is a challenge of kind second-factor enrolment
- **THEN** the mapping returns 403

#### Scenario: Invalid second-factor code
- **WHEN** the error is the invalid second-factor code refusal returned by the verify endpoint
- **THEN** the mapping returns 401

#### Scenario: Expired emailed code
- **WHEN** the error is the refusal of an expired emailed enrolment code
- **THEN** the mapping returns 401

#### Scenario: Throttled enrolment
- **WHEN** the error is the throttled refusal of an enrolment begin
- **THEN** the mapping returns 401

#### Scenario: Already enrolled
- **WHEN** the error is the already-enrolled refusal
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

#### Scenario: Reused password
- **WHEN** a consumer's password-change function returns the password-reused error, wrapped with extra context
- **THEN** the mapping returns 422

#### Scenario: Password history unavailable
- **WHEN** the error is the history-unavailable error wrapping a database connection failure
- **THEN** the mapping returns 500
