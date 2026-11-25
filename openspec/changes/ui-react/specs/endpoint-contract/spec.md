# Spec Delta

## Purpose

Publishes what the chain's browser-facing endpoints accept and answer as a versioned contract, so
clients outside scrty, such as React components, can rely on it and detect a mismatch.

## ADDED Requirements

### Requirement: The browser-facing endpoints carry a contract version
The library SHALL declare a contract version for its browser-facing endpoints, starting at `1`. Any change that removes or renames a request field, an answer field or a problem type, or changes a status, SHALL raise the version. Adding an optional field or a new endpoint SHALL NOT.

#### Scenario: Additive change
- **WHEN** a release adds an optional field to the sign-in's JSON answer
- **THEN** the contract version stays `1`

#### Scenario: Breaking change
- **WHEN** a release renames the sign-in answer's `idle_expires_at`
- **THEN** the contract version becomes `2`

### Requirement: The contract is published as an OpenAPI document
Each release SHALL publish an OpenAPI 3.1 document describing every browser-facing endpoint's path, method, request body, answers, statuses and problem types for its contract version. A build whose endpoint inventory has an endpoint the document lacks SHALL fail its checks.

#### Scenario: Endpoint without a description
- **WHEN** a new browser-facing endpoint is added and the document does not describe it
- **THEN** the project's checks fail, naming the endpoint

### Requirement: Discovery is off until enabled
A chain SHALL answer a discovery endpoint only when the consumer enables it. Without it, the discovery path SHALL pass through to the consumer's handler.

#### Scenario: Not enabled
- **WHEN** a chain is built without discovery and `GET /.well-known/scrty` arrives
- **THEN** it passes through to the consumer's handler

### Requirement: Discovery answers the contract version and enabled flows
When enabled, the discovery endpoint SHALL answer `GET` with JSON holding the contract version, the base path, whether sign-ins are cookie sessions, the CSRF header and field names, and the flows the chain answers, with each federated provider by its configured name. It SHALL hold no secret, user data or key material, and SHALL carry `Cache-Control: no-store`.

#### Scenario: Cookie chain with password and one provider
- **WHEN** discovery is enabled on a cookie chain with form login and OIDC provider `corp`
- **THEN** the answer holds `"contract":"1"`, `"cookieSession":true`, the CSRF names, and flows naming `password` and `sso:corp`, and nothing else from the configuration

#### Scenario: Consumer path
- **WHEN** the consumer moves discovery to `/auth/meta`
- **THEN** it answers there, and the default path passes through
