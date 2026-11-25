## ADDED Requirements

### Requirement: An access-token event names a local user only when there is one
An event about an access-token caller SHALL carry a user reference only when the caller is a local user: a provider token's user, a linked user, or a mapper's caller not declared external. A claims-only caller, or a mapper's caller declared external, SHALL be reported without a user reference, and never with the external subject in its place.

#### Scenario: Claims-only caller refused at a scope rule
- **WHEN** a claims-only caller is refused by an authorization rule
- **THEN** the sink receives `authz_fail` with no user reference

## MODIFIED Requirements

### Requirement: Events use the OWASP Logging Vocabulary names
Each event SHALL carry a name from the OWASP Logging Vocabulary where one applies, at least:
- `authn_login_success`, `authn_login_successafterfail`, `authn_login_fail`, `authn_login_fail_max`, `authn_login_lock`;
- `authn_password_change`, `authn_password_change_fail`;
- `authn_token_created`, `authn_token_revoked`, `authn_token_reuse`;
- `session_created`, `session_renewed`, `session_expired`, `session_use_after_expire`, `session_logout`;
- `authz_fail`;
- `excess_rate_limit_exceeded`, for a rate-limit refusal;
- `malicious_csrf`, for a CSRF refusal.

Outcomes the vocabulary does not name SHALL use names under a `scrty_` prefix, documented in one list, including second-factor verification, enrolment and removal, passkey binding and removal, recovery start, completion and refusal, re-authentication, a sign-in ended through session management, host refusal, DPoP refusal, certificate-binding refusal, automation-challenge refusal, access-token refusal by a resource server and signing-key rotation.

#### Scenario: Lockout
- **WHEN** an identifier reaches its lockout threshold
- **THEN** the sink receives `authn_login_fail_max` for that request

#### Scenario: Library-specific event
- **WHEN** the chain refuses a request for its host
- **THEN** the sink receives an event named with the `scrty_` prefix that the documented list names for host refusals

#### Scenario: Recovery start for an unknown username
- **WHEN** a recovery start is posted for a username no account has
- **THEN** the sink receives the documented recovery-start event, without a user reference, as it would for a known username

#### Scenario: Component outside a chain
- **WHEN** a consumer resets a user's second factor through the MFA component with a sink of its own, outside any chain
- **THEN** that sink receives the documented second-factor removal event

#### Scenario: CSRF refusal
- **WHEN** a CSRF check refuses a request
- **THEN** the sink receives `malicious_csrf`

#### Scenario: Access token refused
- **WHEN** a resource server refuses an expired access token
- **THEN** the sink receives the documented access-token refusal event, naming the resource server's identifier and the source, and carrying no token

#### Scenario: Refused tokens throttled
- **WHEN** a resource server throttles an address after repeated refused tokens
- **THEN** the sink receives `excess_rate_limit_exceeded`
