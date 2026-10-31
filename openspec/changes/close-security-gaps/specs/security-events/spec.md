## Purpose

Tells the consuming application about every security-relevant outcome scrty decides, as typed events with standard names, so the application can record, alert on and investigate them without parsing logs.

## ADDED Requirements

### Requirement: Security events go to an optional consumer sink
The library SHALL emit nothing until the consumer supplies an event sink. Every component that decides a security outcome SHALL accept the sink, and the chain SHALL pass its own sink to the components it builds. The sink SHALL be called synchronously on the deciding request, with a context from which the request's cancellation has been removed, and SHALL NOT be able to change the outcome: a sink that panics or blocks is the consumer's responsibility, and an error it returns SHALL be ignored.

#### Scenario: No sink
- **WHEN** no sink is configured and a login fails
- **THEN** no event is emitted and the login behaves as before

#### Scenario: Sink sees a failed login
- **WHEN** a sink is configured and a login fails for a wrong password
- **THEN** the sink receives one `authn_login_fail` event for that request

### Requirement: Events use the OWASP Logging Vocabulary names
Each event SHALL carry a name from the OWASP Logging Vocabulary where one applies, at least:
- `authn_login_success`, `authn_login_successafterfail`, `authn_login_fail`, `authn_login_fail_max`, `authn_login_lock`;
- `authn_password_change`, `authn_password_change_fail`;
- `authn_token_created`, `authn_token_revoked`, `authn_token_reuse`;
- `session_created`, `session_renewed`, `session_expired`, `session_use_after_expire`, `session_logout`;
- `authz_fail`.

Outcomes the vocabulary does not name SHALL use names under a `scrty_` prefix, documented in one list, including second-factor verification, enrolment and removal, passkey binding and removal, recovery start and completion, re-authentication, CSRF refusal, DPoP refusal, automation-challenge refusal, rate-limit refusal and signing-key rotation.

#### Scenario: Lockout
- **WHEN** an identifier reaches its lockout threshold
- **THEN** the sink receives `authn_login_fail_max` for that request

#### Scenario: Library-specific event
- **WHEN** a CSRF check refuses a request
- **THEN** the sink receives an event named with the `scrty_` prefix that the documented list names for CSRF refusals

### Requirement: Events carry context and never a secret
Every event SHALL carry its name, the time from the component's time source, the outcome, the user reference when one is known, the resolved client address, the first-factor kind where relevant, and the session's identifier digest, never the session identifier itself. No event SHALL carry a password, token, code, link secret, key or stored hash.

#### Scenario: Token issued
- **WHEN** a login issues an access token
- **THEN** the `authn_token_created` event carries the user reference and no part of the token

### Requirement: The existing observers are delivered as events
The lockout observer's report and the session-reuse observer's report SHALL also be delivered to the sink, as `authn_login_lock` and `authn_token_reuse`, so a consumer needs one sink for every security event. The existing observer options SHALL keep working.

#### Scenario: Session reuse
- **WHEN** a superseded session identifier is presented and its family is revoked
- **THEN** the sink receives `authn_token_reuse`, and a configured reuse observer is still called
