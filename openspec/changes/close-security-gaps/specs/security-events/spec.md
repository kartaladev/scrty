## Purpose

Tells the consuming application about every security-relevant outcome scrty decides, as typed events with standard names, so the application can record, alert on and investigate them without parsing logs.

## ADDED Requirements

### Requirement: Security events go to an optional consumer sink
The library SHALL emit nothing until the consumer supplies an event sink. Every component that decides a security outcome SHALL accept the sink, and the chain SHALL pass its own sink to the components it builds; a component the consumer also calls outside a chain SHALL take a sink of its own, used only outside a chain, so one outcome is reported once. The sink SHALL be called synchronously on the deciding request, with a context from which the request's cancellation has been removed, and SHALL NOT be able to change the outcome: an error it returns SHALL be ignored, and a panic in it SHALL be recovered and logged without the event's contents. A sink that blocks is the consumer's responsibility, and the documentation SHALL say so.

#### Scenario: No sink
- **WHEN** no sink is configured and a login fails
- **THEN** no event is emitted and the login behaves as before

#### Scenario: Sink sees a failed login
- **WHEN** a sink is configured and a login fails for a wrong password
- **THEN** the sink receives one `authn_login_fail` event for that request

#### Scenario: Panicking sink
- **WHEN** the sink panics on a successful login's event
- **THEN** the login still succeeds, and the panic is logged

#### Scenario: Client already gone
- **WHEN** a login's request context is cancelled after the outcome is decided
- **THEN** the sink still receives the event, with a context that is not cancelled

### Requirement: Events use the OWASP Logging Vocabulary names
Each event SHALL carry a name from the OWASP Logging Vocabulary where one applies, at least:
- `authn_login_success`, `authn_login_successafterfail`, `authn_login_fail`, `authn_login_fail_max`, `authn_login_lock`;
- `authn_password_change`, `authn_password_change_fail`;
- `authn_token_created`, `authn_token_revoked`, `authn_token_reuse`;
- `session_created`, `session_renewed`, `session_expired`, `session_use_after_expire`, `session_logout`;
- `authz_fail`;
- `excess_rate_limit_exceeded`, for a rate-limit refusal;
- `malicious_csrf`, for a CSRF refusal.

Outcomes the vocabulary does not name SHALL use names under a `scrty_` prefix, documented in one list, including second-factor verification, enrolment and removal, passkey binding and removal, recovery start, completion and refusal, re-authentication, a sign-in ended through session management, host refusal, DPoP refusal, certificate-binding refusal, automation-challenge refusal and signing-key rotation.

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

### Requirement: An event reports what happened, not what was attempted
A creation event, `session_created`, `session_renewed` or `authn_token_created`, SHALL be emitted only after the session it names was stored and its credential handed out. A credential that was issued and then discarded, because its session could not be stored, a racing redemption won, or a rotation's step outlived its window, SHALL produce no creation event. A request whose own context ended before a verdict SHALL produce no failure event. A dependency failure SHALL produce no refusal event.

#### Scenario: Lost redemption race
- **WHEN** two requests redeem one magic link at once and one loses the atomic consume after issuing its credential
- **THEN** the sink receives one `authn_token_created`, for the winner

#### Scenario: Commit fails
- **WHEN** a login's credential is issued and storing its session then fails
- **THEN** the sink receives no `session_created` and no `authn_token_created`

#### Scenario: Store outage at verification
- **WHEN** a bearer request fails because the session store is unavailable
- **THEN** the sink receives no `authn_login_fail` and no `authz_fail`

### Requirement: Events carry context and never a secret
Every event SHALL carry its name, the time from the component's time source, the outcome, the user reference when one is known, the resolved client address, the first-factor kind where relevant, and the session's identifier digest, never the session identifier itself. No event SHALL carry a password, token, code, link secret, key, DPoP proof, certificate, CSRF token or stored hash.

#### Scenario: Token issued
- **WHEN** a login issues an access token
- **THEN** the `authn_token_created` event carries the user reference and no part of the token

#### Scenario: Behind a trusted proxy
- **WHEN** a login from client 203.0.113.7 through trusted proxy 10.20.0.2 fails
- **THEN** the event carries client address 203.0.113.7

### Requirement: The existing observers are delivered as events
The lockout observer's report and the session-reuse observer's report SHALL also be delivered to the sink, as `authn_login_lock` and `authn_token_reuse`, so a consumer needs one sink for every security event. The existing observer options SHALL keep working.

#### Scenario: Session reuse
- **WHEN** a superseded session identifier is presented and its family is revoked
- **THEN** the sink receives `authn_token_reuse`, and a configured reuse observer is still called
