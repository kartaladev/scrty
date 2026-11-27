# Spec Delta

## ADDED Requirements

### Requirement: The chain reports its endpoints and decisions to a telemetry observer
When given a telemetry observer, the chain SHALL report each request a built-in endpoint answers as one operation named for that endpoint. It SHALL report a security event for each login success or failure, locked-account refusal, throttled source, second-factor and re-proof outcome, password change, logout and authorization refusal. It SHALL hand the same observer to the components it builds itself.

#### Scenario: Successful login
- **WHEN** a login succeeds on a chain given an observer
- **THEN** the observer sees the `login` operation end in success, and the events `authn_login_success` and `session_created`

#### Scenario: Authorization refusal
- **WHEN** a centralized authorization rule refuses a request
- **THEN** the observer receives the event `authz_fail`

#### Scenario: Consumer route not an operation
- **WHEN** a request reaches the consumer's handler without a built-in endpoint answering it
- **THEN** no endpoint operation is started for it

#### Scenario: Chain-built source guard
- **WHEN** the password-login source guard the chain built throttles a source
- **THEN** the chain's observer receives `excess_rate_limit_exceeded`, with no option given to the guard

### Requirement: Chain log records carry the operation's context
Every log record the chain writes while serving a built-in endpoint SHALL be written with the context the observer's start returned for that endpoint's operation. Records not tied to a request, such as suppressed-refusal summaries, SHALL keep a context of their own.

#### Scenario: Refusal record correlated
- **WHEN** a login refusal is logged on a chain whose observer adds a trace to the context
- **THEN** the refusal record is written with that trace's context
