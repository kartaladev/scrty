# Spec Delta

## Purpose

Lets operators see what the library does through traces, metrics and correlated logs: how its operations perform and what security decisions it makes. It never costs a consumer who does not use it anything, and it never hands out secrets.

## ADDED Requirements

### Requirement: Telemetry is off unless an observer is given
Every instrumented component SHALL accept an optional telemetry observer. With none given, the component SHALL call nothing and behave exactly as it does without instrumentation.

#### Scenario: No observer
- **WHEN** a chain and a session manager are built without an observer
- **THEN** every request and session operation behaves as before, and no observer method is called

### Requirement: Every instrumented operation is started and ended exactly once
For each instrumented operation, the component SHALL start it with the observer before doing the work and SHALL end it exactly once afterwards, whether the operation succeeds, is refused, fails, is cancelled, or panics.

#### Scenario: Refused login
- **WHEN** a login is refused for invalid credentials
- **THEN** the observer sees one start and one end of the `login` operation

#### Scenario: Panic inside the operation
- **WHEN** a consumer's code called inside an instrumented operation panics
- **THEN** the observer sees the operation ended once before the panic continues

### Requirement: Work runs under the context the observer returned
The observer's start SHALL return the context the operation then runs under. Everything the library does within the operation, its log records included, SHALL use that context.

#### Scenario: Log record carries the operation's context
- **WHEN** an observer's start returns a context carrying a marker, and the operation writes a log record
- **THEN** that record is written with a context carrying the marker

### Requirement: Outcomes are bounded and never carry error text
Each operation SHALL end with one outcome: success; refused, naming the library refusal from its fixed set; or error, naming the error's Go type. An outcome SHALL never carry an error's text.

#### Scenario: Refusal outcome
- **WHEN** a second-factor verification is refused because the method is not usable
- **THEN** the outcome is refused, naming that refusal

#### Scenario: Store failure outcome
- **WHEN** a session store fails with an error whose text quotes a user reference
- **THEN** the outcome is error, naming the error's Go type, and nothing the observer receives contains that text

### Requirement: The observer receives the subject, never a secret
The observer SHALL receive the operation, the method and the outcome. Where the component knows them, it SHALL also receive the opaque user reference and the client address. It SHALL never receive a token, a session identifier, a one-time code, a password, a password hash or a dependency's error text.

#### Scenario: Login subject
- **WHEN** user `u-1` logs in from `203.0.113.7`
- **THEN** the observer receives `u-1` and `203.0.113.7` with the login operation

#### Scenario: No secrets
- **WHEN** a login, a second-factor verification and a session renewal complete
- **THEN** nothing the observer receives contains the password, the code, the session identifier or any token issued

### Requirement: Operations have stable names
Operations SHALL be named from a fixed, documented set:
- each built-in endpoint, by its operation identifier without the `scrty.` prefix (for example `login`, `mfa.verify`, `reauth.verify`);
- `password.hash`, `password.verify`;
- `session.create`, `session.rotate`, `session.renew`;
- `signingkey.rotate`;
- `expiry.run`.

#### Scenario: Endpoint operation name
- **WHEN** a request reaches the MFA verify endpoint
- **THEN** the operation is named `mfa.verify`

### Requirement: Security events use a fixed vocabulary
The library SHALL report security events named from a fixed, documented vocabulary. Events OWASP's logging vocabulary names SHALL use its names, including `authn_login_success`, `authn_login_fail`, `authn_login_lock`, `authn_password_change`, `authn_token_reuse`, `authz_fail`, `excess_rate_limit_exceeded`, `session_created`, `session_renewed` and `session_logout`. Additions SHALL use its style, such as `authn_mfa_fail`.

#### Scenario: Locked account
- **WHEN** a login is refused because the account is locked
- **THEN** the observer receives the event `authn_login_lock`

#### Scenario: Throttled source
- **WHEN** a source is throttled at the login endpoint
- **THEN** the observer receives the event `excess_rate_limit_exceeded`

#### Scenario: Detected reuse
- **WHEN** a superseded session is presented after its window
- **THEN** the observer receives the event `authn_token_reuse`

### Requirement: The OpenTelemetry adapter emits spans named for the operation
The OpenTelemetry adapter SHALL start one internal span per operation, named `scrty.` followed by the operation name, as a child of the span in the context it is given. It SHALL record the outcome on the span, setting `error.type` to the refusal name or the error's Go type, and leaving it unset on success.

#### Scenario: Span for a refused login
- **WHEN** a login is refused for invalid credentials inside a consumer's server span
- **THEN** a span `scrty.login` is recorded as its child, with `scrty.outcome` `refused` and an `error.type` naming the refusal

### Requirement: The OpenTelemetry adapter records two metrics
The adapter SHALL record `scrty.operation.duration` (a histogram in seconds) for each operation, and `scrty.security.events` (a counter in `{event}`) for each security event. Both SHALL carry `scrty.method`, `scrty.outcome` and `error.type`, plus `scrty.operation` or `scrty.event` respectively. Every refusal SHALL be counted, unsampled.

#### Scenario: Refusals counted while logs are sampled
- **WHEN** fifty logins are refused within one refusal-log window
- **THEN** `scrty.security.events` counts fifty `authn_login_fail` events, while the refusal log writes one sampled record

### Requirement: Personal data stays off by default, and never reaches metrics
By default the adapter SHALL record no user reference and no client address. The consumer SHALL be able to add the user reference and the client address to spans. No configuration SHALL add either to a metric.

#### Scenario: Default
- **WHEN** user `u-1` logs in through the adapter with its defaults
- **THEN** no recorded span or metric contains `u-1` or the client address

#### Scenario: Consumer adds the user to spans
- **WHEN** the consumer enables the user attribute and user `u-1` logs in
- **THEN** the `scrty.login` span carries `user.id` `u-1`, and no metric does

### Requirement: The adapter's providers are replaceable
The adapter SHALL use the tracer and meter providers the consumer gives it, and otherwise the globally registered ones. It SHALL depend only on the OpenTelemetry API, never its SDK.

#### Scenario: Injected providers
- **WHEN** the consumer gives the adapter an in-memory tracer and meter provider
- **THEN** every span and metric is recorded there and none reaches the global providers

### Requirement: Chain routes can label the consumer's server span
The adapter SHALL offer a helper that, for a request a chain endpoint answers, gives that endpoint's route as listed in the chain's endpoint list, for use as `http.route` on the consumer's own server span. It SHALL never set an attribute on a span the adapter did not start.

#### Scenario: Route for a chain endpoint
- **WHEN** the helper is asked about `POST /auth/mfa/verify/totp` on a chain with the base path `/auth`
- **THEN** it returns `/auth/mfa/verify/{method}`

#### Scenario: Consumer route
- **WHEN** the helper is asked about `GET /projects/42`, which no chain endpoint answers
- **THEN** it returns no route
