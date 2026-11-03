## Purpose

Lets the consumer put a challenge, such as a CAPTCHA, a managed challenge or a proof of work, in front of scrty's unauthenticated flows, so automated attacks cost more, without scrty choosing a vendor.

## ADDED Requirements

### Requirement: The challenge seam is off until the consumer supplies a verifier
No flow SHALL require a challenge until the consumer supplies a challenge verifier. The library SHALL bundle no verifier for a third-party service. Enabling the seam with a nil verifier, or selecting no flow, SHALL fail construction. Selecting a flow the chain does not enable, or a verifier that stands in front of no enabled flow, SHALL also fail construction.

#### Scenario: Not configured
- **WHEN** no verifier is configured and a login is posted
- **THEN** no challenge is asked for and the login proceeds as before

#### Scenario: Nil verifier
- **WHEN** the consumer enables the challenge seam with a nil verifier
- **THEN** building the chain fails with a configuration error naming the verifier

#### Scenario: Selected flow not enabled
- **WHEN** the consumer selects only passwordless begin on a chain without passkey login
- **THEN** building the chain fails with a configuration error naming the flow

### Requirement: Selected unauthenticated flows ask the verifier before their work
With a verifier configured, form login, Basic authentication, magic-link requests, passwordless passkey begin and recovery start SHALL call it after their source limit and before their guarded work and any account lookup. Each flow SHALL be selectable on its own. Once a verifier is given, form login, magic-link requests, passwordless begin and recovery start SHALL be selected by default; Basic authentication, whose clients re-authenticate on every request and cannot answer a challenge, SHALL be selected only when the consumer names it. The verifier SHALL receive the request and SHALL answer pass, refuse, or not needed. A refusal SHALL be the challenge-required error. A verifier error SHALL fail the request as a dependency failure, with fixed library text, not charged to any throttle and not answered as a refusal. A request whose own context ended while the verifier ran SHALL fail with an error matching that context's error.

#### Scenario: Refused login
- **WHEN** a verifier is configured and refuses a login request
- **THEN** the login is refused with the challenge-required error, no account is looked up, and no lockout failure is recorded

#### Scenario: Basic not selected by default
- **WHEN** a verifier is configured with the default selection on a chain with form login and Basic authentication, and a Basic-authenticated request is made
- **THEN** the verifier is not called and no recent failures are read for the request

#### Scenario: Basic selected by name
- **WHEN** the consumer selects Basic authentication and a Basic-authenticated request is made
- **THEN** the verifier is called after the source limit and before the password is checked

#### Scenario: Default selection on a Basic-only chain
- **WHEN** a verifier is configured with the default selection on a chain whose only selectable flow is Basic authentication
- **THEN** building the chain fails with a configuration error naming the flow selection

#### Scenario: Flow not selected
- **WHEN** the chain enables form login and magic-link requests, the consumer selects only magic-link requests, and a login is posted
- **THEN** the verifier is not called for the login

#### Scenario: Verifier outage
- **WHEN** the verifier returns a connection error for a login
- **THEN** the request fails with an error the default mapping answers with 500, no account is looked up, and nothing is charged to the source limit

#### Scenario: Client leaves during the verifier
- **WHEN** a login's context is cancelled and the verifier fails with that cancellation
- **THEN** the request fails with an error matching the cancellation, and nothing is recorded at ERROR

### Requirement: The verifier can ask only for suspicious requests
The verifier SHALL receive whether the request's source has recent failures recorded by the chain's limiters and, at form login and Basic authentication, whether the identifier has failures within the lockout's failure window, so it can answer not needed for ordinary traffic and ask only for suspicious requests. Recovery start, magic-link requests and passwordless begin SHALL report no identifier failures: an owner's sign-in clears an account's failures, so the signal would let a challenge tell a known account from an unknown one on a flow that otherwise answers alike for both. When the source limiter keeps an IPv6 aggregate, the verifier SHALL also receive whether the aggregate holding the request's source has recent failures, reported apart from the source's own, which keeps its meaning; for IPv4, or without an aggregate, it SHALL be reported as none. The library's limiters, in memory and durable, SHALL answer whether a key has recent failures. A limiter that cannot answer SHALL be reported to the verifier as having recent failures, so it can ask.

#### Scenario: Clean source
- **WHEN** a source with no recorded failures posts a login, and the verifier answers not needed when there are none
- **THEN** the login proceeds without a challenge

#### Scenario: Suspicious identifier
- **WHEN** a clean source posts a login for a username with recent failures
- **THEN** the verifier is told the identifier has recent failures

#### Scenario: Recovery start keeps the identifier out
- **WHEN** a username has recent failures and a recovery start is posted for it
- **THEN** the verifier is told the identifier has no recent failures

#### Scenario: Fresh address in a failing aggregate
- **WHEN** the source limiter keeps a /56 aggregate, failures were recorded from three /64s inside one /56, and a login is posted from a fourth /64 in it
- **THEN** the verifier is told the source has no recent failures and its aggregate has recent failures

#### Scenario: Aggregate not configured
- **WHEN** the source limiter keeps no aggregate and an IPv6 source posts a login
- **THEN** the verifier is told the aggregate has no recent failures

#### Scenario: Durable limiter
- **WHEN** the chain's source limit is kept by the Redis or SQL limiter and a source with no recorded failures posts a login
- **THEN** the verifier is told the source has no recent failures

### Requirement: A challenge refusal is counted against the source
A refused challenge SHALL count against the request's per-source rate limit, like a failed attempt, unless the consumer opts out. It SHALL NOT count against the identifier's lockout. A flow with no per-source limit, such as magic-link requests, counts the refusal nowhere.

#### Scenario: Repeated refusals
- **WHEN** a source is refused by the verifier as many times as the flow's source limit allows
- **THEN** its next request is refused by the source limit before the verifier is called

#### Scenario: Opted out
- **WHEN** the consumer opts out of counting refusals and a source is refused by the verifier as many times as the source limit allows
- **THEN** its next request still reaches the verifier
