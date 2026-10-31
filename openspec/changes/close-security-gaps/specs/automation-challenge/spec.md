## Purpose

Lets the consumer put a challenge, such as a CAPTCHA, a managed challenge or a proof of work, in front of scrty's unauthenticated flows, so automated attacks cost more, without scrty choosing a vendor.

## ADDED Requirements

### Requirement: The challenge seam is off until the consumer supplies a verifier
No flow SHALL require a challenge until the consumer supplies a challenge verifier. The library SHALL bundle no verifier for a third-party service.

#### Scenario: Not configured
- **WHEN** no verifier is configured and a login is posted
- **THEN** no challenge is asked for and the login proceeds as before

### Requirement: Selected unauthenticated flows ask the verifier before their work
With a verifier configured, form login, Basic authentication, magic-link requests, passwordless passkey begin and recovery start SHALL call it before their guarded work and before any account lookup. Each flow SHALL be selectable on its own, and all five SHALL be selected by default once a verifier is given. The verifier SHALL receive the request and SHALL answer pass, refuse, or not needed. A refusal SHALL be the challenge-required error. A verifier error SHALL refuse the request.

#### Scenario: Refused login
- **WHEN** a verifier is configured and refuses a login request
- **THEN** the login is refused with the challenge-required error, no account is looked up, and no lockout failure is recorded

#### Scenario: Flow not selected
- **WHEN** the consumer selects only magic-link requests and a login is posted
- **THEN** the verifier is not called for the login

### Requirement: The verifier can ask only for suspicious requests
The verifier SHALL receive whether the request's source or identifier has recent failures recorded by the chain's limiters, so it can answer not needed for ordinary traffic and ask only for suspicious requests.

#### Scenario: Clean source
- **WHEN** a source with no recorded failures posts a login, and the verifier answers not needed when there are none
- **THEN** the login proceeds without a challenge

### Requirement: A challenge refusal is counted against the source
A refused challenge SHALL count against the request's per-source rate limit, like a failed attempt, unless the consumer opts out.

#### Scenario: Repeated refusals
- **WHEN** a source is refused by the verifier as many times as the flow's source limit allows
- **THEN** its next request is refused by the source limit before the verifier is called
