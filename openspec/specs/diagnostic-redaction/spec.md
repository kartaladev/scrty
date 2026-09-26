# diagnostic-redaction Specification

## Purpose

Keeps the text of a failing consumer-supplied dependency, and the personal data it may quote, out of the library's log records and out of the errors it returns, while leaving operators and consumers able to tell what failed.

## Requirements

### Requirement: Log records carry no dependency error text
When a library log record reports the failure of a consumer-supplied dependency — a store, user loader, address or contact resolver, sender, rate limiter or cipher — it SHALL carry a fixed reason naming what failed and the Go type of the error, and SHALL NOT carry the error's text. This SHALL hold for every component of the library, at every level, sampled or not. The documentation of each component that logs such failures SHALL state that the consumer keeps the full detail by logging inside their own implementation of the dependency.

#### Scenario: Attempt store quotes the username
- **WHEN** form login's attempt store fails recording a failure with an error whose text is `duplicate key: Key (username)=(alice@example.com)`
- **THEN** the error record names the failure and the error's type, and no written record contains `alice@example.com`

#### Scenario: Sender quotes the recipient
- **WHEN** a magic-link send fails with an error whose text is `550 5.1.1 <alice@example.com>: Recipient address rejected`
- **THEN** no written record contains `alice@example.com`

#### Scenario: Limiter names its key
- **WHEN** a source guard's limiter fails with an error whose text names the key `magic-link|203.0.113.7`
- **THEN** the limiter-failure record carries the fixed reason and the error's type, not that text

### Requirement: Returned errors caused by a dependency carry fixed library text
Where a library interceptor, guard or manager returns an error caused by a consumer-supplied dependency, the returned error's text SHALL be fixed library text. The library error it stands for, and the dependency's original error, SHALL stay reachable by error identity and type, so the status it maps to and any consumer match are unchanged. Errors the consumer's own refusal checks, guards, authorizers and rule sets return SHALL be returned unchanged, as their own capabilities require.

#### Scenario: Session store outage at login
- **WHEN** a login's session creation fails with an error quoting the user reference `u-123`
- **THEN** the error reaching the consumer's error handler does not contain `u-123` in its text
- **AND** it matches the store's original error by identity, and maps to the same status as before

#### Scenario: Consumer check unchanged
- **WHEN** a consumer's magic-link refusal check returns its own `terms-not-accepted` error
- **THEN** the error returned is that error, text included

### Requirement: Stated exceptions are deliberate and documented
The following SHALL remain in log records, and each component's documentation SHALL say so and why: the address of a throttled source, in rate-limit records; the opaque user reference, in second-factor and policy records; the email domain, in identity-linking records; and the text of the library's own protocol failures (token verification, provider discovery and key-set retrieval, the provider's token-endpoint response). No other personal data or dependency text SHALL be added to a record without a requirement naming it.

#### Scenario: Throttled source stays visible
- **WHEN** a source is throttled
- **THEN** the throttle record names the source address

#### Scenario: Token verification detail stays visible to operators
- **WHEN** a bearer token fails verification because its signature does not verify
- **THEN** the debug record states the verification failure's own text
