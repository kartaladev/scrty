# Spec Delta

## MODIFIED Requirements

### Requirement: Log records carry no dependency error text
When a library log record reports the failure of a consumer-supplied dependency — a store, user loader, address or contact resolver, sender, rate limiter, cipher, keyring or key source — it SHALL carry a fixed reason naming what failed and the Go type of the error, and SHALL NOT carry the error's text. A key source's failure while a token is verified or issued is such a failure, not one of the library's own token-verification failures whose text a record keeps. This SHALL hold for every component of the library, at every level, sampled or not. The documentation of each component that logs such failures SHALL state that the consumer keeps the full detail by logging inside their own implementation of the dependency.

#### Scenario: Attempt store quotes the username
- **WHEN** form login's attempt store fails recording a failure with an error whose text is `duplicate key: Key (username)=(alice@example.com)`
- **THEN** the error record names the failure and the error's type, and no written record contains `alice@example.com`

#### Scenario: Sender quotes the recipient
- **WHEN** a magic-link send fails with an error whose text is `550 5.1.1 <alice@example.com>: Recipient address rejected`
- **THEN** no written record contains `alice@example.com`

#### Scenario: Limiter names its key
- **WHEN** a source guard's limiter fails with an error whose text names the key `magic-link|203.0.113.7`
- **THEN** the limiter-failure record carries the fixed reason and the error's type, not that text

#### Scenario: Key source names its key
- **WHEN** a consumer key source fails with an error whose text names the key `arn:aws:kms:eu-west-1:111122223333:key/abcd`
- **THEN** no written record contains that text
