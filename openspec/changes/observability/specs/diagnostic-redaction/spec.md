# Spec Delta

## ADDED Requirements

### Requirement: A telemetry observer receives no dependency error text
What the library hands a telemetry observer SHALL follow the rule for log records: a dependency failure SHALL be reported by a fixed reason and the error's Go type, never its text. The opaque user reference and the client address SHALL be the only personal data handed to an observer, as a stated exception that the observer's documentation names.

#### Scenario: Sender failure quoting the recipient
- **WHEN** a magic-link send fails with an error whose text is `550 5.1.1 <alice@example.com>: Recipient address rejected`
- **THEN** nothing the telemetry observer receives contains `alice@example.com`

#### Scenario: Stated exception
- **WHEN** a login by user `u-1` from `203.0.113.7` is reported
- **THEN** the observer receives `u-1` and `203.0.113.7`, and the observer's documentation names both as deliberately handed
