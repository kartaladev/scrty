# Spec Delta

## ADDED Requirements

### Requirement: Issuance can be bounded atomically per subject
The manager SHALL offer an issue bounded by a limit, which issues a token for a subject, under its purpose, only while fewer than the limit were issued for it within the issuance window. The count and the issue SHALL be one atomic store operation, so concurrent bounded issues never take the count past the limit. A refused issue SHALL report an identifiable limit-reached outcome and issue nothing. A limit below 1 SHALL be refused.

#### Scenario: Under the limit
- **WHEN** two tokens for `ada@example.com` were issued 10 minutes ago and a bounded issue with a limit of 5 is made
- **THEN** a token is issued

#### Scenario: At the limit
- **WHEN** five tokens for `ada@example.com` were issued within the window and a bounded issue with a limit of 5 is made
- **THEN** the limit-reached outcome is reported and no token is issued

#### Scenario: Concurrent bounded issues
- **WHEN** 20 bounded issues for `ada@example.com` with a limit of 5 run concurrently and none were issued before
- **THEN** exactly 5 tokens are issued
