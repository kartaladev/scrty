## MODIFIED Requirements

### Requirement: Consumer refusal checks are returned unchanged
A consumer SHALL be able to supply refusal checks, each receiving the resolved principal and the user's password-change time. The first check that returns an error SHALL stop redemption, and later checks SHALL NOT run.
- A check's error SHALL be returned unchanged when its chain can be walked.
- When the chain cannot be walked (a cycle, a fan-out past the bound, or a panicking method), the library's fixed error SHALL be returned in its place, as the http-error-propagation capability requires for every consumer dependency's error.

Checks SHALL be documented as required to have no side effects, because each of several racing redemptions of one link may run them.

#### Scenario: Consumer sentinel
- **WHEN** a consumer check returns the consumer's `terms-not-accepted` error
- **THEN** redemption returns an error matching `terms-not-accepted`
- **AND** the link stays redeemable

#### Scenario: Unwalkable check error
- **WHEN** a consumer check returns an error whose chain contains itself
- **THEN** redemption returns the library's fixed error without hanging, and it does not match the invalid-link error
- **AND** the link stays redeemable
