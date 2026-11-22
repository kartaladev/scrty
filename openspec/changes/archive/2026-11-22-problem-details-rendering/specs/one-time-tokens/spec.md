## MODIFIED Requirements

### Requirement: A refusal between check and consume does not spend the token
A caller SHALL be able to run its own refusal checks after a successful check and before consumption. A refusal or lookup failure at that point SHALL leave the token redeemable until it expires. The manager SHALL provide a single redemption operation that checks, runs the caller's refusal checks in order and then consumes.
- A refusal check's error SHALL be returned unchanged when its chain can be walked, and the token SHALL NOT be consumed.
- When the chain cannot be walked, the library's fixed error SHALL be returned in its place, as the http-error-propagation capability requires, and the token SHALL NOT be consumed.
- When marking the token consumed fails, redemption SHALL return the invalid-token error and no subject, and the failure SHALL be logged at error level.

#### Scenario: Policy refusal keeps the link
- **WHEN** a valid token is redeemed with a refusal check that denies because the user must enrol in MFA, and the same token is later redeemed with no refusal
- **THEN** the first redemption returns the enrolment error unchanged
- **AND** the second redemption succeeds

#### Scenario: Unwalkable refusal keeps the link
- **WHEN** a valid token is redeemed with a refusal check whose error's `Unwrap` method panics
- **THEN** redemption returns the library's fixed error without panicking
- **AND** the token stays redeemable

#### Scenario: Consumption failure is not a success
- **WHEN** a token passes its check and refusal checks, but the store fails while marking it consumed
- **THEN** redemption returns the invalid-token error and no subject
