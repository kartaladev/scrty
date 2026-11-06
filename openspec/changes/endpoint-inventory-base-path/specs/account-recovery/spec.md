# Spec Delta

## MODIFIED Requirements

### Requirement: Recovery is off by default, and its wiring mistakes fail at construction
No recovery endpoint SHALL exist until the consumer enables recovery on the chain. Saved codes, issued codes, the password proof and the MFA-method proof SHALL each be enabled separately. Construction SHALL fail with a configuration error when:
- no recovery code kind is enabled;
- only one proof kind is enabled, so no pair of different kinds is possible;
- issued codes are enabled with no sender, or the password proof with no password authenticator, or the MFA-method proof with no method that can serve;
- the reset has no authenticator kind registered;
- any endpoint path does not have the shape `http-security-chain` requires of endpoint paths, or collides with another recovery path or another endpoint the chain answers, as that capability's chain-wide collision requirement judges.

#### Scenario: Off by default
- **WHEN** a chain is built without enabling recovery and a POST is sent to `/recovery/complete`
- **THEN** no recovery is attempted by the library

#### Scenario: One proof kind
- **WHEN** recovery is enabled with saved codes only
- **THEN** construction fails with a configuration error

#### Scenario: Path collision
- **WHEN** the start path is set to the sign-out path
- **THEN** construction fails with a configuration error naming recovery and logout
