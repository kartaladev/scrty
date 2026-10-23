# Spec Delta

## ADDED Requirements

### Requirement: The logout token maximum age is bounded
Construction SHALL fail with a configuration error when the logout token's maximum age is longer than one hour, because the maximum age is the replay window of a captured logout token.

#### Scenario: Maximum age of a day
- **WHEN** back-channel logout is configured with a 24-hour maximum age
- **THEN** construction fails with a configuration error

#### Scenario: Consumer maximum age within the bound
- **WHEN** back-channel logout is configured with a 10-minute maximum age
- **THEN** construction succeeds
