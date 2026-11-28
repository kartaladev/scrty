# Spec Delta

## MODIFIED Requirements

### Requirement: A cap is refused unless its wiring can enforce it
Construction SHALL fail with a configuration error, naming the option, when:
- the cap is not above the threshold;
- a retention is zero or less, given without a cap, or shorter than the lockout window.

Every attempt store SHALL keep consecutive counts and holds, so a cap never depends on which store the consumer supplies.

#### Scenario: Store without consecutive counts
- **WHEN** a policy is configured with a cap and a consumer's attempt store
- **THEN** construction succeeds, and the cap is enforced from the consecutive counts and holds that store keeps

#### Scenario: Retention without a cap
- **WHEN** a policy is configured with a retention and no cap
- **THEN** construction fails with a configuration error

#### Scenario: Cap at the threshold
- **WHEN** a policy is configured with a threshold of 5 and a cap of 5
- **THEN** construction fails with a configuration error
