# Spec Delta

## MODIFIED Requirements

### Requirement: A consumer can cap the live parked requests
A consumer MAY set a ceiling on the number of live parked requests. It is off by default. Once the ceiling is reached, a valid request that would be parked SHALL be answered at its redirect URI with `temporarily_unavailable`, `state` and `iss`, and SHALL NOT be stored. Every pending-request store SHALL count its live requests.

#### Scenario: Default has no ceiling
- **WHEN** no ceiling is set and requests are parked
- **THEN** every valid request is parked

#### Scenario: Ceiling reached
- **WHEN** the consumer sets a ceiling of 1000, 1000 requests are live, and another valid request arrives
- **THEN** the browser is redirected with `error=temporarily_unavailable`, `state` and `iss`, and nothing is stored

#### Scenario: Store cannot count
- **WHEN** the consumer sets a ceiling and supplies its own pending-request store
- **THEN** construction succeeds, and the ceiling is enforced from the live count that store reports
