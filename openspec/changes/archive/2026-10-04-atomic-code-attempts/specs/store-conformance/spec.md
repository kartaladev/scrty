## ADDED Requirements

### Requirement: The enrolment suites prove the TOTP attempt charge
The MFA enrolment suite SHALL cover charging and giving back TOTP verification attempts, and the race suite SHALL release many concurrent chargers against many independent confirmed enrolments at once, requiring exactly the limit to succeed per enrolment. Each suite case SHALL be shown to fail against a store variant with the defect it targets.

#### Scenario: TOTP attempt charge race
- **WHEN** the race suite releases 20 chargers, with a limit of 5, for each of 50 independent confirmed enrolments at once
- **THEN** it passes only if every enrolment has exactly five successful charges

#### Scenario: Uncapped charge caught
- **WHEN** the suites run against a store variant whose charge ignores the limit
- **THEN** the suites fail

#### Scenario: Read-then-write charge caught
- **WHEN** the race suite runs against a store variant whose charge reads the count and then writes it unconditionally
- **THEN** the suite fails

#### Scenario: Window that never ends caught
- **WHEN** the suites run against a store variant that keeps counting in an ended window
- **THEN** the suites fail

#### Scenario: Give-back across windows caught
- **WHEN** the suites run against a store variant whose give-back ignores the window it names
- **THEN** the suites fail
