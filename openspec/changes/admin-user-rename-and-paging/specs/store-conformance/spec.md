# Spec Delta

## MODIFIED Requirements

### Requirement: The enrolment suites prove generation-conditional writes
The enrolment suites SHALL prove that confirming an enrolment and recording an accepted time step are refused when they name an enrolment generation other than the current one, and when they name no generation. For every store, they SHALL also prove that confirming an enrolment whose device is proven is refused and changes nothing, whether or not the proof issued an emailed code, and whether or not that code has expired or run out of attempts. The race suite SHALL prove that a confirmation and a device proof of one generation, released together, never both succeed, so a store cannot pass by checking the proof and then writing separately.

#### Scenario: Store ignoring the generation
- **WHEN** the enrolment suite runs against a store whose confirmation ignores the named generation
- **THEN** the suite fails on the case that confirms naming a replaced generation

#### Scenario: Store ignoring the device proof
- **WHEN** the enrolment suite runs against a store whose confirmation ignores the device proof
- **THEN** the suite fails on the case that confirms a proven enrolment

#### Scenario: Store confirming by reading and then writing
- **WHEN** the race suite runs against a store whose confirmation checks the device proof and then writes in a separate step
- **THEN** the suite fails on the case that races a confirmation against a device proof

#### Scenario: Store whose refusal still writes
- **WHEN** the enrolment suite runs against a store whose confirmation of a proven enrolment reports false and clears the emailed code
- **THEN** the suite fails on the case that confirms a proven enrolment

#### Scenario: Store honouring only a live emailed code
- **WHEN** the enrolment suite runs against a store whose confirmation refuses a proven enrolment only while its emailed code is unexpired
- **THEN** the suite fails on the case that confirms a proven enrolment whose code has expired
