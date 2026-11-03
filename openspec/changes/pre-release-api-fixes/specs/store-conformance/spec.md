# Spec Delta

## ADDED Requirements

### Requirement: The key-store suite proves deletion
The signing-key store suite SHALL prove, for every key store, that deleting removes only the named keys, that a missing identifier or none is no error and changes nothing, that a deleted key is no longer loaded, and that a deleted identifier can be stored again. The in-memory default store SHALL pass it. The ambient-transaction suite SHALL cover deletion wherever it covers the store's other writes.

#### Scenario: Store with an over-broad delete
- **WHEN** the key-store suite runs against a store whose delete removes every record
- **THEN** the suite fails on the case that deletes only the named keys

#### Scenario: Store refusing a missing key
- **WHEN** the key-store suite runs against a store whose delete fails on an identifier it does not hold
- **THEN** the suite fails on the case that deletes a missing key

## MODIFIED Requirements

### Requirement: The enrolment suites prove generation-conditional writes
The enrolment suites SHALL prove that confirming an enrolment and recording an accepted time step are refused when they name an enrolment generation other than the current one, and when they name no generation. For a store that implements the device-proof operations, they SHALL also prove that confirming an enrolment whose device is proven is refused and changes nothing, whether or not the proof issued an emailed code, and whether or not that code has expired or run out of attempts. The race suite SHALL prove that a confirmation and a device proof of one generation, released together, never both succeed, so a store cannot pass by checking the proof and then writing separately.

#### Scenario: Store ignoring the generation
- **WHEN** the enrolment suite runs against a store whose confirmation ignores the named generation
- **THEN** the suite fails on the case that confirms naming a replaced generation

#### Scenario: Store ignoring the device proof
- **WHEN** the device-proof suite runs against a store whose confirmation ignores the device proof
- **THEN** the suite fails on the case that confirms a proven enrolment

#### Scenario: Store confirming by reading and then writing
- **WHEN** the race suite runs against a store whose confirmation checks the device proof and then writes in a separate step
- **THEN** the suite fails on the case that races a confirmation against a device proof

#### Scenario: Store whose refusal still writes
- **WHEN** the device-proof suite runs against a store whose confirmation of a proven enrolment reports false and clears the emailed code
- **THEN** the suite fails on the case that confirms a proven enrolment

#### Scenario: Store honouring only a live emailed code
- **WHEN** the device-proof suite runs against a store whose confirmation refuses a proven enrolment only while its emailed code is unexpired
- **THEN** the suite fails on the case that confirms a proven enrolment whose code has expired
