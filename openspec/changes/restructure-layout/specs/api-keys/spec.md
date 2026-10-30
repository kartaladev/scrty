# Spec Delta

## ADDED Requirements

### Requirement: Key owners can be required to be active
By default, API key authentication SHALL NOT look up a verified key's principal reference, which belongs to the consumer and need not name a user. Its documentation SHALL say so. A consumer SHALL be able to give it a user loader. Then the reference SHALL be loaded as a user, and the request refused as a wrong key is when the user is missing or inactive, or with the unavailable error, uncounted against the source, when the loader fails.

#### Scenario: Default does not look the owner up
- **WHEN** API key authentication has no user loader, and a key issued for `svc-billing` is presented
- **THEN** the request is authenticated without any user lookup

#### Scenario: Inactive owner
- **WHEN** API key authentication has a user loader, and a key issued for `u-1` is presented after `u-1` was made inactive
- **THEN** the request is refused exactly as a wrong key is, and a failure is counted against the source

#### Scenario: Missing owner
- **WHEN** API key authentication has a user loader, and a key whose principal reference names no user is presented
- **THEN** the request is refused exactly as a wrong key is

#### Scenario: Active owner
- **WHEN** API key authentication has a user loader, and a key issued for active user `u-1` is presented
- **THEN** the request is authenticated as the key's service principal

#### Scenario: Owner lookup fails
- **WHEN** API key authentication has a user loader that returns a connection error
- **THEN** the request is refused with the unavailable error, answered 503, and no failure is counted against the source
