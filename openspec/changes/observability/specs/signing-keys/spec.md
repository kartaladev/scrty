# Spec Delta

## ADDED Requirements

### Requirement: The key manager reports rotations to a telemetry observer
When given a telemetry observer, the key manager SHALL report each rotation it attempts, scheduled or initial, as a `signingkey.rotate` operation with the algorithm as its method. A rotation that fails SHALL end with an error outcome naming the error's Go type, and SHALL report the event `crypt_key_rotate_fail`. The observer SHALL never receive key material.

#### Scenario: Scheduled rotation
- **WHEN** a scheduled rotation for `ES256` succeeds
- **THEN** the observer sees a `signingkey.rotate` operation with the method `ES256` end in success

#### Scenario: Store failure during rotation
- **WHEN** storing the new key fails
- **THEN** the operation ends with an error outcome, the observer receives `crypt_key_rotate_fail`, and nothing it receives contains key material
