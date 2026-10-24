# Spec Delta

## ADDED Requirements

### Requirement: An empty digest never verifies
Issuing a key SHALL fail when the digest function returns an empty digest, and verification SHALL refuse with the verification-failed error when either the stored digest or the digest of the presented secret is empty. Construction SHALL fail with a configuration error when the consumer's digest function returns an empty digest, or the same digest for two different inputs, on a probe at construction.

#### Scenario: Digest returning nothing
- **WHEN** the manager is constructed with a digest function that returns an empty value
- **THEN** construction fails with a configuration error

#### Scenario: Empty stored digest
- **WHEN** a stored record has an empty digest and any well-formed secret is presented for its key identifier
- **THEN** verification fails with the verification-failed error

## MODIFIED Requirements

### Requirement: Keys can be rotated
Rotating a key SHALL issue a new key for the same principal reference, name and scopes, with the lifetime the caller gives, and then revoke the old key. The new key SHALL be returned only when both steps succeed. Rotating an unknown key SHALL fail and issue nothing. Rotating a revoked or expired key SHALL fail with an identifiable rotation-refused error and issue nothing. Revoking the old key SHALL be a conditional write that succeeds only while the old key is live; when it finds the key already revoked by a concurrent rotation or revocation, the new key SHALL be revoked and the rotation SHALL fail with the rotation-refused error, so that of any number of concurrent rotations of one key at most one leaves a live replacement. The two steps SHALL be atomic when rotation runs inside a store transaction the caller attached, and SHALL otherwise be documented as two separate writes.

#### Scenario: Rotation
- **WHEN** a key is rotated
- **THEN** the new key verifies with the same principal and scopes
- **AND** the old key fails with the verification-failed error

#### Scenario: Revoke fails inside a transaction
- **WHEN** a key is rotated inside an attached transaction, revoking the old key fails, and the transaction is rolled back
- **THEN** no new key exists
- **AND** the old key still verifies

#### Scenario: Revoked key
- **WHEN** a revoked admin-scoped key is rotated
- **THEN** rotation fails with the rotation-refused error and no new key is issued

#### Scenario: Expired key
- **WHEN** a key past its lifetime is rotated
- **THEN** rotation fails with the rotation-refused error and no new key is issued

#### Scenario: Concurrent rotations
- **WHEN** two rotations of the same live key run concurrently
- **THEN** exactly one returns a new key, the other fails with the rotation-refused error, and exactly one key derived from the old one verifies
