## ADDED Requirements

### Requirement: An encoder can report that a stored hash needs upgrading
Each built-in encoder SHALL report, for a stored hash it recognises, whether the hash was produced with parameters weaker than the encoder's current ones or by another algorithm the caller's encoder supersedes, without deriving a key. The report SHALL be optional for a consumer's own encoder, and an encoder that does not offer it SHALL be treated as never needing an upgrade.

#### Scenario: Raised Argon2id memory
- **WHEN** an Argon2id encoder at 128 MiB is asked about a stored Argon2id hash at 64 MiB
- **THEN** it reports that the hash needs upgrading

#### Scenario: Current parameters
- **WHEN** the same encoder is asked about a hash it produced itself
- **THEN** it reports that no upgrade is needed

## REMOVED Requirements

### Requirement: Password reuse is not checked unless the consumer enables it
**Reason**: Reuse checking becomes the reuse rule of the one password policy, so every rule for a new password is configured in one place.
**Migration**: Replace `NewReuseGuard(history, encoder, depth)` with a password policy built with the reuse rule over the same history and depth; the off-by-default guarantee moves to the `password-policy` capability.

### Requirement: The reuse guard refuses the current password and the N−1 before it
**Reason**: Moved to the `password-policy` capability as the reuse rule.
**Migration**: The same behaviour, with the same depth semantics, is reached through the policy's reuse rule.

### Requirement: Reuse is detected by verifying the candidate against each stored hash
**Reason**: Moved to the `password-policy` capability as the reuse rule.
**Migration**: The default matchers and the matcher option move to the policy's reuse rule unchanged.

### Requirement: A successful change retires the old hash and bounds history to N−1
**Reason**: Moved to the `password-policy` capability, whose change runs every rule before retiring and writing.
**Migration**: Call the policy's change instead of the guard's.

### Requirement: A change through the reuse guard records when it happened
**Reason**: Moved to the `password-policy` capability.
**Migration**: The clock option and the ready-made provisioner write move to the policy unchanged.

### Requirement: The reuse guard fails closed
**Reason**: Moved to the `password-policy` capability.
**Migration**: The history-unavailable error is unchanged.

### Requirement: Reuse refusals and history failures carry no credential
**Reason**: Moved to the `password-policy` capability, which extends it to every rule.
**Migration**: None needed; the password-reused and history-unavailable errors keep their identities.

### Requirement: Reuse guard wiring mistakes fail at construction
**Reason**: Moved to the `password-policy` capability.
**Migration**: The same mistakes fail the policy's construction.
