## ADDED Requirements

### Requirement: A password update can be conditional on the stored hash
Updating a user SHALL accept an option naming the password hash the caller expects to replace. With it, the store SHALL write the new password only when the stored hash still equals the expected one, deciding it in the write itself rather than by a preceding read, and SHALL otherwise change nothing and report a distinct not-updated result that is not a storage failure. The password-changed time SHALL NOT move on a conditional update unless the caller names it. Every shipped identity store SHALL honour the option, and the conformance suite SHALL check it.

#### Scenario: Hash unchanged
- **WHEN** a user's stored hash is `H1` and an update names `H2` as the new password conditional on `H1`
- **THEN** the stored hash becomes `H2`

#### Scenario: Password changed meanwhile
- **WHEN** a user's stored hash was `H1`, a password change stored `H3`, and an update names `H2` conditional on `H1`
- **THEN** the stored hash stays `H3`, and the update reports not-updated without a storage error

#### Scenario: Concurrent conditional updates
- **WHEN** two updates conditional on the same stored hash run at the same time
- **THEN** exactly one changes the stored hash, and the other reports not-updated

#### Scenario: Consumer store ignoring the condition
- **WHEN** a consumer runs the conformance suite against a store that writes the password whatever the stored hash is
- **THEN** the suite fails, naming the conditional-update check
