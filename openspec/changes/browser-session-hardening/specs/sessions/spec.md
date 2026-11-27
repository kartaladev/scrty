## ADDED Requirements

### Requirement: A grace rotation can carry the caller's verified state
`RotateWithGrace` and `RotateWithGraceIssuing` SHALL take `WithSuccessorFromCaller()`, which builds the successor's verification state from the caller's session. Its user, family, binding, CSRF token, sign-in metadata and role SHALL come from the stored record, and its absolute deadline SHALL be the earlier of the stored and the caller's. A superseded session SHALL be refused with `ErrRenewalConflict`, storing nothing.

#### Scenario: Verified state carried
- **WHEN** a caller grace-rotates its copy of a session with the second factor satisfied and a refreshed authentication time, with `WithSuccessorFromCaller()`
- **THEN** the stored successor has the second factor satisfied and the refreshed authentication time, and the old record keeps its own state

#### Scenario: Default unchanged
- **WHEN** the same rotation is made without the option
- **THEN** the successor is built from the stored record, as before

#### Scenario: Sign-in state not taken from the caller
- **WHEN** the caller's copy carries another CSRF token or key binding
- **THEN** the successor carries the stored record's

#### Scenario: Copy cannot extend or clear
- **WHEN** the caller's copy carries a later absolute deadline, another selected role, or `PasswordChangePending` false while the stored record has it true
- **THEN** the successor keeps the stored absolute deadline and role, and `PasswordChangePending` true

#### Scenario: Already superseded
- **WHEN** a session a renewal superseded inside its window is rotated with the option
- **THEN** the rotation fails with `ErrRenewalConflict`, and nothing is stored or revoked

#### Scenario: Strict rotation
- **WHEN** `Rotate` is given the option
- **THEN** it fails with `ErrConfig`, and nothing is stored
