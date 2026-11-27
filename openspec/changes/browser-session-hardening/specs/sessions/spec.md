## ADDED Requirements

### Requirement: A grace rotation can carry the caller's verified state
`RotateWithGrace` and `RotateWithGraceIssuing` SHALL take `WithSuccessorFromCaller()`, which builds the successor from the caller's session as a strict rotation does, while the key binding, CSRF token and sign-in metadata still come from the stored record. With it, rotating a session that is already superseded SHALL be refused with `ErrRenewalConflict`, storing nothing. A strict rotation SHALL refuse the option with `ErrConfig`.

#### Scenario: Verified state carried
- **WHEN** a caller grace-rotates its copy of a session with the second factor satisfied and a refreshed authentication time, with `WithSuccessorFromCaller()`
- **THEN** the stored successor has the second factor satisfied and the refreshed authentication time, and the old record keeps its own state

#### Scenario: Default unchanged
- **WHEN** the same rotation is made without the option
- **THEN** the successor is built from the stored record, as before

#### Scenario: Sign-in state not taken from the caller
- **WHEN** the caller's copy carries another CSRF token or key binding
- **THEN** the successor carries the stored record's

#### Scenario: Already superseded
- **WHEN** a session a renewal superseded inside its window is rotated with the option
- **THEN** the rotation fails with `ErrRenewalConflict`, and nothing is stored or revoked

#### Scenario: Strict rotation
- **WHEN** `Rotate` is given the option
- **THEN** it fails with `ErrConfig`, and nothing is stored
