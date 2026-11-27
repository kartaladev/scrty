## ADDED Requirements

### Requirement: A grace rotation can carry the caller's verified state
`RotateWithGrace` and `RotateWithGraceIssuing` SHALL take `WithSuccessorFromCaller()`, which builds the successor's verification state from the caller's session. Its user, family, binding, CSRF token, sign-in metadata and role SHALL come from the stored record. A superseded session SHALL be refused with `ErrRenewalConflict`, storing nothing.

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
- **WHEN** the stored record is not confined, and the caller's copy carries a later absolute deadline, another selected role, or `PasswordChangePending` false while the stored record has it true
- **THEN** the successor keeps the stored absolute deadline and role, and `PasswordChangePending` true

#### Scenario: Lifted confinement
- **WHEN** the stored record is confined, and the caller's copy has cleared the confinement and restored the origin deadline
- **THEN** the successor takes the restored deadline; a copy claiming a deadline past the origin keeps the stored one

#### Scenario: Record changed since the copy was loaded
- **WHEN** another request saves a confinement or a pending password change on the session after the caller loaded it, and the caller then rotates its copy with `WithSuccessorFromCaller(loaded)`
- **THEN** the rotation fails with `ErrRenewalConflict`, and nothing is written

#### Scenario: Already superseded
- **WHEN** a session a renewal superseded inside its window is rotated with the option
- **THEN** the rotation fails with `ErrRenewalConflict`, and nothing is stored or revoked

#### Scenario: Strict rotation
- **WHEN** `Rotate` is given the option
- **THEN** it fails with `ErrConfig`, and nothing is stored

### Requirement: A caller's copy cannot extend a grace successor's deadline
With `WithSuccessorFromCaller`, the successor's absolute deadline SHALL be the earlier of the stored record's and the caller's copy's, except when the copy lifted a stored confinement: then it SHALL be the copy's, never later than the stored origin deadline.

#### Scenario: Copy lowers the deadline
- **WHEN** the caller's copy was confined during the request, lowering its absolute deadline
- **THEN** the successor ends at the copy's lower deadline

#### Scenario: Copy raises the deadline
- **WHEN** the stored record is not confined and the copy carries a later absolute deadline
- **THEN** the successor keeps the stored deadline

### Requirement: A strict rotation never extends a session or moves it to another user
`Rotate` and `RotateIssuing` SHALL refuse a caller's copy that names another user with `ErrConfig`, storing nothing. The successor's first factor SHALL come from the stored record, and its absolute and idle deadlines SHALL each be the earlier of the stored record's and the copy's, unless the copy lifted a stored confinement, when they SHALL be the copy's, never past the stored origin deadline.

#### Scenario: Copy with a later deadline
- **WHEN** a caller strictly rotates a copy whose absolute and idle deadlines are a day later than the stored record's
- **THEN** the successor keeps the stored deadlines

#### Scenario: Copy of another user
- **WHEN** a caller strictly rotates a copy whose user is another user's
- **THEN** the rotation fails with `ErrConfig`, and nothing is stored

#### Scenario: Verification out of a confinement on a header-bearer chain
- **WHEN** second-factor verification restores the sign-in's deadlines on its copy and rotates strictly
- **THEN** the successor takes the restored deadlines
