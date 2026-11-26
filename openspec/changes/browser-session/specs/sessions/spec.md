# Spec Delta

## ADDED Requirements

### Requirement: A session records whether its browser cookie persists
The manager SHALL let a caller create a session marked as holding a persistent browser cookie, in the same store write that creates it. Every successor created by rotation, renewal or re-authentication SHALL carry the mark. Saving a session SHALL NOT change it. A session created without the mark SHALL report it unset. The mark is library-owned: a consumer SHALL NOT set it through session data.

#### Scenario: Created persistent
- **WHEN** a session is created with the persistent-cookie mark, and then loaded
- **THEN** it reports the mark set, and the store received exactly one write for the creation

#### Scenario: Renewal keeps the mark
- **WHEN** a session created with the mark is renewed
- **THEN** the successor reports the mark set

#### Scenario: Save cannot set the mark
- **WHEN** a copy of a session created without the mark, its mark set in memory, is saved
- **THEN** the stored session still reports the mark unset

#### Scenario: Consumer data cannot claim it
- **WHEN** a session is created with consumer data whose keys resemble the mark's name
- **THEN** it reports the mark unset, and the consumer data is returned unchanged

### Requirement: A rotation can record the successor's selected role in its own write
The manager SHALL let a caller of a rotation with a grace window name the successor's selected role, and SHALL store the successor with that role in the same atomic store operation that supersedes the current session. Without a named role, the successor SHALL take the role stored on the superseded session, as before. A store that does not record the named role SHALL make the rotation fail.

#### Scenario: Role named at rotation
- **WHEN** a session whose selected role is `admin` is rotated with the successor's role named `audit`
- **THEN** the successor loads with `audit`, and the store received one supersession and no separate role selection

#### Scenario: Empty role clears it
- **WHEN** a session with a selected role is rotated with the successor's role named as empty
- **THEN** the successor loads with no selected role

#### Scenario: Superseded session gone before the write
- **WHEN** the current session is removed after it was loaded and before the rotation naming a role writes
- **THEN** the rotation fails, and no successor is stored

#### Scenario: Store ignores the named role
- **WHEN** a store supersedes the session but writes the successor with a role other than the one named
- **THEN** the rotation fails with an error, and the caller is not handed the successor as a success
