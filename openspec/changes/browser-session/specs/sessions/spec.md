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
