## ADDED Requirements

### Requirement: Every rotation keeps the second-factor-at-login mark of the stored record
Whether a session's second factor was met at login SHALL be fixed by the write that created its sign-in. Every rotation — strict or with a grace window, with or without `WithSuccessorFromCaller` — SHALL give the successor the stored record's mark, whatever the caller's copy carries.

#### Scenario: Copy sets the mark at a strict rotation
- **WHEN** a session created without its second factor met at login is loaded, its copy is marked as met at login, and the copy is strictly rotated
- **THEN** the stored successor is not marked as met at login

#### Scenario: Copy clears the mark at a caller-built grace rotation
- **WHEN** a session created with its second factor met at login is loaded, its copy's mark is cleared, and the copy is grace-rotated with `WithSuccessorFromCaller(loaded)`
- **THEN** the stored successor is still marked as met at login

#### Scenario: Mark carried unchanged
- **WHEN** a session created with its second factor met at login is rotated with any rotation, its copy unchanged
- **THEN** the stored successor is marked as met at login
