## ADDED Requirements

### Requirement: The session suite covers listing, metadata and binding
The shared session-store suite SHALL check that a store lists a user's live sign-ins one per family, excludes expired and superseded members, never lists another user's sessions, persists sign-in metadata and key binding unchanged, and keeps the key binding across save, rotation and renewal. A consumer's own session store SHALL be able to run these checks.

#### Scenario: Consumer store missing the listing
- **WHEN** a consumer runs the session suite against their own store whose listing returns another user's session
- **THEN** the suite fails, naming the listing check
