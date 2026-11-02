## ADDED Requirements

### Requirement: The session suite covers listing, metadata and binding
The shared session-store suite SHALL check that a store lists a user's live sign-ins one per family, excludes expired and superseded members, never lists another user's sessions, matches the user reference exactly, persists sign-in metadata, key binding and CSRF token unchanged, keeps all three across save, and inserts a successor with them on supersession. A listing SHALL NOT be required to return sealed fields (the retained ID token and the CSRF token), and the suite SHALL NOT compare them in a listing. A consumer's own session store SHALL be able to run these checks.

#### Scenario: Consumer store missing the listing
- **WHEN** a consumer runs the session suite against their own store whose listing returns another user's session
- **THEN** the suite fails, naming the listing check

#### Scenario: Consumer store that lets save change the binding
- **WHEN** a consumer runs the session suite against a store whose save overwrites the key binding
- **THEN** the suite fails, naming the binding check
