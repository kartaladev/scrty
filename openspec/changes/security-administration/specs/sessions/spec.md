# Spec Delta

## ADDED Requirements

### Requirement: A session can record a selected active role
A session SHALL carry an optional selected role name, empty by default. Recording it SHALL change only that field, conditional on the session still existing, and SHALL NOT re-create a deleted session or change its deadlines. Every store, in memory and durable, SHALL keep it.

#### Scenario: Recorded
- **WHEN** the selected role `audit` is recorded on a live session and the session is loaded
- **THEN** the session's selected role is `audit` and its deadlines are unchanged

#### Scenario: Deleted session
- **WHEN** a selected role is recorded on a session that was deleted
- **THEN** recording fails with the session-not-found error and nothing is created

### Requirement: Rotation carries the selected role
Every rotation and renewal SHALL carry the session's selected role to its successor unchanged.

#### Scenario: Renewal
- **WHEN** a session with selected role `audit` is renewed
- **THEN** the successor's selected role is `audit`
