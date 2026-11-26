# Spec Delta

## ADDED Requirements

### Requirement: A persistent browser cookie choice survives a durable store
Durable session stores SHALL store and return unchanged a session's persistent-cookie mark. A session stored without it, including one stored before the mark existed, SHALL read back with it unset.

#### Scenario: Mark round trip across backends
- **WHEN** a session created with the persistent-cookie mark is saved through the store of one supported backend and loaded through another
- **THEN** it loads with the mark set

#### Scenario: Session stored before the migration
- **WHEN** a session row written before the persistent-cookie column existed is loaded after the migration
- **THEN** it loads with the mark unset

### Requirement: Durable stores record a successor role named at supersession
Durable session stores SHALL, when a supersession names the successor's selected role, insert the successor with that role in the same atomic operation, instead of the role stored on the superseded session, and SHALL write that role back to the caller's successor. Without a named role they SHALL keep taking the superseded session's stored role.

#### Scenario: Named role across backends
- **WHEN** a session with selected role `admin` is superseded through the store of one supported backend with the successor's role named `audit`, and the successor is loaded through another
- **THEN** it loads with `audit`, and the superseded session's stored role is unchanged

#### Scenario: Named empty role
- **WHEN** the successor's role is named as empty
- **THEN** the successor loads with no selected role

#### Scenario: No named role
- **WHEN** a session with selected role `admin` is superseded without naming the successor's role
- **THEN** the successor loads with `admin`
