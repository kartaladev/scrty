# Spec Delta

## ADDED Requirements

### Requirement: The session suite covers the strict-rotation mark
The session store suite SHALL cover, for every session store, the strict-rotation mark: recorded by a supersession made without grace, not recorded by one made with a grace window, returned on load, never written by create or save, a save of a marked record refused as not-found, and removed with the session by the sweep once its retention deadline passes. The in-memory default store SHALL pass it.

#### Scenario: Store that drops the mark caught
- **WHEN** the session suite runs against a store variant that does not persist the strict-rotation mark
- **THEN** the suite fails on the case that loads a session superseded without grace

#### Scenario: Store whose save writes the mark caught
- **WHEN** the session suite runs against a store variant whose save writes the strict-rotation mark
- **THEN** the suite fails on the save case

#### Scenario: Store that saves onto a strictly rotated record caught
- **WHEN** the session suite runs against a store variant whose save writes a record marked as rotated without grace
- **THEN** the suite fails on the save-refused case

#### Scenario: Managers sharing a store
- **WHEN** the suite rotates a session without grace through one manager and its old identifier through another manager over the same store
- **THEN** the second rotation fails with the renewal-conflict error for every store that passes the suite
