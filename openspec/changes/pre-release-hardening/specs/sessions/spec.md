# Spec Delta

## ADDED Requirements

### Requirement: A store result with no session is a missing session
When the session store returns no session and no error, every manager operation that loads a session SHALL treat it as a missing session, and SHALL NOT panic.

#### Scenario: Store returns nothing
- **WHEN** a session is loaded and the store returns no session and no error
- **THEN** the load fails with the session-not-found error

### Requirement: A session whose first use could not be recorded cannot later be recovered as unused
With unused-successor recovery enabled, when recording a session's first successful load fails, that load SHALL fail, so that a successor that was in fact used is never later judged unused. With recovery disabled, a failure to record first use SHALL NOT fail the load.

#### Scenario: First-use write fails with recovery enabled
- **WHEN** unused-successor recovery is enabled, successor S1 is loaded, and recording its first use fails
- **THEN** the load fails, and a later late renewal of S1's predecessor is treated as reuse

#### Scenario: First-use write fails with recovery disabled
- **WHEN** unused-successor recovery is disabled, a session is loaded, and recording its first use fails
- **THEN** the load succeeds
