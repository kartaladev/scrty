# Spec Delta

## MODIFIED Requirements

### Requirement: An in-memory store is the default
When no store is configured, the manager SHALL use an in-memory store. That store SHALL:
- hold its own copies of records, so a caller mutating a returned session cannot change stored state;
- run housekeeping that deletes expired sessions once per interval while started, and stops at shutdown. Housekeeping SHALL carry the values of the context given to start, but SHALL NOT stop when that context is cancelled.

Housekeeping SHALL be paced by the store's time source, which defaults to the system clock and is replaceable by an option, so a controlled source runs housekeeping without real waiting. Each run SHALL start one interval after the previous run finishes. Starting a store whose housekeeping is running SHALL fail with an already-started error, and starting a store that has been shut down SHALL fail with an already-shut-down error. Shutdown SHALL be terminal and idempotent, SHALL wait for a run in progress to finish, but no longer than the context given to it allows, and SHALL return that context's error if it is done first. A later shutdown SHALL wait again under its own context. Shutdown SHALL end housekeeping only: a shut-down store SHALL keep saving, loading and deleting sessions. The housekeeping interval SHALL default to one minute and be replaceable by an option. Constructing the store with a housekeeping interval of zero or less, or with a nil time source, typed nil included, SHALL fail with a configuration error. Without starting, expired sessions SHALL still never be returned, but SHALL stay in memory until deleted, and this SHALL be documented. Any implementation of the store contract SHALL be usable in its place.

#### Scenario: Caller mutation is isolated
- **WHEN** a loaded session's consumer data is modified by the caller without saving
- **THEN** loading the session again returns the stored data unchanged

#### Scenario: Housekeeping while started
- **WHEN** the store is started with a 10-second housekeeping interval and a session expires
- **THEN** within one interval the expired session is no longer held

#### Scenario: Housekeeping on a controlled time source
- **WHEN** a store with a controlled time source and a 10-second housekeeping interval is started, a session expires, and the source advances by 10 seconds
- **THEN** the expired session is no longer held, with no real waiting

#### Scenario: Cancelled start context
- **WHEN** a store is started with a request context that is then cancelled, a session expires, and one housekeeping interval passes
- **THEN** the expired session is no longer held

#### Scenario: Double start and stop
- **WHEN** the store is started twice and shut down twice
- **THEN** the second start fails with the already-started error, both shutdowns return no error, and no housekeeping keeps running

#### Scenario: Start after shutdown
- **WHEN** the store is shut down and then started
- **THEN** start fails with the already-shut-down error and no housekeeping runs

#### Scenario: Store serves after shutdown
- **WHEN** a started store is shut down, and a session is then saved and loaded
- **THEN** the session is saved and loaded as before shutdown, and no housekeeping runs

#### Scenario: Invalid housekeeping configuration
- **WHEN** the store is constructed with a housekeeping interval of zero, or with a nil time source, typed nil included
- **THEN** construction fails with a configuration error and returns no store

#### Scenario: Consumer store
- **WHEN** the manager is configured with a consumer's store
- **THEN** every session operation is served by that store
