# Spec Delta

## MODIFIED Requirements

### Requirement: An in-memory store is the default
When no store is configured, the manager SHALL use an in-memory store. That store SHALL:
- hold its own copies of records, so a caller mutating a returned session cannot change stored state;
- run housekeeping that deletes expired sessions once per interval while started, and stops on request or when its context ends.

Housekeeping SHALL be paced by the store's time source, which defaults to the system clock and is replaceable by an option, so a controlled source runs housekeeping without real waiting. Each run SHALL start one interval after the previous run finishes. Starting and stopping SHALL be idempotent. The housekeeping interval SHALL default to one minute and be replaceable by an option. Without starting, expired sessions SHALL still never be returned, but SHALL stay in memory until deleted, and this SHALL be documented. Any implementation of the store contract SHALL be usable in its place.

#### Scenario: Caller mutation is isolated
- **WHEN** a loaded session's consumer data is modified by the caller without saving
- **THEN** loading the session again returns the stored data unchanged

#### Scenario: Housekeeping while started
- **WHEN** the store is started with a 10-second housekeeping interval and a session expires
- **THEN** within one interval the expired session is no longer held

#### Scenario: Housekeeping on a controlled time source
- **WHEN** a store with a controlled time source and a 10-second housekeeping interval is started, a session expires, and the source advances by 10 seconds
- **THEN** the expired session is no longer held, with no real waiting

#### Scenario: Double start and stop
- **WHEN** the store is started twice and stopped twice
- **THEN** no error or panic occurs and no housekeeping keeps running

#### Scenario: Consumer store
- **WHEN** the manager is configured with a consumer's store
- **THEN** every session operation is served by that store
