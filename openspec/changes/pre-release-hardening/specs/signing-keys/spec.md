# Spec Delta

## MODIFIED Requirements

### Requirement: Keys survive a restart
Construction SHALL load the keys in the store, publishing every key that is within the key lifetime and, for each configured algorithm, the newest key whatever its age. It SHALL NOT publish a key past the key lifetime that is not the newest key of a configured algorithm, and SHALL NOT generate a replacement for an algorithm that already has a stored key. A token signed before a restart by a key within its lifetime SHALL verify after it. For each algorithm, the current key SHALL be the stored key created most recently among those not created later than the present time plus the reload interval, whatever order the store returns keys in. When creation times are equal, it SHALL be the key the store lists later. Construction, reload and housekeeping SHALL apply the same rule for which keys are published.

#### Scenario: Restart keeps tokens valid
- **WHEN** a token is signed by a key manager and a second key manager is constructed over the same store
- **THEN** the second manager publishes the token's key and uses it as the current key

#### Scenario: Store returns keys out of order
- **WHEN** a store returns a key created at 11:00 before a key created at 10:00, both RS256
- **THEN** the current RS256 key is the one created at 11:00

#### Scenario: Key past its lifetime after a restart
- **WHEN** the store holds a current RS256 key and a non-current RS256 key created 30 days ago, with the default 24-hour lifetime, and a key manager is constructed over it
- **THEN** a token signed by the 30-day-old key does not verify

#### Scenario: Stale current key kept
- **WHEN** the only stored RS256 key was created 3 days ago, and a key manager configured for RS256 is constructed over it
- **THEN** that key is published and is the current key, and no replacement is generated

#### Scenario: Future-dated key at construction
- **WHEN** the store holds an RS256 key created now and another dated one year ahead
- **THEN** the current RS256 key is the one created now

### Requirement: Replicas sharing a store reload each other's keys
Once started, the key manager SHALL reload every key from the store each reload interval, which is 1 minute by default and configurable. Each reload SHALL publish every stored key not already held, except keys older than the key lifetime. After each reload, the current key for each configured algorithm SHALL be the most recently created key held for it among those not created later than the present time plus the reload interval. A reload failure SHALL keep the keys already held, and SHALL be reported like a rotation failure. A reload interval of zero or less, or one that is not shorter than the rotation interval, SHALL fail at construction.

#### Scenario: Key rotated in by another replica
- **WHEN** replicas A and B share a store and replica A rotates in key `k2` and signs a token with it
- **THEN** within one reload interval, replica B verifies that token
- **AND** replica B uses `k2` as its current key

#### Scenario: Consumer reload interval
- **WHEN** a consumer configures a 10-second reload interval
- **THEN** keys stored by another replica are published within 10 seconds

#### Scenario: Reload interval too long
- **WHEN** a key manager is constructed with a 2-hour reload interval and a 1-hour rotation interval
- **THEN** construction fails with a configuration error

#### Scenario: Reload failure
- **WHEN** a reload fails because the store is unreachable
- **THEN** the manager keeps signing and verifying with the keys it already holds
- **AND** the failure is reported to the configured logger

#### Scenario: Future-dated key does not undo rotation
- **WHEN** a key dated one year ahead is in the store and the manager rotates in a new key
- **THEN** after the next reload the new key is still the current key

### Requirement: Housekeeping removes old keys but never the current one
Once started, the key manager SHALL run housekeeping each housekeeping interval, which is 1 hour by default and configurable. Housekeeping SHALL stop publishing every key created longer ago than the key lifetime, which is 24 hours by default and configurable, and every key dated more than one key lifetime after the present time, except the current key of each algorithm. A key lifetime not longer than the rotation interval SHALL fail at construction.

#### Scenario: Old key removed
- **WHEN** a key created 25 hours ago is not current and housekeeping runs with the default lifetime
- **THEN** that key is no longer published

#### Scenario: Current key kept
- **WHEN** the current key was created 25 hours ago because rotation has not run, and housekeeping runs
- **THEN** that key is still published and still signs

#### Scenario: Lifetime shorter than rotation
- **WHEN** a key manager is constructed with a 30-minute key lifetime and a 1-hour rotation interval
- **THEN** construction fails with a configuration error

#### Scenario: Far-future key removed
- **WHEN** a non-current key is dated two days ahead and housekeeping runs with the default lifetime
- **THEN** that key is no longer published
