# Spec Delta

## MODIFIED Requirements

### Requirement: Housekeeping removes old keys but never the current one
Once started, the key manager SHALL run housekeeping each housekeeping interval, which is 1 hour by default and configurable. Housekeeping SHALL stop publishing every key created longer ago than the key lifetime, which is 24 hours by default and configurable, and every key dated more than one key lifetime after the present time, except the current key of each algorithm. A key lifetime not longer than the rotation interval SHALL fail at construction.

By default, housekeeping SHALL also delete from the key store every key it stops publishing because it was created longer ago than the key lifetime. It SHALL NOT delete a key it stops publishing because it is dated in the future, since that date may come from another replica's clock. A failed delete SHALL be reported to the configured logger and error hook, SHALL leave the key unpublished, and SHALL be attempted again at the next housekeeping run. The consumer SHALL be able to keep retired keys in the store instead.

#### Scenario: Old key removed
- **WHEN** a key created 25 hours ago is not current and housekeeping runs with the default lifetime
- **THEN** that key is no longer published
- **AND** that key is no longer in the key store

#### Scenario: Consumer keeps retired keys
- **WHEN** a key manager configured to keep retired keys runs housekeeping over a key created 25 hours ago that is not current
- **THEN** that key is no longer published, and is still in the key store

#### Scenario: Failed delete retried
- **WHEN** the key store fails to delete a retired key during housekeeping, and the next housekeeping run finds the store working
- **THEN** the failure is reported, the key stays unpublished, and the next run deletes it

#### Scenario: Current key kept
- **WHEN** the current key was created 25 hours ago because rotation has not run, and housekeeping runs
- **THEN** that key is still published and still signs, and is still in the key store

#### Scenario: Lifetime shorter than rotation
- **WHEN** a key manager is constructed with a 30-minute key lifetime and a 1-hour rotation interval
- **THEN** construction fails with a configuration error

#### Scenario: Far-future key removed
- **WHEN** a non-current key is dated two days ahead and housekeeping runs with the default lifetime
- **THEN** that key is no longer published, and is still in the key store
