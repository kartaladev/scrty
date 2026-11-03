# Spec Delta

## MODIFIED Requirements

### Requirement: Keys survive a restart
Construction SHALL load the keys in the store, publishing every key that has not passed its retire time and, for each configured algorithm, the current key whatever its age. It SHALL NOT publish a key that has passed its retire time that is not the current key of a configured algorithm, and SHALL NOT generate a replacement for an algorithm that already has a stored key that can be current. When every stored key for an algorithm is dated later than the present time plus the reload interval, none can be current, and construction SHALL generate one. A token signed before a restart by a key that has not passed its retire time SHALL verify after it. For each algorithm, the current key SHALL be the stored key created most recently among those not created later than the present time plus the reload interval, whatever order the store returns keys in. When creation times are equal, it SHALL be the key the store lists later. Construction, reload and housekeeping SHALL apply the same rule for which keys are published.

A key's retire time SHALL be one reload interval after the later of its creation time plus the key lifetime, and its successor's creation time plus the key lifetime minus the rotation interval. Its successor is the next newer stored key of its algorithm, not counting a key dated later than the present time plus the reload interval. A key with no successor counts only its creation time plus the key lifetime. So a key replaced on time retires one key lifetime and one reload interval after its creation, and a key replaced late stays published for as long as a token it signed can be valid: a token's lifetime is capped at the key lifetime minus the rotation interval, and a replica may go on signing with a replaced key until its next reload.

#### Scenario: Restart keeps tokens valid
- **WHEN** a token is signed by a key manager and a second key manager is constructed over the same store
- **THEN** the second manager publishes the token's key and uses it as the current key

#### Scenario: Store returns keys out of order
- **WHEN** a store returns a key created at 11:00 before a key created at 10:00, both RS256
- **THEN** the current RS256 key is the one created at 11:00

#### Scenario: Key past its lifetime after a restart
- **WHEN** the store holds a current RS256 key and a non-current RS256 key created 30 days ago and replaced 29 days ago, with the default 24-hour lifetime, and a key manager is constructed over it
- **THEN** a token signed by the 30-day-old key does not verify

#### Scenario: Key replaced late survives a restart
- **WHEN** an RS256 key was current for 28 hours because rotation kept failing, was replaced 5 minutes ago, and a key manager is constructed over the store
- **THEN** that key is published, and a token it signed before it was replaced verifies

#### Scenario: Stale current key kept
- **WHEN** the only stored RS256 key was created 3 days ago, and a key manager configured for RS256 is constructed over it
- **THEN** that key is published and is the current key, and no replacement is generated

#### Scenario: Future-dated key at construction
- **WHEN** the store holds an RS256 key created now and another dated one year ahead
- **THEN** the current RS256 key is the one created now

#### Scenario: Only far-future keys stored
- **WHEN** the only stored RS256 key is dated one year ahead, and a key manager configured for RS256 is constructed over it
- **THEN** a new RS256 key is generated and is the current key, and the far-future key does not sign

### Requirement: Replicas sharing a store reload each other's keys
Once started, the key manager SHALL reload every key from the store each reload interval, which is 1 minute by default and configurable. Each reload SHALL publish every stored key not already held that the shared publishing rule allows: a key that has not passed its retire time, or the current key of a configured algorithm. A manager holding a key that has passed its retire time, and that the store no longer lists, SHALL stop publishing it at the reload. A held key that has not passed its retire time SHALL stay published whether or not the listing includes it, since another replica may have deleted it, or rotation may have stored it after the listing. After each reload, the current key for each configured algorithm SHALL be the most recently created key held for it among those not created later than the present time plus the reload interval; when creation times are equal, it SHALL be the key the store lists later, as at construction. A reload SHALL never leave a configured algorithm without a current key: when no held key of it qualifies, as after the clock steps back, its previous current key stays current. A reload failure SHALL keep the keys already held, and SHALL be reported like a rotation failure. A reload interval of zero or less, or one that is not shorter than the rotation interval, SHALL fail at construction.

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

#### Scenario: Clock stepped back keeps a signer
- **WHEN** a started key manager's clock steps back further than the reload interval, so every held RS256 key is dated after the present time plus the reload interval, and a reload runs
- **THEN** the previous current RS256 key stays current and tokens can still be signed

#### Scenario: Future-dated key does not undo rotation
- **WHEN** a key dated one year ahead is in the store and the manager rotates in a new key
- **THEN** after the next reload the new key is still the current key

#### Scenario: Deleted key not republished on reload
- **WHEN** one replica's housekeeping deletes a retired key, and another replica sharing the store then reloads its keys
- **THEN** the reloading replica does not publish that key

#### Scenario: Held key within its retire time is kept when the store does not list it
- **WHEN** a reload's listing does not include a key this replica holds that has not reached its retire time, because another replica deleted it or because rotation stored it after the listing
- **THEN** the replica still publishes that key, and a current key stays current

### Requirement: Housekeeping removes old keys but never the current one
Once started, the key manager SHALL run housekeeping each housekeeping interval, which is 1 hour by default and configurable. Housekeeping SHALL stop publishing every key that has passed its retire time, and every key dated more than one key lifetime after the present time, except the current key of each algorithm. A key lifetime not longer than the rotation interval SHALL fail at construction.

By default, housekeeping SHALL also delete from the key store every stored key whose retire time passed longer ago than the retired-key grace, which is one key lifetime by default and configurable, except a current key of this manager and the newest stored key of each algorithm, whether or not this manager is configured for that algorithm. It SHALL find these keys in the store's own listing at each run, so a key this manager never held, or whose delete failed before a restart, is still deleted. It SHALL NOT delete a key it stops publishing because it is dated in the future, since that date may come from another replica's clock. A failed listing or a failed delete SHALL be reported to the configured logger and error hook, SHALL leave the key unpublished, and SHALL be attempted again at the next housekeeping run. A failure once shutdown has ended the background work SHALL NOT be reported, whether it arose in rotation, reload or housekeeping. The consumer SHALL be able to keep retired keys in the store instead. A negative grace, or a grace together with keeping retired keys, SHALL fail at construction.

Replicas sharing a store SHALL be configured alike, in key lifetime, rotation interval, reload interval, retired-key grace and whether retired keys are kept, and keep synchronised clocks. A replica judges a key's age by its own clock and configuration, so the grace reduces the harm of a skewed clock and does not remove it. The key manager's documentation SHALL state this.

#### Scenario: Old key removed
- **WHEN** a key created 50 hours ago and replaced on time is not current, and housekeeping runs with the default lifetime and grace
- **THEN** that key is no longer published
- **AND** that key is no longer in the key store

#### Scenario: Retired key waits out its grace
- **WHEN** a key created 25 hours ago and replaced on time is not current, and housekeeping runs with the default lifetime and grace
- **THEN** that key is no longer published, and is still in the key store

#### Scenario: Consumer sets the grace
- **WHEN** a key manager configured with a grace of zero runs housekeeping over a key created 25 hours ago and replaced on time
- **THEN** that key is no longer published, and is no longer in the key store

#### Scenario: Negative grace
- **WHEN** a key manager is constructed with a negative retired-key grace
- **THEN** construction fails with a configuration error

#### Scenario: Grace and kept keys together
- **WHEN** a key manager is constructed with a retired-key grace and configured to keep retired keys
- **THEN** construction fails with a configuration error

#### Scenario: Consumer keeps retired keys
- **WHEN** a key manager configured to keep retired keys runs housekeeping over a key created 50 hours ago and replaced on time that is not current
- **THEN** that key is no longer published, and is still in the key store

#### Scenario: Key replaced late stays published
- **WHEN** a key is current for 28 hours because rotation kept failing, a rotation then succeeds, and housekeeping runs while a token it signed 5 minutes ago is unexpired
- **THEN** that key is still published, and that token verifies
- **AND** housekeeping stops publishing it once the key lifetime minus the rotation interval, plus one reload interval, has passed since its replacement

#### Scenario: A replica still signing before its reload
- **WHEN** a replica that has not yet reloaded signs a token at the lifetime cap with a key another replica has just replaced
- **THEN** that token verifies until it expires

#### Scenario: Future-dated key does not hold back retirement
- **WHEN** a non-current key was created 25 hours ago and replaced on time, the store also holds a key of that algorithm dated one year ahead, and housekeeping runs
- **THEN** that key is no longer published

#### Scenario: Failed delete retried
- **WHEN** the key store fails to delete a retired key during housekeeping, and the next housekeeping run finds the store working
- **THEN** the failure is reported, the key stays unpublished, and the next run deletes it

#### Scenario: Failed delete survives a restart
- **WHEN** a retired key's delete fails, the process restarts, and housekeeping runs with the store working
- **THEN** that key is no longer in the key store

#### Scenario: Key past its lifetime at start is deleted
- **WHEN** a key manager is constructed over a store holding a non-current key created 30 days ago and replaced 29 days ago, and housekeeping runs
- **THEN** that key is no longer in the key store

#### Scenario: Store cannot list during housekeeping
- **WHEN** housekeeping runs over a retired key and the key store's load fails
- **THEN** the key stops being published, the failure is reported to the logger and the error hook, nothing is deleted, and the next run tries again

#### Scenario: Key removed from the store since the last reload
- **WHEN** a key is removed from the store outside the manager, no reload has happened since, and housekeeping runs over an older key that is now the newest stored
- **THEN** that older key stays in the store

#### Scenario: Shutdown during a store call
- **WHEN** shutdown ends the background work while a rotation, a reload or a housekeeping run is inside a store call, and the store returns its context's error
- **THEN** neither the logger nor the error hook receives a failure for it, and shutdown returns no error

#### Scenario: Store failure before shutdown
- **WHEN** a store call fails with an error matching a cancelled context while the background work is still running
- **THEN** the failure is reported to the logger and the error hook

#### Scenario: Replicas delete the same retired key
- **WHEN** two key managers sharing a store both run housekeeping over a key created 50 hours ago and replaced on time that is not current
- **THEN** both runs succeed, no failure is reported, and the key is no longer in the key store

#### Scenario: Current key kept
- **WHEN** the current key was created 25 hours ago because rotation has not run, and housekeeping runs
- **THEN** that key is still published and still signs, and is still in the key store

#### Scenario: Newest stored key not yet loaded
- **WHEN** a replica's current key is 60 hours old, the store also holds a key of that algorithm created 55 hours ago that the replica has not loaded, and housekeeping runs
- **THEN** neither key is deleted

#### Scenario: Retired key of an unconfigured algorithm
- **WHEN** a manager configured for RS256 alone runs housekeeping over a store holding two ES256 keys, both created more than 50 hours ago
- **THEN** neither ES256 key is published
- **AND** the older is no longer in the key store, and the newer is still there, since another replica may still be signing with it

#### Scenario: Replica with a fast clock leaves keys in place
- **WHEN** a replica whose clock is 19 hours fast runs housekeeping over keys that replicas with correct clocks are signing with, or have live tokens signed with
- **THEN** those keys stay in the key store, and a restarted replica with a correct clock publishes them

#### Scenario: Replica with a slow clock leaves its key in place
- **WHEN** a replica whose clock is 19 hours slow is signing with a key, and a replica with a correct clock runs housekeeping
- **THEN** that key stays in the key store, and a replica restarted afterwards can load it

#### Scenario: Replica with a shorter lifetime
- **WHEN** a replica configured with a 24-hour key lifetime runs housekeeping over a key 40 hours old, inside another replica's 72-hour lifetime, and that key was replaced on time
- **THEN** that key is still in the key store

#### Scenario: Lifetime shorter than rotation
- **WHEN** a key manager is constructed with a 30-minute key lifetime and a 1-hour rotation interval
- **THEN** construction fails with a configuration error

#### Scenario: Far-future key removed
- **WHEN** a non-current key is dated two days ahead and housekeeping runs with the default lifetime
- **THEN** that key is no longer published, and is still in the key store

### Requirement: The key store is replaceable and treats private bytes as opaque
The key manager SHALL persist keys only through a key store that can store a key record, load all records and delete records by key identifier. Storing a record whose key identifier is already stored SHALL replace that record. Loading SHALL return records oldest first by creation time. Deleting SHALL remove only the named records; a missing identifier, or none, SHALL be no error and change nothing. With no store configured, the manager SHALL use an in-memory store that does not survive a restart. A consumer-supplied store SHALL replace it. A store SHALL persist a record's private bytes exactly as given, without interpreting them. A sealing store SHALL forward a delete to the store it wraps, and report that store's failure behind fixed library text with the failure still reachable.

#### Scenario: Default store is not durable
- **WHEN** a key manager with no configured store signs a token, and a new key manager with no configured store is constructed
- **THEN** the new manager does not publish the first manager's key

#### Scenario: Consumer store
- **WHEN** a consumer supplies a durable store and restarts the process
- **THEN** the key manager reloads the keys from that store

#### Scenario: Private bytes returned unchanged
- **WHEN** a conforming store stores a record whose private bytes are an arbitrary sealed envelope and loads it back
- **THEN** the private bytes are identical to those stored

#### Scenario: Delete removes only the named keys
- **WHEN** a conforming store holds keys `k1` and `k2`, and `k1` is deleted
- **THEN** loading returns `k2` only

#### Scenario: Delete of a missing key
- **WHEN** a key that is not stored is deleted
- **THEN** no error is returned and nothing changes

#### Scenario: Delete naming no key
- **WHEN** delete is called with no key identifiers
- **THEN** no error is returned and every stored key remains

#### Scenario: Delete of many keys
- **WHEN** a durable store is asked to delete more key identifiers in one call than the database accepts as bound parameters
- **THEN** every named key is deleted and no error is returned

#### Scenario: Sealing store forwards a delete
- **WHEN** a key is deleted through the sealing store
- **THEN** the inner store no longer holds it, and an inner failure stays reachable behind fixed text
