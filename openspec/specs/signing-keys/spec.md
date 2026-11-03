# signing-keys Specification

## Purpose

Manages the asymmetric keys tokens are signed with. It generates keys and persists them before use, reloads them so a restart invalidates no token, and rotates them and removes old ones on a schedule. It exposes the public keys as the verification keys token verification selects from, and persists each key's publishable public JWK, and its background work starts and stops without leaving goroutines behind.

## Requirements

### Requirement: A current key per algorithm exists from construction
Constructing a key manager SHALL leave it with a current signing key for every configured algorithm. The configured algorithms SHALL default to RS256; ES256 and EdDSA SHALL also be supported. When the store holds no key for a configured algorithm, construction SHALL generate one and write it to the store before returning. RSA keys SHALL be 2048 bits. Configuring an unsupported algorithm SHALL fail at construction.

#### Scenario: Empty store
- **WHEN** a key manager is constructed over an empty store with no options
- **THEN** it has a current RS256 key and the store holds that key

#### Scenario: Consumer algorithms
- **WHEN** a consumer configures ES256 and EdDSA
- **THEN** the manager has a current key for each and reports both as supported

#### Scenario: Unsupported algorithm
- **WHEN** a key manager is constructed with algorithm `HS256`
- **THEN** construction returns an error

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

### Requirement: Construction fails closed
When the store cannot be read, when any stored key cannot be decoded, or when writing an initial key fails, construction SHALL return an error. It SHALL NOT skip an undecodable key or generate a key to replace it.

#### Scenario: Corrupt stored key
- **WHEN** a key manager is constructed over a store holding a key whose private bytes are corrupt
- **THEN** construction returns an error naming that key's identifier
- **AND** no key is added to the store

#### Scenario: Store write fails
- **WHEN** construction over an empty store cannot write its initial key
- **THEN** construction returns an error

### Requirement: Construction takes the caller's context
Constructing a key manager SHALL take a context from the caller, and SHALL pass that context to the key store both for loading the stored keys and for writing any key construction mints. Construction SHALL NOT substitute a context of its own and SHALL NOT impose a deadline of its own. When the store abandons its work because that context is cancelled or its deadline has passed, construction SHALL fail with that error and SHALL leave no key manager, no held key and no key added to the store. The default in-memory store performs no input or output and therefore cannot be cancelled: construction over it SHALL succeed whatever state the context is in.

#### Scenario: Cancelled context
- **WHEN** a key manager is constructed over a durable store with a context that is already cancelled
- **THEN** construction fails with the store's cancellation error and returns no key manager

#### Scenario: Consumer bounds a slow startup
- **WHEN** a consumer gives construction a context with a two-second deadline and the store takes longer than that to answer
- **THEN** construction returns the store's deadline error rather than blocking until the store answers

#### Scenario: The default store cannot be cancelled
- **WHEN** a key manager is constructed over the default in-memory store with a context that is already cancelled
- **THEN** construction succeeds with a current key, because that store performs no input or output

### Requirement: A key is stored before it is used
A newly generated key SHALL be written to the store before it becomes current or is published. When the write fails, the previous current key SHALL remain current.

#### Scenario: Rotation write fails
- **WHEN** a rotation generates a key and the store rejects the write
- **THEN** the new key is neither current nor published
- **AND** the previous key still signs

### Requirement: Key identifiers are key thumbprints
Every key identifier SHALL be the base64url-encoded RFC 7638 SHA-256 thumbprint of the key's public part. Every published key SHALL be published with the algorithm it verifies, and the public JWK persisted with it SHALL declare that key identifier, that algorithm and signature use.

#### Scenario: Identifier matches thumbprint
- **WHEN** the RFC 7638 SHA-256 thumbprint of a published key is computed independently
- **THEN** it equals the key's identifier

#### Scenario: The stored public JWK is publishable as it stands
- **WHEN** the public JWK stored with a key record is read back
- **THEN** it declares that key's identifier, its algorithm and signature use, so a consumer serves a JWK Set without decoding private material

### Requirement: Keys rotate on a schedule
Once started, the key manager SHALL generate a new key for every configured algorithm each rotation interval, which is 1 hour by default and configurable. Each new key SHALL become the current key for its algorithm as soon as it is stored. Keys it replaces SHALL remain published until housekeeping removes them. A failed rotation SHALL leave the previous key current, SHALL be attempted again at the next interval, and SHALL be reported to the configured logger, which defaults to the process's default structured logger, and to an optional error hook. Repeated failure logs SHALL be sampled, and each record written SHALL state how many failures were suppressed before it.

#### Scenario: Rotation failure is observable
- **WHEN** a rotation fails because the store rejects the write
- **THEN** the configured logger receives a record for the failure
- **AND** a consumer-supplied error hook is called with an error wrapping the store's error

#### Scenario: Rotation
- **WHEN** a started key manager with current RS256 key `k1` reaches its rotation interval
- **THEN** a new key `k2` is current
- **AND** `k1` is still published

#### Scenario: Consumer interval
- **WHEN** a consumer configures a 6-hour rotation interval
- **THEN** new keys are generated every 6 hours

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

### Requirement: A key for an unconfigured algorithm is published but never signed with
A key found in the store for an algorithm the manager was not configured with SHALL be published among the verification keys, so a token another replica signed with it still verifies, and SHALL NOT be made current. Requesting a signer for an algorithm the manager was not configured with SHALL return the no-key error.

#### Scenario: A replica publishes another replica's algorithm without adopting it
- **WHEN** a manager configured for RS256 alone starts over a store that also holds an ES256 key
- **THEN** the ES256 key is published among the verification keys, requesting an ES256 signer returns an error matching the no-key error, and the ES256 key is not exempt from housekeeping

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

### Requirement: Published keys carry public material only
The key manager SHALL publish every key it holds as that key's identifier, the algorithm it verifies and its public key. No published key SHALL carry private key material, and no published key SHALL be usable to sign. The key manager SHALL also render its published keys as a serialized RFC 7517 JWK Set, so that a consumer can serve a JWKS endpoint without a JOSE library and without a key store they can read. That document SHALL carry every key the manager holds, in the order it publishes them, each with its identifier, its algorithm and signature use. A consumer SHALL be able to render their own set from the published keys instead, where they need a document the key manager does not produce.

#### Scenario: No private material
- **WHEN** the verification keys of a manager holding RS256 and ES256 keys are rendered as a JWK Set and serialized
- **THEN** each entry has `kid`, `alg` and `use` `sig`
- **AND** no entry has `d`, `p`, `q`, `dp`, `dq` or `qi`

#### Scenario: A published key cannot sign
- **WHEN** a published key is examined for private material
- **THEN** it holds none, so nothing obtained from the manager's published keys can produce a signature

#### Scenario: Serving a JWKS endpoint
- **WHEN** a consumer serves the key manager's rendered JWK Set from an endpoint, having configured no store and imported no JOSE library
- **THEN** the response is a valid JWK Set holding every key the manager publishes
- **AND** an external verifier reading it verifies a token the manager signed

#### Scenario: The rendered set carries nothing private
- **WHEN** the rendered JWK Set of a manager holding RS256, ES256 and EdDSA keys is parsed
- **THEN** no key in it carries any private parameter

#### Scenario: Consumer renders its own set
- **WHEN** a consumer needs a set the key manager does not produce, such as one carrying only a subset of the keys
- **THEN** they build it from the published verification keys, and the key manager's own rendering is unaffected

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

### Requirement: Signing and verification keys can be supplied without the key manager
Token issuance and verification SHALL obtain the signing key and the verification keys through a key source contract that the key manager implements. The contract SHALL describe a verification key as its key identifier, its algorithm and its public key, using only standard-library types and this capability's own algorithm names, so that implementing it requires no JOSE library. A consumer SHALL be able to supply their own key source, such as one backed by an external key service, in place of the key manager. Verification keys handed to a caller SHALL be copies of what the source holds: writing to a returned key SHALL NOT change the keys the key manager publishes or the key it signs with.

Every request to the key source SHALL carry the caller's context. Issuance SHALL pass the context of the issuing call, and verification the context of the verifying call, without substituting a context of their own or imposing a deadline of their own. The key manager performs no input or output when asked for a key, and SHALL answer whatever state the context is in.

Asked for a signing key, a key source SHALL report a missing key apart from an outage. A source that holds no key for the algorithm SHALL return the no-key error, and the key manager SHALL do so for an algorithm it was not configured with. Any other error SHALL mean the source could not answer.

Issuance SHALL ask for a signing key once for each token, and SHALL use the signer it is given only for that token, never keeping or reusing it. A key source backed by an external service MAY therefore return a signer bound to the context it was asked with.

#### Scenario: External key source
- **WHEN** a consumer supplies a key source backed by an external signing service
- **THEN** tokens are issued and verified with its keys and no key manager is constructed

#### Scenario: A key source implemented without a JOSE library
- **WHEN** a consumer implements the key source contract using only the standard library, returning for each key its identifier, its algorithm and its public key
- **THEN** tokens are issued and verified with those keys, and the implementation imports no JOSE library

#### Scenario: A returned verification key cannot be mutated
- **WHEN** a caller obtains the key manager's verification keys and overwrites the public key material in the key it was given
- **THEN** the key manager still publishes that key unchanged and still verifies tokens signed by it

#### Scenario: The key source receives the caller's context
- **WHEN** a consumer key source records the context it is given, and a token is issued and then verified, each under a context carrying a distinct value
- **THEN** the request for a signing key carries the issuing context's value
- **AND** the request for verification keys carries the verifying context's value

#### Scenario: A signer is asked for once per token and never reused
- **WHEN** a consumer key source returns a fresh signer for each request, and three tokens are issued
- **THEN** the source is asked for a signing key three times, and each signer signs exactly one token

#### Scenario: The key manager answers under a cancelled context
- **WHEN** a key manager configured for RS256 is asked for its RS256 signer and its verification keys under a context that is already cancelled
- **THEN** it returns them with no error

#### Scenario: The key manager reports a missing key
- **WHEN** a key manager configured only for RS256 is asked for an EdDSA signer
- **THEN** it returns an error matching the no-key error

### Requirement: The clock is injectable
The key manager SHALL read time from a configurable time source, defaulting to the system clock, for key creation times, rotation, reload and housekeeping. The same source SHALL pace the rotation, reload and housekeeping background work, so a controlled source drives them without real waiting. The key manager SHALL only accept a time source that can wait as well as read the time. Each background task SHALL next run one interval after its previous run finishes, and an interval stated elsewhere in this capability is measured that way.

#### Scenario: Controlled time
- **WHEN** a key manager's time source advances by 25 hours
- **THEN** rotation and housekeeping behave as if 25 hours had passed without real waiting

#### Scenario: Controlled reload
- **WHEN** replicas A and B share a store and a controlled time source, replica A rotates in key `k2`, and the source advances by one reload interval
- **THEN** replica B publishes `k2` with no real waiting

#### Scenario: Interval measured from the end of a run
- **WHEN** a reload that started at 12:00:00 with a 1-minute reload interval finishes at 12:00:03
- **THEN** the next reload starts at 12:01:03

### Requirement: Start launches the background work once, and construction starts nothing
Construction SHALL start no goroutine. Starting SHALL launch the rotation, reload and housekeeping background work. That work SHALL carry the values of the context given to start, but SHALL NOT end when that context is cancelled: only shutdown ends it. Starting a manager whose work is running SHALL fail with an already-started error and launch nothing. Starting a manager that has been shut down SHALL fail with an already-shut-down error and launch nothing.

#### Scenario: Constructed but not started
- **WHEN** a key manager is constructed and not started
- **THEN** no goroutine started by the key manager is running

#### Scenario: Double start
- **WHEN** a key manager is started twice and then shut down
- **THEN** the second start fails with the already-started error
- **AND** no goroutine started by the key manager remains after shutdown returns

#### Scenario: Cancelled start context
- **WHEN** a key manager is started with a context that is then cancelled, and its rotation interval passes
- **THEN** the rotation still runs

#### Scenario: Start after shutdown
- **WHEN** a key manager is shut down and then started
- **THEN** start fails with the already-shut-down error and launches no goroutine

### Requirement: Shutdown leaves no goroutine behind
Shutdown SHALL end the background work and SHALL be terminal. It SHALL wait for the work to end, including any in-flight key generation or store write, but no longer than the context given to it allows. It SHALL return no error once the work has ended, and that context's error if the context is done first. A later shutdown SHALL wait again under its own context. Shutting down a manager that was never started SHALL return at once. Shutdown SHALL end the background work only: a shut-down manager SHALL keep serving its current signers and verification keys, and SHALL rotate, reload and clean up no more. Concurrent start and shutdown SHALL be free of data races and SHALL leave no goroutine behind.

#### Scenario: Clean shutdown
- **WHEN** a key manager is started, its loops run several times, and it is shut down
- **THEN** shutdown returns no error and no goroutine started by the key manager is running

#### Scenario: Stop during rotation
- **WHEN** shutdown is called while a rotation is generating and storing a key
- **THEN** shutdown returns only after that store write has completed
- **AND** no store write happens after shutdown returns

#### Scenario: Consumer bounds the shutdown
- **WHEN** shutdown is called with a context that expires while a store write is still in flight
- **THEN** shutdown returns that context's error
- **AND** a later shutdown with a sufficient context returns no error once the write has completed

#### Scenario: Shutdown twice
- **WHEN** a started key manager is shut down twice
- **THEN** both calls return no error and no goroutine remains

#### Scenario: Keys served after shutdown
- **WHEN** a started key manager is shut down, and a token is then issued and verified with its keys
- **THEN** issuing and verifying succeed with the keys held at shutdown
- **AND** no rotation happens however much time passes

#### Scenario: Concurrent start and stop
- **WHEN** start and shutdown are called concurrently under the race detector
- **THEN** no data race is reported and no goroutine started by the key manager remains

#### Scenario: Stop before start
- **WHEN** a key manager that was never started is shut down and then started
- **THEN** shutdown returns at once, and start fails with the already-shut-down error and launches no goroutine
