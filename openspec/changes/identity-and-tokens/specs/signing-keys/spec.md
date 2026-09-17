## Purpose

Manages the asymmetric keys tokens are signed with. It generates keys and persists them before use, reloads them so a restart invalidates no token, and rotates them and removes old ones on a schedule. It exposes the public keys as a JWK Set, and its background work starts and stops without leaving goroutines behind.

## ADDED Requirements

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
Construction SHALL load every key in the store and SHALL NOT generate a replacement for an algorithm that already has a stored key. A token signed before a restart SHALL verify after it. For each algorithm, the current key SHALL be the stored key created most recently, whatever order the store returns keys in. When creation times are equal, it SHALL be the key the store lists later.

#### Scenario: Restart keeps tokens valid
- **WHEN** a token is signed by a key manager and a second key manager is constructed over the same store
- **THEN** the second manager publishes the token's key and uses it as the current key

#### Scenario: Store returns keys out of order
- **WHEN** a store returns a key created at 11:00 before a key created at 10:00, both RS256
- **THEN** the current RS256 key is the one created at 11:00

### Requirement: Construction fails closed
When the store cannot be read, when any stored key cannot be decoded, or when writing an initial key fails, construction SHALL return an error. It SHALL NOT skip an undecodable key or generate a key to replace it.

#### Scenario: Corrupt stored key
- **WHEN** a key manager is constructed over a store holding a key whose private bytes are corrupt
- **THEN** construction returns an error naming that key's identifier
- **AND** no key is added to the store

#### Scenario: Store write fails
- **WHEN** construction over an empty store cannot write its initial key
- **THEN** construction returns an error

### Requirement: A key is stored before it is used
A newly generated key SHALL be written to the store before it becomes current or is published. When the write fails, the previous current key SHALL remain current.

#### Scenario: Rotation write fails
- **WHEN** a rotation generates a key and the store rejects the write
- **THEN** the new key is neither current nor published
- **AND** the previous key still signs

### Requirement: Key identifiers are key thumbprints
Every key identifier SHALL be the base64url-encoded RFC 7638 SHA-256 thumbprint of the key's public part. Each published key SHALL declare its algorithm and signature use.

#### Scenario: Identifier matches thumbprint
- **WHEN** the RFC 7638 SHA-256 thumbprint of a published key is computed independently
- **THEN** it equals the key's identifier

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
Once started, the key manager SHALL reload every key from the store each reload interval, which is 1 minute by default and configurable. Each reload SHALL publish every stored key not already held, except keys older than the key lifetime. After each reload, the current key for each configured algorithm SHALL be the most recently created key held for it. A reload failure SHALL keep the keys already held, and SHALL be reported like a rotation failure. A reload interval of zero or less, or one that is not shorter than the rotation interval, SHALL fail at construction.

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

### Requirement: A key for an unconfigured algorithm is published but never signed with
A key found in the store for an algorithm the manager was not configured with SHALL be published in the JWK Set, so a token another replica signed with it still verifies, and SHALL NOT be made current. Requesting a signer for an algorithm the manager was not configured with SHALL report that none is available.

#### Scenario: A replica publishes another replica's algorithm without adopting it
- **WHEN** a manager configured for RS256 alone starts over a store that also holds an ES256 key
- **THEN** the ES256 key is published in the JWK Set, requesting an ES256 signer reports none available, and the ES256 key is not exempt from housekeeping

### Requirement: Housekeeping removes old keys but never the current one
Once started, the key manager SHALL run housekeeping each housekeeping interval, which is 1 hour by default and configurable. Housekeeping SHALL stop publishing every key created longer ago than the key lifetime, which is 24 hours by default and configurable, except the current key of each algorithm. A key lifetime not longer than the rotation interval SHALL fail at construction.

#### Scenario: Old key removed
- **WHEN** a key created 25 hours ago is not current and housekeeping runs with the default lifetime
- **THEN** that key is no longer published

#### Scenario: Current key kept
- **WHEN** the current key was created 25 hours ago because rotation has not run, and housekeeping runs
- **THEN** that key is still published and still signs

#### Scenario: Lifetime shorter than rotation
- **WHEN** a key manager is constructed with a 30-minute key lifetime and a 1-hour rotation interval
- **THEN** construction fails with a configuration error

### Requirement: The JWK Set publishes public keys only
The key manager SHALL expose every key it holds as an RFC 7517 JWK Set containing each key's public part, key identifier, algorithm and signature use. No entry SHALL contain private key material.

#### Scenario: No private material
- **WHEN** the JWK Set of a manager holding RS256 and ES256 keys is serialized
- **THEN** each entry has `kid`, `alg` and `use` `sig`
- **AND** no entry has `d`, `p`, `q`, `dp`, `dq` or `qi`

### Requirement: The key store is replaceable and treats private bytes as opaque
The key manager SHALL persist keys only through a key store that can store a key record and load all records. Storing a record whose key identifier is already stored SHALL replace that record. Loading SHALL return records oldest first by creation time. With no store configured, the manager SHALL use an in-memory store that does not survive a restart. A consumer-supplied store SHALL replace it. A store SHALL persist a record's private bytes exactly as given, without interpreting them.

#### Scenario: Default store is not durable
- **WHEN** a key manager with no configured store signs a token, and a new key manager with no configured store is constructed
- **THEN** the new manager does not publish the first manager's key

#### Scenario: Consumer store
- **WHEN** a consumer supplies a durable store and restarts the process
- **THEN** the key manager reloads the keys from that store

#### Scenario: Private bytes returned unchanged
- **WHEN** a conforming store stores a record whose private bytes are an arbitrary sealed envelope and loads it back
- **THEN** the private bytes are identical to those stored

### Requirement: Signing and verification keys can be supplied without the key manager
Token issuance and verification SHALL obtain signing keys and the verification key set through a key source contract that the key manager implements. A consumer SHALL be able to supply their own key source, such as one backed by an external key service, in place of the key manager.

#### Scenario: External key source
- **WHEN** a consumer supplies a key source backed by an external signing service
- **THEN** tokens are issued and verified with its keys and no key manager is constructed

### Requirement: The clock is injectable
The key manager SHALL read time from a configurable time source, defaulting to the system clock, for key creation times, rotation and housekeeping.

#### Scenario: Controlled time
- **WHEN** a key manager's time source advances by 25 hours
- **THEN** rotation and housekeeping behave as if 25 hours had passed without real waiting

### Requirement: Start is idempotent and construction starts nothing
Construction SHALL start no goroutine. Starting SHALL launch the rotation, reload and housekeeping background work. Starting again SHALL launch nothing and return no error. Cancelling the context given to start SHALL end the background work. Starting again under a fresh context, on a manager that has not been stopped, SHALL relaunch it.

#### Scenario: Constructed but not started
- **WHEN** a key manager is constructed and not started
- **THEN** no goroutine started by the key manager is running

#### Scenario: Double start
- **WHEN** a key manager is started twice and then stopped
- **THEN** no goroutine started by the key manager remains

### Requirement: Stop leaves no goroutine behind
Stopping SHALL signal the background work to end, and SHALL return only after it has ended. When a key generation or store write is in flight, stop SHALL wait for it, so no store write happens after stop returns. Stopping SHALL be idempotent. Stopping a manager that was never started SHALL return immediately, and a later start SHALL launch nothing. Concurrent start and stop SHALL be free of data races and SHALL leave no goroutine behind.

#### Scenario: Clean shutdown
- **WHEN** a key manager is started, its loops run several times, and it is stopped
- **THEN** no goroutine started by the key manager is running when stop returns

#### Scenario: Stop during rotation
- **WHEN** stop is called while a rotation is generating and storing a key
- **THEN** stop returns only after that store write has completed
- **AND** no store write happens after stop returns

#### Scenario: Concurrent start and stop
- **WHEN** start and stop are called concurrently under the race detector
- **THEN** no data race is reported and no goroutine started by the key manager remains

#### Scenario: Stop before start
- **WHEN** a key manager that was never started is stopped and then started
- **THEN** stop returns immediately and start launches no goroutine
