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
A key found in the store for an algorithm the manager was not configured with SHALL be published among the verification keys, so a token another replica signed with it still verifies, and SHALL NOT be made current. Requesting a signer for an algorithm the manager was not configured with SHALL report that none is available.

#### Scenario: A replica publishes another replica's algorithm without adopting it
- **WHEN** a manager configured for RS256 alone starts over a store that also holds an ES256 key
- **THEN** the ES256 key is published among the verification keys, requesting an ES256 signer reports none available, and the ES256 key is not exempt from housekeeping

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
Token issuance and verification SHALL obtain the signing key and the verification keys through a key source contract that the key manager implements. The contract SHALL describe a verification key as its key identifier, its algorithm and its public key, using only standard-library types and this capability's own algorithm names, so that implementing it requires no JOSE library. A consumer SHALL be able to supply their own key source, such as one backed by an external key service, in place of the key manager. Verification keys handed to a caller SHALL be copies of what the source holds: writing to a returned key SHALL NOT change the keys the key manager publishes or the key it signs with.

#### Scenario: External key source
- **WHEN** a consumer supplies a key source backed by an external signing service
- **THEN** tokens are issued and verified with its keys and no key manager is constructed

#### Scenario: A key source implemented without a JOSE library
- **WHEN** a consumer implements the key source contract using only the standard library, returning for each key its identifier, its algorithm and its public key
- **THEN** tokens are issued and verified with those keys, and the implementation imports no JOSE library

#### Scenario: A returned verification key cannot be mutated
- **WHEN** a caller obtains the key manager's verification keys and overwrites the public key material in the key it was given
- **THEN** the key manager still publishes that key unchanged and still verifies tokens signed by it

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
